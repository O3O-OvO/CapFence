import ts from "typescript";

export interface JavaScriptUse {
  kind: "process" | "network" | "read" | "literal" | "interpreter";
  start: number;
  end: number;
  text: string;
  value?: string;
  dynamic?: boolean;
  command?: string;
}

type Binding = { module: string; member?: string };

function commandExecutable(command: string | undefined): string | undefined {
  if (!command) return undefined;
  // Recognize only a literal leading executable; shell expansions stay unresolved.
  const match = /^\s*(?:"([^"$`%]+)"|'([^'$`%]+)'|([A-Za-z0-9_./\\:-]+))(?=\s|$)/.exec(command);
  return match?.[1] ?? match?.[2] ?? match?.[3];
}
const processMethods = new Set(["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"]);
const networkMethods = new Set(["get", "post", "put", "patch", "delete", "head", "options", "request"]);

function literal(node: ts.Expression | undefined): string | undefined {
  if (!node) return undefined;
  if (ts.isStringLiteralLike(node)) return node.text;
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node)) return literal(node.expression);
  return undefined;
}

export function inspectJavaScript(file: string, content: string): { uses: JavaScriptUse[]; issues: string[] } {
  const source = ts.createSourceFile(file, content, ts.ScriptTarget.Latest, true, /\.(?:ts|mts|cts)$/i.test(file) ? ts.ScriptKind.TS : ts.ScriptKind.JS);
  // A single-file, no-resolution program supplies lexical symbols without loading dependencies.
  const host: ts.CompilerHost = {
    getSourceFile: (name) => name === file ? source : undefined,
    getDefaultLibFileName: () => "", writeFile: () => {}, getCurrentDirectory: () => "",
    getDirectories: () => [], fileExists: (name) => name === file,
    readFile: (name) => name === file ? content : undefined,
    getCanonicalFileName: (name) => name, useCaseSensitiveFileNames: () => true, getNewLine: () => "\n",
  };
  const program = ts.createProgram([file], { noLib: true, noResolve: true, allowJs: true }, host);
  const checker = program.getTypeChecker();
  const bindings = new Map<ts.Symbol, Binding>();
  const bind = (name: ts.Node, binding: Binding): void => {
    const symbol = checker.getSymbolAtLocation(name);
    if (symbol) bindings.set(symbol, binding);
  };
  const requiredModule = (node: ts.Expression | undefined): string | undefined => {
    if (!node || !ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== "require" || checker.getSymbolAtLocation(node.expression)?.declarations?.length) return undefined;
    return literal(node.arguments[0])?.replace(/^node:/, "");
  };
  const collect = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && node.importClause && !node.importClause.isTypeOnly) {
      const module = node.moduleSpecifier.text.replace(/^node:/, "");
      if (node.importClause.name) bind(node.importClause.name, { module });
      const named = node.importClause.namedBindings;
      if (named && ts.isNamespaceImport(named)) bind(named.name, { module });
      if (named && ts.isNamedImports(named)) for (const item of named.elements) {
        if (!item.isTypeOnly) bind(item.name, { module, member: (item.propertyName ?? item.name).text });
      }
    }
    if (ts.isVariableDeclaration(node)) {
      let module = requiredModule(node.initializer);
      let member: string | undefined;
      if (!module && node.initializer && ts.isPropertyAccessExpression(node.initializer)) {
        module = requiredModule(node.initializer.expression);
        member = node.initializer.name.text;
      }
      if (module && ts.isIdentifier(node.name)) bind(node.name, { module, member });
      if (module && ts.isObjectBindingPattern(node.name)) for (const item of node.name.elements) {
        if (!item.dotDotDotToken && ts.isIdentifier(item.name)) bind(item.name, { module, member: item.propertyName && ts.isIdentifier(item.propertyName) ? item.propertyName.text : item.name.text });
      }
    }
    ts.forEachChild(node, collect);
  };
  collect(source);
  const resolve = (node: ts.Expression): Binding | undefined => {
    if (ts.isIdentifier(node)) {
      const symbol = checker.getSymbolAtLocation(node);
      return symbol ? bindings.get(symbol) : undefined;
    }
    if (ts.isPropertyAccessExpression(node)) {
      const base = resolve(node.expression);
      if (base && !base.member) return { ...base, member: node.name.text };
    }
    if (ts.isElementAccessExpression(node)) {
      const base = resolve(node.expression);
      const member = literal(node.argumentExpression);
      if (base && !base.member && member) return { ...base, member };
    }
    const module = requiredModule(node);
    return module ? { module } : undefined;
  };
  const uses: JavaScriptUse[] = [];
  const add = (node: ts.Node, use: Omit<JavaScriptUse, "start" | "end" | "text">): void => {
    uses.push({ ...use, start: node.getStart(source), end: node.end, text: node.getText(source) });
  };
  const visit = (node: ts.Node): void => {
    if (ts.isStringLiteralLike(node) && !ts.isImportDeclaration(node.parent)) add(node, { kind: "literal", value: node.text });
    if ((ts.isCallExpression(node) || ts.isNewExpression(node)) && ts.isIdentifier(node.expression)
      && (node.expression.text === "Function" || ts.isCallExpression(node) && node.expression.text === "eval")
      && !checker.getSymbolAtLocation(node.expression)) {
      add(node, { kind: "interpreter" });
    }
    if (ts.isCallExpression(node)) {
      const binding = resolve(node.expression);
      const first = literal(node.arguments[0]);
      if (binding?.module === "child_process" && processMethods.has(binding.member ?? "")) {
        const shellCommand = binding.member === "exec" || binding.member === "execSync";
        const args = node.arguments[1];
        const values = args && ts.isArrayLiteralExpression(args) ? args.elements.map((item) => literal(item)) : [];
        const optionsOrCallback = args && (ts.isObjectLiteralExpression(args)
          || binding.member === "execFile" && (ts.isArrowFunction(args) || ts.isFunctionExpression(args)));
        const options = optionsOrCallback && args && ts.isObjectLiteralExpression(args) ? args : node.arguments[2];
        const shellEnabled = options && ts.isObjectLiteralExpression(options) && options.properties.some((property) => {
          if (ts.isSpreadAssignment(property)) return true;
          const name = property.name && (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) ? property.name.text : undefined;
          return name === "shell" && (!ts.isPropertyAssignment(property) || property.initializer.kind !== ts.SyntaxKind.FalseKeyword);
        });
        const dynamic = first === undefined || !!shellEnabled || (!shellCommand && !!args && !optionsOrCallback
          && (!ts.isArrayLiteralExpression(args) || values.some((value) => value === undefined)));
        // Only command-string APIs and known shell executables expose command text to shell rules.
        const shell = first !== undefined && /(?:^|[\\/])(?:ba|z|da)?sh$|(?:^|[\\/])(?:pwsh|powershell|cmd)(?:\.exe)?$/i.test(first);
        add(node, { kind: "process", value: shellCommand ? commandExecutable(first) : first, dynamic, command: shellCommand ? first : shell && !dynamic ? [first, ...values].join(" ") : undefined });
      }
      const globalFetch = ts.isIdentifier(node.expression) && node.expression.text === "fetch" && !checker.getSymbolAtLocation(node.expression);
      if (globalFetch || binding?.module === "axios" && (!binding.member || networkMethods.has(binding.member)) || (binding?.module === "http" || binding?.module === "https") && ["get", "request"].includes(binding.member ?? "")) {
        add(node, { kind: "network", value: first, dynamic: first === undefined });
      }
      if ((binding?.module === "fs" || binding?.module === "fs/promises") && ["readFile", "readFileSync", "open", "openSync"].includes(binding.member ?? "")) add(node, { kind: "read", value: first });
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  const issues = program.getSyntacticDiagnostics(source).map((diagnostic) => {
    const line = source.getLineAndCharacterOfPosition(diagnostic.start ?? 0).line + 1;
    return `JavaScript/TypeScript syntax error at line ${line} (TS${diagnostic.code})`;
  });
  return { uses, issues };
}
