import { parser } from "@lezer/python";

type Node = ReturnType<typeof parser.parse>["topNode"];
export interface PythonUse {
  kind: "network" | "process" | "read" | "write" | "literal" | "interpreter";
  start: number;
  end: number;
  text: string;
  value?: string;
  dynamic?: boolean;
  shell?: boolean;
  command?: string;
}

export function inspectPython(content: string): { uses: PythonUse[]; issues: string[] } {
  const tree = parser.parse(content);
  const uses: PythonUse[] = [];
  const issues: string[] = [];
  const text = (node: Node): string => content.slice(node.from, node.to);
  const children = (node: Node): Node[] => {
    const result: Node[] = [];
    for (let child = node.firstChild; child; child = child.nextSibling) result.push(child);
    return result;
  };
  const literal = (node: Node | undefined): string | undefined => {
    if (node?.name !== "String") return undefined;
    const match = /^(?:r|u)?(['"])([\s\S]*)\1$/i.exec(text(node));
    // Escapes and triple-quoted literals are left unresolved, not guessed.
    return match && !match[2]!.includes("\\") && !match[2]!.startsWith(match[1]!) ? match[2] : undefined;
  };
  const add = (node: Node, use: Omit<PythonUse, "start" | "end" | "text">): void => {
    uses.push({ ...use, start: node.from, end: node.to, text: text(node) });
  };
  const resolve = (node: Node | undefined, bindings: Map<string, string>): string | undefined => {
    if (!node) return undefined;
    if (node.name === "VariableName") return bindings.get(text(node));
    if (node.name === "MemberExpression") {
      const base = resolve(node.firstChild ?? undefined, bindings);
      return base ? `${base}.${text(node.lastChild!)}` : undefined;
    }
    return undefined;
  };
  const clientType = (node: Node | undefined, bindings: Map<string, string>): string | undefined => {
    if (node?.name !== "CallExpression") return undefined;
    const name = resolve(node.firstChild ?? undefined, bindings);
    return name && /^(?:httpx\.(?:AsyncClient|Client)|requests\.Session)$/.test(name) ? name.split(".")[0] : undefined;
  };
  const visit = (node: Node, bindings: Map<string, string>): void => {
    if (node.type.isError) {
      const message = `Python parse limitation at line ${content.slice(0, node.from).split("\n").length}: invalid or unsupported syntax`;
      if (!issues.includes(message)) issues.push(message);
    }
    const parts = children(node);
    if (node.name === "ImportStatement") {
      const statement = text(node);
      const from = /^from\s+([\w.]+)\s+import\s+([\s\S]+)$/.exec(statement);
      const imports = (from?.[2] ?? statement.replace(/^import\s+/, "")).replace(/[()]/g, "");
      for (const item of imports.split(",")) {
        const match = /^\s*([\w.]+)(?:\s+as\s+(\w+))?\s*$/.exec(item);
        if (!match) continue;
        const name = match[1]!;
        bindings.set(match[2] ?? (from ? name : name.split(".")[0]!), from ? `${from[1]}.${name}` : match[2] ? name : name.split(".")[0]!);
      }
      return;
    }
    if (node.name === "FunctionDefinition" || node.name === "ClassDefinition") {
      const name = parts.find(child => child.name === "VariableName");
      if (name) bindings.set(text(name), "local");
      bindings = new Map(bindings);
      const params = parts.find(child => child.name === "ParamList");
      for (const parameter of params ? children(params) : []) if (parameter.name === "VariableName") bindings.set(text(parameter), "local");
    }
    if (node.name === "WithStatement") {
      for (let i = 0; i < parts.length; i++) {
        if (parts[i]?.name !== "as" || !parts[i + 1]) continue;
        if (parts[i + 1]?.name !== "VariableName") {
          const shadow = (target: Node): void => {
            if (target.name === "VariableName") bindings.set(text(target), "local");
            else for (const child of children(target)) shadow(child);
          };
          shadow(parts[i + 1]!);
          continue;
        }
        const name = text(parts[i + 1]!);
        const type = clientType(parts[i - 1], bindings);
        bindings.set(name, "local");
        if (type) bindings.set(name, type);
      }
    }
    if (node.name === "AssignStatement" && parts[0]?.name === "VariableName") {
      const type = clientType(parts[2], bindings);
      bindings.set(text(parts[0]), "local");
      if (type) bindings.set(text(parts[0]), type);
    }
    if (node.name === "String") add(node, { kind: "literal", value: literal(node) });
    if (node.name === "CallExpression") {
      const name = resolve(node.firstChild ?? undefined, bindings);
      const args = parts.find(child => child.name === "ArgList");
      const positional: Node[] = [];
      const keywords = new Map<string, Node>();
      let argumentParts: Node[] = [];
      const finishArgument = (): void => {
        if (argumentParts[0]?.name === "VariableName" && argumentParts[1]?.name === "AssignOp" && argumentParts[2]) keywords.set(text(argumentParts[0]), argumentParts[2]);
        else if (argumentParts[0]) positional.push(argumentParts[0]);
        argumentParts = [];
      };
      for (const child of args ? children(args) : []) {
        if (child.name === "," || child.name === ")") finishArgument();
        else if (child.name !== "(") argumentParts.push(child);
      }
      const argument = (index: number, keyword: string): Node | undefined => keywords.get(keyword) ?? positional[index];
      const first = literal(argument(0, "args"));
      if (name && /^(?:(?:httpx|requests)\.(?:get|post|put|patch|delete|head|options|request)|urllib\.request\.urlopen)$/.test(name)) {
        add(node, { kind: "network", value: literal(argument(name.endsWith(".request") ? 1 : 0, "url")) });
      }
      if (name && /^(?:subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system)$/.test(name)) {
        const shellOption = keywords.get("shell");
        const shell = name === "os.system" || !!shellOption && text(shellOption) !== "False";
        const dynamic = first === undefined;
        add(node, { kind: "process", dynamic, shell, command: shell ? first : undefined });
      }
      if (!name && node.firstChild?.name === "VariableName" && ["eval", "exec"].includes(text(node.firstChild))) add(node, { kind: "interpreter" });
      if (!name && node.firstChild?.name === "VariableName" && text(node.firstChild) === "open") {
        const file = literal(argument(0, "file"));
        const modeNode = argument(1, "mode");
        const mode = modeNode ? literal(modeNode) : "r";
        if (!mode || mode.startsWith("r") || mode.includes("+")) add(node, { kind: "read", value: file });
        if (!mode || /[wax+]/.test(mode)) add(node, { kind: "write", value: file });
      }
    }
    for (const child of parts) visit(child, bindings);
  };
  visit(tree.topNode, new Map());
  return { uses, issues };
}
