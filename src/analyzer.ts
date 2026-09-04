import path from "node:path";

import { discoverFiles, type SourceFile } from "./discovery.js";
import { parseJsonLike, parseYaml, walkValues, type ParsedStructured } from "./parsers.js";
import { locationFromOffsets, locationForLine } from "./utils/locations.js";
import { clip, isDynamic, normalizeScope, redactSecrets } from "./utils/text.js";
import type {
  Capability,
  CapabilityKind,
  Finding,
  Location,
  ScanResult,
  Severity,
} from "./types.js";

interface AnalyzeContext {
  file: string;
  content: string;
  lineOffset?: number;
  columnOffset?: number;
  root: string;
  source: Capability["source"];
  subject?: string;
}

const SENSITIVE_PATHS = /(?:~\/|\$HOME\/|%USERPROFILE%[\\/]|(?:^|[\\/])(?:\.ssh|\.aws|\.config\/gcloud|\.kube|\.docker)[\\/]|(?:^|[\\/])\.env(?:\b|[.]))/i;
const SENSITIVE_ENV = /(?:TOKEN|API[_-]?KEY|SECRET|PASSWORD|PRIVATE[_-]?KEY|CREDENTIAL|AWS_ACCESS_KEY|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)/i;
const TOKEN_PATTERNS: Array<{ re: RegExp; provider: string }> = [
  { re: /ghp_[A-Za-z0-9]{30,}/g, provider: "GitHub token" },
  { re: /github_pat_[A-Za-z0-9_]{30,}/g, provider: "GitHub token" },
  { re: /sk-[A-Za-z0-9_-]{24,}/g, provider: "OpenAI-compatible API key" },
  { re: /AKIA[0-9A-Z]{16}/g, provider: "AWS access key" },
  { re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, provider: "Slack token" },
  { re: /AIza[0-9A-Za-z_-]{30,}/g, provider: "Google API key" },
];
const LIFECYCLE_HOOKS = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
  "postpack",
]);

function addCapability(capabilities: Capability[], context: AnalyzeContext, kind: CapabilityKind, scope: string, evidence: string, location?: Location): Capability {
  const capability: Capability = {
    kind,
    scope: normalizeScope(scope),
    source: context.source,
    location: location ?? locationForLine(context.file, context.content, (context.lineOffset ?? 0) + 1),
    evidence: redactSecrets(clip(evidence)),
    ...(context.subject ? { subject: context.subject } : {}),
  };
  const fingerprint = capabilityFingerprint(capability);
  if (!capabilities.some((item) => capabilityFingerprint(item) === fingerprint)) capabilities.push(capability);
  return capability;
}

export function capabilityFingerprint(capability: Pick<Capability, "kind" | "scope">): string {
  return `${capability.kind}|${normalizeScope(capability.scope)}`;
}

function addFinding(findings: Finding[], id: string, severity: Severity, title: string, message: string, remediation: string, location: Location, evidence: string, capabilities: Capability[]): void {
  const fingerprints = capabilities.map(capabilityFingerprint);
  const key = `${id}|${location.file}|${location.startLine}|${message}`;
  if (findings.some((finding) => `${finding.id}|${finding.location.file}|${finding.location.startLine}|${finding.message}` === key)) return;
  findings.push({
    id,
    severity,
    title,
    message,
    remediation,
    location,
    evidence: redactSecrets(clip(evidence)),
    capabilityFingerprints: fingerprints,
  });
}

function lineLocation(context: AnalyzeContext, index: number, length = 1): Location {
  const base = context.lineOffset ?? 0;
  const columnOffset = context.columnOffset ?? 0;
  const location = locationFromOffsets(context.file, context.content, index, index + Math.max(1, length));
  return {
    ...location,
    startLine: location.startLine + base,
    endLine: location.endLine + base,
    startColumn: location.startColumn + (location.startLine === 1 ? columnOffset : 0),
    endColumn: location.endColumn + (location.endLine === 1 ? columnOffset : 0),
  };
}

function addNetworkCapability(capabilities: Capability[], context: AnalyzeContext, url: string, location: Location): Capability {
  let scope = "dynamic";
  try {
    if (!isDynamic(url)) {
      const parsed = new URL(url);
      scope = `${parsed.protocol.replace(":", "")}|${parsed.host}`;
    }
  } catch {
    if (!isDynamic(url)) scope = normalizeScope(url);
  }
  return addCapability(capabilities, context, "network.connect", scope, url, location);
}

function analyzeCommandText(context: AnalyzeContext, capabilities: Capability[], findings: Finding[]): void {
  const lines = context.content.split(/\r?\n/);
  let offset = 0;
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const rawLine = lines[lineIndex] ?? "";
    const trimmed = rawLine.trim();
    const effective = trimmed.replace(/^\s*(?:#|\/\/|;|::).*/, "");
    if (!effective) {
      offset += rawLine.length + 1;
      continue;
    }
    const current = { ...context, content: rawLine, lineOffset: (context.lineOffset ?? 0) + lineIndex };
    const loc = lineLocation(current, Math.max(0, rawLine.indexOf(trimmed)), Math.max(1, trimmed.length));

    const shell = /\b(?:bash|sh|zsh|dash|busybox\s+sh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\b/i.exec(effective);
    const shellHasC = /\b(?:bash|sh|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\b[^\n]*?(?:^|\s)(?:-c|\/c|-Command|-EncodedCommand|-enc)(?:\s|=)/i.test(effective);
    const dynamic = isDynamic(effective) || /\bINPUT_[A-Z0-9_]+\b|process\.env|github\.event|`[^`]+`/.test(effective);
    if (shell) {
      const shellScope = dynamic || shellHasC ? (dynamic ? "shell:dynamic" : "shell:static") : "shell:static";
      const processCapability = addCapability(capabilities, current, "process.execute", shellScope, trimmed, loc);
      if (shellHasC && dynamic) {
        const dynamicCapability = addCapability(capabilities, current, "dynamic.execute", "shell", trimmed, loc);
        addFinding(findings, "CF-EXEC-001", "high", "Dynamic shell execution", "A shell interpreter receives externally controlled or templated input.", "Use a fixed argument list and validate every value before invoking a shell.", loc, trimmed, [processCapability, dynamicCapability]);
      }
      if (/\b(?:-EncodedCommand|-enc)\b/i.test(effective)) {
        const encoded = addCapability(capabilities, current, "dynamic.execute", "encoded", trimmed, loc);
        addFinding(findings, "CF-DYN-001", "high", "Encoded command execution", "An encoded PowerShell command hides the code that will execute.", "Replace encoded commands with reviewed, versioned scripts.", loc, trimmed, [processCapability, encoded]);
      }
    }

    const evalMatch = /\b(?:eval|Invoke-Expression|iex)\s*(?:\(|\s)/i.exec(effective);
    if (evalMatch) {
      const processCapability = addCapability(capabilities, current, "process.execute", "shell:dynamic", trimmed, loc);
      const dynamicCapability = addCapability(capabilities, current, "dynamic.execute", "interpreter", trimmed, loc);
      addFinding(findings, "CF-EXEC-001", "high", "Dynamic code execution", "Input is passed to a dynamic interpreter.", "Avoid eval-like interpreters; use an allowlisted command or parser.", loc, trimmed, [processCapability, dynamicCapability]);
    }

    const downloadPipe = /\b(?:curl|wget|iwr|irm)\b[^\n|]*\|\s*(?:sh|bash|zsh|pwsh|powershell|python|node)\b/i.exec(effective);
    if (downloadPipe) {
      const network = addNetworkCapability(capabilities, current, (effective.match(/https?:\/\/[^\s|)]+/i)?.[0] ?? "dynamic"), loc);
      const processCapability = addCapability(capabilities, current, "process.execute", "shell:downloaded-script", trimmed, loc);
      const dynamicCapability = addCapability(capabilities, current, "dynamic.execute", "downloaded-script", trimmed, loc);
      addFinding(findings, "CF-EXEC-002", "critical", "Downloaded script piped to an interpreter", "A remote response is executed without a reviewable local artifact.", "Pin and verify a reviewed artifact before executing it; never pipe remote content into a shell.", loc, trimmed, [network, processCapability, dynamicCapability]);
    }

    if (/(?:base64|openssl\s+enc|certutil)[^\n]*(?:-d|decode|--decode)[^\n]*\|[^\n]*(?:sh|bash|pwsh|powershell|node|python)/i.test(effective)) {
      const dynamicCapability = addCapability(capabilities, current, "dynamic.execute", "encoded", trimmed, loc);
      const processCapability = addCapability(capabilities, current, "process.execute", "shell:dynamic", trimmed, loc);
      addFinding(findings, "CF-DYN-001", "high", "Decoded content is executed", "Encoded data is decoded and sent directly to an interpreter.", "Store executable code as reviewed source and verify it before execution.", loc, trimmed, [dynamicCapability, processCapability]);
    }

    const urls = effective.match(/https?:\/\/[^\s'"`)>]+/gi) ?? [];
    for (const url of urls) addNetworkCapability(capabilities, current, url, loc);

    if (SENSITIVE_PATHS.test(effective)) {
      const readCapability = addCapability(capabilities, current, "filesystem.read", "sensitive-path", trimmed, loc);
      if (/\b(?:curl|wget|iwr|irm|nc|netcat|upload|fetch|requests?\.post|axios\.post)\b/i.test(effective) && /(?:@|data|body|--upload-file|--data)/i.test(effective)) {
        const network = addCapability(capabilities, current, "network.connect", "dynamic", trimmed, loc);
        addFinding(findings, "CF-CRED-001", "critical", "Sensitive file sent over the network", "A credential-bearing path is combined with an upload or outbound request.", "Remove the sensitive file from the data path and restrict outbound destinations.", loc, trimmed, [readCapability, network]);
      }
    }

    for (const token of TOKEN_PATTERNS) {
      const match = token.re.exec(effective);
      token.re.lastIndex = 0;
      if (!match) continue;
      const credential = addCapability(capabilities, current, "credential.read", `literal:${token.provider}`, "credential value redacted", loc);
      addFinding(findings, "CF-CRED-002", "critical", "Credential embedded in active content", `${token.provider} material appears in a command or configuration value.`, "Revoke the exposed credential, remove it from source, and inject it through a secret store.", loc, match[0], [credential]);
    }

    if (/\b(?:npx|pnpm\s+dlx|yarn\s+dlx|bunx|uvx|pipx\s+run)\b/i.test(effective)) {
      const runner = effective.match(/\b(?:npx|pnpm\s+dlx|yarn\s+dlx|bunx|uvx|pipx\s+run)\b[^\s]*/i)?.[0] ?? "runner";
      const packageRef = effective.replace(/^.*?\b(?:npx|pnpm\s+dlx|yarn\s+dlx|bunx|uvx|pipx\s+run)\b\s*/i, "").trim().split(/\s+/)[0] ?? "unknown";
      const pinned = /(?:@\d+\.\d+\.\d+(?:[-+][^\s]+)?$|==\d+\.\d+\.\d+$)/.test(packageRef);
      const lifecycle = addCapability(capabilities, current, "package.lifecycle", `${runner}:runtime-fetch`, trimmed, loc);
      if (!pinned && !/--no-install\b/.test(effective)) addFinding(findings, "CF-PKG-001", "medium", "Unpinned package execution", "A package runner may resolve and execute a different version on each run.", "Pin the exact package version and verify its integrity.", loc, trimmed, [lifecycle]);
    }

    if (/\b(?:sudo|doas)\b/i.test(effective)) {
      const elevated = addCapability(capabilities, current, "process.execute", "elevated", trimmed, loc);
      addFinding(findings, "CF-PRIV-001", "critical", "Elevated process execution", "The command requests administrator privileges.", "Drop privileges and grant only the specific capability required by the task.", loc, trimmed, [elevated]);
    }
    offset += rawLine.length + 1;
  }

  const downloadLines = context.content.match(/(?:curl|wget)\s+[^\n]+(?:-o|--output|-O)\s+(\S+)[\s\S]{0,400}?(?:^|\n)\s*(?:sh|bash|chmod\s+\+x)\s+\1/im);
  if (downloadLines?.index !== undefined) {
    const loc = lineLocation(context, downloadLines.index, downloadLines[0].length);
    const network = addCapability(capabilities, context, "network.connect", "dynamic", downloadLines[0], loc);
    const write = addCapability(capabilities, context, "filesystem.write", normalizeScope(downloadLines[1] ?? "download"), downloadLines[0], loc);
    const process = addCapability(capabilities, context, "process.execute", "shell:downloaded-script", downloadLines[0], loc);
    addFinding(findings, "CF-EXEC-003", "high", "Downloaded file is executed", "A downloaded artifact is later executed from the same command flow.", "Verify a pinned checksum before execution and keep downloads outside executable paths.", loc, downloadLines[0], [network, write, process]);
  }
}

function extractMarkdownBlocks(source: SourceFile): Array<{ content: string; lineOffset: number; language: string }> {
  const blocks: Array<{ content: string; lineOffset: number; language: string }> = [];
  const re = /^```([^\r\n]*)\r?\n([\s\S]*?)^```\s*$/gm;
  let match: RegExpExecArray | null;
  while ((match = re.exec(source.content)) !== null) {
    const language = (match[1] ?? "").trim().toLowerCase();
    if (!["sh", "bash", "zsh", "shell", "powershell", "pwsh", "ps1", "cmd", "bat", "dockerfile"].includes(language)) continue;
    const lineOffset = source.content.slice(0, match.index).split(/\r?\n/).length;
    blocks.push({ content: match[2] ?? "", lineOffset, language });
  }
  return blocks;
}

function safeStructuredParse(source: SourceFile): ParsedStructured {
  if (/\.ya?ml$/i.test(source.relativePath)) return parseYaml(source.content);
  return parseJsonLike(source.content);
}

function findValueLocation(source: SourceFile, key: string, value: unknown, fromOffset = 0): Location {
  const needle = typeof value === "string" ? value : key;
  const index = source.content.indexOf(needle, Math.max(0, fromOffset));
  return index === -1
    ? locationForLine(source.relativePath, source.content, 1)
    : locationFromOffsets(source.relativePath, source.content, index, index + Math.max(1, needle.length));
}

function findServerOffset(source: SourceFile, name: string, fromOffset: number): number {
  const start = Math.max(0, fromOffset);
  for (const quote of ['"', "'"]) {
    const index = source.content.indexOf(`${quote}${name}${quote}`, start);
    if (index !== -1) return index;
  }
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const keyPattern = new RegExp(`(?:^|\\r?\\n)[\\t ]*(?:[\\"']?${escaped}[\\"']?)\\s*:`, "g");
  keyPattern.lastIndex = start;
  const match = keyPattern.exec(source.content);
  return match?.index ?? -1;
}

function analyzeMcpObject(source: SourceFile, value: unknown, capabilities: Capability[], findings: Finding[], subjectPrefix: string, fromOffset = 0): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) return;
  for (const [name, raw] of Object.entries(value as Record<string, unknown>)) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const server = raw as Record<string, unknown>;
    const subject = `${subjectPrefix}:${name}`;
    const serverOffset = findServerOffset(source, name, fromOffset);
    const serverStart = serverOffset === -1 ? fromOffset : serverOffset;
    const context: AnalyzeContext = { file: source.relativePath, content: source.content, root: path.dirname(source.absolutePath), source: "configuration", subject };
    const command = typeof server.command === "string" ? server.command : undefined;
    const args = Array.isArray(server.args) ? server.args.filter((arg): arg is string => typeof arg === "string") : [];
    if (command) {
      const commandText = [command, ...args].join(" ");
      const dynamicArgument = args.find((arg) => isDynamic(arg));
      const commandLocation = findValueLocation(source, "command", command, serverStart);
      const loc = dynamicArgument ? findValueLocation(source, "args", dynamicArgument, serverStart) : commandLocation;
      const dynamicCommand = isDynamic(commandText);
      const processScope = dynamicCommand ? "dynamic-binary" : `binary:${command}`;
      addCapability(capabilities, context, "process.execute", processScope, commandText, loc);
      if (dynamicCommand) {
        const process = addCapability(capabilities, context, "process.execute", "dynamic-binary", commandText, loc);
        addFinding(findings, "CF-MCP-001", "high", "Dynamic MCP server command", "The MCP server executable or arguments contain a template or runtime variable.", "Resolve the executable from a fixed, reviewed configuration and validate arguments.", loc, commandText, [process]);
      }
      analyzeCommandText({ ...context, content: commandText, lineOffset: loc.startLine - 1, columnOffset: loc.startColumn - 1 }, capabilities, findings);
    }
    if (typeof server.url === "string") {
      const loc = findValueLocation(source, "url", server.url, serverStart);
      const network = addNetworkCapability(capabilities, context, server.url, loc);
      try {
        const parsed = new URL(server.url);
        if (parsed.protocol === "http:" && !["localhost", "127.0.0.1", "::1"].includes(parsed.hostname)) {
          addFinding(findings, "CF-MCP-001", "high", "Remote MCP endpoint uses plain HTTP", "A remote MCP endpoint is configured without transport encryption.", "Use HTTPS or restrict the endpoint to loopback during local development.", loc, server.url, [network]);
        }
      } catch {
        if (isDynamic(server.url)) {
          addFinding(findings, "CF-MCP-001", "high", "Dynamic MCP endpoint", "The MCP endpoint host is resolved at runtime and cannot be reviewed statically.", "Use a fixed HTTPS endpoint or make the allowed host explicit in policy.", loc, server.url, [network]);
        }
      }
    }
    for (const [key, rawValue] of Object.entries(server.env ?? {})) {
      if (SENSITIVE_ENV.test(key)) {
        const loc = findValueLocation(source, key, rawValue, serverStart);
        addCapability(capabilities, context, "credential.read", `injected-env:${key}`, `${key}=<injected>`, loc);
        if (typeof rawValue === "string" && TOKEN_PATTERNS.some(({ re }) => re.test(rawValue))) {
          for (const token of TOKEN_PATTERNS) token.re.lastIndex = 0;
          const credential = addCapability(capabilities, context, "credential.read", `literal:${key}`, "credential value redacted", loc);
          addFinding(findings, "CF-CRED-002", "critical", "Credential embedded in MCP configuration", `A credential value is embedded in the MCP server environment for ${key}.`, "Replace the literal with a secret reference and rotate the exposed value.", loc, `${key}=<redacted>`, [credential]);
        }
      }
    }
    if (typeof server.envFile === "string") {
      const loc = findValueLocation(source, "envFile", server.envFile, serverStart);
      if (SENSITIVE_PATHS.test(server.envFile)) addCapability(capabilities, context, "filesystem.read", "sensitive-path", server.envFile, loc);
    }
    if (typeof server.cwd === "string") {
      const loc = findValueLocation(source, "cwd", server.cwd, serverStart);
      addCapability(capabilities, context, "filesystem.read", server.cwd, server.cwd, loc);
    }
    if (server.sandbox === false || server.allowedDomains === "*" || server.allowedDomains === undefined && server.network === "any") {
      const loc = findValueLocation(source, "sandbox", server.sandbox, serverStart);
      addCapability(capabilities, context, "process.execute", "sandbox:disabled", "sandbox disabled", loc);
    }
  }
}

function analyzeStructured(source: SourceFile, capabilities: Capability[], findings: Finding[], analysisLimited: ScanResult["analysisLimited"]): void {
  const parsed = safeStructuredParse(source);
  if (parsed.issues.length > 0) {
    analysisLimited.push({ file: source.relativePath, message: parsed.issues.map((issue) => issue.message).join("; ") });
    return;
  }
  const value = parsed.value;
  if (/package\.json$/i.test(source.relativePath)) {
    const scripts = (value && typeof value === "object" ? (value as Record<string, unknown>).scripts : undefined);
    if (scripts && typeof scripts === "object" && !Array.isArray(scripts)) {
      for (const [hook, script] of Object.entries(scripts as Record<string, unknown>)) {
        if (!LIFECYCLE_HOOKS.has(hook) || typeof script !== "string") continue;
        const context: AnalyzeContext = { file: source.relativePath, content: script, root: path.dirname(source.absolutePath), source: "lifecycle", subject: `package:${hook}` };
        const loc = findValueLocation(source, hook, script);
        addCapability(capabilities, context, "package.lifecycle", hook, script, loc);
        analyzeCommandText({ ...context, lineOffset: loc.startLine - 1 }, capabilities, findings);
      }
    }
  }
  const roots: Array<{ key: string; value: unknown }> = [];
  walkValues(value, (child, keyPath) => {
    const key = keyPath.at(-1) ?? "";
    if (["mcpServers", "servers"].includes(key) && child && typeof child === "object") roots.push({ key, value: child });
    if (keyPath.join(".") === "customizations.vscode.mcp.servers" && child && typeof child === "object") roots.push({ key: "vscode.mcp.servers", value: child });
  });
  for (const root of roots) {
    const rootOffset = source.content.indexOf(`\"${root.key}\"`);
    analyzeMcpObject(source, root.value, capabilities, findings, `mcp:${root.key}`, rootOffset);
  }
}

function analyzeSource(source: SourceFile, root: string, capabilities: Capability[], findings: Finding[], analysisLimited: ScanResult["analysisLimited"]): void {
  const file = source.relativePath;
  if (/\.(md|markdown)$/i.test(file)) {
    for (const block of extractMarkdownBlocks(source)) analyzeCommandText({ file, content: block.content, lineOffset: block.lineOffset, root, source: "instruction" }, capabilities, findings);
    return;
  }
  if (/\.jsonc?$|\.ya?ml$/i.test(file)) {
    analyzeStructured(source, capabilities, findings, analysisLimited);
    return;
  }
  if (/Dockerfile|\.dockerfile$/i.test(path.basename(file))) {
    analyzeCommandText({ file, content: source.content, root, source: "build" }, capabilities, findings);
    if (/--privileged|--pid=host|--network=host|--cap-add(?:=|\s+)SYS_ADMIN|\.\.\/var\/run\/docker\.sock|security=insecure/i.test(source.content)) {
      const match = /--privileged|--pid=host|--network=host|--cap-add(?:=|\s+)SYS_ADMIN|docker\.sock|security=insecure/i.exec(source.content);
      const loc = match ? lineLocation({ file, content: source.content, root, source: "build" }, match.index ?? 0, match[0].length) : locationForLine(file, source.content, 1);
      const elevated = addCapability(capabilities, { file, content: source.content, root, source: "build" }, "process.execute", "elevated", match?.[0] ?? "privileged", loc);
      addFinding(findings, "CF-PRIV-001", "critical", "Container privilege boundary weakened", "The container configuration requests host-level or privileged access.", "Remove the privileged option and grant the smallest required capability.", loc, match?.[0] ?? "privileged", [elevated]);
    }
    return;
  }
  if (/\.(sh|bash|zsh|ps1|cmd|bat)$/i.test(file) || /^#!.*\b(?:sh|bash|zsh|pwsh|powershell)\b/m.test(source.content.slice(0, 160))) {
    analyzeCommandText({ file, content: source.content, root, source: "runtime" }, capabilities, findings);
    return;
  }
  if (/\.(js|mjs|cjs|ts|mts|cts|py)$/i.test(file)) {
    const context: AnalyzeContext = { file, content: source.content, root, source: "runtime" };
    const lines = source.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? "";
      if (/^\s*(?:\/\/|#|\*)/.test(line)) continue;
      const current = { ...context, content: line, lineOffset: i };
      const loc = lineLocation(current, 0, Math.max(1, line.length));
      const processApi = /(?:child_process\.)?(?:exec|execFile|spawn|spawnSync)\s*\(/i.test(line)
        || /(?:subprocess\.(?:run|popen|call|check_call|check_output)|os\.system)\s*\(/i.test(line);
      if (processApi) {
        const dynamic = isDynamic(line) || /process\.env|os\.environ|\b(?:input|args|command|prompt)\b/i.test(line);
        const process = addCapability(capabilities, current, "process.execute", dynamic ? "shell:dynamic" : "process", line, loc);
        if (dynamic) {
          const dyn = addCapability(capabilities, current, "dynamic.execute", "process-input", line, loc);
          addFinding(findings, "CF-EXEC-001", "high", "Dynamic process execution", "A process API is called with a value that appears to be externally controlled.", "Use an allowlisted executable and pass structured arguments without a shell.", loc, line, [process, dyn]);
        }
      }
      if (SENSITIVE_PATHS.test(line) && /(?:readFile|read_text|open\s*\(|cat\s+)/i.test(line)) addCapability(capabilities, current, "filesystem.read", "sensitive-path", line, loc);
      if (/(?:fetch|axios\.(?:get|post|put|delete)|requests?\.(?:get|post|put|delete)|urllib\.request\.urlopen|http\.request)\s*\(/i.test(line)) {
        const url = line.match(/https?:\/\/[^\s'"`)>]+/i)?.[0];
        if (url) addNetworkCapability(capabilities, current, url, loc);
        else addCapability(capabilities, current, "network.connect", isDynamic(line) ? "dynamic" : "runtime", line, loc);
      }
      analyzeCommandText(current, capabilities, findings);
    }
  }
}

export function scanTarget(target: string): ScanResult {
  const discovered = discoverFiles(target);
  const capabilities: Capability[] = [];
  const findings: Finding[] = [];
  const analysisLimited: ScanResult["analysisLimited"] = [];
  for (const source of discovered.files) analyzeSource(source, discovered.root, capabilities, findings, analysisLimited);
  return {
    schemaVersion: 1,
    target: path.resolve(target),
    scannedFiles: discovered.files.length,
    capabilities,
    findings,
    analysisLimited,
  };
}
