import fs from "node:fs";
import path from "node:path";

export interface SourceFile {
  absolutePath: string;
  relativePath: string;
  content: string;
}

const IGNORED_DIRECTORIES = new Set([
  ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "coverage",
  ".next", ".nuxt", ".venv", "venv", "__pycache__",
]);
const SUPPORTED_EXTENSIONS = new Set([
  ".md", ".markdown", ".json", ".jsonc", ".yaml", ".yml", ".js", ".mjs", ".cjs",
  ".ts", ".mts", ".cts", ".py", ".sh", ".bash", ".zsh", ".ps1", ".cmd", ".bat", ".dockerfile",
]);
const SUPPORTED_NAMES = new Set(["SKILL.md", "AGENTS.md", "CLAUDE.md", "Dockerfile", "dockerfile", "package.json", "mcp.json", "mcp.jsonc", "mcp.yaml", "mcp.yml"]);

export interface DiscoveryIssue {
  file: string;
  message: string;
}

export interface DiscoveryOptions {
  maxFileBytes?: number;
  onIssue?: (issue: DiscoveryIssue) => void;
}

export function isSupportedPath(filePath: string, content = ""): boolean {
  const name = path.basename(filePath);
  return SUPPORTED_NAMES.has(name) || SUPPORTED_EXTENSIONS.has(path.extname(name).toLowerCase())
    || /^(?:#!.*\b(?:sh|bash|zsh|pwsh|powershell)\b)/.test(content.slice(0, 160));
}

export function iterateFiles(target: string, options: DiscoveryOptions = {}): { root: string; files: Iterable<SourceFile> } {
  const maxFileBytes = options.maxFileBytes ?? 2 * 1024 * 1024;
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1) throw new Error("maxFileBytes must be a positive integer");
  const absoluteTarget = path.resolve(target);
  let stat: fs.Stats;
  try { stat = fs.lstatSync(absoluteTarget); }
  catch { throw new Error(`Target not found: ${target}`); }
  if (!stat.isFile() && !stat.isDirectory()) throw new Error(`Target is not a file or directory: ${target}`);
  const root = stat.isFile() ? path.dirname(absoluteTarget) : absoluteTarget;
  const relative = (file: string): string => path.relative(root, file).replaceAll("\\", "/") || path.basename(file);
  const issue = (file: string, message: string): void => options.onIssue?.({ file: relative(file), message });

  function readSource(file: string): SourceFile | undefined {
    let info: fs.Stats;
    try { info = fs.lstatSync(file); }
    catch { issue(file, "Unable to inspect file."); return; }
    if (!info.isFile()) return;
    if (info.size > maxFileBytes) {
      if (isSupportedPath(file) || !path.extname(file) || file === absoluteTarget) issue(file, `File exceeds ${maxFileBytes} byte analysis limit.`);
      return;
    }
    let content: string;
    try { content = fs.readFileSync(file, "utf8"); }
    catch { issue(file, "Unable to read file."); return; }
    if (!isSupportedPath(file, content)) return;
    return { absolutePath: file, relativePath: relative(file), content };
  }

  function* walk(directory: string): Generator<SourceFile> {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(directory, { withFileTypes: true }); }
    catch { issue(directory, "Unable to read directory."); return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const file = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        issue(file, "Symbolic link was not followed.");
      } else if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) yield* walk(file);
      } else {
        const source = readSource(file);
        if (source) yield source;
      }
    }
  }

  function* singleFile(): Generator<SourceFile> {
    const source = readSource(absoluteTarget);
    if (source) yield source;
    else if (!isSupportedPath(absoluteTarget)) issue(absoluteTarget, "Target is not a supported source file.");
  }
  return { root, files: stat.isFile() ? singleFile() : walk(absoluteTarget) };
}

// Retain the materialized API for callers that need random access to source files.
export function discoverFiles(target: string, options: DiscoveryOptions = {}): { root: string; files: SourceFile[] } {
  const discovered = iterateFiles(target, options);
  return { root: discovered.root, files: [...discovered.files].sort((a, b) => a.relativePath.localeCompare(b.relativePath)) };
}
