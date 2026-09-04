import fs from "node:fs";
import path from "node:path";

export interface SourceFile {
  absolutePath: string;
  relativePath: string;
  content: string;
}

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  ".venv",
  "venv",
  "__pycache__",
]);

const SUPPORTED_EXTENSIONS = new Set([
  ".md",
  ".markdown",
  ".json",
  ".jsonc",
  ".yaml",
  ".yml",
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".mts",
  ".cts",
  ".py",
  ".sh",
  ".bash",
  ".zsh",
  ".ps1",
  ".cmd",
  ".bat",
  ".dockerfile",
]);

const SUPPORTED_NAMES = new Set([
  "SKILL.md",
  "AGENTS.md",
  "CLAUDE.md",
  "Dockerfile",
  "dockerfile",
  "package.json",
  "mcp.json",
  "mcp.jsonc",
  "mcp.yaml",
  "mcp.yml",
]);

export interface DiscoveryOptions {
  maxFileBytes?: number;
}

function isSupportedFile(filePath: string, content: string): boolean {
  const name = path.basename(filePath);
  if (SUPPORTED_NAMES.has(name)) return true;
  if (SUPPORTED_EXTENSIONS.has(path.extname(name).toLowerCase())) return true;
  return /^(?:#!.*\b(?:sh|bash|zsh|pwsh|powershell)\b)/.test(content.slice(0, 160));
}

export function isSupportedPath(filePath: string, content = ""): boolean {
  return isSupportedFile(filePath, content);
}

function readSource(root: string, filePath: string, maxFileBytes: number): SourceFile | undefined {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    return undefined;
  }
  if (!stat.isFile() || stat.size > maxFileBytes) return undefined;
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch {
    return undefined;
  }
  if (!isSupportedFile(filePath, content)) return undefined;
  return {
    absolutePath: filePath,
    relativePath: path.relative(root, filePath).replaceAll("\\", "/") || path.basename(filePath),
    content,
  };
}

export function discoverFiles(target: string, options: DiscoveryOptions = {}): { root: string; files: SourceFile[] } {
  const maxFileBytes = options.maxFileBytes ?? 2 * 1024 * 1024;
  const absoluteTarget = path.resolve(target);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(absoluteTarget);
  } catch {
    throw new Error(`Target not found: ${target}`);
  }

  if (stat.isFile()) {
    const root = path.dirname(absoluteTarget);
    const source = readSource(root, absoluteTarget, maxFileBytes);
    return { root, files: source ? [source] : [] };
  }
  if (!stat.isDirectory()) throw new Error(`Target is not a file or directory: ${target}`);

  const files: SourceFile[] = [];
  function walk(directory: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) walk(fullPath);
        continue;
      }
      const source = readSource(absoluteTarget, fullPath, maxFileBytes);
      if (source) files.push(source);
    }
  }
  walk(absoluteTarget);
  files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  return { root: absoluteTarget, files };
}
