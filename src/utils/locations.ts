import path from "node:path";

import type { Location } from "../types.js";

export function relativePath(root: string, file: string): string {
  const relative = path.relative(root, file).replaceAll("\\", "/");
  return relative || path.basename(file);
}

export function offsetToLineColumn(content: string, offset: number): { line: number; column: number } {
  const safeOffset = Math.max(0, Math.min(offset, content.length));
  const before = content.slice(0, safeOffset);
  const line = before.split("\n").length;
  const lastNewline = before.lastIndexOf("\n");
  return { line, column: safeOffset - lastNewline };
}

export function locationFromOffsets(file: string, content: string, start: number, end: number): Location {
  const from = offsetToLineColumn(content, start);
  const to = offsetToLineColumn(content, Math.max(start, end));
  return {
    file,
    startLine: from.line,
    startColumn: from.column,
    endLine: to.line,
    endColumn: to.column,
  };
}

export function locationForLine(file: string, content: string, lineNumber: number, column = 1, width = 1): Location {
  const lines = content.split("\n");
  const line = Math.max(1, Math.min(lineNumber, lines.length));
  const lineText = lines[line - 1] ?? "";
  const startColumn = Math.max(1, Math.min(column, lineText.length + 1));
  return {
    file,
    startLine: line,
    startColumn,
    endLine: line,
    endColumn: Math.max(startColumn, Math.min(startColumn + Math.max(0, width - 1), lineText.length + 1)),
  };
}

export function findLocation(file: string, content: string, needle: string, fromOffset = 0): Location {
  const index = content.indexOf(needle, Math.max(0, fromOffset));
  if (index === -1) return locationForLine(file, content, 1);
  return locationFromOffsets(file, content, index, index + Math.max(1, needle.length));
}
