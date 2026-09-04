import { parse as parseJsonc, ParseError, parseTree, Node as JsonNode } from "jsonc-parser";
import { parseDocument, YAMLParseError, isMap, isSeq, type Document, type YAMLMap, type Pair } from "yaml";

export interface ParseIssue {
  message: string;
  offset?: number;
  line?: number;
}

export interface ParsedStructured {
  value: unknown;
  tree?: JsonNode;
  document?: Document;
  issues: ParseIssue[];
}

export function parseJsonLike(content: string): ParsedStructured {
  const errors: ParseError[] = [];
  const value = parseJsonc(content, errors, { allowTrailingComma: true, disallowComments: false });
  const tree = errors.length === 0 ? parseTree(content, errors, { allowTrailingComma: true, disallowComments: false }) : undefined;
  return {
    value,
    tree,
    issues: errors.map((error) => ({ message: `JSON parse error (${error.error})`, offset: error.offset })),
  };
}

export function parseYaml(content: string): ParsedStructured {
  const document = parseDocument(content, { prettyErrors: false, strict: false });
  const issues = document.errors.map((error: YAMLParseError) => ({ message: error.message, line: error.pos[0] }));
  return { value: document.toJS(), document, issues };
}

export function objectEntries(value: unknown): Array<[string, unknown]> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, unknown>);
}

export function walkValues(value: unknown, visit: (value: unknown, keyPath: string[]) => void, keyPath: string[] = []): void {
  visit(value, keyPath);
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkValues(item, visit, [...keyPath, String(index)]));
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      walkValues(child, visit, [...keyPath, key]);
    }
  }
}

export function getPath(value: unknown, path: string[]): unknown {
  let current = value;
  for (const part of path) {
    if (!current || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

export function yamlMapEntries(node: unknown): Array<{ key: string; value: unknown }> {
  if (!isMap(node)) return [];
  return (node as YAMLMap).items.flatMap((item: Pair<unknown, unknown>) => {
    const keyNode = item.key as { value?: unknown } | null | undefined;
    const key = typeof keyNode?.value === "string" ? keyNode.value : String(keyNode?.value ?? "");
    return [{ key, value: item.value }];
  });
}

export function isYamlMapNode(node: unknown): boolean {
  return isMap(node);
}

export function isYamlSequenceNode(node: unknown): boolean {
  return isSeq(node);
}
