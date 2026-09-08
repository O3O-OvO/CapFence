import type { CapabilityKind } from "../types.js";

export function isDynamic(value: string): boolean {
  return /\$\{|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^}]+\}\}|\$\{\{[^}]+\}\}/.test(value);
}

export function redactSecrets(value: string): string {
  return value
    .replace(/ghp_[A-Za-z0-9]{20,}/g, "ghp_[REDACTED]")
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, "github_pat_[REDACTED]")
    .replace(/sk-[A-Za-z0-9_-]{20,}/g, "sk-[REDACTED]")
    .replace(/AKIA[0-9A-Z]{16}/g, "AKIA[REDACTED]")
    .replace(/xox[baprs]-[A-Za-z0-9-]{10,}/g, "xox*-[REDACTED]")
    .replace(/AIza[0-9A-Za-z_-]{30,}/g, "AIza[REDACTED]");
}

export function normalizeScope(value: string, kind?: CapabilityKind): string {
  const normalized = value.trim().replaceAll("\\", "/").replace(/\/+/g, "/");
  if (kind === "network.connect" || kind === "dynamic.execute") return normalized.toLowerCase();
  if (kind === "process.execute") {
    if (/^binary:/i.test(normalized)) return `binary:${normalized.slice(7)}`;
    if (/^(?:shell:[a-z-]+|dynamic-binary|elevated|process|sandbox:disabled)$/i.test(normalized)) return normalized.toLowerCase();
  }
  if (kind === "credential.read") return normalized.replace(/^(?:injected-env|literal):/i, (prefix) => prefix.toLowerCase());
  if ((kind === "filesystem.read" || kind === "filesystem.write") && /^sensitive-path$/i.test(normalized)) return "sensitive-path";
  return normalized;
}

export function clip(value: string, maxLength = 180): string {
  const redacted = redactSecrets(value).replace(/\s+/g, " ").trim();
  return redacted.length <= maxLength ? redacted : `${redacted.slice(0, maxLength - 3)}...`;
}
