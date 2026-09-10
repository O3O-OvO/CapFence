import type { CapabilityChange, PermissionSummary, PermissionSummaryEntry, PolicyResult, ScanResult, Severity } from "./types.js";
import { summarizeFindings } from "./reporters.js";
import { normalizeScope } from "./utils/text.js";

const changeWeight: Record<PermissionSummaryEntry["type"], number> = { policy: 0, added: 1, widened: 2, removed: 3 };
const severityWeight: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function capabilityText(kind: string, scope: string): string {
  return `${kind}:${scope}`;
}

export function buildPermissionSummary(result: ScanResult, changes: CapabilityChange[] = [], policy?: PolicyResult, hasBaseline = false): PermissionSummary {
  const entries: PermissionSummaryEntry[] = [];
  const provenance = (kind: PermissionSummaryEntry["capability"], scope: string) => {
    const sources = result.capabilities.filter((item) => item.kind === kind && normalizeScope(item.scope, kind) === normalizeScope(scope, kind));
    const source = sources[0];
    return { locations: sources.map((item) => ({ ...item.location })), ...(source ? { source: source.source, subject: source.subject, evidence: source.evidence } : {}) };
  };
  for (const change of changes) {
    const capability = change.current ?? change.previous?.[0];
    if (!capability) continue;
    entries.push({ type: change.type, capability: capability.kind, scope: capability.scope, ...provenance(capability.kind, capability.scope) });
  }
  for (const violation of policy?.violations ?? []) {
    entries.push({ type: "policy", capability: violation.capability.kind, scope: violation.capability.scope, severity: violation.severity, reason: violation.reason, ...provenance(violation.capability.kind, violation.capability.scope) });
  }
  entries.sort((a, b) => changeWeight[a.type] - changeWeight[b.type] || (severityWeight[b.severity ?? "info"] - severityWeight[a.severity ?? "info"]) || capabilityText(a.capability, a.scope).localeCompare(capabilityText(b.capability, b.scope)));
  return {
    schemaVersion: 1,
    target: result.target,
    baseline: hasBaseline,
    scannedFiles: result.scannedFiles,
    excludedPaths: result.excludedPaths,
    analysisLimited: result.analysisLimited.map((item) => ({ ...item })),
    changes: {
      added: changes.filter((change) => change.type === "added").length,
      widened: changes.filter((change) => change.type === "widened").length,
      removed: changes.filter((change) => change.type === "removed").length,
    },
    findings: summarizeFindings(result),
    policyViolations: policy?.violations.length ?? 0,
    entries,
  };
}

export function formatPermissionSummaryJson(summary: PermissionSummary): string {
  return JSON.stringify(summary, null, 2);
}

function escapeMarkdown(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replace(/[\\`*_{}\[\]()#+!|~\-]/g, (character) => `&#${character.charCodeAt(0)};`)
    .replace(/\r\n|\r|\n/g, "<br>");
}

export function formatPermissionSummaryMarkdown(summary: PermissionSummary): string {
  const changed = summary.changes.added + summary.changes.widened;
  const limited = summary.analysisLimited ?? [];
  const status = limited.length > 0 ? "Warning: analysis incomplete; results may omit capabilities or findings"
    : changed > 0 || summary.policyViolations > 0 ? "Permission changes or policy violations detected"
    : summary.baseline ? "No new permission changes detected" : "No baseline provided; permission changes not assessed";
  const lines = ["## CapFence permission summary", "", `**Target:** ${escapeMarkdown(summary.target)}`, `**Baseline:** ${summary.baseline ? "yes" : "not provided"}`, `**Files scanned:** ${summary.scannedFiles ?? "unknown"}`, `**Status:** ${status}`, "", `Changes: **${summary.changes.added} added**, **${summary.changes.widened} widened**, **${summary.changes.removed} removed**.`];
  if (summary.excludedPaths?.length) lines.push(`Excluded paths: ${escapeMarkdown(JSON.stringify(summary.excludedPaths))}`);
  if (summary.entries.length > 0) {
    lines.push("", "| Type | Capability | Scope | Source | Locations | Severity | Reason |", "| --- | --- | --- | --- | --- | --- | --- |");
    for (const entry of summary.entries) {
      const locations = (entry.locations ?? []).map((location) => `${location.file}:${location.startLine}:${location.startColumn}`).join("\n");
      const cells = [entry.type, entry.capability, entry.scope, entry.source ?? "-", locations || "-", entry.severity ?? "-", entry.reason ?? "-"];
      lines.push(`| ${cells.map(escapeMarkdown).join(" | ")} |`);
    }
  } else lines.push("", summary.baseline && limited.length === 0 ? "No capability changes or policy violations." : "No capability change or policy violation entries reported.");
  if (limited.length > 0) {
    lines.push("", "### Analysis limited", "", "Warning: this scan is incomplete. Absence of findings does not establish a clean result.", "", "| File | Diagnostic |", "| --- | --- |");
    for (const item of limited) lines.push(`| ${escapeMarkdown(item.file)} | ${escapeMarkdown(item.message)} |`);
  }
  if (summary.policyViolations > 0) lines.push("", `Policy violations: **${summary.policyViolations}**.`);
  const findingTotal = Object.values(summary.findings).reduce((total, count) => total + count, 0);
  lines.push("", `Findings: **${findingTotal}** total (${summary.findings.critical} critical, ${summary.findings.high} high, ${summary.findings.medium} medium, ${summary.findings.low} low, ${summary.findings.info} info).`);
  return lines.join("\n");
}
