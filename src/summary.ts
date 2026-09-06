import type { CapabilityChange, PermissionSummary, PermissionSummaryEntry, PolicyResult, ScanResult, Severity } from "./types.js";
import { summarizeFindings } from "./reporters.js";

const changeWeight: Record<PermissionSummaryEntry["type"], number> = { policy: 0, added: 1, widened: 2, removed: 3 };
const severityWeight: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function capabilityText(kind: string, scope: string): string {
  return `${kind}:${scope}`;
}

export function buildPermissionSummary(result: ScanResult, changes: CapabilityChange[] = [], policy?: PolicyResult): PermissionSummary {
  const entries: PermissionSummaryEntry[] = [];
  for (const change of changes) {
    const capability = change.current ?? change.previous?.[0];
    if (!capability) continue;
    const source = result.capabilities.find((item) => item.kind === capability.kind && item.scope === capability.scope);
    entries.push({ type: change.type, capability: capability.kind, scope: capability.scope, ...(source ? { source: source.source, subject: source.subject, evidence: source.evidence } : {}) });
  }
  for (const violation of policy?.violations ?? []) {
    const source = result.capabilities.find((item) => item.kind === violation.capability.kind && item.scope === violation.capability.scope);
    entries.push({ type: "policy", capability: violation.capability.kind, scope: violation.capability.scope, severity: violation.severity, reason: violation.reason, ...(source ? { source: source.source, subject: source.subject, evidence: source.evidence } : {}) });
  }
  entries.sort((a, b) => changeWeight[a.type] - changeWeight[b.type] || (severityWeight[b.severity ?? "info"] - severityWeight[a.severity ?? "info"]) || capabilityText(a.capability, a.scope).localeCompare(capabilityText(b.capability, b.scope)));
  return {
    schemaVersion: 1,
    target: result.target,
    baseline: changes.length > 0,
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

export function formatPermissionSummaryMarkdown(summary: PermissionSummary): string {
  const changed = summary.changes.added + summary.changes.widened;
  const status = changed > 0 || summary.policyViolations > 0 ? "⚠️ Permission changes or policy violations detected" : "✅ No new permission changes detected";
  const lines = ["## CapFence permission summary", "", `**Target:** \`${summary.target}\``, `**Baseline:** ${summary.baseline ? "yes" : "not provided"}`, `**Status:** ${status}`, "", `Changes: **${summary.changes.added} added**, **${summary.changes.widened} widened**, **${summary.changes.removed} removed**.`];
  if (summary.entries.length > 0) {
    lines.push("", "| Type | Capability | Scope | Source | Severity | Reason |", "| --- | --- | --- | --- | --- | --- |");
    for (const entry of summary.entries) lines.push(`| ${entry.type} | \`${entry.capability}\` | \`${entry.scope}\` | ${entry.source ?? "-"} | ${entry.severity ?? "-"} | ${(entry.reason ?? "-").replaceAll("|", "\\|")} |`);
  } else lines.push("", "No capability changes or policy violations.");
  if (summary.policyViolations > 0) lines.push("", `Policy violations: **${summary.policyViolations}**.`);
  const findingTotal = Object.values(summary.findings).reduce((total, count) => total + count, 0);
  lines.push("", `Findings: **${findingTotal}** total (${summary.findings.critical} critical, ${summary.findings.high} high, ${summary.findings.medium} medium, ${summary.findings.low} low, ${summary.findings.info} info).`);
  return lines.join("\n");
}
