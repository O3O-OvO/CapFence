import type { CapabilityChange, Finding, PolicyResult, ScanResult } from "./types.js";

function severityWeight(severity: Finding["severity"]): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity];
}

export function summarizeFindings(result: ScanResult): Record<Finding["severity"], number> {
  return result.findings.reduce(
    (summary, finding) => {
      summary[finding.severity] += 1;
      return summary;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Finding["severity"], number>,
  );
}

export function formatText(result: ScanResult, changes?: CapabilityChange[], policy?: PolicyResult): string {
  const lines: string[] = [];
  lines.push(`CapFence scan: ${result.target}`);
  lines.push(`Files scanned: ${result.scannedFiles}`);
  lines.push(`Capabilities: ${result.capabilities.length}`);
  lines.push("");
  if (result.findings.length === 0) lines.push("No deterministic security findings.");
  for (const finding of [...result.findings].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))) {
    const loc = `${finding.location.file}:${finding.location.startLine}:${finding.location.startColumn}`;
    lines.push(`${finding.severity.toUpperCase()} ${finding.id} ${loc}`);
    lines.push(`  ${finding.title}: ${finding.message}`);
    lines.push(`  Evidence: ${finding.evidence}`);
    lines.push(`  Fix: ${finding.remediation}`);
  }
  if (changes) {
    lines.push("");
    lines.push(`Capability changes: ${changes.filter((change) => change.type !== "removed").length} added/widened, ${changes.filter((change) => change.type === "removed").length} removed`);
    for (const change of changes) {
      const capability = change.current ?? change.previous?.[0];
      if (!capability) continue;
      lines.push(`  ${change.type.toUpperCase()} ${capability.kind}:${capability.scope}`);
    }
  }
  if (policy) {
    lines.push("");
    lines.push(`Policy violations: ${policy.violations.length}`);
    for (const violation of policy.violations) lines.push(`  ${violation.severity.toUpperCase()} ${violation.capability.kind}:${violation.capability.scope} - ${violation.reason}`);
  }
  if (result.analysisLimited.length > 0) {
    lines.push("");
    lines.push("Analysis limited:");
    for (const item of result.analysisLimited) lines.push(`  ${item.file}: ${item.message}`);
  }
  const summary = summarizeFindings(result);
  lines.push("");
  lines.push(`Summary: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low`);
  return lines.join("\n");
}

export function formatJson(result: ScanResult, changes?: CapabilityChange[], policy?: PolicyResult): string {
  return JSON.stringify({ ...result, ...(changes ? { changes } : {}), ...(policy ? { policy } : {}) }, null, 2);
}

export function formatSarif(result: ScanResult, toolVersion = "0.1.0", changes: CapabilityChange[] = [], policy?: PolicyResult): string {
  const rules = new Map(result.findings.map((finding) => [finding.id, finding]));
  const capabilityRuleIds = new Set<string>();
  if (changes.some((change) => change.type === "added")) capabilityRuleIds.add("CF-CAP-001");
  if (changes.some((change) => change.type === "widened")) capabilityRuleIds.add("CF-CAP-002");
  if (policy?.violations.length) capabilityRuleIds.add("CF-POLICY-001");
  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "CapFence",
          version: toolVersion,
          informationUri: "https://github.com/O3O-OvO/CapFence",
          rules: [
            ...Array.from(rules.values()).map((finding) => ({
            id: finding.id,
            shortDescription: { text: finding.title },
            fullDescription: { text: finding.message },
            help: { text: finding.remediation },
            defaultConfiguration: { level: finding.severity === "critical" || finding.severity === "high" ? "error" : "warning" },
            })),
            ...(capabilityRuleIds.has("CF-CAP-001") ? [{
              id: "CF-CAP-001",
              shortDescription: { text: "New capability added" },
              fullDescription: { text: "A capability was added compared with the checked-in baseline." },
              defaultConfiguration: { level: "error" },
            }] : []),
            ...(capabilityRuleIds.has("CF-CAP-002") ? [{
              id: "CF-CAP-002",
              shortDescription: { text: "Capability widened" },
              fullDescription: { text: "An existing capability became broader than the checked-in baseline." },
              defaultConfiguration: { level: "error" },
            }] : []),
            ...(capabilityRuleIds.has("CF-POLICY-001") ? [{
              id: "CF-POLICY-001",
              shortDescription: { text: "Capability violates policy" },
              fullDescription: { text: "A newly added or widened capability violates the configured CapFence policy." },
              defaultConfiguration: { level: "error" },
            }] : []),
          ],
        },
      },
      results: [
        ...result.findings.map((finding) => ({
          ruleId: finding.id,
          level: finding.severity === "critical" || finding.severity === "high" ? "error" : "warning",
          message: { text: `${finding.title}: ${finding.message}` },
          properties: { evidence: finding.evidence },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: finding.location.file },
              region: {
                startLine: finding.location.startLine,
                startColumn: finding.location.startColumn,
                endLine: finding.location.endLine,
                endColumn: finding.location.endColumn,
              },
            },
          }],
        })),
        ...changes.filter((change) => change.type === "added" || change.type === "widened").map((change) => {
          const capability = change.current;
          if (!capability) return undefined;
          const source = result.capabilities.find((item) => item.kind === capability.kind && item.scope === capability.scope);
          return {
            ruleId: change.type === "added" ? "CF-CAP-001" : "CF-CAP-002",
            level: "error",
            message: { text: `${change.type === "added" ? "Added" : "Widened"} capability: ${capability.kind}:${capability.scope}` },
            properties: { changeType: change.type, capability: `${capability.kind}:${capability.scope}` },
            ...(source ? { locations: [{ physicalLocation: { artifactLocation: { uri: source.location.file }, region: { startLine: source.location.startLine, startColumn: source.location.startColumn, endLine: source.location.endLine, endColumn: source.location.endColumn } } }] } : {}),
          };
        }).filter((item): item is NonNullable<typeof item> => Boolean(item)),
        ...(policy?.violations ?? []).map((violation) => {
          const source = result.capabilities.find((item) => item.kind === violation.capability.kind && item.scope === violation.capability.scope);
          return {
            ruleId: "CF-POLICY-001",
            level: violation.severity === "critical" || violation.severity === "high" ? "error" : "warning",
            message: { text: `Policy violation: ${violation.capability.kind}:${violation.capability.scope} - ${violation.reason}` },
            properties: { capability: `${violation.capability.kind}:${violation.capability.scope}`, reason: violation.reason },
            ...(source ? { locations: [{ physicalLocation: { artifactLocation: { uri: source.location.file }, region: { startLine: source.location.startLine, startColumn: source.location.startColumn, endLine: source.location.endLine, endColumn: source.location.endColumn } } }] } : {}),
          };
        }),
      ],
    }],
  };
  return JSON.stringify(sarif, null, 2);
}

export function formatGithub(result: ScanResult, changes: CapabilityChange[] = [], policy?: PolicyResult): string {
  const output: string[] = [];
  for (const finding of result.findings) {
    const command = finding.severity === "critical" || finding.severity === "high" ? "error" : "warning";
    output.push(`::${command} file=${escapeCommandValue(finding.location.file)},line=${finding.location.startLine},col=${finding.location.startColumn},title=${escapeCommandValue(finding.id)}::${escapeCommandValue(finding.title)}: ${escapeCommandValue(finding.message)} Evidence: ${escapeCommandValue(finding.evidence)}`);
  }
  const summary = summarizeFindings(result);
  output.push(`CapFence: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low finding(s).`);
  if (changes.length > 0) output.push(`Capability changes: ${changes.filter((change) => change.type !== "removed").length} added/widened.`);
  if (policy?.violations.length) output.push(`Policy violations: ${policy.violations.length}.`);
  return output.join("\n");
}

function escapeCommandValue(value: string): string {
  return value.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A").replaceAll(":", "%3A").replaceAll(",", "%2C");
}
