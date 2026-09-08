import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";

import { diffBaseline, toBaseline } from "../src/baseline.js";
import { evaluatePolicy, loadPolicy } from "../src/policy.js";
import { formatGithub, formatJson, formatSarif, formatText } from "../src/reporters.js";
import type { Baseline, ScanResult } from "../src/types.js";
import { scanTarget } from "../src/analyzer.js";
import { buildPermissionSummary, formatPermissionSummaryJson, formatPermissionSummaryMarkdown } from "../src/summary.js";

const baseResult = (scope: string): ScanResult => ({
  schemaVersion: 1,
  target: "/fixture",
  scannedFiles: 1,
  capabilities: [{
    kind: "network.connect",
    scope,
    source: "configuration",
    location: { file: "mcp.json", startLine: 4, startColumn: 12, endLine: 4, endColumn: 30 },
    evidence: "https://api.example.com",
  }],
  findings: [],
  analysisLimited: [],
});

describe("baseline and capability diff", () => {
  it("normalizes duplicate capabilities and identifies a widened network scope", () => {
    const previous: Baseline = toBaseline(baseResult("https|api.example.com"), "2026-01-01T00:00:00.000Z");
    const current = baseResult("dynamic");
    current.capabilities.push({ ...current.capabilities[0]!, scope: "DYNAMIC" });
    const diff = diffBaseline(previous, current);

    expect(previous.capabilities).toHaveLength(1);
    expect(diff.changes).toHaveLength(1);
    expect(diff.changes[0]?.type).toBe("widened");
    expect(diff.changes[0]?.current?.scope).toBe("dynamic");
  });

  it("does not report a moved capability as a permission change", () => {
    const previous: Baseline = toBaseline(baseResult("binary:node"));
    const current = baseResult("binary:node");
    current.capabilities[0]!.location = { file: "other.json", startLine: 99, startColumn: 1, endLine: 99, endColumn: 10 };
    expect(diffBaseline(previous, current).changes).toEqual([]);
  });

  it("treats a replacement network host as added and removed, not widened", () => {
    const previous = toBaseline(baseResult("https|api.example.com"));
    const diff = diffBaseline(previous, baseResult("https|evil.example.com"));
    expect(diff.changes.map((change) => change.type).sort()).toEqual(["added", "removed"]);
  });

  it("treats a dynamic binary as a widened process capability", () => {
    const previous = toBaseline({ ...baseResult("binary:node"), capabilities: [{ ...baseResult("binary:node").capabilities[0]!, kind: "process.execute" }] });
    const current = { ...baseResult("dynamic-binary"), capabilities: [{ ...baseResult("dynamic-binary").capabilities[0]!, kind: "process.execute" }] };
    expect(diffBaseline(previous, current).changes.map((change) => change.type)).toEqual(["widened"]);
  });
});

describe("policy evaluation", () => {
  it("treats an explicit empty network allowlist as deny all", () => {
    const changes = diffBaseline({ schemaVersion: 1, generatedAt: "2026-01-01", capabilities: [] }, baseResult("https|api.example.com")).changes;
    expect(evaluatePolicy(changes, { network: { allow: [] } }).violations).toHaveLength(1);
    expect(evaluatePolicy(changes, { network: {} }).violations).toHaveLength(0);
    expect(evaluatePolicy([], { network: { allow: [] } }).violations).toHaveLength(0);
  });

  it("applies deny rules and network allowlists only to added or widened capabilities", () => {
    const baseline: Baseline = toBaseline(baseResult("https|api.example.com"));
    const diff = diffBaseline(baseline, baseResult("dynamic"));
    const policy = evaluatePolicy(diff.changes, {
      deny: [{ capability: "network.connect", scope: "dynamic", reason: "Dynamic hosts require review", severity: "critical" }],
      network: { allow: ["api.example.com"] },
    });
    expect(policy.violations).toHaveLength(1);
    expect(policy.violations[0]?.severity).toBe("critical");
    expect(policy.violations[0]?.reason).toContain("Dynamic hosts");
  });

  it("does not mistake an allowlisted literal dynamic-named host for a template", () => {
    const changes = diffBaseline({ schemaVersion: 1, generatedAt: "now", capabilities: [] }, baseResult("https|dynamic.example.com")).changes;
    expect(evaluatePolicy(changes, { network: { allow: ["DYNAMIC.example.com"] } }).violations).toHaveLength(0);
  });

  it("preserves executable case in deny rules and baseline identity", () => {
    const before = baseResult("binary:/opt/tools/Safe");
    before.capabilities[0]!.kind = "process.execute";
    const after = baseResult("binary:/opt/tools/safe");
    after.capabilities[0]!.kind = "process.execute";
    const changes = diffBaseline(toBaseline(before), after).changes;
    expect(changes.map(item => item.type).sort()).toEqual(["added", "removed"]);
    expect(evaluatePolicy(changes, { deny: [{ capability: "process.execute", scope: "binary:/opt/tools/Safe" }] }).violations).toHaveLength(0);
    expect(evaluatePolicy(changes, { deny: [{ capability: "process.execute", scope: "binary:/opt/tools/safe" }] }).violations[0]?.reason).toBe("Capability is denied by policy.");
  });

  it("rejects malformed policy values before evaluation", () => {
    const policyPath = fileURLToPath(new URL("./fixtures/invalid-policy.yaml", import.meta.url));
    expect(() => loadPolicy(policyPath)).toThrow("Invalid policy.network.allow");
  });

  it("rejects unknown policy keys instead of silently disabling controls", () => {
    const policyPath = fileURLToPath(new URL("./fixtures/unknown-policy.yaml", import.meta.url));
    expect(() => loadPolicy(policyPath)).toThrow("Invalid policy: unknown key(s): denny");
  });
});

describe("permission summary", () => {
  it("records baseline presence explicitly even when unchanged", () => {
    const result = baseResult("dynamic");
    const changes = diffBaseline(toBaseline(result), result).changes;
    const unchanged = buildPermissionSummary(result, changes, undefined, true);
    expect(unchanged.baseline).toBe(true);
    expect(formatPermissionSummaryMarkdown(unchanged)).toContain("No new permission changes detected");
    const withoutBaseline = buildPermissionSummary(result);
    expect(withoutBaseline.baseline).toBe(false);
    expect(formatPermissionSummaryMarkdown(withoutBaseline)).toContain("permission changes not assessed");
    expect(formatPermissionSummaryMarkdown(withoutBaseline)).not.toContain("No capability changes or policy violations.");
    expect(buildPermissionSummary(result, [{ type: "added", current: toBaseline(result).capabilities[0]! }]).baseline).toBe(false);
  });

  it("retains every matching source location for changes and policy entries", () => {
    const result = baseResult("DYNAMIC");
    result.capabilities.push({ ...result.capabilities[0]!, scope: "dynamic", source: "runtime", location: { file: "second.ts", startLine: 8, startColumn: 2, endLine: 8, endColumn: 10 } });
    const changes = diffBaseline(toBaseline(baseResult("https|api.example.com")), result).changes;
    const policy = evaluatePolicy(changes, { deny: ["network.connect"] });
    const summary = buildPermissionSummary(result, changes, policy, true);
    expect(summary.entries).toHaveLength(2);
    for (const entry of summary.entries) expect(entry.locations).toEqual(result.capabilities.map((capability) => capability.location));
    const markdown = formatPermissionSummaryMarkdown(summary);
    expect(markdown).toContain("mcp.json:4:12<br>second.ts:8:2");
    for (const item of JSON.parse(formatSarif(result, "0.1.0", changes, policy)).runs[0].results) expect(item.locations).toHaveLength(2);
    expect(formatGithub(result, changes, policy)).toContain("file=second.ts,line=8,col=2,title=CF-CAP-002");
    const removed = buildPermissionSummary(baseResult("different"), [{ type: "removed", previous: toBaseline(result).capabilities }], undefined, true);
    expect(removed.entries[0]!.locations).toEqual([]);
  });

  it("escapes every untrusted Markdown table cell and target", () => {
    const result = baseResult("https|host`\n<script>");
    result.target = "target`\n<script>";
    result.capabilities[0]!.location.file = "file|`\n<script>";
    const capability = { kind: "network.connect" as const, scope: result.capabilities[0]!.scope, source: "configuration" as const };
    const summary = buildPermissionSummary(result, [{ type: "added", current: capability }], { violations: [{ severity: "high", capability, reason: "reason|`\r\n<script> [link](url)" }] }, true);
    summary.entries[0]!.source = "source|`\n<script>" as "configuration";
    const markdown = formatPermissionSummaryMarkdown(summary);
    expect(markdown).not.toContain("<script>");
    expect(markdown).not.toContain("`");
    expect(markdown).toContain("https&#124;host&#96;<br>&lt;script&gt;");
    expect(markdown).toContain("source&#124;&#96;<br>&lt;script&gt;");
    expect(markdown).toContain("reason&#124;&#96;<br>&lt;script&gt; &#91;link&#93;&#40;url&#41;");
    for (const line of markdown.split("\n").filter((line) => line.startsWith("|"))) expect(line.split("|")).toHaveLength(9);
  });
});

describe("report formats", () => {
  it("preserves incomplete-analysis diagnostics in every report", () => {
    const result = baseResult("dynamic");
    result.analysisLimited = [{ file: "broken.json", message: "Cannot parse configuration" }];
    const summary = buildPermissionSummary(result, [], undefined, true);
    for (const output of [formatText(result), formatJson(result), formatSarif(result), formatGithub(result), formatPermissionSummaryJson(summary), formatPermissionSummaryMarkdown(summary)]) {
      expect(output).toContain("broken.json");
      expect(output).toContain("Cannot parse configuration");
    }
    const run = JSON.parse(formatSarif(result)).runs[0];
    expect(run.invocations[0].executionSuccessful).toBe(false);
    expect(run.invocations[0].toolExecutionNotifications[0]).toMatchObject({ level: "warning", locations: [{ physicalLocation: { artifactLocation: { uri: "broken.json" } } }] });
    expect(formatGithub(result)).toContain("::warning file=broken.json,title=CF-ANALYSIS-LIMITED::Analysis incomplete");
    expect(formatPermissionSummaryMarkdown(summary)).toContain("Warning: analysis incomplete");
    expect(formatPermissionSummaryMarkdown(summary)).not.toContain("No new permission changes detected");
    expect(summary.scannedFiles).toBe(1);
    expect(summary.analysisLimited).toEqual(result.analysisLimited);
    expect(JSON.parse(formatSarif(baseResult("dynamic"))).runs[0].invocations[0]).toEqual({ executionSuccessful: true, toolExecutionNotifications: [] });
  });

  it("emits located added, widened and policy GitHub annotations with escaped reasons", () => {
    for (const previousScope of ["https|old.example.com", "https|api.example.com"]) {
      const result = baseResult(previousScope.includes("old") ? "https|new.example.com" : "dynamic");
      result.capabilities[0]!.location.file = "odd,\nfile.json";
      const changes = diffBaseline(toBaseline(baseResult(previousScope)), result).changes;
      const policy = { violations: [{ severity: "high" as const, capability: changes.find((change) => change.current)!.current!, reason: "Review, now\n::error::injected" }] };
      const output = formatGithub(result, changes, policy);
      const rule = result.capabilities[0]!.scope === "dynamic" ? "CF-CAP-002" : "CF-CAP-001";
      expect(output).toContain(`::error file=odd%2C%0Afile.json,line=4,col=12,title=${rule}::`);
      expect(output).toContain("title=CF-POLICY-001::Policy violation");
      expect(output).toContain("Review%2C now%0A%3A%3Aerror%3A%3Ainjected");
      expect(output).not.toContain("\n::error::injected");
    }
  });

  it("redacts credential material from text, JSON, SARIF, and GitHub output", () => {
    const result = scanTarget(fileURLToPath(new URL("./fixtures/risky/composite", import.meta.url)));
    const token = "ghp_123456789012345678901234567890123456";
    for (const output of [formatText(result), formatJson(result), formatSarif(result), formatGithub(result)]) {
      expect(output).not.toContain(token);
      expect(output).toContain("REDACTED");
    }
  });

  it("emits valid SARIF locations and stable GitHub workflow commands", () => {
    const result = scanTarget(fileURLToPath(new URL("./fixtures/risky/composite", import.meta.url)));
    const sarif = JSON.parse(formatSarif(result)) as { version: string; runs: Array<{ results: Array<{ locations: Array<{ physicalLocation: { region: { startLine: number } } }> }> }> };
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.results.length).toBeGreaterThan(0);
    expect(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.region.startLine).toBeGreaterThan(1);
    expect(formatGithub(result)).toMatch(/::(?:error|warning) file=run\.sh,line=\d+,col=\d+/);
  });

  it("includes capability changes and policy violations in SARIF", () => {
    const result = baseResult("dynamic");
    const changes = diffBaseline(toBaseline(baseResult("https|api.example.com")), result).changes;
    const policy = evaluatePolicy(changes, { deny: [{ capability: "network.connect", scope: "dynamic", severity: "critical", reason: "Dynamic hosts require review" }] });
    const sarif = JSON.parse(formatSarif(result, "0.1.0", changes, policy)) as {
      runs: Array<{ tool: { driver: { rules: Array<{ id: string }> } }; results: Array<{ ruleId: string; message: { text: string } }> }>;
    };
    const rules = sarif.runs[0]?.tool.driver.rules.map((rule) => rule.id) ?? [];
    const results = sarif.runs[0]?.results ?? [];
    expect(rules).toEqual(expect.arrayContaining(["CF-CAP-002", "CF-POLICY-001"]));
    expect(results.map((item) => item.ruleId)).toEqual(expect.arrayContaining(["CF-CAP-002", "CF-POLICY-001"]));
    expect(results.some((item) => item.message.text.includes("Dynamic hosts require review"))).toBe(true);
  });
});
