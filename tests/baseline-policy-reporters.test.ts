import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";

import { diffBaseline, toBaseline } from "../src/baseline.js";
import { evaluatePolicy, loadPolicy } from "../src/policy.js";
import { formatGithub, formatJson, formatSarif, formatText } from "../src/reporters.js";
import type { Baseline, ScanResult } from "../src/types.js";
import { scanTarget } from "../src/analyzer.js";

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

  it("rejects malformed policy values before evaluation", () => {
    const policyPath = fileURLToPath(new URL("./fixtures/invalid-policy.yaml", import.meta.url));
    expect(() => loadPolicy(policyPath)).toThrow("Invalid policy.network.allow");
  });

  it("rejects unknown policy keys instead of silently disabling controls", () => {
    const policyPath = fileURLToPath(new URL("./fixtures/unknown-policy.yaml", import.meta.url));
    expect(() => loadPolicy(policyPath)).toThrow("Invalid policy: unknown key(s): denny");
  });
});

describe("report formats", () => {
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
});
