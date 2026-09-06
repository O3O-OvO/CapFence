import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { beforeAll, afterAll, describe, expect, it } from "vitest";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const cliPath = path.join(repoRoot, "dist", "cli.js");
const fixtures = path.join(repoRoot, "tests", "fixtures");
let tempRoot = "";

function runCli(...args: string[]) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    windowsHide: true,
  });
}

describe("CLI black-box contract", () => {
  beforeAll(() => {
    if (!fs.existsSync(cliPath)) throw new Error(`CLI build missing: ${cliPath}`);
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "capfence-cli-"));
  });

  afterAll(() => {
    if (tempRoot) fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it("returns version and scans JSON successfully", () => {
    const version = runCli("--version");
    expect(version.status).toBe(0);
    expect(version.stdout.trim()).toBe("0.1.0");

    const safe = runCli("scan", path.join(fixtures, "safe", "static-shell"), "--format", "json");
    expect(safe.status).toBe(0);
    const report = JSON.parse(safe.stdout) as { findings: unknown[]; capabilities: unknown[] };
    expect(report.findings).toEqual([]);
    expect(report.capabilities.length).toBeGreaterThan(0);
  });

  it("writes output files and fails on critical findings", () => {
    const outputPath = path.join(tempRoot, "scan.json");
    const risky = runCli("scan", path.join(fixtures, "risky", "composite"), "--format", "json", "--fail-on", "critical", "--output", outputPath);
    expect(risky.status).toBe(1);
    expect(risky.stdout).toBe("");
    expect(JSON.parse(fs.readFileSync(outputPath, "utf8"))).toMatchObject({ findings: expect.any(Array) });
  });

  it("creates a baseline, reports capability changes, and honors allow-changes", () => {
    const baselinePath = path.join(tempRoot, "baseline.json");
    const baseline = runCli("baseline", path.join(fixtures, "safe", "mcp-authenticated-remote"), "--output", baselinePath);
    expect(baseline.status).toBe(0);
    expect(fs.existsSync(baselinePath)).toBe(true);

    const changed = runCli("diff", path.join(fixtures, "risky", "mcp"), "--baseline", baselinePath, "--format", "json");
    expect(changed.status).toBe(1);
    const changedReport = JSON.parse(changed.stdout) as { changes: Array<{ type: string }> };
    expect(changedReport.changes.some((change) => change.type === "added" || change.type === "widened")).toBe(true);

    const allowed = runCli("diff", path.join(fixtures, "risky", "mcp"), "--baseline", baselinePath, "--allow-changes", "--format", "json");
    expect(allowed.status).toBe(0);
  });

  it("applies policy failures and returns exit code 2 for invalid input", () => {
    const policyPath = path.join(tempRoot, "policy.yml");
    fs.writeFileSync(policyPath, "deny:\n  - capability: process.execute\n    severity: critical\n", "utf8");
    const policy = runCli("scan", path.join(fixtures, "safe", "static-shell"), "--policy", policyPath, "--format", "json");
    expect(policy.status).toBe(1);
    expect(JSON.parse(policy.stdout)).toMatchObject({ policy: { violations: expect.any(Array) } });

    const invalid = runCli("scan", path.join(fixtures, "safe", "static-shell"), "--unknown");
    expect(invalid.status).toBe(2);
    expect(invalid.stderr).toContain("Unknown option");
  });

  it("fails with exit code 2 for malformed baselines", () => {
    const baselinePath = path.join(tempRoot, "invalid-baseline.json");
    fs.writeFileSync(baselinePath, "{\"nope\":true}\n", "utf8");
    const result = runCli("diff", path.join(fixtures, "safe", "static-shell"), "--baseline", baselinePath);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Invalid baseline");
  });

  it("exports a deterministic capability graph", () => {
    const graph = runCli("graph", path.join(fixtures, "risky", "composite"));
    expect(graph.status).toBe(0);
    const report = JSON.parse(graph.stdout) as { schemaVersion: number; nodes: Array<{ type: string }>; edges: Array<{ type: string }> };
    expect(report.schemaVersion).toBe(1);
    expect(report.nodes.some((node) => node.type === "target")).toBe(true);
    expect(report.nodes.some((node) => node.type === "source")).toBe(true);
    expect(report.nodes.some((node) => node.type === "capability")).toBe(true);
    expect(report.nodes.some((node) => node.type === "finding")).toBe(true);
    expect(report.edges.map((edge) => edge.type)).toEqual(expect.arrayContaining(["contains", "declares", "evidences"]));
  });

  it("exposes MCP subjects and resource relationships in the graph", () => {
    const graph = runCli("graph", path.join(fixtures, "safe", "mcp-authenticated-remote"));
    expect(graph.status).toBe(0);
    const report = JSON.parse(graph.stdout) as { nodes: Array<{ type: string; id: string; resourceType?: string; evidence?: string; confidence?: string; subjects?: string[] }>; edges: Array<{ type: string }> };
    expect(report.nodes.some((node) => node.type === "subject" && node.id.includes("mcp:mcpServers:github"))).toBe(true);
    expect(report.nodes.some((node) => node.type === "resource" && node.resourceType === "network" && node.id.includes("api.github.com"))).toBe(true);
    expect(report.nodes.some((node) => node.type === "resource" && node.resourceType === "credential" && node.id.includes("injected-env:github_token"))).toBe(true);
    expect(report.edges.some((edge) => edge.type === "uses")).toBe(true);
    const capability = report.nodes.find((node) => node.type === "capability" && node.id.includes("network.connect"));
    expect(capability?.evidence).toContain("api.github.com");
    expect(capability?.confidence).toBe("high");
    expect(capability?.subjects).toContain("mcp:mcpServers:github");
  });

  it("annotates graph capabilities with baseline change types", () => {
    const baselinePath = path.join(tempRoot, "graph-baseline.json");
    const baseline = runCli("baseline", path.join(fixtures, "safe", "mcp-authenticated-remote"), "--output", baselinePath);
    expect(baseline.status).toBe(0);
    const graph = runCli("graph", path.join(fixtures, "risky", "mcp"), "--baseline", baselinePath);
    expect(graph.status).toBe(0);
    const report = JSON.parse(graph.stdout) as { nodes: Array<{ type: string; changeType?: string }> };
    expect(report.nodes.some((node) => node.type === "capability" && (node.changeType === "added" || node.changeType === "widened"))).toBe(true);
  });

  it("exports markdown and JSON permission summaries", () => {
    const baselinePath = path.join(tempRoot, "summary-baseline.json");
    const policyPath = path.join(tempRoot, "summary-policy.yml");
    const summaryPath = path.join(tempRoot, "summary.md");
    expect(runCli("baseline", path.join(fixtures, "safe", "mcp-authenticated-remote"), "--output", baselinePath).status).toBe(0);
    fs.writeFileSync(policyPath, "deny:\n  - capability: network.connect\n    severity: high\n", "utf8");
    const markdown = runCli("summary", path.join(fixtures, "risky", "mcp"), "--baseline", baselinePath, "--policy", policyPath, "--output", summaryPath);
    expect(markdown.status).toBe(1);
    expect(fs.readFileSync(summaryPath, "utf8")).toContain("## CapFence permission summary");
    expect(fs.readFileSync(summaryPath, "utf8")).toContain("Policy");

    const json = runCli("summary", path.join(fixtures, "risky", "mcp"), "--baseline", baselinePath, "--format", "json");
    expect(json.status).toBe(1);
    const report = JSON.parse(json.stdout) as { schemaVersion: number; baseline: boolean; entries: Array<{ type: string }> };
    expect(report.schemaVersion).toBe(1);
    expect(report.baseline).toBe(true);
    expect(report.entries.some((entry) => entry.type === "added" || entry.type === "widened")).toBe(true);
  });
});
