import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { discoverFiles } from "../src/discovery.js";
import { scanTarget } from "../src/analyzer.js";

const fixtures = fileURLToPath(new URL("./fixtures", import.meta.url));
const fixture = (...parts: string[]) => path.join(fixtures, ...parts);

describe("file discovery", () => {
  it("discovers supported files in stable order and ignores unsupported prose", () => {
    const discovered = discoverFiles(fixture("safe", "skill-prose-only"));
    expect(discovered.files.map((file) => file.relativePath)).toEqual(["SKILL.md"]);
    expect(discovered.files[0]?.content).toContain("ordinary prose");
  });

  it("enforces the maximum file size without failing the whole scan", () => {
    const discovered = discoverFiles(fixture("safe", "skill-prose-only"), { maxFileBytes: 8 });
    expect(discovered.files).toHaveLength(0);
  });
});

describe("capability analysis", () => {
  it("does not scan prose or unlabelled markdown blocks as commands", () => {
    const result = scanTarget(fixture("safe", "skill-prose-only"));
    expect(result.scannedFiles).toBe(1);
    expect(result.capabilities).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  it("records a static shell capability without flagging it as dynamic", () => {
    const result = scanTarget(fixture("safe", "static-shell"));
    expect(result.capabilities.some((item) => item.kind === "process.execute" && item.scope === "shell:static")).toBe(true);
    expect(result.capabilities.some((item) => item.kind === "dynamic.execute")).toBe(false);
    expect(result.findings).toEqual([]);
  });

  it("records normal MCP capabilities without treating injected secrets as hard-coded", () => {
    const result = scanTarget(fixture("safe", "mcp-authenticated-remote"));
    expect(result.findings).toEqual([]);
    expect(result.capabilities.some((item) => item.kind === "process.execute")).toBe(true);
    expect(result.capabilities.some((item) => item.kind === "network.connect" && item.scope.includes("api.github.com"))).toBe(true);
    expect(result.capabilities.some((item) => item.kind === "credential.read" && item.scope.toLowerCase().includes("github_token"))).toBe(true);
  });

  it("parses an equivalent YAML MCP configuration", () => {
    const result = scanTarget(fixture("safe", "mcp-yaml"));
    expect(result.analysisLimited).toEqual([]);
    expect(result.findings).toEqual([]);
    expect(result.capabilities.some((item) => item.kind === "process.execute")).toBe(true);
    expect(result.capabilities.some((item) => item.kind === "network.connect" && item.scope.includes("example.com"))).toBe(true);
  });

  it("does not flag a pinned package runner or ordinary SSH identity use", () => {
    const pinned = scanTarget(fixture("safe", "pinned-runner"));
    expect(pinned.findings.some((finding) => finding.id === "CF-PKG-001")).toBe(false);

    const ssh = scanTarget(fixture("safe", "normal-ssh"));
    expect(ssh.findings.some((finding) => finding.id === "CF-CRED-001")).toBe(false);
    expect(ssh.capabilities.some((item) => item.kind === "filesystem.read")).toBe(true);
  });

  it("detects composite command risks and preserves precise source locations", () => {
    const result = scanTarget(fixture("risky", "composite"));
    const ids = new Set(result.findings.map((finding) => finding.id));
    expect([...ids]).toEqual(expect.arrayContaining(["CF-EXEC-002", "CF-CRED-001", "CF-CRED-002", "CF-PKG-001", "CF-PRIV-001"]));
    for (const finding of result.findings) {
      expect(finding.location.file).toBe("run.sh");
      expect(finding.location.startLine).toBeGreaterThan(1);
      expect(finding.location.startColumn).toBeGreaterThanOrEqual(1);
    }
    expect(result.capabilities.some((item) => item.kind === "network.connect")).toBe(true);
    expect(result.capabilities.some((item) => item.kind === "credential.read")).toBe(true);
    expect(result.capabilities.some((item) => item.kind === "package.lifecycle")).toBe(true);
  });

  it("handles JSONC MCP configuration and reports malformed structured input as limited", () => {
    const mcp = scanTarget(fixture("risky", "mcp"));
    const ids = new Set(mcp.findings.map((finding) => finding.id));
    expect(ids.has("CF-MCP-001")).toBe(true);
    expect(mcp.capabilities.some((item) => item.kind === "credential.read")).toBe(true);

    const malformed = scanTarget(fixture("risky", "malformed"));
    expect(malformed.analysisLimited).toHaveLength(1);
    expect(malformed.analysisLimited[0]?.file).toBe("broken.json");
    expect(malformed.capabilities).toEqual([]);
    expect(malformed.findings).toEqual([]);
  });

  it("keeps repeated MCP values attached to their own server entry", () => {
    const result = scanTarget(fixture("risky", "repeated-mcp-values"));
    const dynamic = result.findings.filter((finding) => finding.id === "CF-MCP-001" && finding.title === "Dynamic MCP server command");
    expect(dynamic).toHaveLength(1);
    expect(dynamic[0]?.location.startLine).toBe(9);

    const shell = result.findings.filter((finding) => finding.id === "CF-EXEC-001");
    expect(shell).toHaveLength(1);
    expect(shell[0]?.location.startLine).toBe(9);
  });

  it("analyzes lifecycle hooks but leaves ordinary package scripts outside the lifecycle scope", () => {
    const result = scanTarget(fixture("risky", "lifecycle"));
    expect(result.capabilities.some((item) => item.kind === "package.lifecycle" && item.scope === "postinstall")).toBe(true);
    expect(result.findings.some((finding) => finding.id === "CF-EXEC-002")).toBe(true);
    expect(result.findings.every((finding) => finding.location.file === "package.json")).toBe(true);
  });

  it("analyzes Python process and network APIs", () => {
    const result = scanTarget(fixture("risky", "python-process"));
    expect(result.findings.some((finding) => finding.id === "CF-EXEC-001")).toBe(true);
    expect(result.capabilities.some((item) => item.kind === "network.connect" && item.scope.includes("api.example.com"))).toBe(true);
  });

  it("never executes commands from scanned files", () => {
    const marker = path.resolve("capfence-test-marker-should-not-exist");
    try {
      if (fs.existsSync(marker)) fs.rmSync(marker);
      scanTarget(fixture("risky", "no-execution"));
      expect(fs.existsSync(marker)).toBe(false);
    } finally {
      if (fs.existsSync(marker)) fs.rmSync(marker);
    }
  });
});
