import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { discoverFiles } from "../src/discovery.js";
import { capabilityFingerprint, scanTarget } from "../src/analyzer.js";
import { parseYaml, walkValues } from "../src/parsers.js";
import { normalizeScope } from "../src/utils/text.js";

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

function scanContent(name: string, content: string) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "capfence-analysis-"));
  try {
    fs.writeFileSync(path.join(directory, name), content);
    return scanTarget(directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

describe("capability analysis", () => {
  it.each(["-EncodedCommand", "-enc", "-ENC", "-EncodedCommand="])("detects PowerShell encoded flag %s", (flag) => {
    const result = scanContent("run.ps1", `powershell ${flag} SQBFAFgA`);
    expect(result.findings.some((finding) => finding.id === "CF-DYN-001")).toBe(true);
  });

  it.each(["-encoding", "-enc-more", "prefix-enc", "-EncodedCommandExtra"])("rejects partial encoded flag %s", (flag) => {
    const result = scanContent("run.ps1", `pwsh ${flag} SQBFAFgA`);
    expect(result.findings.some((finding) => finding.id === "CF-DYN-001")).toBe(false);
  });

  it("preserves executable, path, and environment case in scopes and fingerprints", () => {
    const result = scanContent("mcp.json", JSON.stringify({ mcpServers: {
      upper: { command: "Tool", cwd: "/Data/Project", env: { API_TOKEN: "injected" } },
      lower: { command: "tool", cwd: "/data/project", env: { api_token: "injected" } },
    } }));
    expect(result.capabilities.map(capabilityFingerprint)).toEqual(expect.arrayContaining([
      "process.execute|binary:Tool", "process.execute|binary:tool",
      "filesystem.read|/Data/Project", "filesystem.read|/data/project",
      "credential.read|injected-env:API_TOKEN", "credential.read|injected-env:api_token",
    ]));
    expect(normalizeScope("HTTPS|EXAMPLE.COM", "network.connect")).toBe("https|example.com");
    expect(normalizeScope("SHELL:DYNAMIC", "process.execute")).toBe("shell:dynamic");
    expect(normalizeScope("ENCODED", "dynamic.execute")).toBe("encoded");
    expect(normalizeScope("prepublishOnly", "package.lifecycle")).toBe("prepublishOnly");
  });

  it("reports YAML conversion failures as limited without throwing", () => {
    const result = scanContent("mcp.yaml", "mcpServers: *missing\n");
    expect(result.analysisLimited).toHaveLength(1);
    expect(result.analysisLimited[0]?.message).toContain("YAML conversion failed");
    expect(result.capabilities).toEqual([]);
  });

  it("reports YAML alias expansion limits as analysis limitations", () => {
    const yaml = "a: &a [x, x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\n";
    expect(scanContent("mcp.yaml", yaml).analysisLimited[0]?.message).toContain("YAML conversion failed");
  });

  it("bounds cyclic YAML traversal while analyzing reachable servers", () => {
    const result = scanContent("mcp.yaml", "loop: &loop\n  self: *loop\nmcpServers:\n  local:\n    command: Tool\n");
    expect(result.analysisLimited[0]?.message).toContain("Cyclic structured value");
    expect(result.capabilities.some((item) => item.scope === "binary:Tool")).toBe(true);
  });

  it("visits shared aliases under each path without reporting cycles", () => {
    const parsed = parseYaml("shared: &shared { command: Tool }\nmcpServers: { local: *shared }\n");
    const paths: string[] = [];
    expect(walkValues(parsed.value, (_value, keyPath) => paths.push(keyPath.join(".")))).toEqual([]);
    expect(paths).toContain("mcpServers.local.command");
  });

  it("preserves repeated resource occurrences at distinct source locations", () => {
    const result = scanContent("run.sh", "bash script.sh\nbash script.sh\n");
    expect(result.capabilities.filter((item) => item.scope === "shell:static").map((item) => item.location.startLine)).toEqual([1, 2]);
  });

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
