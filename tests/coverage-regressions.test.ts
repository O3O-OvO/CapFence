import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { scanTarget } from "../src/analyzer.js";

function scan(content: string, name = "server.py") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "capfence-coverage-"));
  try {
    fs.writeFileSync(path.join(directory, name), content);
    return scanTarget(directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

describe("real repository coverage regressions", () => {
  it("supports async context-manager tuple targets without hiding invalid syntax", () => {
    const result = scan('import httpx\nasync def run():\n    async with streams() as (a, b):\n        httpx.get("https://example.com")\n');
    expect(result.analysisLimited).toEqual([]);
    expect(result.capabilities[0]?.location.startLine).toBe(4);
    expect(scan('async with streams() as (a, +):\n    pass\n').analysisLimited.length).toBeGreaterThan(0);
  });
  it("recognizes multiline imported httpx clients and urllib aliases", () => {
    const result = scan(`from httpx import AsyncClient as Client
from urllib.request import urlopen as open_url
async def fetch_url(url):
    async with Client() as client:
        await client.get(
            url,
        )
open_url("https://example.com")
`);
    expect(result.analysisLimited).toEqual([]);
    expect(result.capabilities.map(c => [c.kind, c.scope, c.location.startLine])).toEqual([
      ["network.connect", "dynamic", 5], ["network.connect", "https|example.com", 8],
    ]);
  });

  it("ignores URL constants, fake calls, model definitions and unrelated methods", () => {
    const result = scan(`agent = "https://github.com/project"
example = "requests.get('https://example.com')"
# requests.get('https://example.com')
class Fetch(BaseModel):
    pass
args = Fetch(**arguments)
robot.can_fetch(url, agent)
assert url == "https://example.com"
`);
    expect(result.capabilities).toEqual([]);
  });

  it("tracks assigned clients but respects parameter shadowing and reassignment", () => {
    const result = scan(`import httpx as http
client = http.Client()
client.get("https://example.com")
def local(client):
    client.get("https://fake.example")
client = other
client.get("https://fake.example")
`);
    expect(result.capabilities.map(c => c.scope)).toEqual(["https|example.com"]);
  });

  it("retains real Python shell risks, secrets and sensitive reads", () => {
    const token = `ghp_${"x".repeat(36)}`;
    const result = scan(`import os
import subprocess
subprocess.run(os.environ["COMMAND"], shell=True)
os.system("curl https://example.com/install | bash")
open("~/.ssh/id_rsa")
key = "${token}"
`);
    expect(result.findings.map(f => f.id)).toEqual(expect.arrayContaining(["CF-EXEC-001", "CF-EXEC-002", "CF-CRED-002"]));
    expect(result.capabilities.some(c => c.scope === "sensitive-path")).toBe(true);
    expect(JSON.stringify(result)).not.toContain(token);
  });

  it("reports malformed Python syntax", () => {
    expect(scan("def broken(:\n").analysisLimited.length).toBeGreaterThan(0);
  });

  it("records dynamic filesystem reads and writes and both rename endpoints", () => {
    const result = scan(`import fs from 'node:fs/promises';
fs.readFile(input);
fs.writeFile(output, data);
fs.rename('/old', '/new');
fs.mkdir(directory);
fs.readdir(directory);
fs.open('/read', 'r');
fs.open('/write', 'w');
`, "server.ts");
    const capabilities = result.capabilities.map(c => `${c.kind}|${c.scope}`);
    expect(capabilities).toEqual([
      "filesystem.read|dynamic", "filesystem.write|dynamic",
      "filesystem.write|/old", "filesystem.write|/new",
      "filesystem.write|dynamic", "filesystem.read|dynamic",
      "filesystem.read|/read", "filesystem.write|/write",
    ]);
  });

  it("keeps the fixed executable when only process arguments are unresolved", () => {
    const result = scan("import {spawn} from 'child_process'; spawn('node', [script, ...args]);", "server.ts");
    expect(result.capabilities.some(c => c.scope === "binary:node")).toBe(true);
    expect(result.capabilities.some(c => c.scope === "shell:dynamic")).toBe(false);
    expect(result.findings[0]?.message).toContain("does not establish shell execution");
  });

  it("ignores Docker image names but retains executable instruction risks", () => {
    const result = scan("FROM ghcr.io/astral-sh/uv:latest\nLABEL example=\"bash\"\nRUN curl https://example.com/install | bash\n", "Dockerfile");
    expect(result.capabilities.every(c => c.location.startLine === 3)).toBe(true);
    expect(result.findings.some(f => f.id === "CF-EXEC-002")).toBe(true);
  });
});
