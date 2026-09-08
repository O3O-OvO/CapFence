import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repo = fileURLToPath(new URL("..", import.meta.url));
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "capfence-package-"));
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, stdio: "inherit", windowsHide: true });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${command} failed with status ${result.status}`);
}
function npm(args, cwd) {
  // npm_execpath is supplied by npm/pnpm scripts; invoke its JS entry directly on Windows.
  if (!process.env.npm_execpath) throw new Error("Run this check through npm run test:package or pnpm run test:package");
  run(process.execPath, [process.env.npm_execpath, ...args], cwd);
}
try {
  run(process.execPath, [path.join(repo, "node_modules/typescript/bin/tsc"), "-p", "tsconfig.json"], repo);
  npm(["pack", "--pack-destination", temp], repo);
  const archives = fs.readdirSync(temp).filter(file => file.endsWith(".tgz"));
  assert.equal(archives.length, 1);
  const consumer = path.join(temp, "consumer");
  fs.mkdirSync(consumer);
  fs.writeFileSync(path.join(consumer, "package.json"), JSON.stringify({ private: true, type: "module" }));
  npm(["install", "--ignore-scripts", "--production", path.join(temp, archives[0])], consumer);
  const installed = path.join(consumer, "node_modules", "capfence");
  const manifest = JSON.parse(fs.readFileSync(path.join(installed, "package.json"), "utf8"));
  assert.ok(manifest.dependencies.typescript, "AST parser must be a runtime dependency");
  const cli = path.join(installed, manifest.bin.capfence);
  assert.ok(fs.readFileSync(cli, "utf8").startsWith("#!/usr/bin/env node"));
  run(process.execPath, [cli, "--version"], consumer);
  const input = path.join(consumer, "input");
  fs.mkdirSync(input);
  fs.writeFileSync(path.join(input, "client.ts"), 'fetch(\n  "https://api.example.com"\n);\n');
  const report = path.join(consumer, "report.json");
  run(process.execPath, [cli, "scan", input, "--format", "json", "--fail-on-incomplete", "--output", report], consumer);
  const result = JSON.parse(fs.readFileSync(report, "utf8"));
  assert.equal(result.analysisLimited.length, 0);
  assert.ok(result.capabilities.some(item => item.kind === "network.connect" && item.scope === "https|api.example.com"));
  console.log("Package installation smoke test passed.");
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
