import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const demo = path.join(root, "examples", "mcp-demo");
const cli = path.join(root, "dist", "cli.js");
const baseline = path.join(demo, "baseline.json");
const args = [cli, "baseline", path.join(demo, "safe"), "--output", baseline];
let result = spawnSync(process.execPath, args, { cwd: root, stdio: "inherit" });
if (result.status !== 0) process.exit(result.status ?? 1);
result = spawnSync(process.execPath, [cli, "diff", path.join(demo, "dangerous"), "--baseline", baseline, "--policy", path.join(demo, "policy.yml"), "--format", "text", "--allow-changes"], { cwd: root, stdio: "inherit" });
fs.rmSync(baseline, { force: true });
process.exit(result.status ?? 1);
