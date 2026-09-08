import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { scanTarget } from "../dist/analyzer.js";

const count = Number(process.argv.slice(2).filter(value => value !== "--")[0] ?? 1000);
if (!Number.isSafeInteger(count) || count < 1 || count > 100000) throw new Error("File count must be 1..100000");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "capfence-bench-"));
try {
  for (let index = 0; index < count; index++) {
    fs.writeFileSync(path.join(root, `${String(index).padStart(6, "0")}.ts`), `fetch("https://host-${index}.example.com");\n`);
  }
  const start = performance.now();
  const result = scanTarget(root);
  console.log(JSON.stringify({ files: result.scannedFiles, capabilities: result.capabilities.length, limitations: result.analysisLimited.length, durationMs: Math.round(performance.now() - start), peakRssKiB: process.resourceUsage().maxRSS, node: process.version }, null, 2));
  if (result.scannedFiles !== count || result.capabilities.length !== count || result.analysisLimited.length) process.exitCode = 1;
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
