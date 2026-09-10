import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { diffBaseline, toBaseline } from "../src/baseline.js";
import { scanTarget } from "../src/analyzer.js";

function fixture(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "capfence-scope-"));
  fs.mkdirSync(path.join(directory, "tests"));
  fs.writeFileSync(path.join(directory, "main.ts"), "import {spawn} from 'child_process';\nspawn('node', unknownArgs);\n");
  fs.writeFileSync(path.join(directory, "tests", "ignored.ts"), "fetch('https://ignored.example');\n");
  return directory;
}

describe("scan scope and process severity", () => {
  it("excludes relative paths and reports the scope", () => {
    const directory = fixture();
    try {
      const result = scanTarget(directory, { exclude: ["tests"] });
      expect(result.scannedFiles).toBe(1);
      expect(result.excludedPaths).toEqual(["tests"]);
      expect(result.capabilities.some(item => item.scope.includes("ignored.example"))).toBe(false);
      const baseline = toBaseline(result);
      expect(baseline.excludedPaths).toEqual(["tests"]);
      expect(() => diffBaseline(baseline, scanTarget(directory))).toThrow("Baseline exclusions differ");
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it("uses medium severity for fixed ordinary executables with unresolved args", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "capfence-severity-"));
    try {
      fs.writeFileSync(path.join(directory, "run.ts"), "import {spawn} from 'child_process';\nspawn('git', unknownArgs);\n");
      expect(scanTarget(directory).findings[0]?.severity).toBe("medium");
      fs.writeFileSync(path.join(directory, "run.ts"), "import {spawn} from 'child_process';\nspawn('python', unknownArgs);\n");
      expect(scanTarget(directory).findings[0]?.severity).toBe("high");
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
