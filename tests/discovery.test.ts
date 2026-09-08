import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { discoverFiles, iterateFiles, type DiscoveryIssue } from "../src/discovery.js";

const roots: string[] = [];
function root(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "capfence-discovery-"));
  roots.push(dir);
  return dir;
}
afterEach(() => { vi.restoreAllMocks(); for (const dir of roots.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });

describe("discovery completeness and streaming", () => {
  it("reports oversized supported files without loading them", () => {
    const dir = root();
    fs.writeFileSync(path.join(dir, "big.js"), "x".repeat(100));
    const issues: DiscoveryIssue[] = [];
    expect(discoverFiles(dir, { maxFileBytes: 10, onIssue: issue => issues.push(issue) }).files).toEqual([]);
    expect(issues).toEqual([{ file: "big.js", message: "File exceeds 10 byte analysis limit." }]);
  });
  it("defers reads until iteration and preserves deterministic order", () => {
    const dir = root();
    fs.writeFileSync(path.join(dir, "b.sh"), "echo b");
    fs.writeFileSync(path.join(dir, "a.sh"), "echo a");
    const spy = vi.spyOn(fs, "readFileSync");
    const discovered = iterateFiles(dir);
    expect(spy).not.toHaveBeenCalled();
    expect([...discovered.files].map(file => file.relativePath)).toEqual(["a.sh", "b.sh"]);
    expect(spy).toHaveBeenCalledTimes(2);
  });
  it("reports unreadable directories instead of a silent empty scan", () => {
    const dir = root();
    vi.spyOn(fs, "readdirSync").mockImplementation(() => { throw new Error("EACCES"); });
    const issues: DiscoveryIssue[] = [];
    expect(discoverFiles(dir, { onIssue: issue => issues.push(issue) }).files).toEqual([]);
    expect(issues[0]?.message).toBe("Unable to read directory.");
  });
});
