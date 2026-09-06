#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

import { diffBaseline, findingFingerprint, toBaseline } from "./baseline.js";
import { scanTarget } from "./analyzer.js";
import { loadPolicy, evaluatePolicy } from "./policy.js";
import { formatGithub, formatJson, formatSarif, formatText } from "./reporters.js";
import { buildCapabilityGraph } from "./graph.js";
import { buildPermissionSummary, formatPermissionSummaryJson, formatPermissionSummaryMarkdown } from "./summary.js";
import type { Baseline, ReportFormat, Severity } from "./types.js";

const VERSION = "0.1.0";
const args = process.argv.slice(2);
const REPORT_FORMATS = new Set<ReportFormat>(["text", "json", "sarif", "github"]);
const SEVERITY_LEVELS = new Set<Severity>(["critical", "high", "medium", "low", "info"]);
const VALUE_OPTIONS = new Set(["--format", "--baseline", "--policy", "--fail-on", "--output"]);
const BOOLEAN_OPTIONS = new Set(["--fail-existing", "--allow-changes"]);

function usage(): string {
  return `CapFence ${VERSION}

Capability-diff security for AI agent skills and MCP servers.

Usage:
  capfence scan <path> [options]       Scan supported files without executing them
  capfence baseline <path> [options]   Write a capability baseline
  capfence diff <path> [options]       Compare capabilities with a baseline
  capfence graph <path> [options]      Export a capability relationship graph
  capfence summary <path> [options]    Export a pull request permission summary

Options:
  --format text|json|sarif|github       Output format (default: text)
  --baseline <file>                    Baseline JSON for diff/policy evaluation
  --policy <file>                      YAML policy for capability deny rules
  --fail-on critical|high|medium|low   Exit non-zero at this severity
  --fail-existing                      Include findings already present in baseline
  --allow-changes                      Do not fail on added or widened capabilities
  --output <file>                      Write output to a file instead of stdout
  --help                               Show this help
`;
}

function option(name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

function has(name: string): boolean {
  return args.includes(name);
}

function validateArguments(): string {
  let target: string | undefined;
  const seen = new Set<string>();
  for (let index = 1; index < args.length; index += 1) {
    const argument = args[index]!;
    if (BOOLEAN_OPTIONS.has(argument)) {
      if (seen.has(argument)) throw new Error(`Duplicate option: ${argument}`);
      seen.add(argument);
      continue;
    }
    if (VALUE_OPTIONS.has(argument)) {
      if (seen.has(argument)) throw new Error(`Duplicate option: ${argument}`);
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
      seen.add(argument);
      index += 1;
      continue;
    }
    if (argument.startsWith("--")) throw new Error(`Unknown option: ${argument}`);
    if (target) throw new Error(`Unexpected positional argument: ${argument}`);
    target = argument;
  }
  return target ?? ".";
}

function readBaseline(filePath: string): Baseline {
  const parsed: unknown = JSON.parse(fs.readFileSync(filePath, "utf8"));
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as Baseline).capabilities)) throw new Error(`Invalid baseline: ${filePath}`);
  return parsed as Baseline;
}

function severityAtOrAbove(actual: Severity, threshold: Severity): boolean {
  const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return rank[actual] >= rank[threshold];
}

function writeOutput(output: string): void {
  const outputPath = option("--output");
  if (outputPath) fs.writeFileSync(path.resolve(outputPath), `${output}\n`, "utf8");
  else process.stdout.write(`${output}\n`);
}

function main(): void {
  const command = args[0];
  if (!command || has("--help") || command === "help") {
    writeOutput(usage());
    return;
  }
  if (command === "version" || command === "--version") {
    writeOutput(VERSION);
    return;
  }
  if (!["scan", "baseline", "diff", "graph", "summary"].includes(command)) throw new Error(`Unknown command: ${command}\n\n${usage()}`);
  const target = validateArguments();
  if (command === "diff" && !option("--baseline")) throw new Error("diff requires --baseline <file>");
  const result = scanTarget(target);
  if (command === "graph") {
    const baselinePath = option("--baseline");
    const graphBaseline = baselinePath ? readBaseline(baselinePath) : undefined;
    const graphChanges = graphBaseline ? diffBaseline(graphBaseline, result).changes : [];
    writeOutput(JSON.stringify(buildCapabilityGraph(result, graphChanges), null, 2));
    return;
  }
  const baselinePath = option("--baseline");
  const policyPath = option("--policy");
  const formatValue = option("--format") ?? (command === "summary" ? "markdown" : "text");
  if (command === "summary") {
    if (!["markdown", "json"].includes(formatValue)) throw new Error(`Unsupported summary format: ${formatValue}`);
  }
  if (command !== "summary" && !REPORT_FORMATS.has(formatValue as ReportFormat)) throw new Error(`Unsupported format: ${formatValue}`);
  const format = formatValue as ReportFormat;

  if (command === "baseline") {
    const output = JSON.stringify(toBaseline(result), null, 2);
    if (option("--output")) writeOutput(output);
    else process.stdout.write(`${output}\n`);
    return;
  }

  const baseline = baselinePath ? readBaseline(baselinePath) : undefined;
  const diff = command === "diff" || baseline ? (baseline ? diffBaseline(baseline, result) : undefined) : undefined;
  const policyChanges = diff?.changes ?? (policyPath ? result.capabilities.map((capability) => ({ type: "added" as const, current: { kind: capability.kind, scope: capability.scope, source: capability.source } })) : []);
  const policy = policyPath ? evaluatePolicy(policyChanges, loadPolicy(policyPath)) : undefined;
  const output = command === "summary"
    ? (formatValue === "json" ? formatPermissionSummaryJson(buildPermissionSummary(result, diff?.changes ?? [], policy)) : formatPermissionSummaryMarkdown(buildPermissionSummary(result, diff?.changes ?? [], policy)))
    : format === "json"
    ? formatJson(result, diff?.changes, policy)
    : format === "sarif"
      ? formatSarif(result, VERSION, diff?.changes, policy)
      : format === "github"
        ? formatGithub(result, diff?.changes, policy)
        : formatText(result, diff?.changes, policy);
  writeOutput(output);

  const thresholdValue = option("--fail-on");
  if (thresholdValue && !SEVERITY_LEVELS.has(thresholdValue as Severity)) throw new Error(`Unsupported severity threshold: ${thresholdValue}`);
  const threshold = thresholdValue as Severity | undefined;
  const knownFindings = new Set(baseline?.findings ?? []);
  const findingFailure = threshold && result.findings.some((finding) => {
    if (!severityAtOrAbove(finding.severity, threshold)) return false;
    return has("--fail-existing") || !baseline || !knownFindings.has(findingFingerprint(finding));
  });
  const policyFailure = Boolean(policy?.violations.length);
  const capabilityChangeFailure = Boolean(diff && !has("--allow-changes") && diff.changes.some((change) => change.type === "added" || change.type === "widened"));
  if (findingFailure) process.exitCode = 1;
  if (policyFailure) process.exitCode = 1;
  if (capabilityChangeFailure) process.exitCode = 1;
}

try {
  main();
} catch (error) {
  process.stderr.write(`CapFence error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}
