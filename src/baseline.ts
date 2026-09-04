import type { Baseline, BaselineCapability, Capability, CapabilityChange, DiffResult, Finding, ScanResult } from "./types.js";
import { capabilityFingerprint } from "./analyzer.js";
import { normalizeScope } from "./utils/text.js";

export function toBaseline(result: ScanResult, generatedAt = new Date().toISOString()): Baseline {
  const seen = new Set<string>();
  const capabilities: BaselineCapability[] = [];
  for (const capability of result.capabilities) {
    const normalized: BaselineCapability = { kind: capability.kind, scope: normalizeScope(capability.scope), source: capability.source };
    const fingerprint = capabilityFingerprint(normalized);
    if (!seen.has(fingerprint)) {
      seen.add(fingerprint);
      capabilities.push(normalized);
    }
  }
  capabilities.sort((a, b) => capabilityFingerprint(a).localeCompare(capabilityFingerprint(b)));
  const findings = [...new Set(result.findings.map(findingFingerprint))].sort();
  return { schemaVersion: 1, generatedAt, capabilities, ...(findings.length > 0 ? { findings } : {}) };
}

export function findingFingerprint(finding: Pick<Finding, "id" | "capabilityFingerprints">): string {
  return `${finding.id}|${[...finding.capabilityFingerprints].sort().join(",")}`;
}

export function scopeWidened(previous: string, current: string): boolean {
  const oldScope = normalizeScope(previous);
  const newScope = normalizeScope(current);
  const isDynamicScope = (scope: string): boolean => scope === "dynamic" || scope.startsWith("dynamic-") || scope.includes(":dynamic") || scope.includes("|dynamic");
  const isAnyScope = (scope: string): boolean => scope === "any" || scope.endsWith(":any") || scope.endsWith("|any");
  if (oldScope === newScope) return false;
  if (isDynamicScope(newScope)) return true;
  if (isAnyScope(newScope)) return true;
  if (isDynamicScope(oldScope)) return false;
  if (isAnyScope(oldScope)) return false;
  if (oldScope.endsWith("/**") && newScope.startsWith(oldScope.slice(0, -3))) return false;
  if (newScope.endsWith("/**") && oldScope.startsWith(newScope.slice(0, -2))) return true;
  if (oldScope.includes("|") && newScope.includes("|")) {
    // A different static host is a replacement (added + removed), not a widening.
    return false;
  }
  if (oldScope.startsWith("binary:") && newScope.startsWith("binary:")) return false;
  return false;
}

export function diffBaseline(previous: Baseline, current: ScanResult): DiffResult {
  const currentBaseline = toBaseline(current);
  const previousByKind = new Map<string, BaselineCapability[]>();
  const previousFingerprints = new Set<string>();
  for (const capability of previous.capabilities) {
    const fingerprint = capabilityFingerprint(capability);
    previousFingerprints.add(fingerprint);
    const list = previousByKind.get(capability.kind) ?? [];
    list.push(capability);
    previousByKind.set(capability.kind, list);
  }
  const currentFingerprints = new Set(currentBaseline.capabilities.map(capabilityFingerprint));
  const supersededPrevious = new Set<string>();
  const changes: CapabilityChange[] = [];
  for (const capability of currentBaseline.capabilities) {
    const fingerprint = capabilityFingerprint(capability);
    if (!previousFingerprints.has(fingerprint)) {
      const sameKind = previousByKind.get(capability.kind) ?? [];
      const widenedFrom = sameKind.filter((old) => scopeWidened(old.scope, capability.scope));
      if (widenedFrom.length > 0) {
        changes.push({ type: "widened", current: capability, previous: widenedFrom });
        for (const old of widenedFrom) supersededPrevious.add(capabilityFingerprint(old));
      }
      else changes.push({ type: "added", current: capability, previous: sameKind });
    }
  }
  for (const capability of previous.capabilities) {
    const fingerprint = capabilityFingerprint(capability);
    if (!currentFingerprints.has(fingerprint) && !supersededPrevious.has(fingerprint)) changes.push({ type: "removed", previous: [capability] });
  }
  return { baseline: previous, changes };
}
