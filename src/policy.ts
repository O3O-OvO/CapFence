import fs from "node:fs";

import { parse as parseYaml } from "yaml";

import { CAPABILITY_KINDS, type BaselineCapability, type CapabilityChange, type Policy, type PolicyDenyRule, type PolicyResult, type PolicyViolation, type Severity } from "./types.js";
import { normalizeScope } from "./utils/text.js";

const SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low", "info"]);

function parseDenyRule(value: unknown): PolicyDenyRule | undefined {
  if (typeof value === "object" && value !== null && "capability" in value) {
    const candidate = value as Partial<PolicyDenyRule>;
    if (Object.keys(candidate).some((key) => !["capability", "scope", "severity", "reason"].includes(key))) return undefined;
    if (typeof candidate.capability !== "string" || !CAPABILITY_KINDS.includes(candidate.capability as (typeof CAPABILITY_KINDS)[number])) return undefined;
    if (candidate.scope !== undefined && typeof candidate.scope !== "string") return undefined;
    if (candidate.reason !== undefined && typeof candidate.reason !== "string") return undefined;
    if (candidate.severity !== undefined && (typeof candidate.severity !== "string" || !SEVERITIES.has(candidate.severity as Severity))) return undefined;
    return {
      capability: candidate.capability as PolicyDenyRule["capability"],
      ...(candidate.scope ? { scope: candidate.scope } : {}),
      ...(candidate.severity ? { severity: candidate.severity as Severity } : {}),
      ...(candidate.reason ? { reason: candidate.reason } : {}),
    };
  }
  if (typeof value !== "string") return undefined;
  const [capability, ...scopeParts] = value.split(":");
  if (!capability || !CAPABILITY_KINDS.includes(capability as (typeof CAPABILITY_KINDS)[number])) return undefined;
  const scope = scopeParts.join(":") || undefined;
  return { capability: capability as PolicyDenyRule["capability"], ...(scope ? { scope } : {}) };
}

export function loadPolicy(filePath: string): Policy {
  const content = fs.readFileSync(filePath, "utf8");
  let parsed: unknown;
  try {
    parsed = parseYaml(content) as unknown;
  } catch (error) {
    throw new Error(`Invalid policy YAML: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid policy: expected a mapping");
  const input = parsed as Record<string, unknown>;
  const unknownRootKeys = Object.keys(input).filter((key) => !["deny", "network"].includes(key));
  if (unknownRootKeys.length > 0) throw new Error(`Invalid policy: unknown key(s): ${unknownRootKeys.join(", ")}`);
  const policy: Policy = {};
  if (input.deny !== undefined) {
    if (!Array.isArray(input.deny)) throw new Error("Invalid policy.deny: expected an array");
    const deny = input.deny.map((item) => parseDenyRule(item));
    if (deny.some((item) => !item)) throw new Error("Invalid policy.deny: unknown capability or field type");
    policy.deny = deny.filter((item): item is PolicyDenyRule => Boolean(item));
  }
  if (input.network !== undefined) {
    if (!input.network || typeof input.network !== "object" || Array.isArray(input.network)) throw new Error("Invalid policy.network: expected a mapping");
    const network = input.network as Record<string, unknown>;
    const unknownNetworkKeys = Object.keys(network).filter((key) => key !== "allow");
    if (unknownNetworkKeys.length > 0) throw new Error(`Invalid policy.network: unknown key(s): ${unknownNetworkKeys.join(", ")}`);
    if (network.allow !== undefined && (!Array.isArray(network.allow) || network.allow.some((item) => typeof item !== "string"))) throw new Error("Invalid policy.network.allow: expected string[]");
    if (Array.isArray(network.allow)) policy.network = { allow: network.allow };
  }
  return policy;
}

function matchesScope(ruleScope: string | undefined, capabilityScope: string): boolean {
  if (!ruleScope || normalizeScope(ruleScope) === "*") return true;
  const rule = normalizeScope(ruleScope);
  const actual = normalizeScope(capabilityScope);
  if (rule === actual) return true;
  if (rule.endsWith("/**")) return actual.startsWith(rule.slice(0, -2));
  if (rule.endsWith(":any") || rule === "any") return true;
  return false;
}

function violatesNetworkAllowlist(capability: BaselineCapability, policy: Policy): boolean {
  if (capability.kind !== "network.connect" || !policy.network?.allow?.length) return false;
  if (capability.scope === "dynamic" || capability.scope.includes("dynamic")) return true;
  const host = capability.scope.split("|").at(-1) ?? capability.scope;
  return !policy.network.allow.some((allowed) => matchesScope(allowed, host));
}

export function evaluatePolicy(changes: CapabilityChange[], policy: Policy): PolicyResult {
  const denyRules = (policy.deny ?? []).map(parseDenyRule).filter((rule): rule is PolicyDenyRule => Boolean(rule));
  const violations: PolicyViolation[] = [];
  for (const change of changes) {
    if (change.type === "removed" || !change.current) continue;
    const capability = change.current;
    const matchingRule = denyRules.find((rule) => rule.capability === capability.kind && matchesScope(rule.scope, capability.scope));
    const networkDenied = violatesNetworkAllowlist(capability, policy);
    if (!matchingRule && !networkDenied) continue;
    const severity = matchingRule?.severity && SEVERITIES.has(matchingRule.severity) ? matchingRule.severity : "high";
    violations.push({
      severity,
      capability,
      reason: matchingRule?.reason ?? "Network host is outside the policy allowlist.",
    });
  }
  return { violations };
}
