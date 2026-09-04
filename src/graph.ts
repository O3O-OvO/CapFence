import type { CapabilityChange, CapabilityGraph, CapabilityGraphEdge, CapabilityGraphNode, ScanResult } from "./types.js";

function sourceNodeId(file: string): string {
  return `source:${file}`;
}

function capabilityNodeId(kind: string, scope: string): string {
  return `capability:${kind}|${scope}`;
}

function findingNodeId(id: string, file: string, line: number): string {
  return `finding:${id}|${file}|${line}`;
}

function subjectNodeId(subject: string): string {
  return `subject:${subject}`;
}

function resourceNodeId(type: "network" | "process" | "credential", scope: string): string {
  return `resource:${type}|${scope}`;
}

function confidenceFor(source: "runtime" | "configuration" | "lifecycle" | "build" | "instruction"): "high" | "medium" {
  return source === "configuration" || source === "lifecycle" || source === "build" ? "high" : "medium";
}

export function buildCapabilityGraph(result: ScanResult, changes: CapabilityChange[] = []): CapabilityGraph {
  const changeByFingerprint = new Map<string, CapabilityChange["type"]>();
  for (const change of changes) {
    const capability = change.current ?? change.previous?.[0];
    if (capability) changeByFingerprint.set(`${capability.kind}|${capability.scope}`, change.type);
  }
  const targetId = "target:root";
  const nodes = new Map<string, CapabilityGraphNode>([
    [targetId, { id: targetId, type: "target", label: result.target }],
  ]);
  const edges = new Map<string, CapabilityGraphEdge>();

  const addEdge = (from: string, to: string, type: CapabilityGraphEdge["type"]): void => {
    const id = `${type}:${from}->${to}`;
    edges.set(id, { id, from, to, type });
  };

  for (const capability of result.capabilities) {
    const sourceId = sourceNodeId(capability.location.file);
    const capabilityId = capabilityNodeId(capability.kind, capability.scope);
    if (!nodes.has(sourceId)) nodes.set(sourceId, { id: sourceId, type: "source", label: capability.location.file });
    if (!nodes.has(capabilityId)) {
      nodes.set(capabilityId, {
        id: capabilityId,
        type: "capability",
        label: `${capability.kind}:${capability.scope}`,
        kind: capability.kind,
        scope: capability.scope,
        source: capability.source,
        ...(capability.subject ? { subject: capability.subject, subjects: [capability.subject] } : {}),
        evidence: capability.evidence,
        confidence: confidenceFor(capability.source),
        ...(changeByFingerprint.has(`${capability.kind}|${capability.scope}`) ? { changeType: changeByFingerprint.get(`${capability.kind}|${capability.scope}`) } : {}),
        location: capability.location,
      });
    } else {
      const existing = nodes.get(capabilityId)!;
      if (capability.subject && existing.type === "capability") {
        const subjects = new Set(existing.subjects ?? (existing.subject ? [existing.subject] : []));
        subjects.add(capability.subject);
        existing.subjects = [...subjects].sort();
      }
    }
    addEdge(targetId, sourceId, "contains");
    addEdge(sourceId, capabilityId, "declares");
    const ownerId = capability.subject ? subjectNodeId(capability.subject) : sourceId;
    if (capability.subject) {
      if (!nodes.has(ownerId)) nodes.set(ownerId, { id: ownerId, type: "subject", label: capability.subject });
      addEdge(sourceId, ownerId, "contains");
      addEdge(ownerId, capabilityId, "declares");
    }
    const resourceType = capability.kind === "network.connect"
      ? "network"
      : capability.kind === "process.execute"
        ? "process"
        : capability.kind === "credential.read"
          ? "credential"
          : undefined;
    if (resourceType) {
      const resourceId = resourceNodeId(resourceType, capability.scope);
      if (!nodes.has(resourceId)) {
        nodes.set(resourceId, {
          id: resourceId,
          type: "resource",
          label: `${resourceType}:${capability.scope}`,
          scope: capability.scope,
          resourceType,
          source: capability.source,
          ...(capability.subject ? { subject: capability.subject } : {}),
          evidence: capability.evidence,
          confidence: confidenceFor(capability.source),
          location: capability.location,
        });
      }
      addEdge(ownerId, resourceId, "uses");
    }
  }

  for (const finding of result.findings) {
    const findingId = findingNodeId(finding.id, finding.location.file, finding.location.startLine);
    nodes.set(findingId, {
      id: findingId,
      type: "finding",
      label: `${finding.id}: ${finding.title}`,
      severity: finding.severity,
      location: finding.location,
    });
    for (const fingerprint of finding.capabilityFingerprints) {
      const separator = fingerprint.indexOf("|");
      if (separator < 0) continue;
      const kind = fingerprint.slice(0, separator);
      const scope = fingerprint.slice(separator + 1);
      const capabilityId = capabilityNodeId(kind, scope);
      if (nodes.has(capabilityId)) addEdge(findingId, capabilityId, "evidences");
    }
  }

  for (const change of changes) {
    if (change.type !== "removed" || !change.previous?.[0]) continue;
    const capability = change.previous[0];
    const capabilityId = capabilityNodeId(capability.kind, capability.scope);
    if (!nodes.has(capabilityId)) nodes.set(capabilityId, {
      id: capabilityId,
      type: "capability",
      label: `${capability.kind}:${capability.scope}`,
      kind: capability.kind,
      scope: capability.scope,
      source: capability.source,
      confidence: "high",
      changeType: "removed",
    });
  }

  return {
    schemaVersion: 1,
    target: result.target,
    nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
    edges: [...edges.values()].sort((a, b) => a.id.localeCompare(b.id)),
  };
}
