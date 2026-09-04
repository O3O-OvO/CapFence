import type { CapabilityGraph, CapabilityGraphEdge, CapabilityGraphNode, ScanResult } from "./types.js";

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

export function buildCapabilityGraph(result: ScanResult): CapabilityGraph {
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
        location: capability.location,
      });
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

  return {
    schemaVersion: 1,
    target: result.target,
    nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
    edges: [...edges.values()].sort((a, b) => a.id.localeCompare(b.id)),
  };
}
