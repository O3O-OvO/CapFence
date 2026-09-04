export const CAPABILITY_KINDS = [
  "process.execute",
  "filesystem.read",
  "filesystem.write",
  "network.connect",
  "credential.read",
  "dynamic.execute",
  "package.lifecycle",
] as const;

export type CapabilityKind = (typeof CAPABILITY_KINDS)[number];
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ReportFormat = "text" | "json" | "sarif" | "github";

export interface Location {
  file: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

export interface Capability {
  kind: CapabilityKind;
  scope: string;
  source: "runtime" | "configuration" | "lifecycle" | "build" | "instruction";
  location: Location;
  evidence: string;
  subject?: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  message: string;
  remediation: string;
  location: Location;
  evidence: string;
  capabilityFingerprints: string[];
}

export interface AnalysisLimited {
  file: string;
  message: string;
}

export interface ScanResult {
  schemaVersion: 1;
  target: string;
  scannedFiles: number;
  capabilities: Capability[];
  findings: Finding[];
  analysisLimited: AnalysisLimited[];
}

export interface Baseline {
  schemaVersion: 1;
  generatedAt: string;
  capabilities: BaselineCapability[];
  /** Stable finding identities let CI distinguish new findings from known ones. */
  findings?: string[];
}

export interface BaselineCapability {
  kind: CapabilityKind;
  scope: string;
  /** Descriptive provenance; capability identity is kind + normalized scope. */
  source: Capability["source"];
}

export interface CapabilityChange {
  type: "added" | "removed" | "widened";
  current?: BaselineCapability;
  previous?: BaselineCapability[];
}

export interface DiffResult {
  baseline: Baseline;
  changes: CapabilityChange[];
}

export interface PolicyDenyRule {
  capability: CapabilityKind;
  scope?: string;
  severity?: Severity;
  reason?: string;
}

export interface Policy {
  deny?: Array<PolicyDenyRule | string>;
  network?: {
    allow?: string[];
  };
}

export interface PolicyViolation {
  severity: Severity;
  capability: BaselineCapability;
  reason: string;
}

export interface PolicyResult {
  violations: PolicyViolation[];
}

export type GraphNodeType = "target" | "source" | "subject" | "resource" | "capability" | "finding";

export interface CapabilityGraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  kind?: CapabilityKind;
  scope?: string;
  resourceType?: "network" | "process" | "credential";
  source?: Capability["source"];
  subject?: string;
  subjects?: string[];
  evidence?: string;
  confidence?: "high" | "medium" | "low";
  changeType?: "added" | "removed" | "widened";
  severity?: Severity;
  location?: Location;
}

export interface CapabilityGraphEdge {
  id: string;
  from: string;
  to: string;
  type: "contains" | "declares" | "evidences" | "uses";
}

export interface CapabilityGraph {
  schemaVersion: 1;
  target: string;
  nodes: CapabilityGraphNode[];
  edges: CapabilityGraphEdge[];
}
