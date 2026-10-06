/** Schema version for serialized generalized scan results. */
export const SCAN_SCHEMA_VERSION = '1.0.0' as const;

export type ScanSchemaVersion = typeof SCAN_SCHEMA_VERSION;

export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingConfidence = 'high' | 'medium' | 'low';

export type JsonPrimitive = string | number | boolean | null;

export type JsonValue = JsonPrimitive | { readonly [key: string]: JsonValue } | readonly JsonValue[];

/**
 * Machine-generated, secret-safe evidence supporting a finding.
 * Attributes must contain only minimal, non-sensitive facts. They must never
 * contain matched secrets, credentials, tokens, private keys, or unredacted
 * sensitive source snippets.
 */
export interface FindingEvidence {
  kind: string;
  summary: string;
  attributes?: Readonly<Record<string, JsonValue>>;
}

export interface SourceLocation {
  file: string;
  startLine?: number;
  endLine?: number;
}

export interface SecurityRuleMetadata {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: SecuritySeverity;
  confidence: FindingConfidence;
  applicableStacks: readonly string[];
  impact: string;
  remediation: string;
  detectorId: string;
  references?: readonly string[];
}

export interface RepositoryFile {
  path: string;
  size: number;
}

/** Runtime-only controlled repository access. Never persist this object in a ScanResult. */
export interface RuleExecutionContext {
  readonly detectedStackIds: readonly string[];
  readonly signal?: AbortSignal;
  listFiles(): Promise<readonly RepositoryFile[]>;
  readTextFile(relativePath: string): Promise<string>;
}

export interface SecurityRule extends SecurityRuleMetadata {
  detect(context: RuleExecutionContext): readonly NormalizedFinding[] | Promise<readonly NormalizedFinding[]>;
}

export interface SecurityPack {
  id: string;
  name: string;
  version: string;
  description: string;
  applicableStacks?: readonly string[];
  rules: readonly SecurityRule[];
}

export interface NormalizedFinding {
  findingId: string;
  ruleId: string;
  severity: SecuritySeverity;
  confidence: FindingConfidence;
  title: string;
  description: string;
  location?: SourceLocation;
  evidence: readonly FindingEvidence[];
  impact: string;
  remediation: string;
  detectorId: string;
  fingerprint: string;
}

export interface ScanVersionMetadata {
  engineVersion: string;
  rulesetVersion: string;
  schemaVersion: ScanSchemaVersion;
}

export interface ScanContext {
  target: string;
  detectorIds: readonly string[];
  packIds?: readonly string[];
  stackIds?: readonly string[];
}

export interface ScanResult {
  versions: ScanVersionMetadata;
  context: ScanContext;
  findings: readonly NormalizedFinding[];
}
