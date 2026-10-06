import type {
  FindingConfidence,
  FindingEvidence,
  JsonValue,
  NormalizedFinding,
  ScanResult,
  SecurityPack,
  SecurityRule,
  SecuritySeverity,
  SourceLocation,
} from './contracts.js';
import { SCAN_SCHEMA_VERSION } from './contracts.js';
import { ScannerError } from './errors.js';
import { compareStrings } from './file-policy.js';
import { SecurityPackRegistry } from './registry.js';
import { createRepositoryScanContext } from './repository.js';

const SEVERITY_RANK: Readonly<Record<SecuritySeverity, number>> = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });
const SEVERITIES = new Set<SecuritySeverity>(['critical', 'high', 'medium', 'low', 'info']);
const CONFIDENCES = new Set<FindingConfidence>(['high', 'medium', 'low']);

export interface ScanRepositoryOptions {
  target: string;
  registry?: SecurityPackRegistry;
  packs?: readonly SecurityPack[];
  packIds?: readonly string[];
  engineVersion: string;
  rulesetVersion: string;
  detectedStackIds?: readonly string[];
  ignoreDirectories?: readonly string[];
  ignoreFiles?: readonly string[];
  maxFileBytes?: number;
  concurrency?: number;
  signal?: AbortSignal;
}

function isNonBlank(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function invalidFinding(packId: string, ruleId: string, reason: string): never {
  throw new ScannerError('INVALID_FINDING', `Pack "${packId}" rule "${ruleId}" returned an invalid finding: ${reason}.`, { packId, ruleId });
}

function assertJsonValue(value: unknown, packId: string, ruleId: string, ancestors: Set<object>, depth = 0): asserts value is JsonValue {
  if (depth > 32) invalidFinding(packId, ruleId, 'evidence exceeds the maximum nesting depth');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) invalidFinding(packId, ruleId, 'evidence contains a non-finite number');
    return;
  }
  if (typeof value !== 'object') invalidFinding(packId, ruleId, 'evidence is not JSON-safe');
  if (ancestors.has(value)) invalidFinding(packId, ruleId, 'evidence contains a cycle');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) invalidFinding(packId, ruleId, 'evidence contains an unsupported array object');
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) invalidFinding(packId, ruleId, 'evidence contains a sparse array');
        assertJsonValue(value[index], packId, ruleId, ancestors, depth + 1);
      }
      return;
    }
    if (!isPlainObject(value)) invalidFinding(packId, ruleId, 'evidence contains an unsupported runtime object');
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') invalidFinding(packId, ruleId, 'evidence contains a symbol key');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) {
        invalidFinding(packId, ruleId, 'evidence contains an unsupported property');
      }
      assertJsonValue(descriptor.value, packId, ruleId, ancestors, depth + 1);
    }
  } finally {
    ancestors.delete(value);
  }
}

function validateLocation(value: unknown, packId: string, ruleId: string): SourceLocation | undefined {
  if (value === undefined) return undefined;
  if (!isPlainObject(value) || !isNonBlank(value.file)) invalidFinding(packId, ruleId, 'source location is malformed');
  const file = value.file;
  if (file.includes('\\') || file.includes('\0') || file.startsWith('/') || /^[A-Za-z]:/.test(file)) {
    invalidFinding(packId, ruleId, 'source path must be repository-relative and normalized');
  }
  const segments = file.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    invalidFinding(packId, ruleId, 'source path contains traversal or is not normalized');
  }
  const startLine = value.startLine;
  const endLine = value.endLine;
  if (startLine !== undefined && (!Number.isInteger(startLine) || (startLine as number) < 1)) invalidFinding(packId, ruleId, 'startLine is invalid');
  if (endLine !== undefined && (!Number.isInteger(endLine) || (endLine as number) < 1)) invalidFinding(packId, ruleId, 'endLine is invalid');
  if (endLine !== undefined && startLine === undefined) invalidFinding(packId, ruleId, 'endLine requires startLine');
  if (typeof endLine === 'number' && typeof startLine === 'number' && endLine < startLine) invalidFinding(packId, ruleId, 'endLine precedes startLine');
  return Object.freeze({ file, ...(startLine === undefined ? {} : { startLine: startLine as number }), ...(endLine === undefined ? {} : { endLine: endLine as number }) });
}

function validateEvidence(value: unknown, packId: string, ruleId: string): readonly FindingEvidence[] {
  if (!Array.isArray(value) || value.length === 0) invalidFinding(packId, ruleId, 'evidence must be a non-empty array');
  return Object.freeze(value.map((item): FindingEvidence => {
    if (!isPlainObject(item) || !isNonBlank(item.kind) || !isNonBlank(item.summary)) invalidFinding(packId, ruleId, 'evidence entry is malformed');
    if (item.attributes !== undefined) {
      if (!isPlainObject(item.attributes)) invalidFinding(packId, ruleId, 'evidence attributes must be an object');
      assertJsonValue(item.attributes, packId, ruleId, new Set());
    }
    const attributes = item.attributes === undefined ? undefined : JSON.parse(JSON.stringify(item.attributes)) as Readonly<Record<string, JsonValue>>;
    return Object.freeze({ kind: item.kind, summary: item.summary, ...(attributes === undefined ? {} : { attributes: Object.freeze(attributes) }) });
  }));
}

function validateFinding(value: unknown, pack: SecurityPack, rule: SecurityRule): NormalizedFinding {
  if (!isPlainObject(value)) invalidFinding(pack.id, rule.id, 'finding must be an object');
  for (const field of ['findingId', 'ruleId', 'title', 'description', 'impact', 'remediation', 'detectorId', 'fingerprint'] as const) {
    if (!isNonBlank(value[field])) invalidFinding(pack.id, rule.id, `${field} must be non-empty`);
  }
  if (value.ruleId !== rule.id) invalidFinding(pack.id, rule.id, 'ruleId does not match the executing rule');
  if (value.detectorId !== rule.detectorId) invalidFinding(pack.id, rule.id, 'detectorId does not match the executing rule');
  if (!SEVERITIES.has(value.severity as SecuritySeverity)) invalidFinding(pack.id, rule.id, 'severity is unsupported');
  if (!CONFIDENCES.has(value.confidence as FindingConfidence)) invalidFinding(pack.id, rule.id, 'confidence is unsupported');
  const location = validateLocation(value.location, pack.id, rule.id);
  const evidence = validateEvidence(value.evidence, pack.id, rule.id);
  return Object.freeze({
    findingId: value.findingId as string,
    ruleId: value.ruleId as string,
    severity: value.severity as SecuritySeverity,
    confidence: value.confidence as FindingConfidence,
    title: value.title as string,
    description: value.description as string,
    ...(location === undefined ? {} : { location }),
    evidence,
    impact: value.impact as string,
    remediation: value.remediation as string,
    detectorId: value.detectorId as string,
    fingerprint: value.fingerprint as string,
  });
}

function validateFindingSafely(value: unknown, pack: SecurityPack, rule: SecurityRule): NormalizedFinding {
  try {
    return validateFinding(value, pack, rule);
  } catch (error) {
    if (error instanceof ScannerError && error.code === 'INVALID_FINDING') throw error;
    return invalidFinding(pack.id, rule.id, 'finding validation failed');
  }
}

function isApplicable(restrictions: readonly string[] | undefined, detected: ReadonlySet<string>): boolean {
  return restrictions === undefined || restrictions.length === 0 || restrictions.some((stackId) => detected.has(stackId));
}

function compareFindings(left: NormalizedFinding, right: NormalizedFinding): number {
  return SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity]
    || compareStrings(left.ruleId, right.ruleId)
    || compareStrings(left.location?.file ?? '', right.location?.file ?? '')
    || (left.location?.startLine ?? 0) - (right.location?.startLine ?? 0)
    || compareStrings(left.fingerprint, right.fingerprint)
    || compareStrings(left.findingId, right.findingId);
}

function createRegistry(options: ScanRepositoryOptions): SecurityPackRegistry {
  if ((options.registry === undefined) === (options.packs === undefined)) {
    throw new ScannerError('INVALID_SCAN_OPTIONS', 'Provide exactly one of registry or packs.');
  }
  return options.registry ?? new SecurityPackRegistry(options.packs);
}

export async function scanRepository(options: ScanRepositoryOptions): Promise<ScanResult> {
  if (!isNonBlank(options.engineVersion) || !isNonBlank(options.rulesetVersion)) {
    throw new ScannerError('INVALID_SCAN_OPTIONS', 'engineVersion and rulesetVersion must be non-empty.');
  }
  const registry = createRegistry(options);
  const selectedPacks = registry.selectPacks(options.packIds);
  const context = await createRepositoryScanContext({
    target: options.target,
    ...(options.detectedStackIds === undefined ? {} : { detectedStackIds: options.detectedStackIds }),
    ...(options.ignoreDirectories === undefined ? {} : { ignoreDirectories: options.ignoreDirectories }),
    ...(options.ignoreFiles === undefined ? {} : { ignoreFiles: options.ignoreFiles }),
    ...(options.maxFileBytes === undefined ? {} : { maxFileBytes: options.maxFileBytes }),
    ...(options.concurrency === undefined ? {} : { concurrency: options.concurrency }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  const detectedStacks = new Set(context.detectedStackIds);
  const findings: NormalizedFinding[] = [];
  const detectorIds = new Set<string>();
  const executedPackIds: string[] = [];

  for (const pack of selectedPacks) {
    if (!isApplicable(pack.applicableStacks, detectedStacks)) continue;
    let packExecuted = false;
    for (const rule of pack.rules) {
      if (!isApplicable(rule.applicableStacks, detectedStacks)) continue;
      packExecuted = true;
      detectorIds.add(rule.detectorId);
      let produced: readonly NormalizedFinding[];
      try {
        produced = await rule.detect(context);
      } catch {
        if (options.signal?.aborted) throw new ScannerError('SCAN_ABORTED', 'Repository scan was aborted.');
        throw new ScannerError('RULE_EXECUTION_FAILED', `Pack "${pack.id}" rule "${rule.id}" failed during execution.`, { packId: pack.id, ruleId: rule.id });
      }
      if (!Array.isArray(produced)) invalidFinding(pack.id, rule.id, 'detect must return an array');
      try {
        for (const finding of produced) findings.push(validateFindingSafely(finding, pack, rule));
      } catch (error) {
        if (error instanceof ScannerError && error.code === 'INVALID_FINDING') throw error;
        invalidFinding(pack.id, rule.id, 'finding collection could not be validated');
      }
    }
    if (packExecuted) executedPackIds.push(pack.id);
  }

  findings.sort(compareFindings);
  return Object.freeze({
    versions: Object.freeze({ engineVersion: options.engineVersion, rulesetVersion: options.rulesetVersion, schemaVersion: SCAN_SCHEMA_VERSION }),
    context: Object.freeze({
      target: '.',
      detectorIds: Object.freeze([...detectorIds].sort(compareStrings)),
      packIds: Object.freeze(executedPackIds),
      stackIds: Object.freeze([...detectedStacks].sort(compareStrings)),
    }),
    findings: Object.freeze(findings),
  });
}
