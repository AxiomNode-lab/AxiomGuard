import type { FindingConfidence, SecurityPack, SecurityRule, SecuritySeverity } from './contracts.js';
import { ScannerError } from './errors.js';
import { compareStrings } from './file-policy.js';

const ID_PATTERN = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SEVERITIES = new Set<SecuritySeverity>(['critical', 'high', 'medium', 'low', 'info']);
const CONFIDENCES = new Set<FindingConfidence>(['high', 'medium', 'low']);

function isNonBlank(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function assertId(value: unknown, label: string, packId?: string): asserts value is string {
  if (!isNonBlank(value) || !ID_PATTERN.test(value)) {
    throw new ScannerError('INVALID_PACK', `${label} must be a non-empty stable ID.`, packId === undefined ? {} : { packId });
  }
}

function validateStringList(value: unknown, label: string, packId: string, allowUndefined = false): readonly string[] | undefined {
  if (value === undefined && allowUndefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => !isNonBlank(item) || !ID_PATTERN.test(item)) || new Set(value).size !== value.length) {
    throw new ScannerError('INVALID_PACK', `${label} must contain unique stable IDs.`, { packId });
  }
  return value as readonly string[];
}

function validateReferences(value: unknown, packId: string): readonly string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => {
    if (!isNonBlank(item)) return true;
    try {
      const url = new URL(item);
      return url.protocol !== 'https:' && url.protocol !== 'http:';
    } catch {
      return true;
    }
  })) {
    throw new ScannerError('INVALID_PACK', 'Rule references must be HTTP(S) URLs.', { packId });
  }
  return value as readonly string[];
}

function validateRule(rule: SecurityRule, packId: string): void {
  if (rule === null || typeof rule !== 'object') throw new ScannerError('INVALID_PACK', 'Pack rules must be objects.', { packId });
  assertId(rule.id, 'Rule ID', packId);
  for (const [label, value] of [
    ['Rule title', rule.title],
    ['Rule description', rule.description],
    ['Rule category', rule.category],
    ['Rule impact', rule.impact],
    ['Rule remediation', rule.remediation],
  ] as const) {
    if (!isNonBlank(value)) throw new ScannerError('INVALID_PACK', `${label} must be non-empty.`, { packId, ruleId: rule.id });
  }
  assertId(rule.detectorId, 'Detector ID', packId);
  if (!SEVERITIES.has(rule.severity)) throw new ScannerError('INVALID_PACK', 'Rule severity is invalid.', { packId, ruleId: rule.id });
  if (!CONFIDENCES.has(rule.confidence)) throw new ScannerError('INVALID_PACK', 'Rule confidence is invalid.', { packId, ruleId: rule.id });
  validateStringList(rule.applicableStacks, 'Rule applicableStacks', packId);
  validateReferences(rule.references, packId);
  if (typeof rule.detect !== 'function') throw new ScannerError('INVALID_PACK', 'Rule detect must be a function.', { packId, ruleId: rule.id });
}

function freezeRule(rule: SecurityRule): SecurityRule {
  const references = rule.references === undefined ? undefined : Object.freeze([...rule.references]);
  const frozen: SecurityRule = {
    id: rule.id,
    title: rule.title,
    description: rule.description,
    category: rule.category,
    severity: rule.severity,
    confidence: rule.confidence,
    applicableStacks: Object.freeze([...rule.applicableStacks]),
    impact: rule.impact,
    remediation: rule.remediation,
    detectorId: rule.detectorId,
    detect: rule.detect,
    ...(references === undefined ? {} : { references }),
  };
  return Object.freeze(frozen);
}

function validateAndFreezePack(pack: SecurityPack): SecurityPack {
  if (pack === null || typeof pack !== 'object') throw new ScannerError('INVALID_PACK', 'Pack must be an object.');
  assertId(pack.id, 'Pack ID');
  if (!isNonBlank(pack.name) || !isNonBlank(pack.description)) {
    throw new ScannerError('INVALID_PACK', 'Pack name and description must be non-empty.', { packId: pack.id });
  }
  if (!isNonBlank(pack.version) || !VERSION_PATTERN.test(pack.version)) {
    throw new ScannerError('INVALID_PACK', 'Pack version must be a semantic version.', { packId: pack.id });
  }
  const applicableStacks = validateStringList(pack.applicableStacks, 'Pack applicableStacks', pack.id, true);
  if (!Array.isArray(pack.rules) || pack.rules.length === 0) throw new ScannerError('INVALID_PACK', 'Pack rules must be a non-empty array.', { packId: pack.id });
  for (const rule of pack.rules) validateRule(rule, pack.id);
  const localRuleIds = new Set<string>();
  for (const rule of pack.rules) {
    if (localRuleIds.has(rule.id)) throw new ScannerError('DUPLICATE_RULE_ID', `Duplicate rule ID "${rule.id}".`, { packId: pack.id, ruleId: rule.id });
    localRuleIds.add(rule.id);
  }

  const frozen: SecurityPack = {
    id: pack.id,
    name: pack.name,
    version: pack.version,
    description: pack.description,
    rules: Object.freeze(pack.rules.map(freezeRule).sort((left, right) => compareStrings(left.id, right.id))),
    ...(applicableStacks === undefined ? {} : { applicableStacks: Object.freeze([...applicableStacks]) }),
  };
  return Object.freeze(frozen);
}

export class SecurityPackRegistry {
  readonly #packs = new Map<string, SecurityPack>();
  readonly #ruleOwners = new Map<string, string>();

  constructor(packs: readonly SecurityPack[] = []) {
    for (const pack of packs) this.register(pack);
  }

  register(pack: SecurityPack): void {
    const frozen = validateAndFreezePack(pack);
    if (this.#packs.has(frozen.id)) throw new ScannerError('DUPLICATE_PACK_ID', `Duplicate pack ID "${frozen.id}".`, { packId: frozen.id });
    for (const rule of frozen.rules) {
      const owner = this.#ruleOwners.get(rule.id);
      if (owner !== undefined) {
        throw new ScannerError('DUPLICATE_RULE_ID', `Duplicate rule ID "${rule.id}" in packs "${owner}" and "${frozen.id}".`, { packId: frozen.id, ruleId: rule.id });
      }
    }
    this.#packs.set(frozen.id, frozen);
    for (const rule of frozen.rules) this.#ruleOwners.set(rule.id, frozen.id);
  }

  listPacks(): readonly SecurityPack[] {
    return Object.freeze([...this.#packs.values()].sort((left, right) => compareStrings(left.id, right.id)));
  }

  resolvePack(packId: string): SecurityPack | undefined {
    return this.#packs.get(packId);
  }

  selectPacks(packIds?: readonly string[]): readonly SecurityPack[] {
    if (packIds === undefined) return this.listPacks();
    const selected = new Set(packIds);
    for (const packId of selected) {
      assertId(packId, 'Requested pack ID');
      if (!this.#packs.has(packId)) throw new ScannerError('UNKNOWN_PACK', `Unknown requested pack ID "${packId}".`, { packId });
    }
    return Object.freeze([...selected].sort().map((packId) => this.#packs.get(packId)!));
  }

  listRules(packIds?: readonly string[]): readonly SecurityRule[] {
    return Object.freeze(this.selectPacks(packIds).flatMap((pack) => pack.rules).sort((left, right) => compareStrings(left.id, right.id)));
  }
}
