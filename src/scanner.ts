import { lstat, readdir, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import {
  DEFAULT_FILESYSTEM_CONCURRENCY,
  DEFAULT_IGNORE_DIRECTORIES,
  DEFAULT_MAX_FILE_BYTES,
  globToRegExp,
  isSupportedTextPath,
  mapWithConcurrency,
  normalizePathSeparators,
} from './scanner/file-policy.js';
import { createLegacySecretFingerprint, getInternalSecretRule, inspectSecretText, listInternalSecretRules } from './scanner/secret-detection.js';

export {
  SCAN_SCHEMA_VERSION,
  type FindingConfidence,
  type FindingEvidence,
  type JsonPrimitive,
  type JsonValue,
  type NormalizedFinding,
  type ScanContext,
  type ScanResult,
  type ScanSchemaVersion,
  type ScanVersionMetadata,
  type SecurityRuleMetadata,
  type SecuritySeverity,
  type SourceLocation,
  type RepositoryFile,
  type RuleExecutionContext,
  type SecurityPack,
  type SecurityRule,
} from './scanner/contracts.js';
export { ScannerError, type ScannerErrorCode, type ScannerErrorDetails } from './scanner/errors.js';
export { CORE_SECURITY_PACK_VERSION, createCoreSecurityPack } from './scanner/core-pack.js';
export { SecurityPackRegistry } from './scanner/registry.js';
export { RepositoryScanContext, createRepositoryScanContext, type RepositoryScanContextOptions } from './scanner/repository.js';
export { scanRepository, type ScanRepositoryOptions } from './scanner/runtime.js';

export type SecretSeverity = 'error' | 'warning';

export interface SecretFinding {
  file: string;
  line: number;
  rule: string;
  fingerprint: string;
}

export interface SecretScanOptions {
  ignoreDirectories?: readonly string[];
  ignoreFiles?: readonly string[];
  maxFileBytes?: number;
  baselineFingerprints?: readonly string[];
  /** Maximum files inspected concurrently. Default: 16. */
  concurrency?: number;
}

export interface SecretScanBaseline {
  version: 1;
  fingerprints: string[];
}

export interface SecretScannerConfig {
  version?: 1;
  ignoreDirectories?: readonly string[];
  ignoreFiles?: readonly string[];
  maxFileBytes?: number;
  baseline?: string;
}

export interface SecretRuleInfo {
  name: string;
  description: string;
  severity: SecretSeverity;
}

const DEFAULT_CONCURRENCY = DEFAULT_FILESYSTEM_CONCURRENCY;

const packageVersion = ((): string => {
  try {
    const pkg = createRequire(import.meta.url)('../package.json') as { version?: string };
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

function normalizeRelative(filePath: string): string {
  return normalizePathSeparators(filePath);
}

function shouldRead(filePath: string): boolean {
  return isSupportedTextPath(filePath);
}

function isIgnoredFile(relativePath: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(relativePath));
}

/** Rule metadata without the patterns, for documentation and SARIF consumers. */
export function listSecretRules(): SecretRuleInfo[] {
  return listInternalSecretRules().map(({ name, description, severity }) => ({ name, description, severity }));
}

export function createFindingFingerprint(rule: string, file: string, line: number): string {
  return createLegacySecretFingerprint(rule, file, line);
}

async function inspectFile(root: string, filePath: string, maxFileBytes: number, ignoredFiles: readonly RegExp[]): Promise<SecretFinding[]> {
  if (!shouldRead(filePath)) return [];
  const relativePath = normalizeRelative(path.relative(root, filePath) || path.basename(filePath));
  if (isIgnoredFile(relativePath, ignoredFiles)) return [];

  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.size > maxFileBytes) return [];
  const content = await readFile(filePath, 'utf8').catch(() => null);
  if (content === null || content.includes('\u0000')) return [];

  return inspectSecretText(relativePath, content);
}

async function collectFiles(current: string, ignoredDirectories: ReadonlySet<string>, files: string[]): Promise<void> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const fullPath = path.join(current, entry.name);
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) await collectFiles(fullPath, ignoredDirectories, files);
      continue;
    }
    if (entry.isFile()) files.push(fullPath);
  }
}

export function parseSecretScannerConfig(input: unknown): SecretScannerConfig {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('scanner config must be a JSON object');
  const value = input as Record<string, unknown>;
  if (value.version !== undefined && value.version !== 1) throw new TypeError('scanner config version must be 1');

  const readStringArray = (name: string): readonly string[] | undefined => {
    const item = value[name];
    if (item === undefined) return undefined;
    if (!Array.isArray(item) || item.some((entry) => typeof entry !== 'string' || entry.length === 0)) throw new TypeError(`${name} must be an array of non-empty strings`);
    return item as string[];
  };

  const maxFileBytes = value.maxFileBytes;
  if (maxFileBytes !== undefined && (!Number.isInteger(maxFileBytes) || (maxFileBytes as number) < 1)) throw new TypeError('maxFileBytes must be a positive integer');
  if (value.baseline !== undefined && (typeof value.baseline !== 'string' || value.baseline.length === 0)) throw new TypeError('baseline must be a non-empty path string');

  const config: SecretScannerConfig = {};
  if (value.version !== undefined) config.version = 1;
  const ignoreDirectories = readStringArray('ignoreDirectories');
  const ignoreFiles = readStringArray('ignoreFiles');
  if (ignoreDirectories) config.ignoreDirectories = ignoreDirectories;
  if (ignoreFiles) config.ignoreFiles = ignoreFiles;
  if (maxFileBytes !== undefined) config.maxFileBytes = maxFileBytes as number;
  if (typeof value.baseline === 'string') config.baseline = value.baseline;
  return config;
}

export function createSecretScanBaseline(findings: readonly SecretFinding[]): SecretScanBaseline {
  return { version: 1, fingerprints: [...new Set(findings.map((finding) => finding.fingerprint))].sort() };
}

export function parseSecretScanBaseline(input: unknown): SecretScanBaseline {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('baseline must be a JSON object');
  const value = input as Record<string, unknown>;
  if (value.version !== 1) throw new TypeError('baseline version must be 1');
  if (!Array.isArray(value.fingerprints) || value.fingerprints.some((entry) => typeof entry !== 'string' || !/^[a-f0-9]{64}$/.test(entry))) {
    throw new TypeError('baseline fingerprints must be SHA-256 hex strings');
  }
  return { version: 1, fingerprints: [...new Set(value.fingerprints as string[])].sort() };
}

/**
 * Scan a directory tree (or a single file) for high-confidence secret shapes.
 * Findings never include the matched value. Symbolic links are skipped and
 * `.gitignore` is not consulted; use `ignoreDirectories`/`ignoreFiles`.
 */
export async function scanSecrets(target: string, options: SecretScanOptions = {}): Promise<SecretFinding[]> {
  const resolved = path.resolve(target);
  const stat = await lstat(resolved);
  if (!stat.isDirectory() && !stat.isFile()) throw new Error('scan target must be a directory or a file');

  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  if (!Number.isInteger(maxFileBytes) || maxFileBytes < 1) throw new RangeError('maxFileBytes must be a positive integer');
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 256) throw new RangeError('concurrency must be an integer between 1 and 256');
  const ignoredDirectories = new Set(options.ignoreDirectories ?? DEFAULT_IGNORE_DIRECTORIES);
  const ignoredFiles = (options.ignoreFiles ?? []).map(globToRegExp);
  const baseline = new Set(options.baselineFingerprints ?? []);

  const root = stat.isDirectory() ? resolved : path.dirname(resolved);
  const files: string[] = [];
  if (stat.isDirectory()) await collectFiles(resolved, ignoredDirectories, files);
  else files.push(resolved);

  const results = await mapWithConcurrency(files, concurrency, (file) => inspectFile(root, file, maxFileBytes, ignoredFiles));
  return results
    .flat()
    .filter((finding) => !baseline.has(finding.fingerprint))
    .sort((left, right) => left.file.localeCompare(right.file) || left.line - right.line || left.rule.localeCompare(right.rule));
}

export function findingsToSarif(findings: readonly SecretFinding[]): Record<string, unknown> {
  const usedRules = [...new Set(findings.map((finding) => finding.rule))].sort();
  const ruleIndex = new Map(usedRules.map((name, index) => [name, index]));
  const rules = usedRules.map((ruleName) => {
    const rule = getInternalSecretRule(ruleName);
    return {
      id: ruleName,
      name: ruleName,
      shortDescription: { text: rule?.description ?? 'Potential secret detected.' },
      helpUri: 'https://github.com/AxiomNode-lab/AxiomGuard/blob/main/docs/SCANNER.md',
      defaultConfiguration: { level: rule?.severity ?? 'warning' },
      properties: { tags: ['security', 'secrets'], 'security-severity': rule?.severity === 'error' ? '8.0' : '5.0' },
    };
  });

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'AxiomGuard',
          semanticVersion: packageVersion,
          informationUri: 'https://github.com/AxiomNode-lab/AxiomGuard',
          rules,
        },
      },
      originalUriBaseIds: { SRCROOT: { uri: 'file:///', description: { text: 'Scan root' } } },
      results: findings.map((finding) => ({
        ruleId: finding.rule,
        ruleIndex: ruleIndex.get(finding.rule) ?? 0,
        level: getInternalSecretRule(finding.rule)?.severity ?? 'warning',
        message: { text: `Potential secret detected by ${finding.rule}. The matched value is intentionally not included.` },
        partialFingerprints: { 'axiomguard/v1': finding.fingerprint },
        locations: [{ physicalLocation: { artifactLocation: { uri: finding.file, uriBaseId: 'SRCROOT' }, region: { startLine: finding.line } } }],
      })),
    }],
  };
}
