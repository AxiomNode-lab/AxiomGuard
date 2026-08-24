import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

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

interface SecretRule {
  name: string;
  description: string;
  pattern: RegExp;
}

const DEFAULT_IGNORE_DIRECTORIES = ['.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.axiomguard'];
const DEFAULT_MAX_FILE_BYTES = 1_000_000;

const RULES: readonly SecretRule[] = [
  { name: 'private-key', description: 'Private key material appears to be committed.', pattern: /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----/ },
  { name: 'github-token', description: 'A GitHub token-shaped credential appears to be committed.', pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/ },
  { name: 'aws-access-key', description: 'An AWS access key identifier appears to be committed.', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'sensitive-env-value', description: 'A sensitive environment variable appears to contain a non-placeholder value.', pattern: /^\s*(?:PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|CLIENT_SECRET)\s*=\s*(?!$|["']?(?:changeme|example|placeholder|your[_-]?\w+|<[^>]+>)["']?\s*$).{6,}$/i },
];

const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.yml', '.yaml', '.toml', '.ini', '.conf',
  '.env', '.txt', '.md', '.sh', '.bash', '.zsh', '.py', '.rb', '.go', '.rs', '.java', '.kt', '.php', '.cs',
]);

function normalizeRelative(filePath: string): string {
  return filePath.split(path.sep).join('/');
}

function escapeRegExp(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

function globToRegExp(pattern: string): RegExp {
  const normalized = normalizeRelative(pattern).replace(/^\.\//, '');
  let source = '^';
  for (let index = 0; index < normalized.length; index += 1) {
    const char = normalized[index]!;
    if (char === '*') {
      if (normalized[index + 1] === '*') {
        source += '.*';
        index += 1;
      } else {
        source += '[^/]*';
      }
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += escapeRegExp(char);
    }
  }
  return new RegExp(`${source}$`);
}

function shouldRead(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  return base === '.env' || base.startsWith('.env.') || TEXT_EXTENSIONS.has(path.extname(base));
}

function isIgnoredFile(relativePath: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(relativePath));
}

export function createFindingFingerprint(rule: string, file: string, line: number): string {
  if (!rule || !file || !Number.isInteger(line) || line < 1) throw new TypeError('fingerprint requires rule, file and a positive line number');
  return createHash('sha256').update(`axiomguard:v1\0${rule}\0${normalizeRelative(file)}\0${line}`).digest('hex');
}

async function inspectFile(
  root: string,
  filePath: string,
  findings: SecretFinding[],
  maxFileBytes: number,
  ignoredFiles: readonly RegExp[],
): Promise<void> {
  if (!shouldRead(filePath)) return;
  const relativePath = normalizeRelative(path.relative(root, filePath) || path.basename(filePath));
  if (isIgnoredFile(relativePath, ignoredFiles)) return;

  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.size > maxFileBytes) return;
  const content = await readFile(filePath, 'utf8').catch(() => null);
  if (content === null || content.includes('\u0000')) return;

  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(line)) {
        const lineNumber = index + 1;
        findings.push({
          file: relativePath,
          line: lineNumber,
          rule: rule.name,
          fingerprint: createFindingFingerprint(rule.name, relativePath, lineNumber),
        });
      }
    }
  }
}

async function walk(
  root: string,
  current: string,
  findings: SecretFinding[],
  ignoredDirectories: ReadonlySet<string>,
  ignoredFiles: readonly RegExp[],
  maxFileBytes: number,
): Promise<void> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const fullPath = path.join(current, entry.name);
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) await walk(root, fullPath, findings, ignoredDirectories, ignoredFiles, maxFileBytes);
      continue;
    }
    if (entry.isFile()) await inspectFile(root, fullPath, findings, maxFileBytes, ignoredFiles);
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

export async function scanSecrets(target: string, options: SecretScanOptions = {}): Promise<SecretFinding[]> {
  const root = path.resolve(target);
  const stat = await lstat(root);
  if (!stat.isDirectory()) throw new Error('scan target must be a directory');

  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  if (!Number.isInteger(maxFileBytes) || maxFileBytes < 1) throw new RangeError('maxFileBytes must be a positive integer');
  const ignoredDirectories = new Set(options.ignoreDirectories ?? DEFAULT_IGNORE_DIRECTORIES);
  const ignoredFiles = (options.ignoreFiles ?? []).map(globToRegExp);
  const baseline = new Set(options.baselineFingerprints ?? []);
  const findings: SecretFinding[] = [];
  await walk(root, root, findings, ignoredDirectories, ignoredFiles, maxFileBytes);
  return findings
    .filter((finding) => !baseline.has(finding.fingerprint))
    .sort((left, right) => left.file.localeCompare(right.file) || left.line - right.line || left.rule.localeCompare(right.rule));
}

export function findingsToSarif(findings: readonly SecretFinding[]): Record<string, unknown> {
  const usedRules = [...new Set(findings.map((finding) => finding.rule))];
  const rules = usedRules.map((ruleName) => {
    const rule = RULES.find((candidate) => candidate.name === ruleName);
    return {
      id: ruleName,
      name: ruleName,
      shortDescription: { text: rule?.description ?? 'Potential secret detected.' },
      helpUri: 'https://github.com/AxiomNode-lab/AxiomGuard#scanner-text-json-and-sarif',
      properties: { tags: ['security', 'secrets'] },
    };
  });

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'AxiomGuard', informationUri: 'https://github.com/AxiomNode-lab/AxiomGuard', rules } },
      results: findings.map((finding) => ({
        ruleId: finding.rule,
        level: 'warning',
        message: { text: `Potential secret detected by ${finding.rule}. The matched value is intentionally not included.` },
        partialFingerprints: { 'axiomguard/v1': finding.fingerprint },
        locations: [{ physicalLocation: { artifactLocation: { uri: finding.file }, region: { startLine: finding.line } } }],
      })),
    }],
  };
}
