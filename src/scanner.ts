import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

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

interface SecretRule extends SecretRuleInfo {
  pattern: RegExp;
}

const DEFAULT_IGNORE_DIRECTORIES = ['.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.axiomguard', 'vendor', '.venv', 'venv', '__pycache__', 'target'];
const DEFAULT_MAX_FILE_BYTES = 1_000_000;
const DEFAULT_CONCURRENCY = 16;

// Whole-value placeholders (anchored to the end) and reference prefixes such as `${VAR}`, `%VAR%`, `{{ x }}`.
const PLACEHOLDER_WORD = String.raw`(?:changeme|change-me|example|placeholder|dummy|sample|your[_-]?[a-z0-9_-]+|<[^>]+>|\*{3,}|x{4,}|undefined|null|none|true|false)`;
const PLACEHOLDER_PREFIX = String.raw`(?:\$|%[A-Za-z_]|\{\{|<)`;
const NOT_PLACEHOLDER = String.raw`(?!$|["']?${PLACEHOLDER_WORD}["']?\s*$|["']?${PLACEHOLDER_PREFIX})`;
// Values must look like credentials rather than words: quoted, or containing a digit or symbol.
const CREDENTIAL_VALUE = String.raw`(?:["'][^"']{6,}["']|(?=[^\s"',;]*[0-9!@#$%^&*+/=~_-])[^\s"',;]{6,})`;

// Keep this set deliberately narrow. Each provider-shaped rule should have a
// stable, documented prefix and enough trailing entropy to avoid turning the
// scanner into a generic high-noise string detector.
const RULES: readonly SecretRule[] = [
  { name: 'private-key', severity: 'error', description: 'Private key material appears to be committed.', pattern: /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----/ },
  { name: 'github-token', severity: 'error', description: 'A GitHub token-shaped credential appears to be committed.', pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/ },
  { name: 'gitlab-token', severity: 'error', description: 'A GitLab token-shaped credential appears to be committed.', pattern: /\bgl(?:pat|rt|dt|ptt|soat|oas)-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'aws-access-key', severity: 'error', description: 'An AWS access key identifier appears to be committed.', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/ },
  { name: 'stripe-live-secret', severity: 'error', description: 'A Stripe live-mode secret or restricted API key appears to be committed.', pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/ },
  { name: 'slack-token', severity: 'error', description: 'A Slack bot, user, app-level or refresh token appears to be committed.', pattern: /\bxox(?:[bpasr]|e\.xox[bp])-[A-Za-z0-9-]{20,}\b/ },
  { name: 'slack-webhook-url', severity: 'warning', description: 'A Slack incoming-webhook URL appears to be committed.', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/ },
  { name: 'openai-api-key', severity: 'error', description: 'An OpenAI API key appears to be committed.', pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20}T3BlbkFJ[A-Za-z0-9_-]{20}\b|\bsk-proj-[A-Za-z0-9_-]{60,}\b/ },
  { name: 'anthropic-api-key', severity: 'error', description: 'An Anthropic API key appears to be committed.', pattern: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/ },
  { name: 'google-api-key', severity: 'warning', description: 'A Google API key appears to be committed.', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'npm-token', severity: 'error', description: 'An npm access token appears to be committed.', pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: 'sendgrid-api-key', severity: 'error', description: 'A SendGrid API key appears to be committed.', pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { name: 'huggingface-token', severity: 'error', description: 'A Hugging Face access token appears to be committed.', pattern: /\bhf_[A-Za-z0-9]{34}\b/ },
  { name: 'digitalocean-token', severity: 'error', description: 'A DigitalOcean API token appears to be committed.', pattern: /\bdo[opr]_v1_[a-f0-9]{64}\b/ },
  { name: 'shopify-token', severity: 'error', description: 'A Shopify access token appears to be committed.', pattern: /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/ },
  { name: 'pypi-token', severity: 'error', description: 'A PyPI upload token appears to be committed.', pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/ },
  { name: 'vault-token', severity: 'error', description: 'A HashiCorp Vault token appears to be committed.', pattern: /\bhv[sb]\.[A-Za-z0-9_-]{24,}\b/ },
  { name: 'age-secret-key', severity: 'error', description: 'An age encryption secret key appears to be committed.', pattern: /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/ },
  { name: 'telegram-bot-token', severity: 'warning', description: 'A Telegram bot token appears to be committed.', pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/ },
  { name: 'connection-string-password', severity: 'warning', description: 'A database or broker URL with an embedded password appears to be committed.', pattern: new RegExp(String.raw`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|clickhouse):\/\/[^:/\s@]+:(?!${PLACEHOLDER_WORD}@|${PLACEHOLDER_PREFIX})[^@/\s]{8,}@`, 'i') },
  {
    name: 'sensitive-env-value',
    severity: 'warning',
    description: 'A sensitive environment variable appears to contain a non-placeholder value.',
    pattern: new RegExp(String.raw`^\s*(?:export\s+|ENV\s+|ARG\s+|-\s*)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_?KEY|TOKEN|PRIVATE_KEY)(?:_[A-Z0-9]+)*\s*[=:]\s*${NOT_PLACEHOLDER}${CREDENTIAL_VALUE}`, 'i'),
  },
];

const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.tsx', '.jsx', '.vue', '.svelte', '.astro',
  '.json', '.json5', '.jsonc', '.yml', '.yaml', '.toml', '.ini', '.conf', '.cfg', '.properties', '.xml', '.plist',
  '.env', '.txt', '.md', '.mdx', '.rst', '.adoc',
  '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
  '.py', '.rb', '.go', '.rs', '.java', '.kt', '.kts', '.scala', '.groovy', '.gradle', '.php', '.cs', '.fs', '.swift', '.dart', '.ex', '.exs', '.erl', '.hs', '.lua', '.pl', '.pm', '.r', '.c', '.h', '.cc', '.cpp', '.hpp', '.m', '.mm',
  '.html', '.htm', '.css', '.scss', '.less',
  '.sql', '.graphql', '.gql', '.proto', '.tf', '.tfvars', '.hcl', '.nomad', '.dockerfile', '.ipynb', '.csv', '.tsv',
  '.pem', '.key', '.crt', '.cer', '.p8', '.ppk', '.asc', '.gpg',
]);

const TEXT_BASENAMES = new Set([
  'dockerfile', 'containerfile', 'makefile', 'gnumakefile', 'rakefile', 'gemfile', 'procfile', 'vagrantfile', 'jenkinsfile', 'brewfile', 'justfile',
  '.npmrc', '.yarnrc', '.pypirc', '.netrc', '.htpasswd', '.git-credentials', '.pgpass', '.my.cnf', '.boto', '.s3cfg', '.dockercfg',
  'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'credentials', 'config', 'secrets', 'known_hosts',
]);

const packageVersion = ((): string => {
  try {
    const pkg = createRequire(import.meta.url)('../package.json') as { version?: string };
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

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
        // `**/` matches zero or more directories, like gitignore/minimatch.
        if (normalized[index + 2] === '/') {
          source += '(?:.*/)?';
          index += 2;
        } else {
          source += '.*';
          index += 1;
        }
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
  if (TEXT_BASENAMES.has(base) || base === '.env' || base.startsWith('.env.') || base.endsWith('.env')) return true;
  return TEXT_EXTENSIONS.has(path.extname(base));
}

function isIgnoredFile(relativePath: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(relativePath));
}

/** Rule metadata without the patterns, for documentation and SARIF consumers. */
export function listSecretRules(): SecretRuleInfo[] {
  return RULES.map(({ name, description, severity }) => ({ name, description, severity }));
}

export function createFindingFingerprint(rule: string, file: string, line: number): string {
  if (!rule || !file || !Number.isInteger(line) || line < 1) throw new TypeError('fingerprint requires rule, file and a positive line number');
  return createHash('sha256').update(`axiomguard:v1\0${rule}\0${normalizeRelative(file)}\0${line}`).digest('hex');
}

async function inspectFile(root: string, filePath: string, maxFileBytes: number, ignoredFiles: readonly RegExp[]): Promise<SecretFinding[]> {
  if (!shouldRead(filePath)) return [];
  const relativePath = normalizeRelative(path.relative(root, filePath) || path.basename(filePath));
  if (isIgnoredFile(relativePath, ignoredFiles)) return [];

  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.size > maxFileBytes) return [];
  const content = await readFile(filePath, 'utf8').catch(() => null);
  if (content === null || content.includes('\u0000')) return [];

  const findings: SecretFinding[] = [];
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    if (line.length === 0) continue;
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(line)) {
        const lineNumber = index + 1;
        findings.push({ file: relativePath, line: lineNumber, rule: rule.name, fingerprint: createFindingFingerprint(rule.name, relativePath, lineNumber) });
      }
    }
  }
  return findings;
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

async function mapWithConcurrency<T, R>(items: readonly T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array<R>(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await worker(items[index]!);
    }
  });
  await Promise.all(runners);
  return results;
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
    const rule = RULES.find((candidate) => candidate.name === ruleName);
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
        level: RULES.find((candidate) => candidate.name === finding.rule)?.severity ?? 'warning',
        message: { text: `Potential secret detected by ${finding.rule}. The matched value is intentionally not included.` },
        partialFingerprints: { 'axiomguard/v1': finding.fingerprint },
        locations: [{ physicalLocation: { artifactLocation: { uri: finding.file, uriBaseId: 'SRCROOT' }, region: { startLine: finding.line } } }],
      })),
    }],
  };
}
