import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

export interface SecretFinding {
  file: string;
  line: number;
  rule: string;
}

export interface SecretScanOptions {
  ignoreDirectories?: readonly string[];
  maxFileBytes?: number;
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

function shouldRead(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  return base === '.env' || base.startsWith('.env.') || TEXT_EXTENSIONS.has(path.extname(base));
}

async function inspectFile(root: string, filePath: string, findings: SecretFinding[], maxFileBytes: number): Promise<void> {
  if (!shouldRead(filePath)) return;
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.size > maxFileBytes) return;
  const content = await readFile(filePath, 'utf8').catch(() => null);
  if (content === null || content.includes('\u0000')) return;

  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    for (const rule of RULES) {
      if (rule.pattern.test(line)) {
        findings.push({ file: path.relative(root, filePath) || path.basename(filePath), line: index + 1, rule: rule.name });
      }
    }
  }
}

async function walk(root: string, current: string, findings: SecretFinding[], ignored: ReadonlySet<string>, maxFileBytes: number): Promise<void> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const fullPath = path.join(current, entry.name);
    if (entry.isDirectory()) {
      if (!ignored.has(entry.name)) await walk(root, fullPath, findings, ignored, maxFileBytes);
      continue;
    }
    if (entry.isFile()) await inspectFile(root, fullPath, findings, maxFileBytes);
  }
}

export async function scanSecrets(target: string, options: SecretScanOptions = {}): Promise<SecretFinding[]> {
  const root = path.resolve(target);
  const stat = await lstat(root);
  if (!stat.isDirectory()) throw new Error('scan target must be a directory');

  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  if (!Number.isInteger(maxFileBytes) || maxFileBytes < 1) throw new RangeError('maxFileBytes must be a positive integer');
  const ignored = new Set(options.ignoreDirectories ?? DEFAULT_IGNORE_DIRECTORIES);
  const findings: SecretFinding[] = [];
  await walk(root, root, findings, ignored, maxFileBytes);
  return findings.sort((left, right) => left.file.localeCompare(right.file) || left.line - right.line || left.rule.localeCompare(right.rule));
}

export function findingsToSarif(findings: readonly SecretFinding[]): Record<string, unknown> {
  const usedRules = [...new Set(findings.map((finding) => finding.rule))];
  const rules = usedRules.map((ruleName) => {
    const rule = RULES.find((candidate) => candidate.name === ruleName);
    return {
      id: ruleName,
      name: ruleName,
      shortDescription: { text: rule?.description ?? 'Potential secret detected.' },
      helpUri: 'https://github.com/AxiomNode-lab/AxiomGuard#repository-secret-scanner',
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
        locations: [{ physicalLocation: { artifactLocation: { uri: finding.file.split(path.sep).join('/') }, region: { startLine: finding.line } } }],
      })),
    }],
  };
}
