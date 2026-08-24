#!/usr/bin/env node
import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

interface Finding {
  file: string;
  line: number;
  rule: string;
}

const IGNORE_DIRECTORIES = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache']);
const MAX_FILE_BYTES = 1_000_000;

const RULES: Array<{ name: string; pattern: RegExp }> = [
  { name: 'private-key', pattern: /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----/ },
  { name: 'github-token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/ },
  { name: 'aws-access-key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'sensitive-env-value', pattern: /^\s*(?:PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|CLIENT_SECRET)\s*=\s*(?!$|["']?(?:changeme|example|placeholder|your[_-]?\w+|<[^>]+>)["']?\s*$).{6,}$/i },
];

const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.yml', '.yaml', '.toml', '.ini', '.conf',
  '.env', '.txt', '.md', '.sh', '.bash', '.zsh', '.py', '.rb', '.go', '.rs', '.java', '.kt', '.php', '.cs',
]);

function shouldRead(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  return base === '.env' || base.startsWith('.env.') || TEXT_EXTENSIONS.has(path.extname(base));
}

async function walk(root: string, current: string, findings: Finding[]): Promise<void> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const fullPath = path.join(current, entry.name);
    if (entry.isDirectory()) {
      if (!IGNORE_DIRECTORIES.has(entry.name)) await walk(root, fullPath, findings);
      continue;
    }
    if (!entry.isFile() || !shouldRead(fullPath)) continue;

    const stat = await lstat(fullPath);
    if (stat.size > MAX_FILE_BYTES) continue;
    const content = await readFile(fullPath, 'utf8').catch(() => null);
    if (content === null || content.includes('\u0000')) continue;

    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? '';
      for (const rule of RULES) {
        if (rule.pattern.test(line)) {
          findings.push({ file: path.relative(root, fullPath) || path.basename(fullPath), line: index + 1, rule: rule.name });
        }
      }
    }
  }
}

async function scan(target: string): Promise<Finding[]> {
  const root = path.resolve(target);
  const stat = await lstat(root);
  const findings: Finding[] = [];
  if (stat.isDirectory()) await walk(root, root, findings);
  else throw new Error('scan target must be a directory');
  return findings;
}

function usage(): void {
  console.log(`AxiomGuard CLI\n\nUsage:\n  axiomguard scan [directory] [--json]\n\nThe scanner reports finding type and location only. It never prints detected secret values.`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    usage();
    return;
  }

  const command = args[0];
  if (command !== 'scan') {
    usage();
    process.exitCode = 2;
    return;
  }

  const json = args.includes('--json');
  const target = args.find((arg, index) => index > 0 && !arg.startsWith('-')) ?? '.';
  const findings = await scan(target);

  if (json) {
    console.log(JSON.stringify({ ok: findings.length === 0, findings }, null, 2));
  } else if (findings.length === 0) {
    console.log('AxiomGuard: no high-confidence secret findings detected.');
  } else {
    console.error(`AxiomGuard: ${findings.length} potential secret finding(s):`);
    for (const finding of findings) console.error(`- ${finding.file}:${finding.line} [${finding.rule}]`);
  }
  process.exitCode = findings.length === 0 ? 0 : 1;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`AxiomGuard error: ${message}`);
  process.exitCode = 2;
});
