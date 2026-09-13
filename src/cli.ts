#!/usr/bin/env node
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import process from 'node:process';
import {
  createSecretScanBaseline,
  findingsToSarif,
  listSecretRules,
  parseSecretScanBaseline,
  parseSecretScannerConfig,
  scanSecrets,
  type SecretFinding,
  type SecretScannerConfig,
} from './scanner.js';

type Format = 'text' | 'json' | 'sarif';

interface CliOptions {
  target: string;
  format: Format;
  output?: string | undefined;
  config?: string | undefined;
  baseline?: string | undefined;
  writeBaseline?: string | undefined;
  exclude: string[];
  maxFileBytes?: number | undefined;
  noFail: boolean;
  quiet: boolean;
  githubAnnotations: boolean;
}

const VERSION = ((): string => {
  try {
    return String((createRequire(import.meta.url)('../package.json') as { version?: string }).version ?? '0.0.0');
  } catch {
    return '0.0.0';
  }
})();

function usage(): string {
  return `AxiomGuard ${VERSION}

Usage:
  axiomguard scan [path] [options]
  axiomguard rules
  axiomguard --version

Scan options:
  --format <text|json|sarif>   Output format (default: text). --json and --sarif are shorthands.
  --output <file>              Write the report to a file instead of stdout.
  --config <file>              Scanner config (default: .axiomguard.json in the scan root when present).
  --baseline <file>            Baseline of accepted fingerprints (default: .axiomguard-baseline.json in the scan root).
  --write-baseline <file>      Write all current findings as a baseline (relative to the scan root) and exit 0.
  --exclude <glob>             Ignore files matching a repository-relative glob. Repeatable.
  --max-file-bytes <n>         Skip files larger than n bytes (default: 1000000).
  --github-annotations         Emit GitHub workflow annotations on stderr for new findings.
  --no-fail                    Exit 0 even when new findings exist.
  --quiet                      Suppress the report; exit code still reflects findings.

Exit codes: 0 no new findings, 1 new findings, 2 usage or runtime error.
The scanner reports rule, location and a non-secret fingerprint. It never prints detected secret values.
`;
}

function parseScanArgs(args: string[]): CliOptions {
  let target = '.';
  let targetSet = false;
  let format: Format | undefined;
  let output: string | undefined;
  let config: string | undefined;
  let baseline: string | undefined;
  let writeBaseline: string | undefined;
  let maxFileBytes: number | undefined;
  const exclude: string[] = [];
  let noFail = false;
  let quiet = false;
  let githubAnnotations = false;

  const takeValue = (name: string, index: number): [string, number] => {
    const next = args[index + 1];
    if (next === undefined || next.startsWith('-')) throw new Error(`${name} requires a value`);
    return [next, index + 1];
  };
  const setFormat = (next: Format): void => {
    if (format !== undefined && format !== next) throw new Error('choose a single output format');
    format = next;
  };

  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === '--json') setFormat('json');
    else if (arg === '--sarif') setFormat('sarif');
    else if (arg === '--format') {
      let value: string;
      [value, index] = takeValue('--format', index);
      if (value !== 'text' && value !== 'json' && value !== 'sarif') throw new Error('--format must be text, json or sarif');
      setFormat(value);
    } else if (arg === '--output') [output, index] = takeValue('--output', index);
    else if (arg === '--config') [config, index] = takeValue('--config', index);
    else if (arg === '--baseline') [baseline, index] = takeValue('--baseline', index);
    else if (arg === '--write-baseline') [writeBaseline, index] = takeValue('--write-baseline', index);
    else if (arg === '--exclude') {
      let value: string;
      [value, index] = takeValue('--exclude', index);
      exclude.push(value);
    } else if (arg === '--max-file-bytes') {
      let value: string;
      [value, index] = takeValue('--max-file-bytes', index);
      maxFileBytes = Number(value);
      if (!Number.isInteger(maxFileBytes) || maxFileBytes < 1) throw new Error('--max-file-bytes must be a positive integer');
    } else if (arg === '--github-annotations') githubAnnotations = true;
    else if (arg === '--no-fail') noFail = true;
    else if (arg === '--quiet' || arg === '-q') quiet = true;
    else if (arg.startsWith('-')) throw new Error(`unknown option: ${arg}`);
    else if (!targetSet) {
      target = arg;
      targetSet = true;
    } else throw new Error(`unexpected argument: ${arg}`);
  }

  return { target, format: format ?? 'text', output, config, baseline, writeBaseline, exclude, maxFileBytes, noFail, quiet, githubAnnotations };
}

async function readJsonIfPresent(filePath: string, required = false): Promise<unknown | undefined> {
  try {
    return JSON.parse(await readFile(filePath, 'utf8')) as unknown;
  } catch (error: unknown) {
    if (!required && error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    if (error instanceof SyntaxError) throw new Error(`invalid JSON in ${filePath}: ${error.message}`);
    throw error;
  }
}

function renderText(findings: readonly SecretFinding[]): string {
  if (findings.length === 0) return 'AxiomGuard: no new high-confidence secret findings detected.\n';
  const lines = [`AxiomGuard: ${findings.length} new potential secret finding(s):`];
  for (const finding of findings) lines.push(`- ${finding.file}:${finding.line} [${finding.rule}] ${finding.fingerprint.slice(0, 12)}`);
  return `${lines.join('\n')}\n`;
}

function annotationEscape(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A').replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function emitGitHubAnnotations(findings: readonly SecretFinding[], level: 'error' | 'warning'): void {
  // Workflow commands are honoured on either stream; stderr keeps stdout parseable for --json/--sarif.
  for (const finding of findings) {
    const file = annotationEscape(finding.file);
    const title = annotationEscape(`AxiomGuard: ${finding.rule}`);
    process.stderr.write(`::${level} file=${file},line=${finding.line},title=${title}::Potential secret detected. Matched value intentionally omitted. Fingerprint ${finding.fingerprint.slice(0, 12)}\n`);
  }
}

async function loadConfig(root: string, explicitPath?: string): Promise<SecretScannerConfig> {
  const configPath = explicitPath ? path.resolve(explicitPath) : path.join(root, '.axiomguard.json');
  const raw = await readJsonIfPresent(configPath, explicitPath !== undefined);
  return raw === undefined ? {} : parseSecretScannerConfig(raw);
}

function resolveFromRoot(root: string, value: string): string {
  return path.isAbsolute(value) ? value : path.resolve(root, value);
}

async function loadBaseline(root: string, config: SecretScannerConfig, explicitPath?: string): Promise<readonly string[]> {
  const configured = explicitPath ?? config.baseline ?? '.axiomguard-baseline.json';
  const raw = await readJsonIfPresent(resolveFromRoot(root, configured), explicitPath !== undefined || config.baseline !== undefined);
  return raw === undefined ? [] : parseSecretScanBaseline(raw).fingerprints;
}

function renderRules(): string {
  const rules = listSecretRules();
  const width = Math.max(...rules.map((rule) => rule.name.length));
  return `${rules.map((rule) => `${rule.name.padEnd(width)}  ${rule.severity.padEnd(7)}  ${rule.description}`).join('\n')}\n`;
}

async function runScan(args: string[]): Promise<number> {
  const options = parseScanArgs(args);
  const resolvedTarget = path.resolve(options.target);
  const targetStat = await lstat(resolvedTarget).catch(() => null);
  if (!targetStat || (!targetStat.isDirectory() && !targetStat.isFile())) throw new Error(`scan target does not exist: ${options.target}`);
  const root = targetStat.isDirectory() ? resolvedTarget : path.dirname(resolvedTarget);

  const config = await loadConfig(root, options.config);
  const ignoreFiles = [...(config.ignoreFiles ?? []), ...options.exclude];
  const maxFileBytes = options.maxFileBytes ?? config.maxFileBytes;
  const scanOptions = {
    ...(config.ignoreDirectories ? { ignoreDirectories: config.ignoreDirectories } : {}),
    ...(ignoreFiles.length > 0 ? { ignoreFiles } : {}),
    ...(maxFileBytes ? { maxFileBytes } : {}),
  };

  if (options.writeBaseline) {
    const allFindings = await scanSecrets(resolvedTarget, scanOptions);
    const baseline = createSecretScanBaseline(allFindings);
    const baselinePath = resolveFromRoot(root, options.writeBaseline);
    await writeFile(baselinePath, `${JSON.stringify(baseline, null, 2)}\n`, 'utf8');
    if (!options.quiet) process.stdout.write(`AxiomGuard: wrote ${baseline.fingerprints.length} baseline fingerprint(s) to ${baselinePath}.\n`);
    return 0;
  }

  const baselineFingerprints = await loadBaseline(root, config, options.baseline);
  const findings = await scanSecrets(resolvedTarget, { ...scanOptions, baselineFingerprints });
  if (options.githubAnnotations) emitGitHubAnnotations(findings, options.noFail ? 'warning' : 'error');

  const rendered = options.format === 'json'
    ? `${JSON.stringify({ ok: findings.length === 0, findings }, null, 2)}\n`
    : options.format === 'sarif'
      ? `${JSON.stringify(findingsToSarif(findings), null, 2)}\n`
      : renderText(findings);

  if (options.output) await writeFile(options.output, rendered, 'utf8');
  else if (!options.quiet) process.stdout.write(rendered);

  return findings.length > 0 && !options.noFail ? 1 : 0;
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.includes('--version') || args.includes('-v')) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stdout.write(usage());
    return 0;
  }
  if (args[0] === 'rules') {
    process.stdout.write(renderRules());
    return 0;
  }
  if (args[0] !== 'scan') {
    process.stderr.write(usage());
    return 2;
  }
  return runScan(args);
}

process.stdout.on('error', (error: NodeJS.ErrnoException) => {
  // A closed pipe (e.g. `axiomguard scan | head`) is not an error worth a stack trace.
  if (error.code === 'EPIPE') process.exit(process.exitCode ?? 0);
  throw error;
});

main().then((code) => {
  process.exitCode = code;
}, (error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`AxiomGuard error: ${message}\n`);
  process.exitCode = 2;
});
