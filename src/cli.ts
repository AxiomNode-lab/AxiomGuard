#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import {
  createSecretScanBaseline,
  findingsToSarif,
  parseSecretScanBaseline,
  parseSecretScannerConfig,
  scanSecrets,
  type SecretFinding,
  type SecretScannerConfig,
} from './scanner.js';

interface CliOptions {
  target: string;
  format: 'text' | 'json' | 'sarif';
  output?: string;
  config?: string;
  baseline?: string;
  writeBaseline?: string;
  noFail: boolean;
  githubAnnotations: boolean;
}

function usage(): void {
  console.log(`AxiomGuard CLI\n\nUsage:\n  axiomguard scan [directory] [--json | --sarif] [--output file] [--config file] [--baseline file] [--write-baseline file] [--github-annotations] [--no-fail]\n\nConfig:\n  .axiomguard.json is loaded from the scan root when present.\n  .axiomguard-baseline.json is loaded by default unless the config specifies another baseline.\n\nThe scanner reports finding type, location and a non-secret fingerprint. It never prints detected secret values.`);
}

function parseScanArgs(args: string[]): CliOptions {
  let target = '.';
  let targetSet = false;
  let format: CliOptions['format'] = 'text';
  let output: string | undefined;
  let config: string | undefined;
  let baseline: string | undefined;
  let writeBaseline: string | undefined;
  let noFail = false;
  let githubAnnotations = false;

  const takeValue = (name: string, index: number): [string, number] => {
    const next = args[index + 1];
    if (!next || next.startsWith('-')) throw new Error(`${name} requires a file path`);
    return [next, index + 1];
  };

  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === '--json' || arg === '--sarif') {
      const nextFormat = arg === '--json' ? 'json' : 'sarif';
      if (format !== 'text' && format !== nextFormat) throw new Error('choose either --json or --sarif, not both');
      format = nextFormat;
    } else if (arg === '--output') {
      [output, index] = takeValue('--output', index);
    } else if (arg === '--config') {
      [config, index] = takeValue('--config', index);
    } else if (arg === '--baseline') {
      [baseline, index] = takeValue('--baseline', index);
    } else if (arg === '--write-baseline') {
      [writeBaseline, index] = takeValue('--write-baseline', index);
    } else if (arg === '--github-annotations') {
      githubAnnotations = true;
    } else if (arg === '--no-fail') {
      noFail = true;
    } else if (arg.startsWith('-')) {
      throw new Error(`unknown option: ${arg}`);
    } else if (!targetSet) {
      target = arg;
      targetSet = true;
    } else {
      throw new Error(`unexpected argument: ${arg}`);
    }
  }

  return { target, format, output, config, baseline, writeBaseline, noFail, githubAnnotations };
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

function emitGitHubAnnotations(findings: readonly SecretFinding[]): void {
  for (const finding of findings) {
    const file = annotationEscape(finding.file);
    const title = annotationEscape(`AxiomGuard: ${finding.rule}`);
    process.stdout.write(`::warning file=${file},line=${finding.line},title=${title}::Potential secret detected. Matched value intentionally omitted. Fingerprint ${finding.fingerprint.slice(0, 12)}\n`);
  }
}

async function loadConfig(root: string, explicitPath?: string): Promise<SecretScannerConfig> {
  const configPath = explicitPath ? path.resolve(explicitPath) : path.join(root, '.axiomguard.json');
  const raw = await readJsonIfPresent(configPath, explicitPath !== undefined);
  return raw === undefined ? {} : parseSecretScannerConfig(raw);
}

async function loadBaseline(root: string, config: SecretScannerConfig, explicitPath?: string): Promise<readonly string[]> {
  const configured = explicitPath ?? config.baseline ?? '.axiomguard-baseline.json';
  const baselinePath = path.isAbsolute(configured) ? configured : path.resolve(root, configured);
  const raw = await readJsonIfPresent(baselinePath, explicitPath !== undefined || config.baseline !== undefined);
  return raw === undefined ? [] : parseSecretScanBaseline(raw).fingerprints;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    usage();
    return;
  }
  if (args[0] !== 'scan') {
    usage();
    process.exitCode = 2;
    return;
  }

  const options = parseScanArgs(args);
  const root = path.resolve(options.target);
  const config = await loadConfig(root, options.config);
  const scanOptions = {
    ...(config.ignoreDirectories ? { ignoreDirectories: config.ignoreDirectories } : {}),
    ...(config.ignoreFiles ? { ignoreFiles: config.ignoreFiles } : {}),
    ...(config.maxFileBytes ? { maxFileBytes: config.maxFileBytes } : {}),
  };

  if (options.writeBaseline) {
    const allFindings = await scanSecrets(root, scanOptions);
    const baseline = createSecretScanBaseline(allFindings);
    await writeFile(path.resolve(options.writeBaseline), `${JSON.stringify(baseline, null, 2)}\n`, 'utf8');
    process.stdout.write(`AxiomGuard: wrote ${baseline.fingerprints.length} baseline fingerprint(s) to ${options.writeBaseline}.\n`);
    process.exitCode = 0;
    return;
  }

  const baselineFingerprints = await loadBaseline(root, config, options.baseline);
  const findings = await scanSecrets(root, { ...scanOptions, baselineFingerprints });
  if (options.githubAnnotations) emitGitHubAnnotations(findings);

  const rendered = options.format === 'json'
    ? `${JSON.stringify({ ok: findings.length === 0, findings }, null, 2)}\n`
    : options.format === 'sarif'
      ? `${JSON.stringify(findingsToSarif(findings), null, 2)}\n`
      : renderText(findings);

  if (options.output) await writeFile(options.output, rendered, 'utf8');
  else if (options.format === 'text' && findings.length > 0) process.stderr.write(rendered);
  else process.stdout.write(rendered);

  process.exitCode = findings.length > 0 && !options.noFail ? 1 : 0;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`AxiomGuard error: ${message}`);
  process.exitCode = 2;
});
