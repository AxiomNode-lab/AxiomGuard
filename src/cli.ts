#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import process from 'node:process';
import { findingsToSarif, scanSecrets } from './scanner.js';

interface CliOptions {
  target: string;
  format: 'text' | 'json' | 'sarif';
  output?: string;
  noFail: boolean;
}

function usage(): void {
  console.log(`AxiomGuard CLI\n\nUsage:\n  axiomguard scan [directory] [--json | --sarif] [--output file] [--no-fail]\n\nFormats:\n  text    human-readable findings (default)\n  --json  machine-readable JSON\n  --sarif SARIF 2.1.0 for code scanning systems\n\nThe scanner reports finding type and location only. It never prints detected secret values.`);
}

function parseScanArgs(args: string[]): CliOptions {
  let target = '.';
  let targetSet = false;
  let format: CliOptions['format'] = 'text';
  let output: string | undefined;
  let noFail = false;

  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === '--json' || arg === '--sarif') {
      const nextFormat = arg === '--json' ? 'json' : 'sarif';
      if (format !== 'text' && format !== nextFormat) throw new Error('choose either --json or --sarif, not both');
      format = nextFormat;
    } else if (arg === '--output') {
      const next = args[index + 1];
      if (!next || next.startsWith('-')) throw new Error('--output requires a file path');
      output = next;
      index += 1;
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

  return output === undefined ? { target, format, noFail } : { target, format, output, noFail };
}

function renderText(findings: Awaited<ReturnType<typeof scanSecrets>>): string {
  if (findings.length === 0) return 'AxiomGuard: no high-confidence secret findings detected.\n';
  const lines = [`AxiomGuard: ${findings.length} potential secret finding(s):`];
  for (const finding of findings) lines.push(`- ${finding.file}:${finding.line} [${finding.rule}]`);
  return `${lines.join('\n')}\n`;
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
  const findings = await scanSecrets(options.target);
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
