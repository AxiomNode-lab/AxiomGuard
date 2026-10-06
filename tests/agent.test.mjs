import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createAgentSecurityReport, scanForAgent } from '../dist/agent.js';

const AWS_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

test('agent report enriches findings without exposing matched values', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'axiomguard-agent-'));
  try {
    const content = ['AWS_ACCESS_KEY=' + AWS_KEY, 'TOKEN=${TOKEN}', ''].join('\n');
    await writeFile(path.join(dir, 'config.env'), content);
    const report = await scanForAgent(dir);
    assert.equal(report.schemaVersion, '1');
    assert.equal(report.mode, 'ci-agent');
    assert.equal(report.ok, false);
    assert.equal(report.status, 'fail');
    assert.equal(report.exitCode, 1);
    assert.equal(report.summary.findings, 1);
    assert.equal(report.summary.errors, 1);
    assert.equal(report.findings[0]?.rule, 'aws-access-key');
    assert.equal(report.findings[0]?.severity, 'error');
    assert.match(report.findings[0]?.description ?? '', /AWS/);
    assert.match(report.findings[0]?.remediation ?? '', /rotate|revoke/i);
    assert.doesNotMatch(JSON.stringify(report), new RegExp(AWS_KEY));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('agent report can represent a clean scan', () => {
  const report = createAgentSecurityReport([], '.');
  assert.deepEqual(report.summary, { findings: 0, errors: 0, warnings: 0 });
  assert.equal(report.status, 'pass');
  assert.equal(report.ok, true);
  assert.equal(report.exitCode, 0);
});
