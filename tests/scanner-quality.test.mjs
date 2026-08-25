import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  createSecretScanBaseline,
  findingsToSarif,
  parseSecretScanBaseline,
  parseSecretScannerConfig,
  scanSecrets,
} from '../dist/index.js';

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), 'axiomguard-quality-'));
  await mkdir(path.join(directory, 'fixtures'), { recursive: true });
  await writeFile(path.join(directory, '.env'), 'API_KEY=real-secret-value\n', 'utf8');
  await writeFile(path.join(directory, 'fixtures', 'sample.env'), 'TOKEN=another-secret-value\n', 'utf8');
  return directory;
}

test('scanner fingerprints findings without putting secret values into fingerprints or SARIF', async () => {
  const directory = await fixture();
  try {
    const findings = await scanSecrets(directory);
    assert.equal(findings.length, 2);
    assert.match(findings[0].fingerprint, /^[a-f0-9]{64}$/);
    assert.doesNotMatch(findings[0].fingerprint, /real-secret-value/);
    const sarif = JSON.stringify(findingsToSarif(findings));
    assert.match(sarif, /partialFingerprints/);
    assert.doesNotMatch(sarif, /real-secret-value|another-secret-value/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('scanner detects narrow provider prefixes without embedding fixture credentials in source', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'axiomguard-provider-rules-'));
  try {
    const stripe = ['sk', 'live', 'A'.repeat(24)].join('_');
    const slack = ['xoxb', '123456789012345678901234'].join('-');
    await writeFile(path.join(directory, 'config.txt'), `stripe=${stripe}\nslack=${slack}\n`, 'utf8');
    const findings = await scanSecrets(directory);
    assert.deepEqual(findings.map((finding) => finding.rule).sort(), ['slack-token', 'stripe-live-secret']);
    const serialized = JSON.stringify(findingsToSarif(findings));
    assert.doesNotMatch(serialized, new RegExp(stripe));
    assert.doesNotMatch(serialized, new RegExp(slack));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('scanner does not flag public Stripe publishable-key prefixes or short Slack-like text', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'axiomguard-provider-negatives-'));
  try {
    await writeFile(path.join(directory, 'docs.txt'), 'pk_live_publicExampleValue12345\nxoxb-short-example\n', 'utf8');
    assert.deepEqual(await scanSecrets(directory), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('baseline suppresses only previously accepted finding fingerprints', async () => {
  const directory = await fixture();
  try {
    const initial = await scanSecrets(directory);
    const baseline = createSecretScanBaseline([initial[0]]);
    const remaining = await scanSecrets(directory, { baselineFingerprints: baseline.fingerprints });
    assert.equal(remaining.length, 1);
    assert.notEqual(remaining[0].fingerprint, initial[0].fingerprint);
    assert.deepEqual(parseSecretScanBaseline(baseline), baseline);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('ignoreFiles supports repository-relative * and ** patterns', async () => {
  const directory = await fixture();
  try {
    const findings = await scanSecrets(directory, { ignoreFiles: ['fixtures/**'] });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, '.env');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('scanner config parser rejects unknown versions and malformed arrays', () => {
  assert.deepEqual(parseSecretScannerConfig({ version: 1, ignoreFiles: ['fixtures/**'], maxFileBytes: 1000 }), { version: 1, ignoreFiles: ['fixtures/**'], maxFileBytes: 1000 });
  assert.throws(() => parseSecretScannerConfig({ version: 2 }));
  assert.throws(() => parseSecretScannerConfig({ ignoreFiles: [42] }));
});
