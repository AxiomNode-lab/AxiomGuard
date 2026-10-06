import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  CORE_SECURITY_PACK_VERSION,
  SecurityPackRegistry,
  createCoreSecurityPack,
  createFindingFingerprint,
  createSecretScanBaseline,
  findingsToSarif,
  scanRepository,
  scanSecrets,
} from '../dist/index.js';
import * as scanner from '../dist/scanner.js';

function secretFixtures() {
  return {
    privateKeyMarker: [['-----BEGIN', 'PRIVATE KEY-----'].join(' ')],
    providerToken: [['ghp', 'A'.repeat(24)].join('_')],
    environmentValue: [[['API', 'KEY'].join('_'), 'fixture-value-123'].join('=')],
  };
}

async function withDirectory(run) {
  const directory = await mkdtemp(path.join(tmpdir(), 'axiomguard-core-pack-'));
  try {
    return await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function scanCore(target, options = {}) {
  return scanRepository({
    target,
    packs: [createCoreSecurityPack()],
    engineVersion: '0.7.2',
    rulesetVersion: CORE_SECURITY_PACK_VERSION,
    ...options,
  });
}

test('Core Security Pack has stable valid metadata and registers explicitly', () => {
  const pack = createCoreSecurityPack();
  assert.equal(pack.id, 'core');
  assert.equal(pack.name, 'Core Security');
  assert.equal(pack.version, CORE_SECURITY_PACK_VERSION);
  assert.deepEqual(pack.applicableStacks, []);
  assert.equal(pack.rules.length, 1);
  assert.equal(pack.rules[0].id, 'CORE-001');
  assert.equal(pack.rules[0].category, 'secrets');
  assert.equal(pack.rules[0].detectorId, 'core.secret-scanner');
  assert.deepEqual(pack.rules[0].applicableStacks, []);
  assert.doesNotThrow(() => new SecurityPackRegistry([pack]));
});

test('CORE-001 adapts legacy findings with deterministic identity, locations and secret-safe evidence', async () => withDirectory(async (directory) => {
  const fixtures = secretFixtures();
  await writeFile(path.join(directory, 'a-key.pem'), `${fixtures.privateKeyMarker}\n`);
  await writeFile(path.join(directory, 'b-provider.txt'), `${fixtures.providerToken}\n`);
  await writeFile(path.join(directory, 'c-config.env'), `${fixtures.environmentValue}\n`);

  const legacy = await scanSecrets(directory);
  const result = await scanCore(directory);
  assert.deepEqual(legacy, [
    { file: 'a-key.pem', line: 1, rule: 'private-key', fingerprint: createFindingFingerprint('private-key', 'a-key.pem', 1) },
    { file: 'b-provider.txt', line: 1, rule: 'github-token', fingerprint: createFindingFingerprint('github-token', 'b-provider.txt', 1) },
    { file: 'c-config.env', line: 1, rule: 'sensitive-env-value', fingerprint: createFindingFingerprint('sensitive-env-value', 'c-config.env', 1) },
  ]);
  assert.equal(result.findings.length, legacy.length);

  for (const legacyFinding of legacy) {
    const normalized = result.findings.find((finding) => finding.fingerprint === legacyFinding.fingerprint);
    assert.ok(normalized);
    assert.equal(normalized.ruleId, 'CORE-001');
    assert.equal(normalized.detectorId, 'core.secret-scanner');
    assert.equal(normalized.findingId, `CORE-001:${legacyFinding.fingerprint}`);
    assert.equal(normalized.fingerprint, createFindingFingerprint(legacyFinding.rule, legacyFinding.file, legacyFinding.line));
    assert.deepEqual(normalized.location, { file: legacyFinding.file, startLine: legacyFinding.line, endLine: legacyFinding.line });
    assert.equal(normalized.confidence, 'high');
    assert.deepEqual(normalized.evidence[0].attributes, { secretType: legacyFinding.rule, matchedValueIncluded: false });
  }

  assert.deepEqual(result.findings.map((finding) => finding.severity), ['critical', 'high', 'medium']);
  assert.deepEqual(result.findings.map((finding) => finding.evidence[0].attributes.secretType), ['private-key', 'github-token', 'sensitive-env-value']);
  const serialized = JSON.stringify(result);
  for (const value of Object.values(fixtures).flat()) assert.equal(serialized.includes(value), false);
}));

test('CORE-001 lists once, reads each eligible file once and keeps deterministic order', async () => {
  const fixtures = secretFixtures();
  const reads = new Map();
  let lists = 0;
  const context = {
    detectedStackIds: [],
    listFiles: async () => {
      lists += 1;
      return [{ path: 'a.txt', size: fixtures.environmentValue[0].length }, { path: 'z.txt', size: fixtures.providerToken[0].length }];
    },
    readTextFile: async (file) => {
      reads.set(file, (reads.get(file) ?? 0) + 1);
      return file === 'a.txt' ? fixtures.environmentValue[0] : fixtures.providerToken[0];
    },
  };
  const findings = await createCoreSecurityPack().rules[0].detect(context);
  assert.equal(lists, 1);
  assert.deepEqual([...reads], [['a.txt', 1], ['z.txt', 1]]);
  assert.deepEqual(findings.map((finding) => finding.location.file), ['a.txt', 'z.txt']);
});

test('CORE-001 preserves legacy non-finding behavior for placeholders and public provider keys', async () => withDirectory(async (directory) => {
  await writeFile(path.join(directory, '.env.example'), `${['API', 'KEY'].join('_')}=changeme\n`);
  await writeFile(path.join(directory, 'public.txt'), 'pk_live_publicExampleValue12345\n');
  assert.deepEqual(await scanSecrets(directory), []);
  assert.deepEqual((await scanCore(directory)).findings, []);
}));

test('CORE-001 honors ignored directories, ignored files, size limits and binary skipping', async () => withDirectory(async (directory) => {
  const fixtures = secretFixtures();
  await mkdir(path.join(directory, 'node_modules'), { recursive: true });
  await writeFile(path.join(directory, 'node_modules', 'ignored.txt'), fixtures.providerToken[0]);
  await writeFile(path.join(directory, 'ignored.txt'), fixtures.providerToken[0]);
  await writeFile(path.join(directory, 'large.txt'), `${fixtures.providerToken[0]}${'x'.repeat(100)}`);
  await writeFile(path.join(directory, 'binary.txt'), Buffer.concat([Buffer.from(fixtures.providerToken[0]), Buffer.from([0])]));

  const legacy = await scanSecrets(directory, { ignoreFiles: ['ignored.txt'], maxFileBytes: 40 });
  const generalized = await scanCore(directory, { ignoreFiles: ['ignored.txt'], maxFileBytes: 40 });
  assert.deepEqual(legacy, []);
  assert.deepEqual(generalized.findings, []);
}));

test('CORE-001 skips symbolic links when the platform permits creating them', async (t) => withDirectory(async (directory) => {
  const fixtures = secretFixtures();
  const outside = path.join(directory, 'outside.txt');
  await writeFile(outside, fixtures.providerToken[0]);
  await mkdir(path.join(directory, 'scan'));
  try {
    await symlink(outside, path.join(directory, 'scan', 'linked.txt'), 'file');
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip(`symbolic link creation unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  assert.deepEqual(await scanSecrets(path.join(directory, 'scan')), []);
  assert.deepEqual((await scanCore(path.join(directory, 'scan'))).findings, []);
}));

test('legacy baselines and SARIF remain unchanged and secret-safe after Core adaptation', async () => withDirectory(async (directory) => {
  const fixtures = secretFixtures();
  await writeFile(path.join(directory, 'provider.txt'), fixtures.providerToken[0]);
  const findings = await scanSecrets(directory);
  assert.equal(findings.length, 1);
  assert.deepEqual(await scanSecrets(directory, { baselineFingerprints: createSecretScanBaseline(findings).fingerprints }), []);

  const sarif = findingsToSarif(findings);
  const serialized = JSON.stringify(sarif);
  assert.equal(serialized.includes(fixtures.providerToken[0]), false);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results[0].ruleId, 'github-token');
  assert.equal(sarif.runs[0].results[0].partialFingerprints['axiomguard/v1'], findings[0].fingerprint);
}));

test('Core pack public values are exported from root and scanner entry points', () => {
  assert.equal(scanner.CORE_SECURITY_PACK_VERSION, CORE_SECURITY_PACK_VERSION);
  assert.equal(scanner.createCoreSecurityPack, createCoreSecurityPack);
});
