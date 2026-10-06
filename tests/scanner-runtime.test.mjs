import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  SCAN_SCHEMA_VERSION,
  ScannerError,
  SecurityPackRegistry,
  createRepositoryScanContext,
  scanRepository,
} from '../dist/index.js';
import * as scanner from '../dist/scanner.js';

function makeFinding(ruleId = 'example/rule', overrides = {}) {
  return {
    findingId: `${ruleId}:finding`,
    ruleId,
    severity: 'medium',
    confidence: 'high',
    title: 'Example finding',
    description: 'A deterministic test condition was found.',
    location: { file: 'src/example.ts', startLine: 2, endLine: 2 },
    evidence: [{ kind: 'configuration-state', summary: 'A boolean setting is enabled.', attributes: { enabled: true } }],
    impact: 'The intended control may not apply.',
    remediation: 'Disable the example setting.',
    detectorId: 'example-detector',
    fingerprint: `${ruleId}:fingerprint`,
    ...overrides,
  };
}

function makeRule(id = 'example/rule', overrides = {}) {
  return {
    id,
    title: 'Example rule',
    description: 'Detects a deterministic test condition.',
    category: 'configuration',
    severity: 'medium',
    confidence: 'high',
    applicableStacks: [],
    impact: 'The intended control may not apply.',
    remediation: 'Disable the example setting.',
    detectorId: 'example-detector',
    references: ['https://example.com/security/example-rule'],
    detect: () => [makeFinding(id)],
    ...overrides,
  };
}

function makePack(id = 'example', rules = [makeRule()]) {
  return {
    id,
    name: `${id} pack`,
    version: '1.0.0',
    description: 'Test-only deterministic security rules.',
    rules,
  };
}

async function withDirectory(run) {
  const directory = await mkdtemp(path.join(tmpdir(), 'axiomguard-runtime-'));
  try {
    return await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('registry accepts and freezes valid packs without sharing mutable state', () => {
  const rules = [makeRule()];
  const first = new SecurityPackRegistry([makePack('example', rules)]);
  const second = new SecurityPackRegistry();
  rules.push(makeRule('example/later'));

  assert.deepEqual(first.listPacks().map((pack) => pack.id), ['example']);
  assert.deepEqual(first.listRules().map((rule) => rule.id), ['example/rule']);
  assert.deepEqual(second.listPacks(), []);
  assert.ok(Object.isFrozen(first.listPacks()[0]));
  assert.ok(Object.isFrozen(first.listPacks()[0].rules));
});

test('registry rejects duplicate pack and stable rule IDs', () => {
  const registry = new SecurityPackRegistry([makePack('alpha', [makeRule('shared/rule')])]);
  assert.throws(() => registry.register(makePack('alpha', [makeRule('other/rule')])), (error) => error instanceof ScannerError && error.code === 'DUPLICATE_PACK_ID');
  assert.throws(() => registry.register(makePack('beta', [makeRule('shared/rule')])), (error) => error instanceof ScannerError && error.code === 'DUPLICATE_RULE_ID');
});

test('registry rejects malformed IDs, versions and rule metadata', () => {
  const invalidPacks = [
    { ...makePack(), id: '' },
    { ...makePack(), version: 'today' },
    { ...makePack(), rules: [] },
    makePack('example', [{ ...makeRule(), category: '' }]),
    makePack('example', [{ ...makeRule(), severity: 'warning' }]),
    makePack('example', [{ ...makeRule(), references: ['file:///tmp/reference'] }]),
  ];
  for (const pack of invalidPacks) {
    assert.throws(() => new SecurityPackRegistry([pack]), (error) => error instanceof ScannerError && error.code === 'INVALID_PACK');
  }
});

test('registry pack and rule listing use deterministic ID order', () => {
  const registry = new SecurityPackRegistry([
    makePack('zeta', [makeRule('zeta/b'), makeRule('zeta/a')]),
    makePack('alpha', [makeRule('alpha/b'), makeRule('alpha/a')]),
  ]);
  assert.deepEqual(registry.listPacks().map((pack) => pack.id), ['alpha', 'zeta']);
  assert.deepEqual(registry.listRules().map((rule) => rule.id), ['alpha/a', 'alpha/b', 'zeta/a', 'zeta/b']);
});

test('explicit pack selection, unknown IDs and empty selection are unambiguous', async () => withDirectory(async (directory) => {
  const registry = new SecurityPackRegistry([makePack('alpha', [makeRule('alpha/rule')]), makePack('beta', [makeRule('beta/rule')])]);
  const selected = await scanRepository({ target: directory, registry, packIds: ['beta'], engineVersion: '0.7.2', rulesetVersion: '1.0.0' });
  assert.deepEqual(selected.findings.map((finding) => finding.ruleId), ['beta/rule']);

  const empty = await scanRepository({ target: directory, registry, packIds: [], engineVersion: '0.7.2', rulesetVersion: '1.0.0' });
  assert.deepEqual(empty.findings, []);
  assert.deepEqual(empty.context.packIds, []);

  await assert.rejects(
    scanRepository({ target: directory, registry, packIds: ['missing'], engineVersion: '0.7.2', rulesetVersion: '1.0.0' }),
    (error) => error instanceof ScannerError && error.code === 'UNKNOWN_PACK',
  );
}));

test('stack-independent rules always run and stack restrictions require an intersection', async () => withDirectory(async (directory) => {
  const calls = [];
  const registry = new SecurityPackRegistry([
    makePack('example', [
      makeRule('example/core', { detect: () => { calls.push('core'); return [makeFinding('example/core')]; } }),
      makeRule('example/next', { applicableStacks: ['nextjs'], detect: () => { calls.push('next'); return [makeFinding('example/next')]; } }),
    ]),
    { ...makePack('supabase', [makeRule('supabase/rule', { applicableStacks: [] })]), applicableStacks: ['supabase'] },
  ]);

  const withoutStacks = await scanRepository({ target: directory, registry, engineVersion: '0.7.2', rulesetVersion: '1.0.0' });
  assert.deepEqual(withoutStacks.findings.map((finding) => finding.ruleId), ['example/core']);
  assert.deepEqual(calls, ['core']);

  calls.length = 0;
  const withNext = await scanRepository({ target: directory, registry, detectedStackIds: ['nextjs'], engineVersion: '0.7.2', rulesetVersion: '1.0.0' });
  assert.deepEqual(withNext.findings.map((finding) => finding.ruleId), ['example/core', 'example/next']);
  assert.deepEqual(calls, ['core', 'next']);
}));

test('repository context lists normalized sorted eligible files and applies limits and ignores', async () => withDirectory(async (directory) => {
  await mkdir(path.join(directory, 'src'), { recursive: true });
  await mkdir(path.join(directory, 'node_modules', 'package'), { recursive: true });
  await mkdir(path.join(directory, 'ignored'), { recursive: true });
  await writeFile(path.join(directory, 'z.txt'), 'z');
  await writeFile(path.join(directory, 'src', 'a.ts'), 'a');
  await writeFile(path.join(directory, 'src', 'b.ts'), 'bb');
  await writeFile(path.join(directory, 'binary.txt'), Buffer.from([65, 0, 66]));
  await writeFile(path.join(directory, 'large.md'), 'x'.repeat(20));
  await writeFile(path.join(directory, 'image.png'), 'not eligible');
  await writeFile(path.join(directory, 'node_modules', 'package', 'index.js'), 'ignored by default');
  await writeFile(path.join(directory, 'ignored', 'inside.ts'), 'ignored explicitly');

  const context = await createRepositoryScanContext({
    target: directory,
    maxFileBytes: 10,
    ignoreDirectories: ['node_modules', 'ignored'],
    ignoreFiles: ['z.txt'],
    concurrency: 2,
  });
  assert.deepEqual(await context.listFiles(), [{ path: 'src/a.ts', size: 1 }, { path: 'src/b.ts', size: 2 }]);
  assert.equal(await context.readTextFile('src/a.ts'), 'a');
  await assert.rejects(context.readTextFile('ignored/inside.ts'), (error) => error instanceof ScannerError && error.code === 'FILE_NOT_ELIGIBLE');
}));

test('repository context rejects absolute and traversal paths', async () => withDirectory(async (directory) => {
  await writeFile(path.join(directory, 'safe.txt'), 'safe');
  const context = await createRepositoryScanContext({ target: directory });
  await assert.rejects(context.readTextFile(path.resolve(directory, 'safe.txt')), (error) => error instanceof ScannerError && error.code === 'INVALID_FILE_PATH');
  await assert.rejects(context.readTextFile('../safe.txt'), (error) => error instanceof ScannerError && error.code === 'INVALID_FILE_PATH');
}));

test('repository context skips symbolic links and refuses direct symlink access', async (t) => withDirectory(async (directory) => {
  await writeFile(path.join(directory, 'target.txt'), 'safe');
  try {
    await symlink(path.join(directory, 'target.txt'), path.join(directory, 'linked.txt'), 'file');
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip(`symbolic link creation unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  const context = await createRepositoryScanContext({ target: directory });
  assert.deepEqual((await context.listFiles()).map((file) => file.path), ['target.txt']);
  await assert.rejects(context.readTextFile('linked.txt'), (error) => error instanceof ScannerError && error.code === 'FILE_NOT_ELIGIBLE');
}));

test('scanRepository returns versioned serializable results in deterministic finding order', async () => withDirectory(async (directory) => {
  const rules = [
    makeRule('alpha/low', { detect: () => [makeFinding('alpha/low', { severity: 'low', fingerprint: 'b' })] }),
    makeRule('zeta/critical', { detect: () => [
      makeFinding('zeta/critical', { severity: 'critical', fingerprint: 'z', findingId: 'second', location: { file: 'z.ts', startLine: 3 } }),
      makeFinding('zeta/critical', { severity: 'critical', fingerprint: 'a', findingId: 'first', location: { file: 'a.ts', startLine: 1 } }),
    ] }),
  ];
  const result = await scanRepository({ target: directory, packs: [makePack('example', rules)], engineVersion: '0.7.2', rulesetVersion: '2.0.0', detectedStackIds: ['node'] });
  assert.deepEqual(result.versions, { engineVersion: '0.7.2', rulesetVersion: '2.0.0', schemaVersion: SCAN_SCHEMA_VERSION });
  assert.deepEqual(result.findings.map((finding) => finding.findingId), ['first', 'second', 'alpha/low:finding']);
  assert.equal(result.context.target, '.');
  assert.deepEqual(JSON.parse(JSON.stringify(result)), result);
}));

test('scanRepository rejects malformed findings and non-JSON evidence', async () => withDirectory(async (directory) => {
  const invalidFindings = [
    makeFinding('example/rule', { findingId: ' ' }),
    makeFinding('example/rule', { severity: 'warning' }),
    makeFinding('example/rule', { confidence: 'certain' }),
    makeFinding('example/rule', { location: { file: '/absolute.ts', startLine: 1 } }),
    makeFinding('example/rule', { location: { file: '../outside.ts', startLine: 1 } }),
    makeFinding('example/rule', { location: { file: 'safe.ts', startLine: 0 } }),
    makeFinding('example/rule', { location: { file: 'safe.ts', startLine: 3, endLine: 2 } }),
    makeFinding('example/rule', { evidence: [] }),
    makeFinding('example/rule', { evidence: [{ kind: 'state', summary: 'Invalid number.', attributes: { value: Number.NaN } }] }),
    makeFinding('example/rule', { evidence: [{ kind: 'state', summary: 'Invalid object.', attributes: { value: new Date(0) } }] }),
  ];
  for (const finding of invalidFindings) {
    const rule = makeRule('example/rule', { detect: () => [finding] });
    await assert.rejects(
      scanRepository({ target: directory, packs: [makePack('example', [rule])], engineVersion: '0.7.2', rulesetVersion: '1.0.0' }),
      (error) => error instanceof ScannerError && error.code === 'INVALID_FINDING' && error.packId === 'example' && error.ruleId === 'example/rule',
    );
  }
}));

test('scanRepository rejects rule identity mismatches', async () => withDirectory(async (directory) => {
  const rule = makeRule('example/rule', { detect: () => [makeFinding('different/rule')] });
  await assert.rejects(
    scanRepository({ target: directory, packs: [makePack('example', [rule])], engineVersion: '0.7.2', rulesetVersion: '1.0.0' }),
    (error) => error instanceof ScannerError && error.code === 'INVALID_FINDING' && /ruleId/.test(error.message),
  );
}));

test('rule failures identify pack and rule without echoing repository content', async () => withDirectory(async (directory) => {
  const sensitiveFixtureText = 'fixture-content-that-must-not-appear-in-errors';
  await writeFile(path.join(directory, 'input.txt'), sensitiveFixtureText);
  const rule = makeRule('example/failing', {
    detect: async (context) => {
      const content = await context.readTextFile('input.txt');
      throw new Error(content);
    },
  });
  await assert.rejects(
    scanRepository({ target: directory, packs: [makePack('example', [rule])], engineVersion: '0.7.2', rulesetVersion: '1.0.0' }),
    (error) => {
      assert.ok(error instanceof ScannerError);
      assert.equal(error.code, 'RULE_EXECUTION_FAILED');
      assert.equal(error.packId, 'example');
      assert.equal(error.ruleId, 'example/failing');
      assert.doesNotMatch(error.message, new RegExp(sensitiveFixtureText));
      return true;
    },
  );
}));

test('generalized runtime APIs are exported from root and scanner entry points', () => {
  assert.equal(scanner.scanRepository, scanRepository);
  assert.equal(scanner.SecurityPackRegistry, SecurityPackRegistry);
  assert.equal(scanner.createRepositoryScanContext, createRepositoryScanContext);
  assert.equal(scanner.ScannerError, ScannerError);
});
