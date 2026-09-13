import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { listSecretRules, scanSecrets } from '../dist/index.js';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const VERSION = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version;

function run(args, options = {}) {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', ...options });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

// Fixtures are assembled from fragments so this test file never contains a secret-shaped literal.
const AWS_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const PEM = ['-----BEGIN', 'RSA PRIVATE KEY-----'].join(' ');

async function fixture() {
  const dir = await mkdtemp(path.join(tmpdir(), 'axiomguard-cli-'));
  await mkdir(path.join(dir, 'src'), { recursive: true });
  await mkdir(path.join(dir, 'vendor'), { recursive: true });
  await writeFile(path.join(dir, 'src', 'config.ts'), `export const region = 'eu-west-1';\nexport const key = '${AWS_KEY}';\n`);
  await writeFile(path.join(dir, 'id_rsa'), `${PEM}\nabc\n`);
  await writeFile(path.join(dir, 'Dockerfile'), `FROM node\nENV API_TOKEN=abc123def456ghi\n`);
  await writeFile(path.join(dir, 'vendor', 'x.env'), `PASSWORD=vendored-Secret-123\n`);
  // biome-ignore lint/suspicious/noTemplateCurlyInString: the fixture deliberately contains a shell-style reference.
  await writeFile(path.join(dir, 'clean.md'), '# nothing here\nPASSWORD=changeme\nTOKEN=${TOKEN}\n');
  return dir;
}

test('cli reports version, usage and rules', () => {
  assert.equal(run(['--version']).stdout.trim(), VERSION);
  const help = run([]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /Usage:/);
  const rules = run(['rules']);
  assert.equal(rules.code, 0);
  assert.equal(rules.stdout.trim().split('\n').length, listSecretRules().length);
  assert.equal(run(['bogus']).code, 2);
  assert.equal(run(['scan', '--nope']).code, 2);
});

test('cli scan exit codes, stream discipline and format flags', async () => {
  const dir = await fixture();
  try {
    const text = run(['scan', dir]);
    assert.equal(text.code, 1);
    assert.match(text.stdout, /3 new potential secret finding\(s\)/, 'report goes to stdout');
    assert.match(text.stdout, /Dockerfile:2 \[sensitive-env-value\]/);
    assert.match(text.stdout, /id_rsa:1 \[private-key\]/);
    assert.match(text.stdout, /src\/config\.ts:2 \[aws-access-key\]/);
    assert.doesNotMatch(text.stdout, /vendor/, 'vendor is ignored by default');
    assert.doesNotMatch(text.stdout, new RegExp(AWS_KEY), 'matched values are never printed');
    assert.equal(text.stderr, '');

    const json = run(['scan', dir, '--json', '--github-annotations']);
    assert.equal(json.code, 1);
    const parsed = JSON.parse(json.stdout);
    assert.equal(parsed.ok, false);
    assert.equal(parsed.findings.length, 3);
    assert.match(json.stderr, /^::error file=Dockerfile,line=2,title=AxiomGuard%3A sensitive-env-value::/m, 'annotations go to stderr as errors');

    const soft = run(['scan', dir, '--no-fail', '--github-annotations', '--quiet']);
    assert.equal(soft.code, 0);
    assert.equal(soft.stdout, '');
    assert.match(soft.stderr, /^::warning /m);

    const sarif = run(['scan', dir, '--format', 'sarif']);
    const doc = JSON.parse(sarif.stdout);
    assert.equal(doc.runs[0].tool.driver.semanticVersion, VERSION);
    assert.equal(doc.runs[0].results.find((r) => r.ruleId === 'private-key').level, 'error');
    assert.equal(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uriBaseId, 'SRCROOT');
    assert.equal(run(['scan', dir, '--json', '--sarif']).code, 2);

    const excluded = run(['scan', dir, '--exclude', 'src/**', '--exclude', 'Dockerfile', '--json']);
    assert.deepEqual(JSON.parse(excluded.stdout).findings.map((f) => f.file), ['id_rsa']);

    const single = run(['scan', path.join(dir, 'id_rsa'), '--json']);
    assert.equal(single.code, 1, 'single files can be scanned');
    assert.deepEqual(JSON.parse(single.stdout).findings.map((f) => f.file), ['id_rsa']);

    assert.equal(run(['scan', path.join(dir, 'missing')]).code, 2);
    assert.equal(run(['scan', dir, '--max-file-bytes', '10', '--json']).code, 0, 'size cap skips every fixture');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('cli baselines resolve relative to the scan root regardless of cwd', async () => {
  const dir = await fixture();
  const elsewhere = await mkdtemp(path.join(tmpdir(), 'axiomguard-cwd-'));
  try {
    const write = run(['scan', dir, '--write-baseline', '.axiomguard-baseline.json'], { cwd: elsewhere });
    assert.equal(write.code, 0);
    const baseline = JSON.parse(await readFile(path.join(dir, '.axiomguard-baseline.json'), 'utf8'));
    assert.equal(baseline.fingerprints.length, 3);
    assert.equal(run(['scan', dir], { cwd: elsewhere }).code, 0, 'default baseline is picked up from the scan root');
    assert.equal(run(['scan', dir, '--baseline', '.axiomguard-baseline.json'], { cwd: elsewhere }).code, 0);
    assert.equal(run(['scan', dir, '--baseline', 'nope.json'], { cwd: elsewhere }).code, 2, 'explicit missing baseline is an error');

    await writeFile(path.join(dir, '.axiomguard.json'), JSON.stringify({ version: 1, ignoreFiles: ['**/config.ts'], baseline: 'nothing.json' }));
    assert.equal(run(['scan', dir], { cwd: elsewhere }).code, 2, 'configured baseline must exist');
    await writeFile(path.join(dir, 'nothing.json'), JSON.stringify({ version: 1, fingerprints: [] }));
    const configured = run(['scan', dir, '--json'], { cwd: elsewhere });
    assert.deepEqual(JSON.parse(configured.stdout).findings.map((f) => f.file).sort(), ['Dockerfile', 'id_rsa'], '**/ matches top-level files too');
  } finally {
    await rm(dir, { recursive: true, force: true });
    await rm(elsewhere, { recursive: true, force: true });
  }
});

test('cli survives a closed stdout pipe', async () => {
  const dir = await fixture();
  try {
    const result = spawnSync('sh', ['-c', `"${process.execPath}" "${CLI}" scan "${dir}" --sarif | head -c 1 >/dev/null`], { encoding: 'utf8' });
    assert.doesNotMatch(result.stderr, /EPIPE/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('scanner rule coverage for private keys, provider tokens and env values', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'axiomguard-rules-'));
  try {
    const cases = {
      'pgp.asc': [['-----BEGIN PGP', 'PRIVATE KEY BLOCK-----'].join(' '), 'private-key'],
      'k.pem': [['-----BEGIN', 'EC PRIVATE KEY-----'].join(' '), 'private-key'],
      'g.txt': [['glpat-', 'a'.repeat(20)].join(''), 'gitlab-token'],
      'a.txt': [['ASIA', 'IOSFODNN7EXAMPLE'].join(''), 'aws-access-key'],
      'o.txt': [['sk-proj-', 'a'.repeat(20), 'T3BlbkFJ', 'b'.repeat(20)].join(''), 'openai-api-key'],
      'n.txt': [['npm_', 'a1'.repeat(18)].join(''), 'npm-token'],
      'h.txt': [['hf_', 'ab'.repeat(17)].join(''), 'huggingface-token'],
      'w.yml': [['https://hooks.slack.com/services/', 'T0000000', '/B0000000/', 'a'.repeat(24)].join(''), 'slack-webhook-url'],
      'c.tf': [['postgres://app:', 'P4ssw0rdP4ss', '@db.internal/app'].join(''), 'connection-string-password'],
      'e.env': [['DATABASE_PASSWORD', '=hunter2hunter2'].join(''), 'sensitive-env-value'],
      'y.yaml': [['password', ': hunter2hunter2'].join(''), 'sensitive-env-value'],
    };
    for (const [file, [content]] of Object.entries(cases)) await writeFile(path.join(dir, file), `${content}\n`);
    await writeFile(path.join(dir, 'types.ts'), 'interface A {\n  secret: string;\n  token: string;\n  password?: string;\n}\nconst secret = "abc";\n');
    // biome-ignore lint/suspicious/noTemplateCurlyInString: fixtures deliberately contain variable references.
    await writeFile(path.join(dir, 'placeholders.env'), 'PASSWORD=${DB_PASSWORD}\nTOKEN=$(vault read)\nAPI_KEY=%API_KEY%\nSECRET=xxxxxxxx\nTOKEN=<your-token>\nAPI_KEY="your-api-key"\nTOKEN=${{ secrets.X }}\nPASSWORD=changeme\n');
    await writeFile(path.join(dir, 'pk_test.js'), `const publishable = ['pk_live_', 'a'.repeat(24)].join('');\nconst redis = 'redis://:changeme@host';\n`);
    const findings = await scanSecrets(dir);
    const byFile = Object.fromEntries(findings.map((finding) => [finding.file, finding.rule]));
    for (const [file, [, rule]] of Object.entries(cases)) assert.equal(byFile[file], rule, file);
    assert.equal(byFile['types.ts'], undefined, 'type annotations are not credentials');
    assert.equal(byFile['placeholders.env'], undefined, 'placeholders and references are ignored');
    assert.equal(byFile['pk_test.js'], undefined);
    assert.equal(findings.length, Object.keys(cases).length);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
