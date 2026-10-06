import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { listSecretRules, scanSecrets } from '../dist/index.js';

const repeat = (char, count) => char.repeat(count);
const join = (...parts) => parts.join('');

function positiveCorpus() {
  return [
    ['private-key', join('-----BEGIN', ' RSA PRIVATE KEY-----')],
    ['github-token', join('ghp_', repeat('A', 28))],
    ['gitlab-token', join('glpat-', repeat('A', 24))],
    ['aws-access-key', join('AKIA', repeat('A', 16))],
    ['stripe-live-secret', join('sk', '_live_', repeat('A', 24))],
    ['slack-token', join('xoxb-', repeat('A', 24))],
    ['slack-webhook-url', join('https://hooks.slack.com/services/', 'T', repeat('A', 8), '/', 'B', repeat('A', 8), '/', repeat('A', 20))],
    ['openai-api-key', join('sk-', repeat('A', 20), 'T3BlbkFJ', repeat('A', 20))],
    ['anthropic-api-key', join('sk-ant-api02-', repeat('A', 80))],
    ['google-api-key', join('AIza', repeat('A', 35))],
    ['npm-token', join('npm_', repeat('A', 36))],
    ['sendgrid-api-key', join('SG.', repeat('A', 22), '.', repeat('A', 43))],
    ['huggingface-token', join('hf_', repeat('A', 34))],
    ['digitalocean-token', join('dop_v1_', repeat('a', 64))],
    ['shopify-token', join('shpat_', repeat('a', 32))],
    ['pypi-token', join('pypi-AgEIcHlwaS5vcmc', repeat('A', 52))],
    ['vault-token', join('hvs.', repeat('A', 24))],
    ['age-secret-key', join('AGE-SECRET-KEY-1', repeat('A', 58))],
    ['telegram-bot-token', join('12345678:AA', repeat('A', 33))],
    ['connection-string-password', join('postgres://user:', repeat('A', 12), '@db.example.test/app')],
    ['sensitive-env-value', join('API_', 'KEY=live_', repeat('A', 12), '!')],
  ];
}

test('scanner rule corpus covers every documented secret rule with synthetic positives', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'axiomguard-scanner-corpus-'));
  try {
    const corpus = positiveCorpus();
    const corpusRules = corpus.map(([rule]) => rule).sort();
    const documentedRules = listSecretRules().map((rule) => rule.name).sort();
    assert.deepEqual(corpusRules, documentedRules, 'every scanner rule must have an evaluation sample');

    const content = corpus.map(([rule, value]) => rule === 'sensitive-env-value' ? value : 'case=' + rule + ':' + value).join('\n') + '\n';
    await writeFile(path.join(directory, 'corpus.txt'), content, 'utf8');

    const findings = await scanSecrets(directory, { concurrency: 1 });
    assert.deepEqual(findings.map((finding) => finding.rule).sort(), documentedRules, 'every synthetic positive must be detected exactly once');
    assert.equal(new Set(findings.map((finding) => finding.rule)).size, corpus.length);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('scanner corpus keeps common placeholders and public examples clean', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'axiomguard-scanner-negative-corpus-'));
  try {
    const lines = [
      join('API_', 'KEY=changeme'),
      join('TOKEN=${', 'TOKEN}'),
      join('PASSWORD=placeholder'),
      join('pk_', 'live_', repeat('A', 24)),
      join('xoxb-', 'short-example'),
      join('google=', 'AIza', repeat('x', 10)),
    ];
    await writeFile(path.join(directory, 'negatives.txt'), lines.join('\n') + '\n', 'utf8');
    assert.deepEqual(await scanSecrets(directory), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});