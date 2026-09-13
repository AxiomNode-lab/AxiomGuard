import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  MemoryReplayStore,
  constantTimeCompare,
  createSlackSignature,
  createStripeSignatureHeader,
  signHmacWebhook,
  verifyFreshHmacWebhook,
  verifyGitHubWebhook,
  verifyGitHubWebhookDelivery,
  verifyHmacWebhook,
  verifySlackWebhook,
  verifyStandardWebhook,
  verifyStripeWebhook,
} from '../dist/index.js';

const NOW = 1_800_000_000_000;
const TS = Math.floor(NOW / 1000);

test('verifyFreshHmacWebhook replay claim is keyed on the canonical signature, not its spelling', async () => {
  const payload = Buffer.from('{"event":"ping"}');
  const secret = 'test-secret';
  const hex = createHmac('sha256', secret).update(payload).digest('hex');
  const store = new MemoryReplayStore();

  assert.deepEqual(await verifyFreshHmacWebhook({ payload, signature: `sha256=${hex}`, secret, timestamp: TS }, { now: NOW, replayStore: store }), { ok: true });
  assert.deepEqual(await verifyFreshHmacWebhook({ payload, signature: `sha256=${hex.toUpperCase()}`, secret, timestamp: TS }, { now: NOW, replayStore: store }), { ok: false, reason: 'replay' });
  assert.deepEqual(await verifyFreshHmacWebhook({ payload, signature: hex, secret, timestamp: TS }, { now: NOW, replayStore: store }), { ok: false, reason: 'replay' });
});

test('verifyFreshHmacWebhook can bind the timestamp into the signed input', async () => {
  const payload = 'body';
  const secret = 'test-secret';
  const signed = signHmacWebhook(`${TS}.${payload}`, secret);
  assert.deepEqual(await verifyFreshHmacWebhook({ payload, signature: signed, secret, timestamp: TS }, { now: NOW, signedInput: 'timestamp.payload' }), { ok: true });
  // A captured signature cannot be replayed under a fresh attacker-chosen timestamp.
  assert.deepEqual(await verifyFreshHmacWebhook({ payload, signature: signed, secret, timestamp: TS + 400 }, { now: NOW + 400_000, signedInput: 'timestamp.payload' }), { ok: false, reason: 'invalid-signature' });
  // Payload-only signing accepts the same capture, which is why replayTtlSeconds exists.
  const payloadOnly = signHmacWebhook(payload, secret);
  const store = new MemoryReplayStore();
  assert.deepEqual(await verifyFreshHmacWebhook({ payload, signature: payloadOnly, secret, timestamp: TS }, { now: NOW, replayStore: store, replayTtlSeconds: 3_600 }), { ok: true });
  assert.deepEqual(await verifyFreshHmacWebhook({ payload, signature: payloadOnly, secret, timestamp: TS + 400 }, { now: NOW + 400_000, replayStore: store, replayTtlSeconds: 3_600 }), { ok: false, reason: 'replay' });
});

test('verifyHmacWebhook supports base64 encodings and rejects malformed signatures', () => {
  const payload = 'shopify-body';
  const secret = 'shopify-secret';
  const base64 = createHmac('sha256', secret).update(payload).digest('base64');
  assert.equal(verifyHmacWebhook(payload, base64, secret, { encoding: 'base64', prefix: '' }), true);
  assert.equal(verifyHmacWebhook(payload, base64, secret), false, 'hex mode must not accept base64');
  assert.equal(verifyHmacWebhook(payload, `${base64}x`, secret, { encoding: 'base64', prefix: '' }), false);
  const hex = createHmac('sha256', secret).update(payload).digest('hex');
  assert.equal(verifyHmacWebhook(payload, hex.toUpperCase(), secret), true);
  assert.equal(verifyHmacWebhook(payload, ` ${hex}`, secret), false, 'surrounding whitespace is not trimmed');
  assert.equal(verifyHmacWebhook(payload, hex.slice(0, 63), secret), false, 'odd length hex is rejected');
  assert.equal(verifyHmacWebhook(payload, hex, secret, { algorithm: 'sha512' }), false, 'sha256-length hex never verifies against sha512');
  assert.equal(verifyHmacWebhook(payload, `sha256=${hex}`, secret, { requirePrefix: true }), true);
  assert.equal(verifyHmacWebhook(payload, hex, secret, { requirePrefix: true }), false, 'requirePrefix rejects unprefixed values');
  assert.throws(() => verifyHmacWebhook(payload, hex, ''), /secret/);
  assert.equal(signHmacWebhook(payload, secret), `sha256=${hex}`);
  assert.equal(signHmacWebhook(payload, secret, { encoding: 'base64', prefix: '' }), base64);
});

test('constantTimeCompare handles Buffers, strings and differing lengths', () => {
  assert.equal(constantTimeCompare(Buffer.from('abc'), 'abc'), true);
  assert.equal(constantTimeCompare('abc', Buffer.from('abd')), false);
  assert.equal(constantTimeCompare('abc', 'abcd'), false);
  assert.equal(constantTimeCompare('', ''), true);
});

test('provider helpers require their documented signature prefix', () => {
  const payload = 'x';
  const secret = 's';
  const hex = createHmac('sha256', secret).update(payload).digest('hex');
  assert.equal(verifyGitHubWebhook(payload, `sha256=${hex}`, secret), true);
  assert.equal(verifyGitHubWebhook(payload, hex, secret), false, 'GitHub helper must require the sha256= prefix');
  assert.equal(verifyGitHubWebhook(payload, `sha1=${hex}`, secret), false);
});

test('GitHub delivery replay window boundary and delivery ID validation', async () => {
  const payload = 'hello';
  const secret = 'secret';
  const signature = signHmacWebhook(payload, secret);
  const store = new MemoryReplayStore();
  assert.deepEqual(await verifyGitHubWebhookDelivery(payload, signature, secret, 'd-1', { replayStore: store, now: NOW, replayTtlSeconds: 60 }), { ok: true });
  assert.deepEqual(await verifyGitHubWebhookDelivery(payload, signature, secret, 'd-1', { replayStore: store, now: NOW + 59_999, replayTtlSeconds: 60 }), { ok: false, reason: 'replay' });
  assert.deepEqual(await verifyGitHubWebhookDelivery(payload, signature, secret, 'd-1', { replayStore: store, now: NOW + 60_000, replayTtlSeconds: 60 }), { ok: true });
  assert.deepEqual(await verifyGitHubWebhookDelivery(payload, signature, secret, 'bad\nid', { replayStore: store, now: NOW }), { ok: false, reason: 'invalid-delivery' });
  assert.deepEqual(await verifyGitHubWebhookDelivery(payload, signature, secret, 'x'.repeat(201), { replayStore: store, now: NOW }), { ok: false, reason: 'invalid-delivery' });
});

test('Stripe verifier accepts rotated v1 entries, ignores v0 and signs the literal timestamp text', async () => {
  const payload = '{"id":"evt_1"}';
  const secret = 'whsec_test';
  const good = createHmac('sha256', secret).update(`${TS}.${payload}`).digest('hex');
  const bad = 'a'.repeat(64);
  assert.deepEqual(await verifyStripeWebhook(payload, `t=${TS},v1=${bad},v1=${good},v0=${bad}`, secret, { now: NOW }), { ok: true });
  assert.deepEqual(await verifyStripeWebhook(payload, `t=${TS},v0=${good}`, secret, { now: NOW }), { ok: false, reason: 'invalid-signature' });
  assert.deepEqual(await verifyStripeWebhook(payload, `t=0${TS},v1=${good}`, secret, { now: NOW }), { ok: false, reason: 'invalid-signature' }, 'non-canonical t must not verify against a canonical signature');
  assert.deepEqual(await verifyStripeWebhook(payload, `t=${TS + 301},v1=${createHmac('sha256', secret).update(`${TS + 301}.${payload}`).digest('hex')}`, secret, { now: NOW }), { ok: false, reason: 'stale-timestamp' });
  assert.deepEqual(await verifyStripeWebhook(payload, `t=${TS + 300},v1=${createHmac('sha256', secret).update(`${TS + 300}.${payload}`).digest('hex')}`, secret, { now: NOW }), { ok: true });
  assert.deepEqual(await verifyStripeWebhook(payload, createStripeSignatureHeader(payload, secret, TS), secret, { now: NOW }), { ok: true });
  await assert.rejects(verifyStripeWebhook(payload, `t=${TS},v1=${good}`, ''), /secret/);
});

test('Slack verifier rejects non-decimal timestamps and binds the body bytes', async () => {
  const payload = 'token=abc';
  const secret = 'slack-secret';
  const sign = (ts, body = payload) => `v0=${createHmac('sha256', secret).update(`v0:${ts}:${body}`).digest('hex')}`;
  assert.deepEqual(await verifySlackWebhook(payload, sign(TS), String(TS), secret, { now: NOW }), { ok: true });
  assert.deepEqual(await verifySlackWebhook(payload, createSlackSignature(payload, secret, TS), TS, secret, { now: NOW }), { ok: true });
  assert.deepEqual(await verifySlackWebhook('token=xyz', sign(TS), String(TS), secret, { now: NOW }), { ok: false, reason: 'invalid-signature' });
  for (const odd of [`0x${TS.toString(16)}`, '1.8e9', '-1', '1.5']) {
    assert.deepEqual(await verifySlackWebhook(payload, sign(odd), odd, secret, { now: NOW }), { ok: false, reason: 'invalid-timestamp' }, odd);
  }
});

test('Standard Webhooks (Svix) verification', async () => {
  const payload = '{"type":"user.created"}';
  const rawSecret = Buffer.from('0123456789abcdef0123456789abcdef');
  const secret = `whsec_${rawSecret.toString('base64')}`;
  const id = 'msg_p5jXN8AQM9LWM0D4loKWxJek';
  const sig = createHmac('sha256', rawSecret).update(`${id}.${TS}.${payload}`).digest('base64');
  const headers = { id, timestamp: String(TS), signature: `v1,${'A'.repeat(44)} v1,${sig}` };
  const store = new MemoryReplayStore();
  assert.deepEqual(await verifyStandardWebhook(payload, headers, secret, { now: NOW, replayStore: store }), { ok: true });
  assert.deepEqual(await verifyStandardWebhook(payload, headers, secret, { now: NOW, replayStore: store }), { ok: false, reason: 'replay' });
  assert.deepEqual(await verifyStandardWebhook(payload, { ...headers, signature: `v1,${'B'.repeat(44)}` }, secret, { now: NOW }), { ok: false, reason: 'invalid-signature' });
  assert.deepEqual(await verifyStandardWebhook(payload, { ...headers, timestamp: String(TS - 400) }, secret, { now: NOW }), { ok: false, reason: 'invalid-signature' }, 'timestamp is part of the signed content');
  assert.deepEqual(await verifyStandardWebhook(payload, headers, rawSecret.toString('base64'), { now: NOW }), { ok: true }, 'secret is accepted with or without the whsec_ prefix');
  assert.deepEqual(await verifyStandardWebhook(payload, { ...headers, id: '' }, secret, { now: NOW }), { ok: false, reason: 'invalid-id' });
});
