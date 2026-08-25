import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  MemoryRateLimitStore,
  MemoryReplayStore,
  checkRateLimit,
  isPrivateIPAddress,
  redactSecrets,
  validateEnv,
  verifyGitHubWebhookDelivery,
  verifyStripeWebhook,
} from '../dist/index.js';
import { createNodeRedisRateLimitStore } from '../dist/adapters/redis.js';

test('IPv6 transition and mapped private addresses cannot bypass SSRF policy', () => {
  assert.equal(isPrivateIPAddress('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateIPAddress('::ffff:7f00:1'), true);
  assert.equal(isPrivateIPAddress('::ffff:8.8.8.8'), false);
  assert.equal(isPrivateIPAddress('64:ff9b::808:808'), true);
  assert.equal(isPrivateIPAddress('2002:7f00:1::'), true);
  assert.equal(isPrivateIPAddress('2001:0:4136:e378:8000:63bf:3fff:fdd2'), true);
});

test('MemoryRateLimitStore is bounded under unique attacker-controlled keys', async () => {
  const store = new MemoryRateLimitStore(2);
  await checkRateLimit('a', { limit: 1, windowMs: 60_000, store, now: 1000 });
  await checkRateLimit('b', { limit: 1, windowMs: 60_000, store, now: 1000 });
  await checkRateLimit('c', { limit: 1, windowMs: 60_000, store, now: 1000 });
  const aAgain = await checkRateLimit('a', { limit: 1, windowMs: 60_000, store, now: 1000 });
  assert.equal(aAgain.allowed, true, 'oldest entry should have been evicted instead of growing without bound');
});

test('environment defaults are parsed and constrained like supplied values', () => {
  const good = validateEnv({ PORT: { type: 'port', default: 3000 }, MODE: { default: 'prod', allowed: ['prod', 'dev'] } }, {});
  assert.equal(good.ok, true);
  assert.equal(good.values.PORT, 3000);

  const bad = validateEnv({ PORT: { type: 'port', default: 70000 }, MODE: { default: 'oops', allowed: ['prod'] } }, {});
  assert.equal(bad.ok, false);
  assert.match(bad.errors.join('\n'), /PORT default must be a TCP port/);
  assert.match(bad.errors.join('\n'), /MODE must be one of the allowed values/);
});

test('Stripe verifier authenticates before revealing timestamp freshness', async () => {
  const payload = '{"id":"evt"}';
  const staleTimestamp = 1;
  const invalidHeader = `t=${staleTimestamp},v1=${'0'.repeat(64)}`;
  assert.deepEqual(await verifyStripeWebhook(payload, invalidHeader, 'whsec_test', { now: 1_800_000_000_000 }), { ok: false, reason: 'invalid-signature' });

  const valid = createHmac('sha256', 'whsec_test').update(`${staleTimestamp}.${payload}`).digest('hex');
  assert.deepEqual(await verifyStripeWebhook(payload, `t=${staleTimestamp},v1=${valid}`, 'whsec_test', { now: 1_800_000_000_000 }), { ok: false, reason: 'stale-timestamp' });
});

test('GitHub delivery IDs can be replay-protected after signature verification', async () => {
  const payload = Buffer.from('hello');
  const secret = 'secret';
  const signature = `sha256=${createHmac('sha256', secret).update(payload).digest('hex')}`;
  const store = new MemoryReplayStore();
  const now = Date.now();
  assert.deepEqual(await verifyGitHubWebhookDelivery(payload, signature, secret, 'delivery-1', { replayStore: store, now }), { ok: true });
  assert.deepEqual(await verifyGitHubWebhookDelivery(payload, signature, secret, 'delivery-1', { replayStore: store, now }), { ok: false, reason: 'replay' });
});

test('Redis rate-limit adapter fails closed on invalid negative TTL state', async () => {
  const store = createNodeRedisRateLimitStore({
    set: async () => 'OK',
    eval: async () => [1, -1],
  });
  await assert.rejects(store.consume('client', 1000, 1000), /invalid counters/);
});

test('redaction covers provider-shaped live credentials and validates recursion limits', () => {
  const stripe = ['sk', 'live', 'A'.repeat(24)].join('_');
  const slack = ['xoxb', '123456789012345678901234'].join('-');
  const value = redactSecrets({ message: `stripe=${stripe} slack=${slack}` });
  assert.equal(value.message, 'stripe=[REDACTED] slack=[REDACTED]');
  assert.throws(() => redactSecrets({ ok: true }, { maxDepth: -1 }), /maxDepth/);
});
