import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  MemoryIdempotencyStore,
  claimIdempotencyKey,
  createIdempotencyFingerprint,
  createIdempotencyStoreKey,
  normalizeIdempotencyKey,
} from '../dist/idempotency.js';
import { evaluateRequestPolicy } from '../dist/request-policy.js';
import { MemoryReplayStore, verifyMetaWebhook, verifySlackWebhook } from '../dist/webhooks.js';

test('request policy allows safe methods and blocks cross-site unsafe requests', () => {
  assert.deepEqual(
    evaluateRequestPolicy({ method: 'GET', secFetchSite: 'cross-site', origin: 'https://evil.example' }),
    { allowed: true, reason: 'safe-method' },
  );
  assert.deepEqual(
    evaluateRequestPolicy(
      { method: 'POST', secFetchSite: 'cross-site', origin: 'https://evil.example' },
      { allowedOrigins: ['https://app.example'] },
    ),
    { allowed: false, reason: 'cross-site' },
  );
});

test('request policy trusts same-origin metadata and uses Origin as a fallback', () => {
  assert.deepEqual(
    evaluateRequestPolicy({ method: 'POST', secFetchSite: 'same-origin' }),
    { allowed: true, reason: 'same-origin' },
  );
  assert.deepEqual(
    evaluateRequestPolicy(
      { method: 'PATCH', origin: 'https://app.example' },
      { allowedOrigins: ['https://app.example'] },
    ),
    { allowed: true, reason: 'trusted-origin' },
  );
  assert.deepEqual(
    evaluateRequestPolicy(
      { method: 'PATCH', origin: 'https://evil.example' },
      { allowedOrigins: ['https://app.example'] },
    ),
    { allowed: false, reason: 'untrusted-origin' },
  );
});

test('request policy is conservative for same-site, null and origin-less unsafe requests', () => {
  assert.deepEqual(
    evaluateRequestPolicy({ method: 'POST', secFetchSite: 'same-site' }),
    { allowed: false, reason: 'same-site-not-allowed' },
  );
  assert.deepEqual(
    evaluateRequestPolicy({ method: 'POST', secFetchSite: 'same-site' }, { allowSameSite: true }),
    { allowed: true, reason: 'same-site' },
  );
  assert.deepEqual(
    evaluateRequestPolicy({ method: 'POST', origin: 'null' }),
    { allowed: false, reason: 'null-origin' },
  );
  assert.deepEqual(
    evaluateRequestPolicy({ method: 'POST' }),
    { allowed: false, reason: 'missing-origin' },
  );
  assert.deepEqual(
    evaluateRequestPolicy({ method: 'POST' }, { allowNoOrigin: true }),
    { allowed: true, reason: 'non-browser-client' },
  );
});

test('request policy rejects malformed configuration and metadata', () => {
  assert.deepEqual(
    evaluateRequestPolicy({ method: 'POST', secFetchSite: 'sideways' }),
    { allowed: false, reason: 'invalid-fetch-metadata' },
  );
  assert.deepEqual(
    evaluateRequestPolicy({ method: 'POST', origin: 'https://app.example/path' }),
    { allowed: false, reason: 'invalid-origin' },
  );
  assert.throws(
    () => evaluateRequestPolicy({ method: 'POST' }, { allowedOrigins: ['https://app.example/path'] }),
    /Invalid allowed origin/,
  );
});

test('idempotency fingerprints are stable and bind request semantics', () => {
  const first = createIdempotencyFingerprint({
    method: 'POST',
    target: '/payments?account=1',
    contentType: 'application/json',
    body: '{"amount":10}',
  });
  const same = createIdempotencyFingerprint({
    method: 'post',
    target: '/payments?account=1',
    contentType: 'Application/JSON',
    body: '{"amount":10}',
  });
  const changed = createIdempotencyFingerprint({
    method: 'POST',
    target: '/payments?account=1',
    contentType: 'application/json',
    body: '{"amount":11}',
  });
  assert.equal(first, same);
  assert.notEqual(first, changed);
  assert.match(first, /^[a-f0-9]{64}$/);
});

test('memory idempotency store distinguishes first use, retry and conflicting reuse', async () => {
  const store = new MemoryIdempotencyStore();
  const firstFingerprint = createIdempotencyFingerprint({ method: 'POST', target: '/jobs', body: 'one' });
  const changedFingerprint = createIdempotencyFingerprint({ method: 'POST', target: '/jobs', body: 'two' });
  const now = 1_000_000;

  assert.equal(await claimIdempotencyKey('job-123', firstFingerprint, { store, ttlMs: 5_000, now }), 'accepted');
  assert.equal(await claimIdempotencyKey('job-123', firstFingerprint, { store, ttlMs: 5_000, now: now + 1 }), 'replay');
  assert.equal(await claimIdempotencyKey('job-123', changedFingerprint, { store, ttlMs: 5_000, now: now + 2 }), 'conflict');
  assert.equal(await claimIdempotencyKey('job-123', changedFingerprint, { store, ttlMs: 5_000, now: now + 5_001 }), 'accepted');
});

test('memory idempotency store fails closed at live capacity', async () => {
  const store = new MemoryIdempotencyStore(1);
  const fingerprint = createIdempotencyFingerprint({ method: 'POST', target: '/jobs', body: 'one' });
  const now = 2_000_000;
  assert.equal(await claimIdempotencyKey('first', fingerprint, { store, ttlMs: 5_000, now }), 'accepted');
  assert.equal(await claimIdempotencyKey('second', fingerprint, { store, ttlMs: 5_000, now: now + 1 }), 'capacity');
  assert.equal(store.size, 1);
});

test('idempotency keys normalize quoted values and are hashed before storage', () => {
  assert.equal(normalizeIdempotencyKey(' "job-123" '), 'job-123');
  assert.equal(normalizeIdempotencyKey('"job\\"123"'), 'job"123');
  assert.match(createIdempotencyStoreKey('job-123'), /^[a-f0-9]{64}$/);
  assert.throws(() => normalizeIdempotencyKey('bad\nkey'), /visible ASCII/);
});

test('Meta webhook verification validates X-Hub-Signature-256', () => {
  const body = Buffer.from('{"object":"whatsapp_business_account"}');
  const secret = 'meta-app-secret';
  const signature = `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
  assert.equal(verifyMetaWebhook(body, signature, secret), true);
  assert.equal(verifyMetaWebhook(body, `${signature.slice(0, -1)}0`, secret), false);
});

test('Slack webhook verification binds timestamp, freshness and replay state', async () => {
  const body = Buffer.from('token=ignored&command=%2Fhello');
  const secret = 'slack-signing-secret';
  const now = 1_800_000_000_000;
  const timestamp = Math.floor(now / 1000);
  const signed = Buffer.concat([Buffer.from(`v0:${timestamp}:`), body]);
  const signature = `v0=${createHmac('sha256', secret).update(signed).digest('hex')}`;
  const replayStore = new MemoryReplayStore();

  assert.deepEqual(
    await verifySlackWebhook(body, signature, timestamp, secret, { now, replayStore }),
    { ok: true },
  );
  assert.deepEqual(
    await verifySlackWebhook(body, signature, timestamp, secret, { now: now + 1, replayStore }),
    { ok: false, reason: 'replay' },
  );
  assert.deepEqual(
    await verifySlackWebhook(body, signature, timestamp, secret, { now: now + 301_000 }),
    { ok: false, reason: 'stale-timestamp' },
  );
});
