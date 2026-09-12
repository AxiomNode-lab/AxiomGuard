import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  MemoryIdempotencyStore,
  MemoryReplayStore,
  claimIdempotencyKey,
  createApiKey,
  createCsrfToken,
  createIdempotencyFingerprint,
  createIdempotencyStoreKey,
  hashApiKey,
  maskApiKey,
  parseApiKey,
  verifyApiKey,
  verifyCsrfToken,
} from '../dist/index.js';

const SECRET = '0123456789abcdef0123456789abcdef';
const NOW = 1_800_000_000_000;

test('verifyCsrfToken throws on operator configuration errors instead of silently rejecting', () => {
  const token = createCsrfToken(SECRET, { now: NOW, sessionId: 's1' });
  assert.throws(() => verifyCsrfToken(token, 'short', { sessionId: 's1' }), /secret/);
  assert.throws(() => verifyCsrfToken(token, SECRET, { sessionId: 's1', maxAgeSeconds: 90_000 }), /maxAgeSeconds/);
  assert.throws(() => verifyCsrfToken(token, SECRET, { sessionId: 's1', maxAgeSeconds: 0 }), /maxAgeSeconds/);
  assert.equal(verifyCsrfToken(token, SECRET, { sessionId: 's1', now: NOW }), true);
});

test('verifyCsrfToken enforces clock skew, age, session binding and canonical encoding', () => {
  const token = createCsrfToken(SECRET, { now: NOW, sessionId: 's1' });
  assert.equal(verifyCsrfToken(token, SECRET, { sessionId: 's1', now: NOW - 60_000 }), true, '60s forward skew allowed');
  assert.equal(verifyCsrfToken(token, SECRET, { sessionId: 's1', now: NOW - 61_000 }), false, '61s forward skew rejected');
  assert.equal(verifyCsrfToken(token, SECRET, { sessionId: 's1', now: NOW + 7_200_000 }), true, 'default max age boundary');
  assert.equal(verifyCsrfToken(token, SECRET, { sessionId: 's1', now: NOW + 7_201_000 }), false);
  assert.equal(verifyCsrfToken(token, SECRET, { sessionId: 's2', now: NOW }), false, 'wrong session');
  assert.throws(() => verifyCsrfToken(token, SECRET, { now: NOW }), /sessionId/, 'verifying without a binding is an operator error');
  assert.equal(verifyCsrfToken(token, SECRET, { now: NOW, allowUnbound: true }), false, 'a bound token is not accepted as unbound');
  assert.equal(verifyCsrfToken(token, `${SECRET}x`, { sessionId: 's1', now: NOW }), false, 'other secret');

  const [version, ts, nonce, session, signature] = token.split('.');
  assert.equal(verifyCsrfToken(`${version}.${ts}.${nonce}x.${session}.${signature}`, SECRET, { sessionId: 's1', now: NOW }), false, 'tampered nonce');
  assert.equal(verifyCsrfToken(`v2.${ts}.${nonce}.${session}.${signature}`, SECRET, { sessionId: 's1', now: NOW }), false, 'other version');
  assert.equal(verifyCsrfToken(`${token}x`, SECRET, { sessionId: 's1', now: NOW }), false);
  assert.equal(verifyCsrfToken(`${version}.${ts}.${'a'.repeat(5000)}.${session}.${signature}`, SECRET, { sessionId: 's1', now: NOW }), false, 'oversized token');

  // Non-canonical base64url spellings of the same signature bytes are rejected.
  // 32 bytes = 43 chars with two padding bits, so flipping the lowest bit of the
  // final symbol decodes to identical bytes.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const alternative = alphabet[alphabet.indexOf(signature[signature.length - 1]) ^ 1];
  const malleable = `${version}.${ts}.${nonce}.${session}.${signature.slice(0, -1)}${alternative}`;
  assert.deepEqual(Buffer.from(malleable.split('.')[4], 'base64url'), Buffer.from(signature, 'base64url'), 'fixture decodes to the same bytes');
  assert.equal(verifyCsrfToken(malleable, SECRET, { sessionId: 's1', now: NOW }), false);
});

test('createCsrfToken requires a binding unless explicitly opted out', () => {
  assert.throws(() => createCsrfToken(SECRET, { now: NOW }), /sessionId/);
  const unbound = createCsrfToken(SECRET, { now: NOW, allowUnbound: true });
  assert.equal(verifyCsrfToken(unbound, SECRET, { now: NOW, allowUnbound: true }), true);
  assert.throws(() => verifyCsrfToken(unbound, SECRET, { now: NOW }), /sessionId/);
});

test('API key tokens are parseable and ids never contain the delimiter', () => {
  for (let index = 0; index < 200; index += 1) {
    const key = createApiKey({ prefix: 'svc_v1' });
    const parsed = parseApiKey(key.token);
    assert.ok(parsed, key.token);
    assert.equal(parsed.prefix, 'svc_v1');
    assert.equal(parsed.id, key.id);
    assert.match(key.id, /^[0-9A-Za-z]+$/);
    assert.match(parsed.secret, /^[0-9A-Za-z]+$/);
    assert.equal(verifyApiKey(key.token, key.digest), true);
  }
  assert.equal(parseApiKey('nonsense'), null);
  assert.equal(parseApiKey('axg_only'), null);
  assert.equal(parseApiKey(''), null);
});

test('hashApiKey supports a server-side pepper and verifyApiKey honours it', () => {
  const key = createApiKey();
  const peppered = hashApiKey(key.token, { pepper: 'server-pepper-value-1' });
  assert.notEqual(peppered, key.digest);
  assert.equal(verifyApiKey(key.token, peppered, { pepper: 'server-pepper-value-1' }), true);
  assert.equal(verifyApiKey(key.token, peppered), false);
  assert.equal(verifyApiKey(key.token, key.digest, { pepper: 'server-pepper-value-1' }), false);
  assert.equal(verifyApiKey(key.token, key.digest.toUpperCase()), true, 'digest case is not significant');
  assert.throws(() => hashApiKey(key.token, { pepper: 'short' }), /pepper/);
});

test('maskApiKey never reveals most of a short value', () => {
  assert.equal(maskApiKey('abcde'), '[REDACTED]');
  assert.equal(maskApiKey('axg_'), '[REDACTED]');
  assert.equal(maskApiKey('axg_abcdefgh1234'), 'axg_...1234');
  assert.equal(maskApiKey(''), '[REDACTED]');
});

test('idempotency keys can be scoped to the authenticated caller', async () => {
  const store = new MemoryIdempotencyStore();
  const fingerprint = createIdempotencyFingerprint({ method: 'POST', target: '/orders', body: '{}' });
  assert.equal(await claimIdempotencyKey('order-1', fingerprint, { store, now: NOW, scope: 'tenant-a' }), 'accepted');
  assert.equal(await claimIdempotencyKey('order-1', fingerprint, { store, now: NOW, scope: 'tenant-b' }), 'accepted');
  assert.equal(await claimIdempotencyKey('order-1', fingerprint, { store, now: NOW, scope: 'tenant-a' }), 'replay');
  assert.notEqual(createIdempotencyStoreKey('order-1', 'tenant-a'), createIdempotencyStoreKey('order-1'));
  assert.equal(createIdempotencyStoreKey('"order-1"'), createIdempotencyStoreKey('order-1'));
});

test('claimIdempotencyKey reports missing or invalid header values instead of throwing', async () => {
  const store = new MemoryIdempotencyStore();
  const fingerprint = createIdempotencyFingerprint({ method: 'POST', target: '/orders' });
  assert.equal(await claimIdempotencyKey(undefined, fingerprint, { store, now: NOW }), 'missing-key');
  assert.equal(await claimIdempotencyKey(null, fingerprint, { store, now: NOW }), 'missing-key');
  assert.equal(await claimIdempotencyKey('', fingerprint, { store, now: NOW }), 'missing-key');
  assert.equal(await claimIdempotencyKey(['a', 'b'], fingerprint, { store, now: NOW }), 'invalid-key');
  assert.equal(await claimIdempotencyKey('x'.repeat(256), fingerprint, { store, now: NOW }), 'invalid-key');
  assert.equal(await claimIdempotencyKey('badé', fingerprint, { store, now: NOW }), 'invalid-key');
  assert.equal(await claimIdempotencyKey(['only'], fingerprint, { store, now: NOW }), 'accepted');
});

test('bounded memory stores do not sweep on every call once saturated', () => {
  class CountingIdempotencyStore extends MemoryIdempotencyStore {
    sweeps = 0;
    sweepExpired(now) { this.sweeps += 1; return super.sweepExpired(now); }
  }
  const store = new CountingIdempotencyStore(100);
  const fp = 'a'.repeat(64);
  const keyFor = (value) => createHash('sha256').update(String(value)).digest('hex');
  for (let index = 0; index < 100; index += 1) assert.equal(store.claim(keyFor(index), fp, NOW + 60_000, NOW), 'accepted');
  const before = store.sweeps;
  for (let index = 0; index < 1000; index += 1) assert.equal(store.claim(keyFor(`late-${index}`), fp, NOW + 60_000, NOW + 1), 'capacity');
  assert.equal(store.sweeps - before, 0, 'nothing can have expired, so no sweep should run');
  // Once the earliest entry expires, exactly one sweep reclaims space.
  assert.equal(store.claim('b'.repeat(64), fp, NOW + 120_000, NOW + 60_001), 'accepted');
  assert.equal(store.sweeps - before, 1);

  const replay = new MemoryReplayStore(2);
  assert.equal(replay.claim('a', NOW + 1000, NOW), true);
  assert.equal(replay.claim('b', NOW + 1000, NOW), true);
  assert.equal(replay.claim('c', NOW + 1000, NOW), false);
  assert.equal(replay.size, 2);
  assert.equal(replay.claim('c', NOW + 2000, NOW + 1000), true, 'expired entries are reclaimed');
});
