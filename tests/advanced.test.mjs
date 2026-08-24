import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  MemoryReplayStore,
  buildContentSecurityPolicy,
  createApiKey,
  createSecurityHeaders,
  maskApiKey,
  verifyApiKey,
  verifyFreshHmacWebhook,
} from '../dist/index.js';

test('createApiKey returns a verifiable opaque key without storing plaintext', () => {
  const key = createApiKey({ prefix: 'axg' });
  assert.match(key.token, /^axg_[A-Za-z0-9_-]+_[A-Za-z0-9_-]+$/);
  assert.match(key.digest, /^[a-f0-9]{64}$/);
  assert.equal(verifyApiKey(key.token, key.digest), true);
  assert.equal(verifyApiKey(`${key.token}x`, key.digest), false);
  assert.match(maskApiKey(key.token), /^axg_\.\.\.[A-Za-z0-9_-]{4}$/);
});

test('verifyFreshHmacWebhook rejects stale messages and replayed signatures', async () => {
  const payload = Buffer.from('{"event":"ping"}');
  const secret = 'test-secret';
  const signature = `sha256=${createHmac('sha256', secret).update(payload).digest('hex')}`;
  const now = 1_800_000_000_000;
  const timestamp = Math.floor(now / 1000);
  const store = new MemoryReplayStore();

  assert.deepEqual(await verifyFreshHmacWebhook(
    { payload, signature, secret, timestamp },
    { now, replayStore: store },
  ), { ok: true });

  assert.deepEqual(await verifyFreshHmacWebhook(
    { payload, signature, secret, timestamp },
    { now, replayStore: store },
  ), { ok: false, reason: 'replay' });

  assert.deepEqual(await verifyFreshHmacWebhook(
    { payload, signature, secret, timestamp: timestamp - 1000 },
    { now, toleranceSeconds: 300 },
  ), { ok: false, reason: 'stale-timestamp' });
});

test('buildContentSecurityPolicy produces deterministic output and blocks header injection', () => {
  const csp = buildContentSecurityPolicy({
    'script-src': ["'self'", 'https://cdn.example.com'],
    'default-src': "'self'",
    'object-src': "'none'",
  });
  assert.equal(csp, "default-src 'self'; object-src 'none'; script-src 'self' https://cdn.example.com");
  assert.throws(() => buildContentSecurityPolicy({ 'script-src': ["'self'; report-uri https://evil.example"] }));
});

test('createSecurityHeaders returns conservative defaults and optional HSTS/CSP', () => {
  const headers = createSecurityHeaders({
    hsts: { includeSubDomains: true },
    contentSecurityPolicy: { 'default-src': "'self'", 'object-src': "'none'" },
  });
  assert.equal(headers['X-Content-Type-Options'], 'nosniff');
  assert.equal(headers['X-Frame-Options'], 'DENY');
  assert.equal(headers['Strict-Transport-Security'], 'max-age=31536000; includeSubDomains');
  assert.match(headers['Content-Security-Policy'], /default-src 'self'/);
});
