import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createCorsHeaders, createCspNonce, createCsrfToken, createSecurityHeaders, redactSecrets, serializeCookie, validateEnv, verifyCsrfToken, verifyGitHubWebhook, verifyStripeWebhook, MemoryReplayStore } from '../dist/index.js';

test('secure cookies enforce host prefix invariants', () => {
  const value = serializeCookie('__Host-session', 'abc', { sameSite: 'Strict' });
  assert.match(value, /Secure/); assert.match(value, /HttpOnly/); assert.match(value, /Path=\//);
  assert.throws(() => serializeCookie('__Host-session', 'abc', { domain: 'example.com' }));
  assert.throws(() => serializeCookie('session', 'abc', { sameSite: 'None', secure: false }));
});

test('cors rejects unsafe policies and varies explicit origins', () => {
  assert.throws(() => createCorsHeaders('https://app.example', { origins: '*', allowCredentials: true }));
  assert.throws(() => createCorsHeaders('null', { origins: '*' }));
  assert.throws(() => createCorsHeaders('file:///tmp/test', { origins: '*' }));
  const headers = createCorsHeaders('https://app.example', { origins: ['https://app.example'], allowCredentials: true, allowPrivateNetwork: true });
  assert.equal(headers?.['Access-Control-Allow-Origin'], 'https://app.example');
  assert.equal(headers?.Vary, 'Origin');
  assert.equal(headers?.['Access-Control-Allow-Private-Network'], 'true');
  const nullHeaders = createCorsHeaders('null', { origins: ['null'], allowNullOrigin: true });
  assert.equal(nullHeaders?.['Access-Control-Allow-Origin'], 'null');
});

test('csrf token is signed, session bound and expiring', () => {
  const secret = '0123456789abcdef0123456789abcdef'; const now = 1_800_000_000_000;
  const token = createCsrfToken(secret, { sessionId: 's1', now });
  assert.equal(verifyCsrfToken(token, secret, { sessionId: 's1', now }), true);
  assert.equal(verifyCsrfToken(token, secret, { sessionId: 's2', now }), false);
  assert.equal(verifyCsrfToken(token, secret, { sessionId: 's1', now: now + 8_000_000 }), false);
});

test('header helper emits cross-origin protections and CSP report-only', () => {
  const nonce = createCspNonce(); assert.ok(nonce.length > 20);
  const headers = createSecurityHeaders({ contentSecurityPolicy: { 'default-src': ["'self'"] }, contentSecurityPolicyReportOnly: true });
  assert.equal(headers['Cross-Origin-Opener-Policy'], 'same-origin');
  assert.ok(headers['Content-Security-Policy-Report-Only']);
});

test('env supports ports numbers json and defaults', () => {
  const result = validateEnv({ PORT: { type: 'port' }, RATIO: { type: 'number', min: 0, max: 1 }, FLAGS: { type: 'json' }, MODE: { default: 'prod', required: false } }, { PORT: '443', RATIO: '0.5', FLAGS: '{"a":true}' });
  assert.equal(result.ok, true); assert.equal(result.values.PORT, 443); assert.equal(result.values.RATIO, 0.5); assert.deepEqual(result.values.FLAGS, { a: true }); assert.equal(result.values.MODE, 'prod');
});

test('redaction supports explicit wildcard object paths', () => {
  const result = redactSecrets({ users: [{ profile: { value: 'a' } }, { profile: { value: 'b' } }], req: { headers: { xApi: 'plain-value' } } }, { paths: ['users.*.profile', 'req.headers.xApi'] });
  assert.equal(result.users[0].profile, '[REDACTED]');
  assert.equal(result.users[1].profile, '[REDACTED]');
  assert.equal(result.req.headers.xApi, '[REDACTED]');
});

test('github webhook helper verifies sha256 signatures', () => {
  const payload = Buffer.from('hello'); const secret = 'secret';
  const sig = `sha256=${createHmac('sha256', secret).update(payload).digest('hex')}`;
  assert.equal(verifyGitHubWebhook(payload, sig, secret), true);
});

test('stripe verifier binds timestamp into signed payload and blocks replay', async () => {
  const payload = '{"id":"evt_1"}'; const secret = 'whsec_test'; const timestamp = 1_800_000_000; const now = timestamp * 1000;
  const signature = createHmac('sha256', secret).update(`${timestamp}.${payload}`).digest('hex');
  const header = `t=${timestamp},v1=${signature}`; const store = new MemoryReplayStore();
  assert.deepEqual(await verifyStripeWebhook(payload, header, secret, { now, replayStore: store }), { ok: true });
  assert.deepEqual(await verifyStripeWebhook(payload, header, secret, { now, replayStore: store }), { ok: false, reason: 'replay' });
});
