import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildContentSecurityPolicy,
  clearCookie,
  createCspNonce,
  createPresetSecurityHeaders,
  createSecurityHeaders,
  cspNonceSource,
  getClientIp,
  parseCookies,
  rateLimitBucketForIp,
  requireEnv,
  serializeCookie,
  validateEnv,
} from '../dist/index.js';

test('security headers disable legacy XSS auditors and validate HSTS preload', () => {
  const headers = createSecurityHeaders();
  assert.equal(headers['X-XSS-Protection'], '0');
  assert.equal(createSecurityHeaders({ xssProtection: false })['X-XSS-Protection'], undefined);
  assert.throws(() => createSecurityHeaders({ hsts: { preload: true } }), /preload requires includeSubDomains/);
  assert.throws(() => createSecurityHeaders({ hsts: { preload: true, includeSubDomains: true, maxAge: 3600 } }), /preload/);
  assert.equal(createSecurityHeaders({ hsts: { preload: true, includeSubDomains: true } })['Strict-Transport-Security'], 'max-age=31536000; includeSubDomains; preload');
});

test('CSP builder accepts valueless directives and nonce sources', () => {
  assert.equal(buildContentSecurityPolicy({ 'upgrade-insecure-requests': true, 'default-src': "'self'" }), "default-src 'self'; upgrade-insecure-requests");
  assert.equal(buildContentSecurityPolicy({ 'upgrade-insecure-requests': [] }), 'upgrade-insecure-requests');
  assert.equal(buildContentSecurityPolicy({ 'upgrade-insecure-requests': '' }), 'upgrade-insecure-requests');
  const nonce = createCspNonce();
  assert.match(cspNonceSource(nonce), /^'nonce-[A-Za-z0-9+/=]+'$/);
  assert.throws(() => cspNonceSource("x'; script-src *"), TypeError);
  const web = createPresetSecurityHeaders('web');
  assert.match(web['Content-Security-Policy'], /form-action 'self'/);
  assert.match(web['Content-Security-Policy'], /script-src-attr 'none'/);
  assert.match(web['Content-Security-Policy'], /upgrade-insecure-requests/);
});

test('cookies can be parsed and cleared and reject unsafe attributes', () => {
  const cookie = serializeCookie('session', 'a b=c', { sameSite: 'Strict' });
  assert.equal(cookie, 'session=a%20b%3Dc; Path=/; HttpOnly; Secure; SameSite=Strict');
  assert.deepEqual(parseCookies('session=a%20b%3Dc; theme="dark"; bad; =x; session=dup; raw=%E0%A4%A'), { session: 'a b=c', theme: 'dark', raw: '%E0%A4%A' });
  assert.deepEqual(parseCookies(undefined), {});
  const polluted = parseCookies('__proto__=1; a=2');
  assert.equal(Object.getPrototypeOf(polluted), Object.prototype);
  assert.equal(Object.getOwnPropertyDescriptor(polluted, '__proto__')?.value, '1');
  assert.equal(clearCookie('session', { sameSite: 'Strict' }), 'session=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict');
  assert.throws(() => serializeCookie('a', 'b', { path: 'foo' }), /Path must start with/);
  assert.throws(() => serializeCookie('a', 'b', { domain: 'x y' }), /Domain/);
  assert.throws(() => serializeCookie('a', 'x'.repeat(5000)), RangeError);
});

test('env supports list and duration types, keeps raw URLs and rejects embedded credentials', () => {
  const env = requireEnv({
    TAGS: 'list',
    TIMEOUT: 'duration',
    API_URL: 'url',
    OPT: { type: 'string', required: false },
    RETRIES: { type: 'integer', default: 3, min: 1, max: 10 },
  }, { TAGS: 'a, b,,c', TIMEOUT: '1.5m', API_URL: 'https://Example.COM' });
  assert.deepEqual(env.TAGS, ['a', 'b', 'c']);
  assert.equal(env.TIMEOUT, 90_000);
  assert.equal(env.API_URL, 'https://Example.COM', 'url values are validated, not rewritten');
  assert.equal(env.OPT, undefined);
  assert.equal(env.RETRIES, 3);
  assert.ok(Object.isFrozen(env));

  const bad = validateEnv({ API_URL: 'url', TIMEOUT: 'duration', MODE: { type: 'string', allowed: ['a'] }, toString: 'string' }, { API_URL: 'https://u:p@h', TIMEOUT: '5 weeks', MODE: 'x' });
  assert.equal(bad.ok, false);
  assert.match(bad.errors.join('\n'), /API_URL must not embed credentials/);
  assert.match(bad.errors.join('\n'), /TIMEOUT must be a duration/);
  assert.match(bad.errors.join('\n'), /MODE must be one of/);
  assert.match(bad.errors.join('\n'), /toString is required/, 'prototype properties are not environment variables');
  assert.equal(bad.values.MODE, undefined, 'values that fail constraints are not returned');
  assert.equal(validateEnv({ API_URL: { type: 'url', allowCredentials: true } }, { API_URL: 'https://u:p@h' }).ok, true);
});

test('getClientIp only trusts the configured number of proxies', () => {
  assert.equal(getClientIp('203.0.113.9', '1.1.1.1, 2.2.2.2'), '203.0.113.9', 'header ignored without trusted proxies');
  assert.equal(getClientIp('::ffff:203.0.113.9', undefined), '203.0.113.9');
  assert.equal(getClientIp('10.0.0.1', '198.51.100.7, 172.16.0.2', { trustedProxyCount: 1 }), '172.16.0.2', 'the last hop was added by the trusted proxy');
  assert.equal(getClientIp('10.0.0.1', '198.51.100.7, 172.16.0.2', { trustedProxyCount: 2 }), '198.51.100.7');
  assert.equal(getClientIp('10.0.0.1', '198.51.100.7', { trustedProxyCount: 2 }), '10.0.0.1', 'too few hops falls back to the socket');
  assert.equal(getClientIp('10.0.0.1', 'spoofed, 2001:DB8::1', { trustedProxyCount: 1 }), '2001:db8::1');
  assert.equal(getClientIp('10.0.0.1', 'not-an-ip', { trustedProxyCount: 1 }), '10.0.0.1');
  assert.equal(getClientIp('10.0.0.1', ['1.1.1.1', '2.2.2.2'], { trustedProxyCount: 1 }), '2.2.2.2');
  assert.equal(getClientIp(undefined, undefined), null);
  assert.throws(() => getClientIp('1.1.1.1', '', { trustedProxyCount: -1 }), RangeError);
  assert.equal(rateLimitBucketForIp('2001:db8:85a3:1234:abcd::1'), '2001:0db8:85a3:1234::/64');
  assert.equal(rateLimitBucketForIp('::1'), '0000:0000:0000:0000::/64');
  assert.equal(rateLimitBucketForIp('203.0.113.9'), '203.0.113.9');
});
