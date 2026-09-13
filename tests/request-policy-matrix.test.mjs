import test from 'node:test';
import assert from 'node:assert/strict';
import { RequestPolicyError, createRequestPolicy, evaluateRequestPolicy } from '../dist/index.js';

const LISTED = 'https://app.example.com';
const UNLISTED = 'https://evil.example.net';

const sites = { 'same-origin': 'same-origin', 'same-site': 'same-site', 'cross-site': 'cross-site', none: 'none', absent: null, invalid: 'weird' };
const origins = { listed: LISTED, unlisted: UNLISTED, null: 'null', invalid: 'http://x/path', absent: null, joined: `${LISTED}, ${LISTED}` };

// Expected decision for POST under the default options, keyed by `${site}/${origin}`.
const DEFAULT_EXPECTATIONS = {
  'same-origin/listed': 'same-origin', 'same-origin/unlisted': 'same-origin', 'same-origin/null': 'same-origin', 'same-origin/invalid': 'same-origin', 'same-origin/absent': 'same-origin', 'same-origin/joined': 'same-origin',
  'same-site/listed': 'trusted-origin', 'same-site/unlisted': 'untrusted-origin', 'same-site/null': 'null-origin', 'same-site/invalid': 'invalid-origin', 'same-site/absent': 'same-site-not-allowed', 'same-site/joined': 'invalid-origin',
  'cross-site/listed': 'cross-site', 'cross-site/unlisted': 'cross-site', 'cross-site/null': 'cross-site', 'cross-site/invalid': 'cross-site', 'cross-site/absent': 'cross-site', 'cross-site/joined': 'cross-site',
  'none/listed': 'trusted-origin', 'none/unlisted': 'untrusted-origin', 'none/null': 'null-origin', 'none/invalid': 'invalid-origin', 'none/absent': 'missing-origin', 'none/joined': 'invalid-origin',
  'absent/listed': 'trusted-origin', 'absent/unlisted': 'untrusted-origin', 'absent/null': 'null-origin', 'absent/invalid': 'invalid-origin', 'absent/absent': 'missing-origin', 'absent/joined': 'invalid-origin',
  'invalid/listed': 'invalid-fetch-metadata', 'invalid/unlisted': 'invalid-fetch-metadata', 'invalid/null': 'invalid-fetch-metadata', 'invalid/invalid': 'invalid-fetch-metadata', 'invalid/absent': 'invalid-fetch-metadata', 'invalid/joined': 'invalid-fetch-metadata',
};
const ALLOW_REASONS = new Set(['safe-method', 'same-origin', 'same-site', 'trusted-origin', 'non-browser-client']);

test('request policy decision matrix under default options', () => {
  const policy = createRequestPolicy({ allowedOrigins: [LISTED] });
  for (const [siteName, secFetchSite] of Object.entries(sites)) {
    for (const [originName, origin] of Object.entries(origins)) {
      const expected = DEFAULT_EXPECTATIONS[`${siteName}/${originName}`];
      const decision = policy.evaluate({ method: 'post', origin, secFetchSite });
      assert.equal(decision.reason, expected, `${siteName}/${originName}`);
      assert.equal(decision.allowed, ALLOW_REASONS.has(expected), `${siteName}/${originName} allowed flag`);
    }
  }
});

test('request policy option switches change only their own cells', () => {
  const base = { allowedOrigins: [LISTED] };
  assert.deepEqual(evaluateRequestPolicy({ method: 'POST', secFetchSite: 'same-site', origin: UNLISTED }, { ...base, allowSameSite: true }), { allowed: true, reason: 'same-site' });
  assert.deepEqual(evaluateRequestPolicy({ method: 'POST', secFetchSite: 'same-site' }, { ...base, allowSameSite: true }), { allowed: true, reason: 'same-site' });
  assert.deepEqual(evaluateRequestPolicy({ method: 'POST' }, { ...base, allowNoOrigin: true }), { allowed: true, reason: 'non-browser-client' });
  assert.deepEqual(evaluateRequestPolicy({ method: 'POST', secFetchSite: 'none' }, { ...base, allowNoOrigin: true }), { allowed: true, reason: 'non-browser-client' });
  assert.deepEqual(evaluateRequestPolicy({ method: 'POST', secFetchSite: 'same-site' }, { ...base, allowNoOrigin: true }), { allowed: false, reason: 'same-site-not-allowed' }, 'allowNoOrigin does not relax same-site without Origin');

  const crossSite = { ...base, allowCrossSiteFromAllowedOrigins: true };
  assert.deepEqual(evaluateRequestPolicy({ method: 'POST', secFetchSite: 'cross-site', origin: LISTED }, crossSite), { allowed: true, reason: 'trusted-origin' });
  assert.deepEqual(evaluateRequestPolicy({ method: 'POST', secFetchSite: 'cross-site', origin: UNLISTED }, crossSite), { allowed: false, reason: 'cross-site' });
  assert.deepEqual(evaluateRequestPolicy({ method: 'POST', secFetchSite: 'cross-site' }, crossSite), { allowed: false, reason: 'cross-site' });
  assert.deepEqual(evaluateRequestPolicy({ method: 'POST', secFetchSite: 'cross-site', origin: 'null' }, crossSite), { allowed: false, reason: 'cross-site' });

  assert.deepEqual(evaluateRequestPolicy({ method: 'GET', secFetchSite: 'cross-site' }, { safeMethods: [] }), { allowed: false, reason: 'cross-site' }, 'empty safeMethods makes GET unsafe');
  assert.deepEqual(evaluateRequestPolicy({ method: 'DELETE', secFetchSite: 'cross-site' }, { safeMethods: ['DELETE'] }), { allowed: true, reason: 'safe-method' });
});

test('request policy validates configuration eagerly for every method', () => {
  assert.throws(() => createRequestPolicy({ allowedOrigins: ['not a url'] }), /Invalid allowed origin/);
  assert.throws(() => createRequestPolicy({ allowedOrigins: ['https://app.example.com/path'] }), /Invalid allowed origin/);
  assert.throws(() => createRequestPolicy({ safeMethods: ['G E T'] }), /Invalid safe HTTP method/);
  assert.throws(() => evaluateRequestPolicy({ method: 'GET' }, { allowedOrigins: ['bad'] }), /Invalid allowed origin/, 'safe methods no longer hide configuration errors');
  const policy = createRequestPolicy({ allowedOrigins: [LISTED] });
  assert.throws(() => policy.assert({ method: 'POST', secFetchSite: 'cross-site' }), (error) => error instanceof RequestPolicyError && error.reason === 'cross-site');
  assert.deepEqual(policy.assert({ method: 'GET' }), { allowed: true, reason: 'safe-method' });
  assert.deepEqual(policy.evaluate({ method: '' }), { allowed: false, reason: 'invalid-method' });
  assert.deepEqual(policy.evaluate({ method: 'PO ST' }), { allowed: false, reason: 'invalid-method' });
});
