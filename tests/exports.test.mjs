import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';

const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const require = createRequire(import.meta.url);

// Every value export of the root module. Update deliberately when the public API changes;
// an accidental removal or rename fails here before it reaches a release.
const ROOT_EXPORTS = [
  'MemoryIdempotencyStore', 'MemoryRateLimitStore', 'MemoryReplayStore', 'RequestPolicyError', 'SafeFetchError', 'SafeUrlError',
  'applySecurityHeaders', 'assertRequestAllowed', 'assertSafeResolvedUrl', 'assertSafeUrl', 'buildContentSecurityPolicy',
  'checkRateLimit', 'claimIdempotencyKey', 'clearCookie', 'computeHmacSignature', 'constantTimeCompare', 'createApiKey',
  'createCorsHeaders', 'createCorsPolicy', 'createCspNonce', 'createCsrfToken', 'createExpressSecurityMiddleware',
  'createFastifySecurityHook', 'createFetchSecurityHandler', 'createFindingFingerprint', 'createHonoSecurityMiddleware',
  'createIORedisIdempotencyStore', 'createIORedisRateLimitStore', 'createIORedisReplayStore', 'createIdempotencyFingerprint',
  'createIdempotencyStoreKey', 'createNodeRedisIdempotencyStore', 'createNodeRedisRateLimitStore', 'createNodeRedisReplayStore',
  'createPresetSecurityHeaders', 'createRateLimitHeaders', 'createRequestPolicy', 'createSecretScanBaseline', 'createSecurityCore',
  'createSecurityHeaders', 'createSlackSignature', 'createStripeSignatureHeader', 'createWebhookReplayKey', 'cspNonceSource',
  'decodeDigest', 'evaluateRequestPolicy', 'findingsToSarif', 'getClientIp', 'getSecurityHeaderPreset', 'hashApiKey',
  'isPrivateIPAddress', 'listSecretRules', 'maskApiKey', 'maskPII', 'normalizeHostname', 'normalizeIdempotencyKey', 'parseApiKey',
  'parseCookies', 'parseSecretScanBaseline', 'parseSecretScannerConfig', 'rateLimitBucketForIp', 'redactSecrets', 'requireEnv',
  'safeFetch', 'safePath', 'sanitizeFilename', 'scanSecrets', 'secureToken', 'serializeCookie', 'signHmacWebhook',
  'validateEnv', 'validateRedirect', 'verifyApiKey', 'verifyCsrfToken', 'verifyFreshHmacWebhook', 'verifyGitHubWebhook',
  'verifyGitHubWebhookDelivery', 'verifyHmacWebhook', 'verifyMetaWebhook', 'verifySlackWebhook', 'verifyStandardWebhook',
  'verifyStripeWebhook',
];

test('root export surface matches the documented snapshot', async () => {
  const root = await import('../dist/index.js');
  assert.deepEqual(Object.keys(root).sort(), [...ROOT_EXPORTS].sort());
});

test('every package.json subpath export resolves under import and require', async () => {
  const subpaths = Object.keys(pkg.exports).filter((key) => key !== '.' && key !== './package.json');
  assert.ok(subpaths.length >= 22);
  for (const subpath of subpaths) {
    const target = pkg.exports[subpath];
    assert.equal(target.default, target.import, `${subpath} default and import conditions must agree`);
    assert.match(target.types, /\.d\.ts$/);
    const esm = await import(`../${target.import}`);
    assert.ok(Object.keys(esm).length > 0, `empty subpath export: ${subpath}`);
    const cjs = require(`${pkg.name}${subpath.slice(1)}`);
    assert.deepEqual(Object.keys(cjs).sort(), Object.keys(esm).sort(), `require() surface differs for ${subpath}`);
  }
  assert.equal(require(`${pkg.name}/package.json`).version, pkg.version);
});
