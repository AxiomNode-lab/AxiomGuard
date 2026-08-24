import test from 'node:test';
import assert from 'node:assert/strict';

const subpaths = [
  'api-keys',
  'cookies',
  'cors',
  'crypto',
  'csrf',
  'env',
  'fetch',
  'filesystem',
  'headers',
  'logging',
  'presets',
  'rate-limit',
  'scanner',
  'web',
  'webhooks',
  'adapters',
  'adapters/express',
  'adapters/fastify',
  'adapters/hono',
  'adapters/redis',
];

test('all documented package subpath exports resolve after build', async () => {
  const root = await import('@axiomnode-lab/guard');
  assert.equal(typeof root.secureToken, 'function');
  assert.equal(typeof root.safeFetch, 'function');

  for (const subpath of subpaths) {
    const module = await import(`@axiomnode-lab/guard/${subpath}`);
    assert.ok(Object.keys(module).length > 0, `${subpath} should expose at least one symbol`);
  }
});
