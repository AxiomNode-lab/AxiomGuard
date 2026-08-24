import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  MemoryRateLimitStore,
  checkRateLimit,
  createPresetSecurityHeaders,
  createNodeRedisReplayStore,
  findingsToSarif,
  scanSecrets,
} from '../dist/index.js';
import { createExpressSecurityMiddleware } from '../dist/adapters/express.js';
import { createFastifySecurityHook } from '../dist/adapters/fastify.js';
import { createHonoSecurityMiddleware } from '../dist/adapters/hono.js';

test('rate limiter fails closed after the configured fixed-window limit', async () => {
  const store = new MemoryRateLimitStore();
  const options = { limit: 2, windowMs: 60_000, store, now: 1_000_000 };
  assert.equal((await checkRateLimit('ip:1', options)).allowed, true);
  assert.equal((await checkRateLimit('ip:1', options)).remaining, 0);
  const blocked = await checkRateLimit('ip:1', options);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds, 60);
});

test('security presets stay deployment-conscious and make isolation explicit', () => {
  const api = createPresetSecurityHeaders('api');
  assert.equal(api['Content-Security-Policy'], undefined);
  const isolated = createPresetSecurityHeaders('isolated');
  assert.equal(isolated['Cross-Origin-Embedder-Policy'], 'require-corp');
  assert.match(isolated['Content-Security-Policy'], /default-src/);
});

test('scanner produces SARIF without exposing matched secret values', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'axiomguard-'));
  try {
    const secretLine = ['API_KEY=', 'real-secret-value'].join('');
    await writeFile(path.join(directory, '.env'), `${secretLine}\n`, 'utf8');
    const findings = await scanSecrets(directory);
    assert.equal(findings.length, 1);
    const sarif = JSON.stringify(findingsToSarif(findings));
    assert.match(sarif, /sensitive-env-value/);
    assert.doesNotMatch(sarif, /real-secret-value/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Express adapter applies headers and handles allowed preflight', () => {
  const headers = new Map(); let ended = false; let nextCalls = 0;
  const middleware = createExpressSecurityMiddleware({ cors: { origins: ['https://app.example'], allowMethods: ['GET'] } });
  middleware(
    { method: 'OPTIONS', headers: { origin: 'https://app.example' } },
    { statusCode: 200, setHeader: (name, value) => headers.set(name, value), end: () => { ended = true; } },
    () => { nextCalls += 1; },
  );
  assert.equal(headers.get('Access-Control-Allow-Origin'), 'https://app.example');
  assert.equal(ended, true);
  assert.equal(nextCalls, 0);
});

test('Fastify adapter uses structural reply APIs without a runtime dependency', () => {
  const headers = new Map(); let sent = false; let status = 200;
  const hook = createFastifySecurityHook({ cors: { origins: ['https://app.example'] } });
  const reply = {
    header(name, value) { headers.set(name, value); return this; },
    code(value) { status = value; return this; },
    send() { sent = true; return this; },
  };
  hook({ method: 'OPTIONS', headers: { origin: 'https://app.example' } }, reply);
  assert.equal(status, 204);
  assert.equal(sent, true);
  assert.equal(headers.get('Access-Control-Allow-Origin'), 'https://app.example');
});

test('Hono adapter applies headers after downstream middleware', async () => {
  const headers = new Map(); let nextCalled = false;
  const middleware = createHonoSecurityMiddleware({ headers: { contentSecurityPolicy: false } });
  await middleware(
    { req: { method: 'GET', header: () => undefined }, header: (name, value) => headers.set(name, value) },
    async () => { nextCalled = true; },
  );
  assert.equal(nextCalled, true);
  assert.equal(headers.get('X-Content-Type-Options'), 'nosniff');
});

test('node-redis replay adapter uses an atomic NX+PX claim', async () => {
  const calls = [];
  const client = {
    set: async (...args) => { calls.push(args); return 'OK'; },
    eval: async () => [1, 1000],
  };
  const store = createNodeRedisReplayStore(client, 'test:');
  assert.equal(await store.claim('event', Date.now() + 10_000), true);
  assert.equal(calls[0][0], 'test:event');
  assert.equal(calls[0][2].NX, true);
  assert.ok(calls[0][2].PX > 0);
});
