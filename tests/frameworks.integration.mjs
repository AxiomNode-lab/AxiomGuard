import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import Fastify from 'fastify';
import { Hono } from 'hono';
import { createExpressSecurityMiddleware } from '../dist/adapters/express.js';
import { createFastifySecurityHook } from '../dist/adapters/fastify.js';
import { createHonoSecurityMiddleware } from '../dist/adapters/hono.js';

const adapterOptions = {
  headers: { contentSecurityPolicy: false },
  cors: { origins: ['https://app.example'], allowMethods: ['GET', 'POST'] },
  requestPolicy: { allowedOrigins: ['https://app.example'] },
};

test('Express 5 middleware works in the real framework lifecycle', async () => {
  const app = express();
  app.use(createExpressSecurityMiddleware(adapterOptions));
  app.get('/ok', (_req, res) => res.status(200).send('ok'));
  app.post('/mutate', (_req, res) => res.status(200).send('changed'));
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  try {
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const base = `http://127.0.0.1:${address.port}`;
    const normal = await fetch(`${base}/ok`, { headers: { Origin: 'https://app.example' } });
    assert.equal(normal.status, 200);
    assert.equal(normal.headers.get('access-control-allow-origin'), 'https://app.example');
    assert.equal(normal.headers.get('x-content-type-options'), 'nosniff');

    const trustedPost = await fetch(`${base}/mutate`, { method: 'POST', headers: { Origin: 'https://app.example' } });
    assert.equal(trustedPost.status, 200);
    const blockedPost = await fetch(`${base}/mutate`, { method: 'POST', headers: { Origin: 'https://evil.example' } });
    assert.equal(blockedPost.status, 403);

    const preflight = await fetch(`${base}/ok`, { method: 'OPTIONS', headers: { Origin: 'https://app.example', 'Access-Control-Request-Method': 'GET' } });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get('access-control-allow-origin'), 'https://app.example');
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test('Fastify 5 hook works with inject without double-send', async () => {
  const app = Fastify();
  app.addHook('onRequest', createFastifySecurityHook(adapterOptions));
  app.get('/ok', async () => ({ ok: true }));
  app.post('/mutate', async () => ({ changed: true }));
  try {
    const normal = await app.inject({ method: 'GET', url: '/ok', headers: { origin: 'https://app.example' } });
    assert.equal(normal.statusCode, 200);
    assert.equal(normal.headers['access-control-allow-origin'], 'https://app.example');
    assert.equal(normal.headers['x-content-type-options'], 'nosniff');

    const trustedPost = await app.inject({ method: 'POST', url: '/mutate', headers: { origin: 'https://app.example' } });
    assert.equal(trustedPost.statusCode, 200);
    const blockedPost = await app.inject({ method: 'POST', url: '/mutate', headers: { origin: 'https://evil.example' } });
    assert.equal(blockedPost.statusCode, 403);

    const preflight = await app.inject({ method: 'OPTIONS', url: '/ok', headers: { origin: 'https://app.example', 'access-control-request-method': 'GET' } });
    assert.equal(preflight.statusCode, 204);
    assert.equal(preflight.headers['access-control-allow-origin'], 'https://app.example');
  } finally {
    await app.close();
  }
});

test('Hono 4 middleware applies headers and blocks untrusted unsafe origins', async () => {
  const app = new Hono();
  app.use('*', createHonoSecurityMiddleware(adapterOptions));
  app.get('/ok', (context) => context.text('ok'));
  app.post('/mutate', (context) => context.text('changed'));

  const normal = await app.request('/ok', { headers: { Origin: 'https://app.example' } });
  assert.equal(normal.status, 200);
  assert.equal(normal.headers.get('access-control-allow-origin'), 'https://app.example');
  assert.equal(normal.headers.get('x-content-type-options'), 'nosniff');

  const trustedPost = await app.request('/mutate', { method: 'POST', headers: { Origin: 'https://app.example' } });
  assert.equal(trustedPost.status, 200);
  const blockedPost = await app.request('/mutate', { method: 'POST', headers: { Origin: 'https://evil.example' } });
  assert.equal(blockedPost.status, 403);

  const preflight = await app.request('/ok', { method: 'OPTIONS', headers: { Origin: 'https://app.example', 'Access-Control-Request-Method': 'GET' } });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), 'https://app.example');
});
