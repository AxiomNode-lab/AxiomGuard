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
};

test('Express 5 middleware works in the real framework lifecycle', async () => {
  const app = express();
  app.use(createExpressSecurityMiddleware(adapterOptions));
  app.get('/ok', (_req, res) => res.status(200).send('ok'));
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
  try {
    const normal = await app.inject({ method: 'GET', url: '/ok', headers: { origin: 'https://app.example' } });
    assert.equal(normal.statusCode, 200);
    assert.equal(normal.headers['access-control-allow-origin'], 'https://app.example');
    assert.equal(normal.headers['x-content-type-options'], 'nosniff');

    const preflight = await app.inject({ method: 'OPTIONS', url: '/ok', headers: { origin: 'https://app.example', 'access-control-request-method': 'GET' } });
    assert.equal(preflight.statusCode, 204);
    assert.equal(preflight.headers['access-control-allow-origin'], 'https://app.example');
  } finally {
    await app.close();
  }
});

test('Hono 4 middleware applies headers after downstream handlers', async () => {
  const app = new Hono();
  app.use('*', createHonoSecurityMiddleware(adapterOptions));
  app.get('/ok', (context) => context.text('ok'));

  const normal = await app.request('/ok', { headers: { Origin: 'https://app.example' } });
  assert.equal(normal.status, 200);
  assert.equal(normal.headers.get('access-control-allow-origin'), 'https://app.example');
  assert.equal(normal.headers.get('x-content-type-options'), 'nosniff');

  const preflight = await app.request('/ok', { method: 'OPTIONS', headers: { Origin: 'https://app.example', 'Access-Control-Request-Method': 'GET' } });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), 'https://app.example');
});
