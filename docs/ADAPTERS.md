# Framework and Redis adapters

AxiomGuard keeps framework and Redis clients out of `dependencies`. The adapters use only the structural surface they need, so consumers keep control of framework versions and Redis clients.

## Shared browser request policy

Express, Fastify and Hono can optionally enforce the same Fetch-Metadata/Origin policy before unsafe requests reach application handlers:

```ts
const security = {
  cors: {
    origins: ['https://app.example.com'],
    allowCredentials: true,
    allowMethods: ['GET', 'POST', 'PATCH'],
  },
  requestPolicy: {
    allowedOrigins: ['https://app.example.com'],
  },
};
```

`requestPolicy` is opt-in. It is intended for browser-facing routes. Machine-to-machine endpoints that legitimately omit `Origin` should use a separate adapter policy or explicitly select `allowNoOrigin: true` for that route boundary.

The default blocked response is `403`; `requestPolicyStatus` can select another 4xx response. See [API_PROTECTION.md](API_PROTECTION.md).

## Express

```ts
import express from 'express';
import { createExpressSecurityMiddleware } from '@axiomnode-lab/guard/adapters/express';

const app = express();
app.use(createExpressSecurityMiddleware({
  headers: {
    contentSecurityPolicy: false,
  },
  cors: {
    origins: ['https://app.example.com'],
    allowCredentials: true,
    allowMethods: ['GET', 'POST'],
  },
  requestPolicy: {
    allowedOrigins: ['https://app.example.com'],
  },
}));
```

Allowed `OPTIONS` requests receive a 204 response by default. Set `handlePreflight: false` if another middleware owns preflight handling.

## Fastify

```ts
import Fastify from 'fastify';
import { createFastifySecurityHook } from '@axiomnode-lab/guard/adapters/fastify';

const app = Fastify();
app.addHook('onRequest', createFastifySecurityHook({
  cors: { origins: ['https://app.example.com'] },
  requestPolicy: { allowedOrigins: ['https://app.example.com'] },
}));
```

The adapter is a promise-style `onRequest` hook and does not import Fastify at runtime.

## Hono

```ts
import { Hono } from 'hono';
import { createHonoSecurityMiddleware } from '@axiomnode-lab/guard/adapters/hono';

const app = new Hono();
app.use('*', createHonoSecurityMiddleware({
  cors: { origins: ['https://app.example.com'] },
  requestPolicy: { allowedOrigins: ['https://app.example.com'] },
}));
```

For normal requests, headers are applied after `await next()` so the adapter owns the final defensive values. Allowed preflight requests return a 204 `Response` directly. Request-policy blocks return before downstream handlers run.

## Redis replay protection

### node-redis

```ts
import { createClient } from 'redis';
import { createNodeRedisReplayStore } from '@axiomnode-lab/guard/adapters/redis';

const redis = createClient();
await redis.connect();
const replayStore = createNodeRedisReplayStore(redis);
```

The adapter uses `SET key value NX PX ttl`, so the replay claim is atomic.

### ioredis

```ts
import Redis from 'ioredis';
import { createIORedisReplayStore } from '@axiomnode-lab/guard/adapters/redis';

const redis = new Redis();
const replayStore = createIORedisReplayStore(redis);
```

## Redis rate limiting

AxiomGuard exposes `createNodeRedisRateLimitStore()` and `createIORedisRateLimitStore()`. Both execute a small atomic Lua script that increments the fixed-window counter and sets or repairs its TTL.

```ts
import { checkRateLimit } from '@axiomnode-lab/guard/rate-limit';
import { createNodeRedisRateLimitStore } from '@axiomnode-lab/guard/adapters/redis';

const store = createNodeRedisRateLimitStore(redis);
const result = await checkRateLimit(`user:${user.id}`, {
  limit: 60,
  windowMs: 60_000,
  store,
});

if (!result.allowed) {
  // Return a 429 response in your framework.
}
```

Rate limiting is a traffic-control primitive, not an authentication or abuse-prevention system by itself. Choose keys carefully and use shared storage for multi-instance deployments.

## Redis idempotency

Use `createNodeRedisIdempotencyStore()` or `createIORedisIdempotencyStore()` with `claimIdempotencyKey()` when multiple application instances must share duplicate/conflict state.

```ts
import { claimIdempotencyKey, createIdempotencyFingerprint } from '@axiomnode-lab/guard/idempotency';
import { createNodeRedisIdempotencyStore } from '@axiomnode-lab/guard/adapters/redis';

const store = createNodeRedisIdempotencyStore(redis);
const fingerprint = createIdempotencyFingerprint({
  method: req.method,
  target: req.url,
  contentType: req.headers['content-type'],
  body: rawBody,
});

const status = await claimIdempotencyKey(
  req.headers['idempotency-key'],
  fingerprint,
  { store },
);
```

The Redis adapter stores only a hash-derived key and request fingerprint with TTL. A Lua script decides `accepted`, `replay`, or `conflict` atomically. It does not store an application response or make the application's database transaction atomic.
