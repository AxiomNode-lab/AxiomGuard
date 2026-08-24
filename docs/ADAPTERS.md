# Framework and Redis adapters

AxiomGuard keeps framework and Redis clients out of `dependencies`. The adapters use the small structural surface they need, so consumers keep control of framework versions and Redis clients.

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
}));
```

The adapter returns an `onRequest`-compatible structural hook and does not import Fastify at runtime.

## Hono

```ts
import { Hono } from 'hono';
import { createHonoSecurityMiddleware } from '@axiomnode-lab/guard/adapters/hono';

const app = new Hono();
app.use('*', createHonoSecurityMiddleware({
  cors: { origins: ['https://app.example.com'] },
}));
```

For normal requests, headers are applied after `await next()` so the adapter owns the final defensive values. Allowed preflight requests return a 204 `Response` directly.

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

AxiomGuard also exposes `createNodeRedisRateLimitStore()` and `createIORedisRateLimitStore()`. Both execute a small atomic Lua script that increments the fixed-window counter and sets its TTL on the first request.

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
