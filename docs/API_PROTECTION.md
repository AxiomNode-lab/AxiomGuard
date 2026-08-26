# API protection primitives

AxiomGuard 0.6 adds framework-neutral controls for two request-layer problems that are often implemented inconsistently: browser cross-site request filtering and duplicate non-idempotent operations. It also expands provider-aware webhook verification for Meta/WhatsApp and Slack.

These helpers are defensive building blocks. They do not replace authentication, authorization, transaction boundaries, durable response storage, a WAF, or network policy.

## Browser request policy

`evaluateRequestPolicy()` treats `Sec-Fetch-Site` as the primary browser signal for unsafe methods and falls back to strict `Origin` verification when Fetch Metadata is absent or inconclusive. This follows the deployment shape recommended by the OWASP CSRF Prevention Cheat Sheet: Fetch Metadata is useful, but legacy/non-browser traffic requires an origin-aware fallback.

```ts
import { evaluateRequestPolicy } from '@axiomnode-lab/guard/request-policy';

const decision = evaluateRequestPolicy({
  method: req.method,
  origin: req.headers.origin ?? null,
  secFetchSite: req.headers['sec-fetch-site'] ?? null,
}, {
  allowedOrigins: ['https://app.example.com'],
});

if (!decision.allowed) {
  res.statusCode = 403;
  res.end();
  return;
}
```

Default policy for methods other than `GET`, `HEAD`, and `OPTIONS`:

- `cross-site` Fetch Metadata is rejected.
- `same-origin` is accepted.
- `same-site` is rejected unless `allowSameSite: true` is explicitly selected, or the request carries an origin in `allowedOrigins`.
- `Origin: null` is rejected.
- Missing Fetch Metadata falls back to exact HTTP(S) origin matching.
- Requests with neither browser metadata nor Origin are rejected unless `allowNoOrigin: true` is explicitly configured for a machine-to-machine endpoint.

The helper assumes methods configured as `safeMethods` are actually side-effect free. If an application changes state in `GET`, adding this policy does not repair that design.

### Framework adapters

Express, Fastify and Hono adapters can enforce the same policy before the application handler:

```ts
app.use(createExpressSecurityMiddleware({
  cors: {
    origins: ['https://app.example.com'],
    allowCredentials: true,
    allowMethods: ['GET', 'POST', 'PATCH'],
  },
  requestPolicy: {
    allowedOrigins: ['https://app.example.com'],
  },
}));
```

`requestPolicy` is opt-in to avoid silently breaking API clients. The default blocked status is `403`; `requestPolicyStatus` may be set to another 4xx status.

If a service exposes browser and machine-to-machine routes through the same global middleware, configure them separately rather than setting `allowNoOrigin: true` for every route.

## Idempotency claims

`claimIdempotencyKey()` provides an atomic duplicate/conflict claim primitive. It is useful for create/payment/job endpoints where a client may retry after a timeout.

```ts
import {
  MemoryIdempotencyStore,
  claimIdempotencyKey,
  createIdempotencyFingerprint,
} from '@axiomnode-lab/guard/idempotency';

const store = new MemoryIdempotencyStore();
const fingerprint = createIdempotencyFingerprint({
  method: req.method,
  target: req.url,
  contentType: req.headers['content-type'],
  body: rawBody,
});

const status = await claimIdempotencyKey(
  req.headers['idempotency-key'],
  fingerprint,
  { store, ttlMs: 24 * 60 * 60 * 1000 },
);

switch (status) {
  case 'accepted':
    // Process the operation once.
    break;
  case 'replay':
    // The same key and request fingerprint were already claimed.
    break;
  case 'conflict':
    // The client reused the key for different request semantics.
    break;
  case 'capacity':
    // In-memory protection is saturated; fail closed or return a retryable error.
    break;
}
```

Raw idempotency keys are normalized and SHA-256 hashed before reaching the store. Request fingerprints bind method, request target, normalized content type and raw body with length-delimited hashing.

`MemoryIdempotencyStore` is bounded and single-process. It never evicts a live claim to make room for attacker-controlled high-cardinality keys. Multi-instance deployments should use the node-redis/ioredis adapters:

```ts
import { createNodeRedisIdempotencyStore } from '@axiomnode-lab/guard/adapters/redis';

const store = createNodeRedisIdempotencyStore(redisClient);
```

Redis claims use one Lua script so first-use, retry and conflicting reuse are decided atomically with TTL.

### Important idempotency boundary

AxiomGuard stores the request fingerprint claim, not the application response or database transaction result. A production API that promises clients full response replay still needs durable application-specific result storage and transaction semantics. The `Idempotency-Key` work in the IETF HTTPAPI group expired as an Internet-Draft in April 2026, so AxiomGuard does not claim RFC conformance; the module uses the established concept while keeping its own documented validation contract.

## Meta / WhatsApp webhook signatures

Use the exact raw request body. Parsing and reserializing JSON before verification can change bytes and invalidate the signature.

```ts
import { verifyMetaWebhook } from '@axiomnode-lab/guard/webhooks';

const valid = verifyMetaWebhook(
  rawBody,
  req.headers['x-hub-signature-256'],
  process.env.META_APP_SECRET!,
);
```

The helper verifies the `sha256=` HMAC using constant-time digest comparison. Meta event-level deduplication still belongs to the application because event identifiers vary by product and payload shape.

## Slack signed requests

Slack signs the version, request timestamp and raw body together. AxiomGuard verifies the signature first, then enforces timestamp freshness, and can claim the signature in a replay store.

```ts
import { MemoryReplayStore, verifySlackWebhook } from '@axiomnode-lab/guard/webhooks';

const result = await verifySlackWebhook(
  rawBody,
  req.headers['x-slack-signature'],
  req.headers['x-slack-request-timestamp'],
  process.env.SLACK_SIGNING_SECRET!,
  {
    toleranceSeconds: 300,
    replayStore: new MemoryReplayStore(),
  },
);
```

For multiple instances, use a Redis replay store instead of in-process memory.

## Deployment notes

- Fetch Metadata and Origin policy are browser-request controls, not caller identity.
- CORS and request policy solve different problems; enabling CORS does not automatically prevent CSRF.
- Idempotency keys may be attacker-controlled. Keep TTLs bounded and use a shared store for distributed deployments.
- Never log raw webhook secrets, signatures, idempotency keys or request bodies by default.
- Provider webhook verification must run on the raw bytes received from the provider.
