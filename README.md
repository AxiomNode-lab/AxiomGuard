<div align="center">
  <img src="docs/axiomguard-demo.svg" alt="AxiomGuard terminal demo" width="860" />

  <h1>AxiomGuard</h1>
  <p><strong>Security building blocks for modern Node.js and TypeScript services.</strong></p>
  <p>Zero runtime dependencies · framework-neutral core · focused security primitives</p>

  [![npm version](https://img.shields.io/npm/v/@axiomnode-lab/guard?logo=npm)](https://www.npmjs.com/package/@axiomnode-lab/guard)
  [![npm downloads](https://img.shields.io/npm/dm/@axiomnode-lab/guard?logo=npm)](https://www.npmjs.com/package/@axiomnode-lab/guard)
  [![Node.js](https://img.shields.io/badge/Node.js-20%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
</div>

AxiomGuard is a modular security toolkit for backend services. It provides focused primitives for signed webhooks, API keys, browser request policy, idempotency, SSRF-aware outbound requests, rate limiting, secure cookies, CSRF, CORS, security headers, environment validation, secret-safe logging and repository scanning.

Use the complete package when convenience matters, or import a focused subpath when you only need one control.

## Install

**Requirements:** Node.js 20 or newer. AxiomGuard is published as an ES module.

```bash
npm install @axiomnode-lab/guard
```

Also works with other package managers:

```bash
pnpm add @axiomnode-lab/guard
# or
yarn add @axiomnode-lab/guard
```

## Quick start

### Secure an Express API

If you already use Express, the adapter is the fastest way to add defensive response headers, CORS handling and an opt-in browser request policy.

```ts
import express from 'express';
import { createExpressSecurityMiddleware } from '@axiomnode-lab/guard/adapters/express';

const app = express();

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

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/profile', (_req, res) => {
  res.json({ updated: true });
});

app.listen(3000);
```

With that configuration, ordinary requests receive AxiomGuard's defensive headers, allowed browser origins receive CORS headers, preflight requests are handled automatically, and unsafe browser requests from untrusted origins are rejected.

`requestPolicy` is a CSRF-oriented browser control. It does **not** replace authentication or authorization.

### Fastify

```ts
import Fastify from 'fastify';
import { createFastifySecurityHook } from '@axiomnode-lab/guard/adapters/fastify';

const app = Fastify();

app.addHook('onRequest', createFastifySecurityHook({
  cors: {
    origins: ['https://app.example.com'],
    allowMethods: ['GET', 'POST'],
  },
  requestPolicy: {
    allowedOrigins: ['https://app.example.com'],
  },
}));
```

### Hono

```ts
import { Hono } from 'hono';
import { createHonoSecurityMiddleware } from '@axiomnode-lab/guard/adapters/hono';

const app = new Hono();

app.use('*', createHonoSecurityMiddleware({
  cors: {
    origins: ['https://app.example.com'],
    allowMethods: ['GET', 'POST'],
  },
  requestPolicy: {
    allowedOrigins: ['https://app.example.com'],
  },
}));
```

See [Framework adapters](docs/ADAPTERS.md) for adapter options and Redis-backed integrations.

## Use AxiomGuard by goal

| Goal | Import | Start with |
| --- | --- | --- |
| Generate and verify API keys | `@axiomnode-lab/guard/api-keys` | `createApiKey`, `verifyApiKey` |
| Verify signed webhooks | `@axiomnode-lab/guard/webhooks` | `verifyGitHubWebhookDelivery`, `verifyStripeWebhook`, `verifySlackWebhook`, `verifyMetaWebhook` |
| Protect unsafe browser requests | `@axiomnode-lab/guard/request-policy` | `evaluateRequestPolicy` |
| Add idempotency claims | `@axiomnode-lab/guard/idempotency` | `createIdempotencyFingerprint`, `claimIdempotencyKey` |
| Guard outbound URLs and fetches | `@axiomnode-lab/guard/fetch` | `safeFetch` |
| Rate-limit requests | `@axiomnode-lab/guard/rate-limit` | `checkRateLimit`, `createRateLimitHeaders` |
| Build CORS policy | `@axiomnode-lab/guard/cors` | `createCorsHeaders` |
| Set defensive response headers | `@axiomnode-lab/guard/headers` | `createSecurityHeaders` |
| Create secure cookies | `@axiomnode-lab/guard/cookies` | `serializeCookie` |
| Create and verify CSRF tokens | `@axiomnode-lab/guard/csrf` | `createCsrfToken`, `verifyCsrfToken` |
| Validate environment variables | `@axiomnode-lab/guard/env` | `requireEnv` |
| Redact secrets and PII | `@axiomnode-lab/guard/logging` | `redactSecrets`, `maskPII` |
| Scan a repository for secrets | `@axiomnode-lab/guard/scanner` | `scanSecrets`, CLI `axiomguard scan` |

## Common recipes

### API keys

Generate an opaque API key, return the token once, and store only the identifier and digest.

```ts
import { createApiKey, verifyApiKey } from '@axiomnode-lab/guard/api-keys';

const created = createApiKey({ prefix: 'svc' });

// Return created.token to the client once.
// Persist created.id and created.digest in your database.

const accepted = verifyApiKey(presentedToken, created.digest);

if (!accepted) {
  throw new Error('Invalid API key');
}
```

Generated API keys are high-entropy random credentials. `verifyApiKey()` compares their SHA-256 digests in constant time; this API is not intended for human passwords.

### Signed webhooks with replay protection

Always verify a provider signature against the **exact raw request body**. Parsing and re-serializing JSON before verification can change the signed bytes.

```ts
import {
  MemoryReplayStore,
  verifyGitHubWebhookDelivery,
} from '@axiomnode-lab/guard/webhooks';

const replayStore = new MemoryReplayStore();

const result = await verifyGitHubWebhookDelivery(
  rawBody,
  request.headers['x-hub-signature-256'],
  process.env.GITHUB_WEBHOOK_SECRET!,
  request.headers['x-github-delivery'],
  { replayStore },
);

if (!result.ok) {
  // result.reason is invalid-signature, invalid-delivery, or replay.
  throw new Error(`Rejected webhook: ${result.reason}`);
}
```

A single-process service can use `MemoryReplayStore`. Multi-instance deployments should use one of the Redis replay-store adapters so all instances share replay state.

Provider helpers are also available for Stripe, Slack and Meta/WhatsApp signing formats. See [API reference](docs/API.md).

### Guarded outbound fetches

Use `safeFetch()` when a destination can be influenced by a user or external system.

```ts
import { safeFetch } from '@axiomnode-lab/guard/fetch';

const response = await safeFetch(userSuppliedUrl, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
  maxRedirects: 2,
  timeoutMs: 5_000,
  headers: {
    accept: 'application/json',
  },
});

const data = await response.json();
```

The helper validates the initial destination and followed redirects, limits redirect depth, applies a total timeout and strips sensitive credentials when a redirect crosses origins.

It reduces common SSRF mistakes, but it does not replace egress controls or eliminate DNS rebinding/time-of-check-time-of-use risk. See [Safe Fetch](docs/SAFE_FETCH.md).

### Idempotent write requests

Bind an idempotency key to the semantics of the request that first claimed it.

```ts
import {
  MemoryIdempotencyStore,
  claimIdempotencyKey,
  createIdempotencyFingerprint,
} from '@axiomnode-lab/guard/idempotency';

const store = new MemoryIdempotencyStore();

const fingerprint = createIdempotencyFingerprint({
  method: request.method,
  target: request.url,
  contentType: request.headers['content-type'],
  body: rawBody,
});

const status = await claimIdempotencyKey(
  request.headers['idempotency-key'],
  fingerprint,
  { store, ttlMs: 86_400_000 },
);

switch (status) {
  case 'accepted':
    // Process the operation.
    break;
  case 'replay':
    // Same key and same request semantics.
    break;
  case 'conflict':
    // Same key reused for a different request.
    break;
  case 'capacity':
    // Store is full; fail closed rather than silently evicting a live claim.
    break;
}
```

The idempotency module stores claim state, not your application response or database transaction result. If you need full response replay, persist that result in application-specific durable storage.

### Rate limiting

```ts
import {
  MemoryRateLimitStore,
  checkRateLimit,
  createRateLimitHeaders,
} from '@axiomnode-lab/guard/rate-limit';

const store = new MemoryRateLimitStore();

const result = await checkRateLimit(`ip:${clientIp}`, {
  limit: 60,
  windowMs: 60_000,
  store,
});

const headers = createRateLimitHeaders(result, {
  policyName: 'api',
});

if (!result.allowed) {
  // Return HTTP 429 with the generated rate-limit headers.
}
```

Use a Redis-backed store for distributed or high-volume services.

### Environment validation and safe logging

```ts
import { requireEnv } from '@axiomnode-lab/guard/env';
import { redactSecrets } from '@axiomnode-lab/guard/logging';

const env = requireEnv({
  PORT: { type: 'port', default: 3000 },
  API_URL: 'url',
  MODE: {
    type: 'string',
    allowed: ['development', 'staging', 'production'],
  },
});

const safeEvent = redactSecrets(event, {
  paths: ['req.headers.x-api-key', 'users.*.profile'],
});
```

`redactSecrets()` returns a redacted value without mutating the original object.

## Secret scanner CLI

Installing the package exposes the `axiomguard` command.

```bash
npx axiomguard scan .
```

Useful output modes:

```bash
npx axiomguard scan . --json
npx axiomguard scan . --sarif --output axiomguard.sarif
npx axiomguard scan . --write-baseline .axiomguard-baseline.json
npx axiomguard scan . --no-fail
```

The scanner reports the finding type, file, line and a non-secret fingerprint. It intentionally does not print detected secret values.

See [Scanner](docs/SCANNER.md) and [GitHub Action](docs/GITHUB_ACTION.md).

## Import style

The root package re-exports the complete public API:

```ts
import {
  createApiKey,
  safeFetch,
  redactSecrets,
} from '@axiomnode-lab/guard';
```

Focused subpath imports are also supported:

```ts
import { createApiKey } from '@axiomnode-lab/guard/api-keys';
import { safeFetch } from '@axiomnode-lab/guard/fetch';
import { redactSecrets } from '@axiomnode-lab/guard/logging';
```

Subpath imports make the capability being used explicit and are the recommended style in larger services.

## Package entry points

| Import | Purpose |
| --- | --- |
| `@axiomnode-lab/guard` | Complete public API |
| `@axiomnode-lab/guard/api-keys` | API key generation, hashing, verification and masking |
| `@axiomnode-lab/guard/webhooks` | Generic and provider-specific webhook verification |
| `@axiomnode-lab/guard/request-policy` | Fetch Metadata and Origin request filtering |
| `@axiomnode-lab/guard/idempotency` | Idempotency keys, fingerprints and claim stores |
| `@axiomnode-lab/guard/fetch` | Redirect-aware guarded outbound fetches |
| `@axiomnode-lab/guard/web` | URL, DNS, IP and redirect safety helpers |
| `@axiomnode-lab/guard/rate-limit` | Rate limiting and response-header helpers |
| `@axiomnode-lab/guard/cookies` | Secure cookie serialization |
| `@axiomnode-lab/guard/cors` | CORS policy helpers |
| `@axiomnode-lab/guard/csrf` | Signed CSRF tokens |
| `@axiomnode-lab/guard/headers` | Defensive headers and CSP helpers |
| `@axiomnode-lab/guard/presets` | Security-header presets |
| `@axiomnode-lab/guard/env` | Environment validation |
| `@axiomnode-lab/guard/logging` | Secret redaction and PII masking |
| `@axiomnode-lab/guard/filesystem` | Safe paths and filenames |
| `@axiomnode-lab/guard/scanner` | Secret scanner API and SARIF conversion |
| `@axiomnode-lab/guard/adapters/express` | Express middleware |
| `@axiomnode-lab/guard/adapters/fastify` | Fastify hook |
| `@axiomnode-lab/guard/adapters/hono` | Hono middleware |
| `@axiomnode-lab/guard/adapters/redis` | Redis-backed replay, rate-limit and idempotency stores |

## Security boundaries

AxiomGuard provides security primitives; it is not a replacement for the rest of an application's security architecture. In particular, it does not replace authentication or authorization, a secrets manager, password hashing with Argon2/scrypt/bcrypt, outbound firewalling, durable transaction storage, or application-specific threat modeling.

Read [SECURITY.md](SECURITY.md) for vulnerability reporting and [THREAT_MODEL.md](THREAT_MODEL.md) for design boundaries.

## Documentation

- [API reference](docs/API.md)
- [API protection](docs/API_PROTECTION.md)
- [Framework adapters](docs/ADAPTERS.md)
- [Safe fetch](docs/SAFE_FETCH.md)
- [Scanner](docs/SCANNER.md)
- [GitHub Action](docs/GITHUB_ACTION.md)
- [Security policy](SECURITY.md)
- [Threat model](THREAT_MODEL.md)
- [Changelog](CHANGELOG.md)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

For vulnerability reports, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

MIT — see [LICENSE](LICENSE).
