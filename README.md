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

AxiomGuard is a compact security toolkit for backend applications that need strong defaults without pulling in a large dependency tree. It brings together common controls for API protection, signed webhooks, SSRF-aware outbound requests, idempotency, rate limiting, secure cookies, CSRF, CORS, defensive headers, environment validation, redaction, filesystem safety and repository secret scanning.

The library is intentionally modular. Use the root package for convenience or import only the subpath that matches the control you need.

## Install

```bash
npm install @axiomnode-lab/guard
```

ES modules are supported directly:

```ts
import { generateApiKey, safeFetch } from '@axiomnode-lab/guard';
```

## Why AxiomGuard

- **Zero runtime dependencies** in the core package and adapters.
- **Framework-neutral primitives** that work without forcing an application architecture.
- **Express, Fastify and Hono adapters** for common HTTP integration points.
- **Provider-aware webhook verification** for GitHub, Stripe, Slack and Meta/WhatsApp flows.
- **Fail-closed security decisions** for ambiguous or unsafe request states where appropriate.
- **Explicit boundaries** for controls that cannot replace network isolation, authorization or durable application state.
- **CLI and programmatic scanning** with text, JSON and SARIF output.

## Core capabilities

| Area | What AxiomGuard provides |
| --- | --- |
| API keys | Secure generation, hashing, verification and masking |
| Webhooks | HMAC verification, freshness checks and replay protection helpers |
| Browser request policy | Fetch Metadata and exact-Origin policy for unsafe requests |
| Idempotency | Key normalization, request fingerprints and bounded/atomic claim stores |
| SSRF protection | URL/DNS validation and redirect-aware guarded fetches |
| Rate limiting | Fixed-window limiter, Redis stores and response-header helpers |
| Cookies | Secure serialization with prefix and attribute validation |
| CSRF | Signed, expiring and optionally session-bound tokens |
| CORS | Strict origin and preflight policy helpers |
| Security headers | CSP, HSTS, cross-origin and defensive header builders |
| Environment | Typed configuration parsing with validation and defaults |
| Logging | Secret redaction and PII masking helpers |
| Filesystem | Traversal-safe paths and filename sanitization |
| Scanner | Secret scanning with baselines, fingerprints, JSON and SARIF |
| Framework adapters | Express, Fastify, Hono and Redis integration layers |

## Browser-facing API protection

AxiomGuard can combine CORS, defensive headers and a browser request policy in one framework adapter. The request policy uses Fetch Metadata when available and falls back to exact Origin validation for unsafe browser requests.

```ts
import { createExpressSecurityMiddleware } from '@axiomnode-lab/guard/adapters/express';

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

`requestPolicy` is opt-in so machine-to-machine APIs are not changed silently. For unsafe browser requests it rejects cross-site traffic, `Origin: null`, untrusted origins and missing-origin traffic unless explicitly allowed.

See [API Protection](docs/API_PROTECTION.md).

## Provider-aware webhooks

Always verify signatures against the exact raw request body received from the provider.

```ts
import {
  MemoryReplayStore,
  verifyGitHubWebhookDelivery,
  verifyMetaWebhook,
  verifySlackWebhook,
  verifyStripeWebhook,
} from '@axiomnode-lab/guard/webhooks';

const replayStore = new MemoryReplayStore();

const metaOk = verifyMetaWebhook(
  rawBody,
  req.headers['x-hub-signature-256'],
  process.env.META_APP_SECRET!,
);

const githubResult = await verifyGitHubWebhookDelivery(
  rawBody,
  req.headers['x-hub-signature-256'],
  process.env.GITHUB_WEBHOOK_SECRET!,
  req.headers['x-github-delivery'],
  { replayStore },
);

const stripeResult = await verifyStripeWebhook(
  rawBody,
  req.headers['stripe-signature'],
  process.env.STRIPE_WEBHOOK_SECRET!,
  { toleranceSeconds: 300, replayStore },
);

const slackResult = await verifySlackWebhook(
  rawBody,
  req.headers['x-slack-signature'],
  req.headers['x-slack-request-timestamp'],
  process.env.SLACK_SIGNING_SECRET!,
  { toleranceSeconds: 300, replayStore },
);
```

For multi-instance services, use a shared replay store such as Redis rather than process-local memory.

## Idempotency claims

Bind an idempotency key to the request semantics that first claimed it. Reusing the same key with the same fingerprint is a replay; reusing it with different semantics is a conflict.

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
  { store, ttlMs: 86_400_000 },
);
```

The memory store is bounded. Redis adapters provide atomic claims for distributed services.

AxiomGuard stores the request claim, not your application response or database transaction. Full response replay still belongs in durable application-specific storage.

## Guarded outbound requests

`safeFetch()` validates the initial destination and followed redirects, limits redirect depth, applies a total timeout and strips sensitive credentials when a redirect crosses origins.

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
```

For validation without performing a request:

```ts
import { assertSafeResolvedUrl } from '@axiomnode-lab/guard/web';

const target = await assertSafeResolvedUrl(userInput, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
});
```

These helpers reduce common SSRF mistakes, but they do not replace outbound network controls or eliminate DNS rebinding/time-of-check-time-of-use risk. See [Safe Fetch](docs/SAFE_FETCH.md) and [Threat Model](THREAT_MODEL.md).

## Rate limiting

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
```

Use Redis-backed stores for distributed or high-volume deployments.

## Secure cookies and CSRF

```ts
import { serializeCookie } from '@axiomnode-lab/guard/cookies';
import { createCsrfToken, verifyCsrfToken } from '@axiomnode-lab/guard/csrf';

const cookie = serializeCookie('__Host-session', sessionToken, {
  sameSite: 'Lax',
  maxAge: 3600,
});

const csrf = createCsrfToken(process.env.CSRF_SECRET!, {
  sessionId: session.id,
});

const csrfOk = verifyCsrfToken(csrf, process.env.CSRF_SECRET!, {
  sessionId: session.id,
  maxAgeSeconds: 7200,
});
```

Cookie prefix, `Secure`, `SameSite`, partitioned-cookie and related invariants are validated instead of emitting contradictory combinations.

## Environment validation and redaction

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

Redaction supports key heuristics, credential patterns and explicit wildcard paths without mutating the source object.

## Secret scanner

The `axiomguard` CLI scans repositories for common secret patterns without printing matched credential values.

```bash
axiomguard scan .
axiomguard scan . --json
axiomguard scan . --sarif --output axiomguard.sarif
axiomguard scan . --write-baseline .axiomguard-baseline.json
```

Programmatic use:

```ts
import { findingsToSarif, scanSecrets } from '@axiomnode-lab/guard/scanner';

const findings = await scanSecrets('.');
const sarif = findingsToSarif(findings);
```

See [Scanner](docs/SCANNER.md) and [GitHub Action](docs/GITHUB_ACTION.md).

## Framework adapters

AxiomGuard exposes focused adapters rather than taking ownership of your application lifecycle:

```ts
import { createExpressSecurityMiddleware } from '@axiomnode-lab/guard/adapters/express';
import { createFastifySecurityPlugin } from '@axiomnode-lab/guard/adapters/fastify';
import { createHonoSecurityMiddleware } from '@axiomnode-lab/guard/adapters/hono';
```

Redis adapters are available for replay protection, rate limiting and idempotency state.

See [Adapters](docs/ADAPTERS.md).

## Module map

| Import | Purpose |
| --- | --- |
| `@axiomnode-lab/guard/api-keys` | API key primitives |
| `@axiomnode-lab/guard/webhooks` | Generic and provider-specific webhook verification |
| `@axiomnode-lab/guard/request-policy` | Browser request policy |
| `@axiomnode-lab/guard/idempotency` | Idempotency keys, fingerprints and stores |
| `@axiomnode-lab/guard/cookies` | Secure cookie serialization |
| `@axiomnode-lab/guard/cors` | CORS policy |
| `@axiomnode-lab/guard/csrf` | CSRF tokens |
| `@axiomnode-lab/guard/headers` | Defensive headers and CSP |
| `@axiomnode-lab/guard/presets` | Header presets |
| `@axiomnode-lab/guard/web` | URL and DNS safety checks |
| `@axiomnode-lab/guard/fetch` | Guarded outbound fetches |
| `@axiomnode-lab/guard/rate-limit` | Rate limiting |
| `@axiomnode-lab/guard/logging` | Secret redaction and PII masking |
| `@axiomnode-lab/guard/env` | Environment validation |
| `@axiomnode-lab/guard/filesystem` | Safe paths and filenames |
| `@axiomnode-lab/guard/scanner` | Secret scanner API |
| `@axiomnode-lab/guard/adapters/*` | Framework and Redis adapters |

## Security boundaries

AxiomGuard is a set of security primitives, not a replacement for the rest of your security architecture. In particular, it does not replace:

- authentication or authorization systems
- a WAF or dedicated abuse-prevention platform
- a secrets manager
- password hashing with Argon2, scrypt or bcrypt
- outbound firewalling and cloud metadata protections
- durable transaction/result storage for fully replayable idempotent APIs
- application-specific threat modeling and security review

Read [SECURITY.md](SECURITY.md) for reporting security issues and [THREAT_MODEL.md](THREAT_MODEL.md) for design boundaries.

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
