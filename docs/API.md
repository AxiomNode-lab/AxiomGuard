# AxiomGuard API map

AxiomGuard is split into small modules so applications can import only the surface they need.

## API keys

```ts
import { createApiKey, verifyApiKey } from '@axiomnode-lab/guard/api-keys';

const key = createApiKey({ prefix: 'svc' });
// Store key.digest and key.id. Return key.token once to the caller.

const accepted = verifyApiKey(presentedToken, key.digest);
```

API keys are random opaque credentials. `hashApiKey()` uses SHA-256 intentionally because the generated tokens have high entropy; it is not a password hashing function.

## Webhooks and replay protection

```ts
import {
  MemoryReplayStore,
  verifyFreshHmacWebhook,
  verifyMetaWebhook,
  verifySlackWebhook,
} from '@axiomnode-lab/guard/webhooks';
```

Provider helpers cover GitHub, Meta/WhatsApp, Slack and Stripe signing shapes in addition to generic HMAC verification. The in-memory replay store is suitable for a single process; multi-instance services should use an atomic shared store such as the Redis adapters.

## Browser request policy

```ts
import { evaluateRequestPolicy } from '@axiomnode-lab/guard/request-policy';

const decision = evaluateRequestPolicy({
  method: req.method,
  origin: req.headers.origin ?? null,
  secFetchSite: req.headers['sec-fetch-site'] ?? null,
}, {
  allowedOrigins: ['https://app.example.com'],
});
```

The policy treats Fetch Metadata as the primary browser signal for unsafe methods and uses strict Origin matching as a fallback. It is a CSRF-oriented control, not authentication or authorization.

## Idempotency

```ts
import {
  MemoryIdempotencyStore,
  claimIdempotencyKey,
  createIdempotencyFingerprint,
} from '@axiomnode-lab/guard/idempotency';
```

The idempotency module distinguishes first use, same-request replay and conflicting key reuse. Memory storage is bounded; Redis adapters are available for distributed services. The module stores claim state, not application responses.

## Security headers

```ts
import { createSecurityHeaders } from '@axiomnode-lab/guard/headers';

const headers = createSecurityHeaders({
  contentSecurityPolicy: {
    'default-src': "'self'",
    'object-src': "'none'",
    'base-uri': "'self'",
  },
  hsts: { includeSubDomains: true },
});
```

CSP is application-specific, so AxiomGuard does not invent a default CSP. It validates supplied directive names and rejects CR/LF or semicolon injection inside values.

## Module reference

- `@axiomnode-lab/guard/api-keys` — API key generation, hashing, masking and verification
- `@axiomnode-lab/guard/cookies` — secure cookie serialization and prefix invariants
- `@axiomnode-lab/guard/cors` — strict browser CORS headers
- `@axiomnode-lab/guard/crypto` — secure random tokens, timing-safe comparison, generic HMAC verification
- `@axiomnode-lab/guard/csrf` — signed/session-bound expiring CSRF tokens
- `@axiomnode-lab/guard/env` — typed environment validation
- `@axiomnode-lab/guard/fetch` — guarded redirect-aware outbound Fetch
- `@axiomnode-lab/guard/filesystem` — safe path and filename helpers
- `@axiomnode-lab/guard/headers` — CSP and defensive response headers
- `@axiomnode-lab/guard/idempotency` — request fingerprints and duplicate/conflict claims
- `@axiomnode-lab/guard/logging` — secret and PII masking
- `@axiomnode-lab/guard/presets` — deployment-conscious header presets
- `@axiomnode-lab/guard/rate-limit` — fixed-window limiting and response headers
- `@axiomnode-lab/guard/request-policy` — Fetch Metadata and Origin request filtering
- `@axiomnode-lab/guard/scanner` — programmatic secret scanning and SARIF
- `@axiomnode-lab/guard/web` — URL, redirect, IP and SSRF guardrails
- `@axiomnode-lab/guard/webhooks` — provider-aware signed request verification
- `@axiomnode-lab/guard/adapters/*` — Express, Fastify, Hono and Redis integrations

The root import re-exports the complete public API for convenience. See [API_PROTECTION.md](API_PROTECTION.md) for the request-policy/idempotency failure boundaries.
