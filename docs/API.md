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
} from '@axiomnode-lab/guard/webhooks';

const result = await verifyFreshHmacWebhook(
  { payload: rawBody, signature, secret, timestamp },
  { replayStore: new MemoryReplayStore(), toleranceSeconds: 300 },
);
```

The in-memory replay store is suitable for a single process. Multi-instance services should implement the `ReplayStore` interface with an atomic store such as Redis or a transactional database.

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

CSP is application-specific, so AxiomGuard does not invent a default CSP. It validates the supplied directive names and rejects CR/LF or semicolon injection inside values.

## Existing modules

- `@axiomnode-lab/guard/crypto` — secure random tokens, timing-safe comparison, HMAC verification
- `@axiomnode-lab/guard/env` — typed environment validation
- `@axiomnode-lab/guard/filesystem` — safe path and filename helpers
- `@axiomnode-lab/guard/logging` — secret and PII masking
- `@axiomnode-lab/guard/web` — URL, redirect, IP, and SSRF guardrails

The root import re-exports the complete public API for convenience.
