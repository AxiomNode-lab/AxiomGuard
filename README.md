<div align="center">
  <img src="docs/axiomguard-demo.svg" alt="AxiomGuard terminal demo" width="860" />

  <h1>AxiomGuard</h1>
  <p><strong>Security building blocks for Node.js and TypeScript services.</strong></p>
  <p>Zero runtime dependencies · modular imports · explicit failure modes</p>

  [![CI](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml)
  [![GitHub package](https://img.shields.io/badge/GitHub%20Packages-%40axiomnode--lab%2Fguard-181717?logo=github)](https://github.com/orgs/AxiomNode-lab/packages)
  [![GHCR](https://img.shields.io/badge/GHCR-axiomguard-2496ED?logo=docker&logoColor=white)](https://github.com/orgs/AxiomNode-lab/packages)
  [![Node](https://img.shields.io/badge/Node.js-20%20%7C%2022%20%7C%2024-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
</div>

AxiomGuard collects the small security controls that backend projects tend to rewrite over and over: API keys, webhook signatures, replay protection, secure cookies, CSRF tokens, CORS decisions, defensive headers, URL/SSRF checks, environment validation, log redaction, path safety and repository secret scanning.

It is intentionally not a framework. The package stays small enough to audit, uses Node's standard library, and keeps the boundaries of each helper visible.

## Why this exists

Dedicated projects such as Helmet, Envalid and provider SDKs are excellent when you need their complete feature set. AxiomGuard targets a different use case: services that want a compact, framework-neutral set of security primitives without installing a stack of unrelated runtime dependencies.

The 0.2 line was shaped by a review of mature Node tooling plus GitHub, Stripe and OWASP guidance. The resulting gap analysis is kept in [RESEARCH.md](RESEARCH.md) instead of being hidden in release notes.

## Modules

| Import | Purpose |
| --- | --- |
| `@axiomnode-lab/guard/api-keys` | Generate high-entropy API keys, one-way digests, verification and masking |
| `@axiomnode-lab/guard/webhooks` | Generic HMAC, GitHub SHA-256, Stripe-style signed timestamps and replay stores |
| `@axiomnode-lab/guard/headers` | CSP, nonces, report-only mode, HSTS, cross-origin and legacy hardening headers |
| `@axiomnode-lab/guard/cookies` | Secure cookie serialization and `__Host-` / `__Secure-` invariants |
| `@axiomnode-lab/guard/cors` | Framework-neutral origin policy and preflight headers |
| `@axiomnode-lab/guard/csrf` | Signed, expiring, optionally session-bound CSRF tokens |
| `@axiomnode-lab/guard/web` | SSRF-oriented URL checks, DNS resolution and redirect allowlists |
| `@axiomnode-lab/guard/logging` | Key-, pattern- and path-based secret redaction plus PII masking |
| `@axiomnode-lab/guard/env` | Typed environment parsing, defaults, ranges and allowlists |
| `@axiomnode-lab/guard/filesystem` | Traversal-safe paths and filename sanitization |
| `@axiomnode-lab/guard/crypto` | Secure random tokens and timing-safe comparisons |
| `axiomguard` CLI | Conservative repository secret scanner |

There are **no runtime npm dependencies**.

## Install

GitHub Packages configuration:

```ini
# ~/.npmrc
@axiomnode-lab:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN
```

```bash
npm install @axiomnode-lab/guard
```

Use the root package for convenience:

```ts
import {
  createApiKey,
  createSecurityHeaders,
  redactSecrets,
  verifyGitHubWebhook,
} from '@axiomnode-lab/guard';
```

Or import only the module you need:

```ts
import { verifyStripeWebhook } from '@axiomnode-lab/guard/webhooks';
import { serializeCookie } from '@axiomnode-lab/guard/cookies';
import { createCorsHeaders } from '@axiomnode-lab/guard/cors';
```

## API keys

Generate the credential once and store only its digest.

```ts
import { createApiKey, verifyApiKey } from '@axiomnode-lab/guard/api-keys';

const created = createApiKey({ prefix: 'svc' });

await db.apiKeys.insert({
  id: created.id,
  digest: created.digest,
  fingerprint: created.fingerprint,
});

// Return created.token once. Do not log it.
const accepted = verifyApiKey(presentedToken, created.digest);
```

SHA-256 is appropriate here because the generated token has high random entropy. This helper is not a password-hashing API.

## Provider-aware webhooks

### GitHub

```ts
import { verifyGitHubWebhook } from '@axiomnode-lab/guard/webhooks';

const valid = verifyGitHubWebhook(
  rawBody,
  req.headers['x-hub-signature-256'],
  process.env.WEBHOOK_SECRET!,
);
```

The raw payload is verified with HMAC-SHA256 and the `sha256=` signature format.

### Stripe-style signed timestamps

```ts
import {
  MemoryReplayStore,
  verifyStripeWebhook,
} from '@axiomnode-lab/guard/webhooks';

const result = await verifyStripeWebhook(
  rawBody,
  req.headers['stripe-signature'],
  process.env.STRIPE_WEBHOOK_SECRET!,
  {
    toleranceSeconds: 300,
    replayStore: new MemoryReplayStore(),
  },
);
```

The timestamp is part of the signed message, so freshness cannot be changed without invalidating the signature. A shared deployment should replace `MemoryReplayStore` with a Redis/database implementation of the small `ReplayStore` interface.

## Secure cookies

```ts
import { serializeCookie } from '@axiomnode-lab/guard/cookies';

const cookie = serializeCookie('__Host-session', sessionToken, {
  sameSite: 'Lax',
  maxAge: 3600,
});
```

Defaults are `Secure`, `HttpOnly`, `Path=/`, and `SameSite=Lax`. The serializer rejects invalid combinations such as `SameSite=None` without `Secure`, a `Domain` on `__Host-` cookies, or partitioned cookies without `Secure`.

## CORS policy

```ts
import { createCorsHeaders } from '@axiomnode-lab/guard/cors';

const cors = createCorsHeaders(req.headers.origin, {
  origins: ['https://app.example.com'],
  allowCredentials: true,
  allowMethods: ['GET', 'POST'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
});
```

A wildcard origin combined with credentials is rejected rather than silently producing an unsafe policy.

## CSRF tokens

```ts
import { createCsrfToken, verifyCsrfToken } from '@axiomnode-lab/guard/csrf';

const token = createCsrfToken(process.env.CSRF_SECRET!, {
  sessionId: session.id,
});

const valid = verifyCsrfToken(token, process.env.CSRF_SECRET!, {
  sessionId: session.id,
  maxAgeSeconds: 7200,
});
```

Tokens are HMAC-signed, versioned, expiring and can be bound to a session identifier without placing the session identifier itself in the token.

## Security headers and CSP

```ts
import {
  createCspNonce,
  createSecurityHeaders,
} from '@axiomnode-lab/guard/headers';

const nonce = createCspNonce();

const headers = createSecurityHeaders({
  contentSecurityPolicy: {
    'default-src': ["'self'"],
    'script-src': ["'self'", `'nonce-${nonce}'`],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
  },
  hsts: { includeSubDomains: true },
});
```

The helper also supports report-only CSP, COOP, CORP, optional COEP, Origin-Agent-Cluster, Permissions-Policy, DNS prefetch control and legacy defensive headers. CSP remains application-specific; AxiomGuard does not invent a policy that may break your site.

## Environment validation

```ts
import { requireEnv } from '@axiomnode-lab/guard/env';

const env = requireEnv({
  PORT: { type: 'port', default: 3000 },
  API_URL: 'url',
  RATE: { type: 'number', min: 0, max: 1 },
  ADMIN_EMAIL: 'email',
  FLAGS: { type: 'json', required: false, default: {} },
  MODE: { type: 'string', allowed: ['development', 'staging', 'production'] },
});
```

Validated output is returned as a frozen object. Missing or malformed required values fail early.

## Secret-safe logging

```ts
import { redactSecrets } from '@axiomnode-lab/guard/logging';

const safeEvent = redactSecrets(event, {
  paths: [
    'req.headers.x-api-key',
    'users.*.profile',
  ],
});
```

Redaction combines common secret-key names, high-confidence credential patterns, explicit paths and single-segment wildcards. It never mutates the original value.

## SSRF-oriented URL checks

```ts
import { assertSafeResolvedUrl } from '@axiomnode-lab/guard/web';

const target = await assertSafeResolvedUrl(userInput, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
});
```

The URL layer rejects credentials, localhost, blocked literal addresses and resolved private/link-local/multicast/reserved addresses. Prefer explicit host allowlists when possible. High-risk systems still need outbound network policy because application validation cannot eliminate DNS rebinding and TOCTOU risk by itself.

## Repository scanner

```bash
npx axiomguard scan .
npx axiomguard scan . --json
```

The scanner reports rule, file and line only. It intentionally does not echo a detected credential value.

Container usage:

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  ghcr.io/axiomnode-lab/axiomguard:edge scan /workspace
```

Exit codes are `0` for no finding, `1` for potential findings, and `2` for CLI/runtime errors.

## Qualification

Pull requests are tested on Node.js 20, 22 and 24:

```text
npm ci
  ↓
typecheck
  ↓
unit/regression tests
  ↓
coverage run on Node 24
  ↓
npm pack --dry-run
  ↓
AxiomGuard self-scan
```

The npm package and GHCR image are built from `main`. The package workflow checks whether the version already exists before publishing; container releases include provenance and SBOM metadata.

## What AxiomGuard does not replace

- Helmet when you want a complete Express-focused header middleware stack.
- A secrets manager or key-management service.
- Argon2/scrypt/bcrypt password hashing libraries.
- A distributed rate limiter or authorization framework.
- Egress firewalling and cloud metadata protections.
- A full SAST/secrets-scanning platform.
- A security review of your application.

Keeping these boundaries explicit is part of the project design.

## Development

```bash
git clone https://github.com/AxiomNode-lab/AxiomGuard.git
cd AxiomGuard
npm ci
npm run typecheck
npm test
npm run test:coverage
npm pack --dry-run
npm run scan:self
```

Read [RESEARCH.md](RESEARCH.md) for the competitive gap analysis and [SECURITY.md](SECURITY.md) for vulnerability reporting and security assumptions.

## Contributing

Focused changes are welcome. New security-sensitive behavior should include positive tests, negative tests and a written failure boundary.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).
