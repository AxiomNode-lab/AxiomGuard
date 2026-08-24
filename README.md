<div align="center">
  <img src="docs/axiomguard-demo.svg" alt="AxiomGuard terminal demo" width="860" />

  <h1>AxiomGuard</h1>
  <p><strong>Security building blocks for Node.js and TypeScript services.</strong></p>
  <p>Zero runtime dependencies · modular imports · framework adapters · SARIF-ready scanning</p>

  [![CI](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml)
  [![GitHub package](https://img.shields.io/badge/GitHub%20Packages-%40axiomnode--lab%2Fguard-181717?logo=github)](https://github.com/orgs/AxiomNode-lab/packages)
  [![GHCR](https://img.shields.io/badge/GHCR-axiomguard-2496ED?logo=docker&logoColor=white)](https://github.com/orgs/AxiomNode-lab/packages)
  [![Node](https://img.shields.io/badge/Node.js-20%20%7C%2022%20%7C%2024-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
</div>

AxiomGuard collects backend security controls that are easy to rewrite badly and annoying to install as a dozen unrelated packages: API keys, webhook verification, replay protection, secure cookies, CSRF tokens, CORS policy, defensive headers, SSRF-oriented URL checks, rate limiting, environment validation, secret-safe logging, path safety and repository scanning.

It stays intentionally small. Core and adapters have **no runtime npm dependencies**, and security assumptions are documented next to the feature instead of hidden behind a generic “secure by default” claim.

## Install

GitHub Packages:

```ini
# ~/.npmrc
@axiomnode-lab:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN
```

```bash
npm install @axiomnode-lab/guard
```

The repository also contains an npmjs publishing path for public distribution. It remains disabled until the npm scope and trusted publisher are configured; see [docs/RELEASE.md](docs/RELEASE.md).

## Module map

| Import | Purpose |
| --- | --- |
| `/api-keys` | High-entropy API keys, digests, verification and masking |
| `/webhooks` | Generic HMAC, GitHub, Stripe-style signed timestamps and replay stores |
| `/cookies` | Secure cookie serialization and prefix invariants |
| `/cors` | Strict framework-neutral origin/preflight policy |
| `/csrf` | Signed, expiring, optionally session-bound CSRF tokens |
| `/headers` | CSP/nonces, HSTS, cross-origin and defensive headers |
| `/presets` | Explicit `api`, `web`, and `isolated` header presets |
| `/web` | SSRF-oriented URL/DNS checks and redirect allowlists |
| `/rate-limit` | Fixed-window limiter with a pluggable store |
| `/logging` | Key-, pattern- and path-based secret redaction plus PII masking |
| `/env` | Typed environment parsing, defaults, ranges and allowlists |
| `/filesystem` | Traversal-safe paths and filename sanitization |
| `/scanner` | Programmatic secret scanning and SARIF generation |
| `/adapters/*` | Express, Fastify, Hono and Redis integration layers |
| `axiomguard` | CLI scanner |

Use the root export for convenience or subpath imports for a smaller, clearer dependency surface.

## Provider-aware webhooks

```ts
import {
  MemoryReplayStore,
  verifyGitHubWebhook,
  verifyStripeWebhook,
} from '@axiomnode-lab/guard/webhooks';

const githubOk = verifyGitHubWebhook(
  rawBody,
  req.headers['x-hub-signature-256'],
  process.env.GITHUB_WEBHOOK_SECRET!,
);

const stripeResult = await verifyStripeWebhook(
  rawBody,
  req.headers['stripe-signature'],
  process.env.STRIPE_WEBHOOK_SECRET!,
  {
    toleranceSeconds: 300,
    replayStore: new MemoryReplayStore(),
  },
);
```

For multiple service instances, replace `MemoryReplayStore` with a shared store. AxiomGuard includes node-redis and ioredis adapters that use atomic `NX` + `PX` claims.

## Express, Fastify and Hono

Adapters combine AxiomGuard's header and CORS primitives without taking a runtime dependency on the framework.

```ts
import { createExpressSecurityMiddleware } from '@axiomnode-lab/guard/adapters/express';

app.use(createExpressSecurityMiddleware({
  cors: {
    origins: ['https://app.example.com'],
    allowCredentials: true,
    allowMethods: ['GET', 'POST'],
  },
}));
```

Equivalent adapters are available for Fastify and Hono. See [docs/ADAPTERS.md](docs/ADAPTERS.md) for framework and Redis examples.

## Rate limiting

```ts
import {
  MemoryRateLimitStore,
  checkRateLimit,
} from '@axiomnode-lab/guard/rate-limit';

const store = new MemoryRateLimitStore();
const result = await checkRateLimit(`ip:${clientIp}`, {
  limit: 60,
  windowMs: 60_000,
  store,
});

if (!result.allowed) {
  // Return 429; result.retryAfterSeconds tells you when this window resets.
}
```

The memory store is single-process. Shared deployments can use the Redis adapters. Rate limiting is not authentication and should not be the only control against abusive traffic.

## Security-header presets

Presets are opt-in and deployment-conscious. HSTS is not silently enabled because it is a deployment commitment; cross-origin isolation is a separate preset because it can break resources that are not prepared for it.

```ts
import { createPresetSecurityHeaders } from '@axiomnode-lab/guard/presets';

const webHeaders = createPresetSecurityHeaders('web');
const isolatedHeaders = createPresetSecurityHeaders('isolated');
```

## Secure cookies and CSRF

```ts
import { serializeCookie } from '@axiomnode-lab/guard/cookies';
import { createCsrfToken, verifyCsrfToken } from '@axiomnode-lab/guard/csrf';

const cookie = serializeCookie('__Host-session', sessionToken, {
  sameSite: 'Lax',
  maxAge: 3600,
});

const csrf = createCsrfToken(process.env.CSRF_SECRET!, { sessionId: session.id });
const csrfOk = verifyCsrfToken(csrf, process.env.CSRF_SECRET!, {
  sessionId: session.id,
  maxAgeSeconds: 7200,
});
```

Cookie prefix, `SameSite`, `Secure` and partitioned-cookie invariants are validated instead of being emitted in contradictory combinations.

## Environment validation and log redaction

```ts
import { requireEnv } from '@axiomnode-lab/guard/env';
import { redactSecrets } from '@axiomnode-lab/guard/logging';

const env = requireEnv({
  PORT: { type: 'port', default: 3000 },
  API_URL: 'url',
  MODE: { type: 'string', allowed: ['development', 'staging', 'production'] },
});

const safeEvent = redactSecrets(event, {
  paths: ['req.headers.x-api-key', 'users.*.profile'],
});
```

Validated configuration is frozen. Redaction never mutates the source object and supports secret-key heuristics, credential patterns and explicit wildcard paths.

## SSRF-oriented URL checks

```ts
import { assertSafeResolvedUrl } from '@axiomnode-lab/guard/web';

const target = await assertSafeResolvedUrl(userInput, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
});
```

This blocks common localhost/private/link-local/reserved targets at validation time. It does not eliminate DNS rebinding or time-of-check/time-of-use risk. High-risk fetchers still need outbound network policy.

## Scanner: text, JSON and SARIF

```bash
axiomguard scan .
axiomguard scan . --json
axiomguard scan . --sarif --output axiomguard.sarif
```

The scanner reports rule, file and line but never the matched credential value. `--no-fail` is available for audit-only rollouts.

Programmatic use:

```ts
import { findingsToSarif, scanSecrets } from '@axiomnode-lab/guard/scanner';

const findings = await scanSecrets('.');
const sarif = findingsToSarif(findings);
```

## GitHub Action

```yaml
- uses: actions/checkout@v6
- id: axiomguard
  uses: AxiomNode-lab/AxiomGuard@v0.3.0
  with:
    path: .
    fail-on-findings: 'true'
```

The action exposes a SARIF path that can be uploaded with `github/codeql-action/upload-sarif@v4`. Full workflow: [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md).

## Container

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  ghcr.io/axiomnode-lab/axiomguard:edge scan /workspace
```

## Qualification and delivery

Every pull request qualifies Node.js 20, 22 and 24 with type checking, regression tests, Node 24 coverage, package dry-run and a self scan. CI also runs the repository's composite GitHub Action against itself and validates its SARIF output.

Delivery paths:

```text
main
├── @axiomnode-lab/guard → GitHub Packages
└── ghcr.io/axiomnode-lab/axiomguard:edge → GHCR

GitHub Release
├── GHCR semver/latest + SBOM + provenance
└── npmjs publish (only when explicitly enabled/configured)
```

## What AxiomGuard does not replace

- a WAF, secrets manager, identity provider or authorization framework
- Argon2/scrypt/bcrypt password hashing
- egress firewalling or cloud metadata protection
- a dedicated distributed abuse-prevention platform
- a complete SAST or secrets-scanning platform
- a security review of the application using it

The package is useful when those boundaries are acceptable and explicit.

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

Read [RESEARCH.md](RESEARCH.md), [SECURITY.md](SECURITY.md), [docs/ADAPTERS.md](docs/ADAPTERS.md), and [docs/RELEASE.md](docs/RELEASE.md) before changing security-sensitive behavior.

## Contributing

Security-sensitive changes should include positive tests, negative tests and a written failure boundary. See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).
