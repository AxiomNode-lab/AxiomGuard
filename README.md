<div align="center">
  <img src="docs/axiomguard-demo.svg" alt="AxiomGuard terminal demo" width="860" />

  <h1>AxiomGuard</h1>
  <p><strong>Security building blocks for Node.js and TypeScript services.</strong></p>
  <p>Zero runtime dependencies · modular imports · guarded outbound fetches · framework adapters · SARIF-ready scanning</p>

  [![CI](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml)
  [![GitHub package](https://img.shields.io/badge/GitHub%20Packages-%40axiomnode--lab%2Fguard-181717?logo=github)](https://github.com/orgs/AxiomNode-lab/packages)
  [![GHCR](https://img.shields.io/badge/GHCR-axiomguard-2496ED?logo=docker&logoColor=white)](https://github.com/orgs/AxiomNode-lab/packages)
  [![Node](https://img.shields.io/badge/Node.js-20%20%7C%2022%20%7C%2024-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
</div>

AxiomGuard collects backend security controls that are easy to rewrite badly and annoying to install as a dozen unrelated packages: API keys, webhook verification, replay protection, secure cookies, CSRF tokens, CORS policy, defensive headers, SSRF-oriented URL checks and outbound fetches, rate limiting, environment validation, secret-safe logging, path safety and repository scanning.

It stays intentionally small. Core and adapters have **no runtime npm dependencies**, and security assumptions are documented next to the feature instead of hidden behind a generic “secure by default” claim.

> **Release status:** the source is being qualified for the `0.5.1` release line. A GitHub Release/tag and the public npmjs package are not considered available until they are independently verified after publication. See [docs/RELEASE.md](docs/RELEASE.md).

## Install

### GitHub Packages

GitHub's npm registry requires authentication, including for public packages. Configure the scope and authenticate with a GitHub token that has `read:packages` before installing:

```ini
# ~/.npmrc
@axiomnode-lab:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN
```

```bash
npm install @axiomnode-lab/guard
```

### npmjs

The intended lowest-friction public install path is npmjs. **Do not assume it is live until the release checklist verifies the registry entry.** Once published and verified, installation will be the normal command without a custom registry:

```bash
npm install @axiomnode-lab/guard
```

Normal npmjs releases are designed to use npm Trusted Publishing/OIDC rather than a long-lived npm write token. See [docs/RELEASE.md](docs/RELEASE.md).

## Module map

| Import | Purpose |
| --- | --- |
| `/api-keys` | High-entropy API keys, digests, verification and masking |
| `/webhooks` | Generic HMAC, GitHub/Stripe verification and replay-store helpers |
| `/cookies` | Secure cookie serialization and prefix invariants |
| `/cors` | Strict framework-neutral origin/preflight policy |
| `/csrf` | Signed, expiring, optionally session-bound CSRF tokens |
| `/headers` | CSP/nonces, HSTS, cross-origin and defensive headers |
| `/presets` | Explicit `api`, `web`, and `isolated` header presets |
| `/web` | SSRF-oriented URL/DNS checks and redirect allowlists |
| `/fetch` | Redirect-aware guarded Fetch API wrapper with per-hop validation |
| `/rate-limit` | Fixed-window limiter, Redis adapters and response-header helpers |
| `/logging` | Key-, pattern- and path-based secret redaction plus PII masking |
| `/env` | Typed environment parsing, validated defaults, ranges and allowlists |
| `/filesystem` | Traversal-safe paths and filename sanitization |
| `/scanner` | Programmatic secret scanning, baselines, fingerprints and SARIF |
| `/adapters/*` | Express, Fastify, Hono and Redis integration layers |
| `axiomguard` | CLI scanner |

Use the root export for convenience or subpath imports for a smaller, clearer dependency surface.

## Provider-aware webhooks

```ts
import {
  MemoryReplayStore,
  verifyGitHubWebhookDelivery,
  verifyStripeWebhook,
} from '@axiomnode-lab/guard/webhooks';

const replayStore = new MemoryReplayStore();

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
  {
    toleranceSeconds: 300,
    replayStore,
  },
);
```

For multiple service instances, replace in-memory replay state with a shared store. AxiomGuard includes node-redis and ioredis adapters that use atomic `NX` + `PX` claims. GitHub delivery replay protection is additive because GitHub's HMAC signature itself does not carry a freshness timestamp.

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

Equivalent adapters are available for Fastify and Hono. CI qualifies the adapters against pinned real framework versions in addition to structural unit tests. See [docs/ADAPTERS.md](docs/ADAPTERS.md).

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

if (!result.allowed) {
  // Return 429 and include the generated Retry-After/RateLimit fields.
}
```

The helper can emit the current IETF draft `RateLimit-Policy`/`RateLimit` fields together with compatibility fields. The memory store is bounded and single-process; sustained high-cardinality traffic can evict old entries, so distributed or high-volume deployments should use the Redis adapters.

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

Defaults are validated against their declared type/range/allowlist instead of bypassing schema constraints. Validated configuration is frozen. Redaction never mutates the source object and supports secret-key heuristics, credential patterns and explicit wildcard paths.

## SSRF-oriented URL checks

```ts
import { assertSafeResolvedUrl } from '@axiomnode-lab/guard/web';

const target = await assertSafeResolvedUrl(userInput, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
});
```

The validator rejects common private, loopback, link-local, multicast, reserved/documentation, IPv4-mapped IPv6 and selected transition forms. It does not eliminate DNS rebinding or time-of-check/time-of-use risk.

## Guarded outbound fetches

`safeFetch()` turns the URL checks into a practical outbound-request primitive. It validates the initial target and every followed redirect, limits redirect depth, applies a total timeout, strips sensitive credentials on cross-origin redirects, and refuses transport-header overrides and unsafe body replay.

```ts
import { safeFetch } from '@axiomnode-lab/guard/fetch';

const response = await safeFetch(userSuppliedUrl, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
  maxRedirects: 2,
  timeoutMs: 5_000,
  headers: { accept: 'application/json' },
});
```

The underlying Fetch implementation can still resolve DNS again when opening the connection, so this is **not** a complete DNS-rebinding/TOCTOU boundary. High-risk fetchers still need outbound network controls. See [docs/SAFE_FETCH.md](docs/SAFE_FETCH.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Scanner: text, JSON and SARIF

```bash
axiomguard scan .
axiomguard scan . --json
axiomguard scan . --sarif --output axiomguard.sarif
axiomguard scan . --write-baseline .axiomguard-baseline.json
```

The scanner reports rule, file, line and a non-secret fingerprint but never the matched credential value. Config files and reviewed baselines allow teams to roll it out without permanently hiding moved/new findings. See [docs/SCANNER.md](docs/SCANNER.md).

Programmatic use:

```ts
import { findingsToSarif, scanSecrets } from '@axiomnode-lab/guard/scanner';

const findings = await scanSecrets('.');
const sarif = findingsToSarif(findings);
```

## GitHub Action

No immutable release tag exists yet, so pre-release evaluation uses `main`:

```yaml
- uses: actions/checkout@v6
- id: axiomguard
  uses: AxiomNode-lab/AxiomGuard@main
  with:
    path: .
    fail-on-findings: 'true'
```

For production, replace `@main` with a published release tag or immutable release commit SHA after the first GitHub Release is verified. The action exposes a SARIF path that can be uploaded with `github/codeql-action/upload-sarif@v4`. Full workflow: [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md).

## Container

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  ghcr.io/axiomnode-lab/axiomguard:edge scan /workspace
```

The image runs the CLI as the non-root `node` user. Release builds are configured for OCI metadata, SBOM and provenance.

## Qualification and delivery

Pull requests qualify Node.js 20, 22 and 24 with type checking, regression tests, Node 24 coverage, a real packed-tarball clean-room install, CLI/type-declaration checks, package dry-run and a self scan. Separate CI jobs exercise real Express/Fastify/Hono lifecycles and node-redis/ioredis against a Redis service. CI also runs the composite GitHub Action against the repository and validates SARIF, while CodeQL provides an additional JavaScript/TypeScript analysis layer.

Delivery paths:

```text
main
├── @axiomnode-lab/guard → GitHub Packages
└── ghcr.io/axiomnode-lab/axiomguard:edge → GHCR

GitHub Release
├── GHCR semver/latest + SBOM + provenance
└── npmjs publish (only after trusted-publisher configuration)
```

Publication is considered successful only after the workflow reads the exact version back from the target registry. Registry/auth/network errors are not treated as proof that a version is missing.

## What AxiomGuard does not replace

- a WAF, secrets manager, identity provider or authorization framework
- Argon2/scrypt/bcrypt password hashing
- egress firewalling, cloud metadata protection, or destination-pinned networking
- a dedicated distributed abuse-prevention platform
- a complete SAST or secrets-scanning platform
- a security review of the application using it

Read [THREAT_MODEL.md](THREAT_MODEL.md) for assets, attacker capabilities, trust boundaries and explicit non-goals.

## Development

```bash
git clone https://github.com/AxiomNode-lab/AxiomGuard.git
cd AxiomGuard
npm ci
npm run typecheck
npm test
npm run test:coverage
npm run test:package
npm pack --dry-run
npm run scan:self
```

Read [RESEARCH.md](RESEARCH.md), [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), [docs/ADAPTERS.md](docs/ADAPTERS.md), [docs/SCANNER.md](docs/SCANNER.md), [docs/SAFE_FETCH.md](docs/SAFE_FETCH.md), and [docs/RELEASE.md](docs/RELEASE.md) before changing security-sensitive behavior.

## Contributing

Security-sensitive changes should include positive tests, negative tests and a written failure boundary. See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).
