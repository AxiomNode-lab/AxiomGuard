<div align="center">
  <img src="docs/axiomguard-demo.svg" alt="AxiomGuard terminal demo" width="860" />

  <h1>AxiomGuard</h1>
  <p><strong>Practical security primitives for Node.js and TypeScript services.</strong></p>
  <p>Zero runtime dependencies. Small modules. Explicit failure modes.</p>

  [![CI](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml)
  [![GitHub package](https://img.shields.io/badge/GitHub%20Packages-%40axiomnode--lab%2Fguard-181717?logo=github)](https://github.com/orgs/AxiomNode-lab/packages)
  [![Container](https://img.shields.io/badge/GHCR-axiomguard-2496ED?logo=docker&logoColor=white)](https://github.com/orgs/AxiomNode-lab/packages)
  [![Node](https://img.shields.io/badge/Node.js-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
  [![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
</div>

AxiomGuard exists for the security work that keeps getting rewritten in every backend: validating webhook signatures, stopping simple replay attacks, generating API keys, redacting credentials before they reach logs, checking outbound URLs before a fetch, keeping user paths inside an allowed directory, and setting defensive HTTP headers without pulling in a large framework.

The project stays intentionally small. It is a library and CLI, not a WAF, identity provider, secrets manager, antivirus product, or substitute for network policy and security review.

## What you get

| Module | What it handles |
| --- | --- |
| API keys | Generate opaque keys, store one-way digests, verify presented keys, safe display masking |
| Webhooks | HMAC verification, timestamp freshness windows, replay protection interface |
| Web security | SSRF-oriented URL checks, DNS resolution checks, redirect allowlists, private IP detection |
| HTTP headers | CSP construction, header-injection checks, HSTS and conservative security headers |
| Logging | Recursive secret redaction and PII masking without mutating the source object |
| Environment | Typed environment validation for strings, integers, booleans, URLs and required values |
| Crypto | Secure random tokens and timing-safe comparison helpers |
| Filesystem | Path traversal prevention and filename sanitization |
| CLI | Repository secret scanning that reports locations without printing the matched secret |

There are **no runtime npm dependencies**. AxiomGuard uses Node's standard library and exposes subpath imports so a service can import only the part it needs.

## Install

GitHub Packages registry configuration:

```ini
# ~/.npmrc
@axiomnode-lab:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN
```

```bash
npm install @axiomnode-lab/guard
```

Or work directly from the repository:

```bash
git clone https://github.com/AxiomNode-lab/AxiomGuard.git
cd AxiomGuard
npm ci
npm test
```

## Package layout

Use the root export when convenience matters:

```ts
import {
  createApiKey,
  redactSecrets,
  verifyFreshHmacWebhook,
  assertSafeResolvedUrl,
} from '@axiomnode-lab/guard';
```

Or import one module directly:

```ts
import { createApiKey, verifyApiKey } from '@axiomnode-lab/guard/api-keys';
import { verifyFreshHmacWebhook } from '@axiomnode-lab/guard/webhooks';
import { createSecurityHeaders } from '@axiomnode-lab/guard/headers';
import { assertSafeResolvedUrl } from '@axiomnode-lab/guard/web';
```

Available subpaths:

```text
@axiomnode-lab/guard
├── /api-keys
├── /crypto
├── /env
├── /filesystem
├── /headers
├── /logging
├── /web
└── /webhooks
```

## API keys without storing plaintext credentials

Generate an opaque credential once, return the token to the caller, and store only the digest and identifier.

```ts
import {
  createApiKey,
  maskApiKey,
  verifyApiKey,
} from '@axiomnode-lab/guard/api-keys';

const created = createApiKey({ prefix: 'svc' });

await db.apiKeys.insert({
  id: created.id,
  digest: created.digest,
  fingerprint: created.fingerprint,
});

// Return this once. Do not log it.
console.log(created.token);

const accepted = verifyApiKey(presentedToken, created.digest);
console.log(maskApiKey(presentedToken)); // svc_...Ab9x
```

The digest uses SHA-256 because generated API keys have high random entropy. It is deliberately **not** presented as a password hashing function.

## Webhook verification + replay protection

Signature verification by itself does not stop a previously valid request from being replayed. AxiomGuard can combine the HMAC check with a provider timestamp and an atomic replay claim.

```ts
import {
  MemoryReplayStore,
  verifyFreshHmacWebhook,
} from '@axiomnode-lab/guard/webhooks';

const replayStore = new MemoryReplayStore();

const result = await verifyFreshHmacWebhook(
  {
    payload: rawBody,
    signature: req.headers['x-signature'],
    secret: process.env.WEBHOOK_SECRET!,
    timestamp: req.headers['x-timestamp']!,
  },
  {
    replayStore,
    toleranceSeconds: 300,
  },
);

if (!result.ok) {
  throw new Error(`Webhook rejected: ${result.reason}`);
}
```

`MemoryReplayStore` is for a single Node process. Multi-instance services should implement the small `ReplayStore` contract using Redis, a transactional database, or another store that can atomically claim a key.

## Outbound URL / SSRF guardrails

```ts
import { assertSafeResolvedUrl } from '@axiomnode-lab/guard/web';

const target = await assertSafeResolvedUrl(userInput, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
});

const response = await fetch(target);
```

The resolver blocks common private, loopback and link-local targets at validation time. That is useful application-side defense, but it does not replace egress firewall rules and it cannot eliminate every DNS rebinding or time-of-check/time-of-use problem.

For high-risk fetchers, apply both application validation and network-level outbound restrictions.

## Security headers and CSP

AxiomGuard does not guess an application CSP. You provide the policy; the builder validates directive names and rejects obvious header injection.

```ts
import { createSecurityHeaders } from '@axiomnode-lab/guard/headers';

const headers = createSecurityHeaders({
  contentSecurityPolicy: {
    'default-src': "'self'",
    'object-src': "'none'",
    'base-uri': "'self'",
    'script-src': ["'self'", 'https://cdn.example.com'],
  },
  hsts: {
    includeSubDomains: true,
  },
});
```

The default set includes `X-Content-Type-Options`, a strict referrer policy, frame protection and a conservative permissions policy. HSTS and CSP are opt-in because they depend on deployment and application behavior.

## Secret-safe logging

```ts
import { maskPII, redactSecrets } from '@axiomnode-lab/guard/logging';

const event = redactSecrets({
  user: 'demo',
  authorization: 'Bearer very-sensitive-value',
  nested: {
    apiKey: 'secret-value',
  },
});

console.log(event);
console.log(maskPII('user@example.com connected from 192.168.10.12'));
```

Redaction is a last line of defense, not permission to log arbitrary request bodies. Prefer not collecting sensitive data in the first place.

## Typed environment validation

```ts
import { requireEnv } from '@axiomnode-lab/guard/env';

const env = requireEnv({
  API_URL: 'url',
  PORT: 'integer',
  ENABLED: 'boolean',
  JWT_SECRET: { type: 'string', minLength: 32 },
});
```

Invalid or missing required values fail early instead of surfacing later as ambiguous runtime errors.

## Safe paths and filenames

```ts
import { safePath, sanitizeFilename } from '@axiomnode-lab/guard/filesystem';

const destination = safePath('/srv/app/uploads', userSuppliedPath);
const filename = sanitizeFilename(originalFilename);
```

`safePath()` resolves the candidate and verifies that it remains under the configured base directory instead of relying on a string-prefix check.

## Repository secret scanner

The CLI is intentionally conservative: it reports the rule, file and line number, but does not print the matched credential.

```bash
npx axiomguard scan .
```

JSON output:

```bash
npx axiomguard scan . --json
```

Container usage:

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  ghcr.io/axiomnode-lab/axiomguard:edge scan /workspace
```

Exit codes:

- `0` — no high-confidence finding
- `1` — one or more potential secrets found
- `2` — CLI usage or runtime failure

## CI and package delivery

Every pull request runs the same basic qualification on Node.js 20 and 22:

```text
npm ci
  ↓
typecheck
  ↓
test suite
  ↓
npm pack --dry-run
  ↓
AxiomGuard self-scan
```

Package delivery is automated:

```text
main
├── @axiomnode-lab/guard → GitHub npm Packages
└── ghcr.io/axiomnode-lab/axiomguard:edge → GHCR

GitHub Release vX.Y.Z
├── npm package version check
└── GHCR semver + latest tags, provenance and SBOM
```

The npm workflow first checks whether the current version already exists. A normal documentation or source push will not continuously attempt to overwrite an immutable published version.

Both registries use the repository-scoped `GITHUB_TOKEN`; the repository does not need a long-lived package token.

## Project boundaries

AxiomGuard tries to make small security controls predictable, but the limits matter:

- URL checks do not replace egress network controls.
- Replay protection needs a shared atomic store when multiple processes serve traffic.
- In-memory state disappears on restart.
- Redaction rules cannot guarantee that arbitrary logs are safe.
- Pattern-based secret scanners always have both false positives and false negatives.
- Security headers can break an application if their policy does not match the deployment.
- API-key hashing assumes AxiomGuard-generated, high-entropy random credentials; passwords need a dedicated password hashing scheme.

These boundaries are documented because a security helper that hides its assumptions is harder to use safely.

## Development

```bash
npm ci
npm run typecheck
npm test
npm run scan:self
npm pack --dry-run
```

For the module map and shorter examples, see [docs/API.md](docs/API.md).

## Contributing

Focused bug reports and pull requests are welcome. Security-sensitive changes should include both positive and negative tests so the expected boundary is visible in code.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).
