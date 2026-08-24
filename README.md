<div align="center">
  <img src="docs/axiomguard-demo.svg" alt="AxiomGuard terminal demo" width="860" />

  <h1>AxiomGuard</h1>
  <p>Small, dependency-light security utilities for Node.js and TypeScript.</p>

  [![CI](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/AxiomNode-lab/AxiomGuard/actions/workflows/ci.yml)
  [![GitHub package](https://img.shields.io/badge/GitHub%20Packages-%40axiomnode--lab%2Fguard-181717?logo=github)](https://github.com/orgs/AxiomNode-lab/packages)
  [![Node](https://img.shields.io/badge/Node.js-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
  [![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
</div>

AxiomGuard started from a repetitive problem: the same handful of security checks kept being rewritten in small services, CLIs, webhooks, and internal tools. Most of them are not large enough to justify a framework, but they are easy to get subtly wrong.

This package keeps those checks in one place and makes their behavior explicit. It currently covers secret-safe logging, environment validation, HMAC webhook verification, URL/SSRF guardrails, filesystem path checks, redirect allowlists, token generation, and a repository secret scanner.

It is intentionally narrow. AxiomGuard is not a WAF, a secrets manager, an antivirus product, or a replacement for a security review.

## Install

AxiomGuard is configured to publish through GitHub Packages. The install command below becomes available after the first tagged release is published.

```ini
# ~/.npmrc
@axiomnode-lab:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN
```

```bash
npm install @axiomnode-lab/guard
```

For local development from the repository:

```bash
git clone https://github.com/AxiomNode-lab/AxiomGuard.git
cd AxiomGuard
npm ci
npm test
```

## Quick example

```ts
import {
  assertSafeResolvedUrl,
  redactSecrets,
  requireEnv,
  secureToken,
  verifyHmacWebhook,
} from '@axiomnode-lab/guard';

const env = requireEnv({
  API_URL: 'url',
  PORT: 'integer',
  JWT_SECRET: { type: 'string', minLength: 32 },
});

console.log(redactSecrets({
  user: 'demo',
  apiKey: env.JWT_SECRET,
}));

const requestId = secureToken(18);
const target = await assertSafeResolvedUrl(env.API_URL, {
  protocols: ['https:'],
});
```

## What is included

| Area | Utility | Purpose |
| --- | --- | --- |
| Logging | `redactSecrets()` | Recursively masks secret-bearing fields and common token formats |
| Logging | `maskPII()` | Masks email, phone-like values, and IPv4 strings |
| Config | `validateEnv()` / `requireEnv()` | Parses and validates environment variables against a small schema |
| Crypto | `secureToken()` | Generates cryptographically secure Base64URL tokens |
| Crypto | `constantTimeCompare()` | Timing-safe comparison helper for secret values |
| Webhooks | `verifyHmacWebhook()` | Verifies HMAC signatures against the exact raw request payload |
| Web | `assertSafeUrl()` | Rejects unsupported schemes and blocked literal IP addresses |
| Web | `assertSafeResolvedUrl()` | Resolves hostnames and rejects private, loopback, and link-local targets |
| Web | `validateRedirect()` | Enforces an exact-origin redirect allowlist |
| Filesystem | `safePath()` | Prevents traversal outside an allowed base directory |
| Filesystem | `sanitizeFilename()` | Removes path components and unsafe filename characters |
| CLI | `axiomguard scan` | Finds high-confidence secret patterns without printing the matched value |

## Webhook verification

Verify the raw request bytes before parsing JSON. Re-serializing parsed JSON changes the byte sequence and can make a valid signature fail.

```ts
const valid = verifyHmacWebhook(
  rawBody,
  req.headers['x-hub-signature-256'],
  process.env.WEBHOOK_SECRET!,
  { algorithm: 'sha256', prefix: 'sha256=' },
);

if (!valid) {
  throw new Error('Invalid webhook signature');
}
```

## URL and SSRF checks

```ts
const url = await assertSafeResolvedUrl(userInput, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
});
```

The resolver rejects addresses in common private, loopback, and link-local ranges at validation time. That is useful application-side validation, but it does not eliminate DNS rebinding or time-of-check/time-of-use problems. High-risk services should also enforce outbound network policy and validate redirect targets again before following them.

## Safe filesystem paths

```ts
const filePath = safePath('/srv/app/uploads', userSuppliedPath);
const fileName = sanitizeFilename(originalName);
```

`safePath()` resolves the candidate path and verifies that it stays under the configured base directory instead of relying on string-prefix checks.

## Repository secret scanner

The scanner is deliberately conservative. Findings contain the rule name, file path, and line number; the matched secret itself is never printed.

```bash
npx axiomguard scan .
```

Container usage after the first release:

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  ghcr.io/axiomnode-lab/axiomguard:latest scan /workspace
```

Exit codes:

- `0` — no finding
- `1` — potential secret found
- `2` — usage or runtime error

## Development

```bash
npm ci
npm run typecheck
npm test
npm run scan:self
npm pack --dry-run
```

CI currently runs against Node.js 20 and 22.

## Releases and packages

Releases are versioned from `package.json`. A release tag must match the package version, for example `v0.1.0` for version `0.1.0`.

Publishing workflows then build and publish:

```text
@axiomnode-lab/guard
└── npm.pkg.github.com

ghcr.io/axiomnode-lab/axiomguard
└── OCI image + provenance + SBOM
```

The workflows use the repository-scoped `GITHUB_TOKEN`; no long-lived registry token is stored in the repository.

## Security notes

Security-sensitive helpers are designed to fail closed where practical, but each utility has a boundary. For example, URL validation cannot provide network isolation, redaction cannot make arbitrary logs safe by itself, and pattern-based secret scanning will always involve false positives and false negatives.

Please read [SECURITY.md](SECURITY.md) before using AxiomGuard in a sensitive path. Vulnerability reports should follow the private reporting guidance there rather than being posted publicly.

## Contributing

Bug reports and focused pull requests are welcome. If you are adding a security check, include both positive and negative tests so the expected boundary is obvious.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).
