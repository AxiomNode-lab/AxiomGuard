# Changelog

All notable changes to this project are documented here.

## [0.3.0] - Unreleased

### Added

- Express, Fastify and Hono security adapters without framework runtime dependencies.
- Fixed-window rate-limit primitive with an injectable store contract and in-memory implementation.
- node-redis and ioredis replay-store adapters using atomic `NX` + `PX` claims.
- node-redis and ioredis fixed-window rate-limit stores backed by an atomic Lua script.
- Deployment-conscious `api`, `web`, and `isolated` security-header presets.
- Reusable scanner library API plus SARIF 2.1.0 output.
- CLI `--sarif`, `--output`, and `--no-fail` options.
- Reusable GitHub Action with SARIF and exit-code outputs.
- Optional npmjs release workflow with OIDC/provenance support.
- Dependabot configuration, structured issue forms, PR template, adapter docs and release policy.

### Changed

- Scanner implementation moved from the CLI into `@axiomnode-lab/guard/scanner` for programmatic use.
- Package exports expanded with `/presets`, `/rate-limit`, `/scanner`, and `/adapters/*` entry points.
- Package version advanced to `0.3.0`.
- CI now smoke-tests the repository's own GitHub Action in addition to Node.js 20/22/24 qualification.

## [0.2.0]

### Added

- Provider-aware GitHub and Stripe-style webhook verification.
- Replay protection support for signed Stripe webhook events.
- Secure cookie serialization with `__Host-` / `__Secure-` enforcement, SameSite, Partitioned and Priority options.
- Framework-neutral CORS policy helper with strict HTTP(S) origin validation, credential/wildcard safety, `Origin: null` fail-closed behavior and opt-in Private Network Access.
- HMAC-signed, expiring and optionally session-bound CSRF tokens.
- CSP nonce generation and report-only CSP support.
- Cross-origin and additional defensive HTTP headers.
- Richer environment types, defaults, numeric ranges and allowed values.
- Explicit dot-path and wildcard secret redaction.
- Dedicated `/cookies`, `/cors`, and `/csrf` package exports.
- `RESEARCH.md` with competitive review, rationale and non-goals.
- Node.js 24 CI qualification and coverage execution.

### Fixed

- Environment URL validation no longer falls through into integer parsing.
- Strict TypeScript narrowing for optional COEP configuration.

## [0.1.0]

### Added

- Secret redaction and PII masking helpers.
- Typed environment validation.
- HMAC webhook verification and constant-time comparison helper.
- Cryptographically secure token generation.
- URL/SSRF guardrails with DNS resolution checks.
- Redirect origin allowlisting.
- Safe path and filename utilities.
- Conservative repository secret scanner CLI.
- API-key generation, hashing, verification and masking.
- Fresh webhook verification with replay-store abstraction.
- CSP builder and framework-neutral security headers.
- GitHub Packages and GHCR delivery workflows.
