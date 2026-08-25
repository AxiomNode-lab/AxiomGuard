# Changelog

All notable changes to this project are documented here.

## [0.5.0] - 2026-08-25

### Added

- `safeFetch()` for guarded outbound HTTP(S) requests with initial and per-redirect URL/DNS validation.
- Cross-origin redirect stripping for `Authorization`, `Cookie`, and `Proxy-Authorization` by default.
- Total redirect-chain timeout and bounded redirect depth for guarded fetches.
- Fail-closed rejection of transport authority/framing header overrides and request-body replay across preserving redirects.
- `createRateLimitHeaders()` for current IETF draft `RateLimit-Policy`/`RateLimit` fields, compatibility fields, and `Retry-After` on blocked requests.
- Package subpath import smoke tests covering every documented export.
- `docs/SAFE_FETCH.md` with explicit SSRF/DNS-rebinding boundaries.
- Manual `workflow_dispatch` support for GitHub Packages publishing and post-publish read-back verification.

### Changed

- `RateLimitResult` now includes the configured `windowMs` so response policies can be rendered without duplicating configuration.
- GitHub Packages publish qualification now includes `npm pack --dry-run` and clearer first-package diagnostics.
- Package version advanced to `0.5.0` and added the `/fetch` export.
- npmjs publishing now uses tokenless Trusted Publishing for normal releases, verifies the package version after publish, and fails closed on release-tag/version mismatches.
- Container and GitHub Packages release paths reject mismatched release tags before publication.

## [0.4.0]

### Added

- Deterministic non-secret scanner fingerprints.
- `.axiomguard.json` configuration with narrow file/directory exclusions.
- Reviewed baseline files and `--write-baseline` support.
- CLI `--config`, `--baseline`, and `--github-annotations` options.
- SARIF partial fingerprints for result correlation without credential values.
- GitHub Action inputs for config, baseline, and workflow annotations.
- Scanner regression coverage for baselines, globs, configuration validation, and SARIF secrecy.
- `docs/SCANNER.md` and `docs/PACKAGES.md`.

### Changed

- GitHub Packages workflow verifies a new package version after publishing.
- Container image metadata explicitly identifies the source repository.

## [0.3.0]

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
- CI smoke-tests the repository's own GitHub Action in addition to Node.js 20/22/24 qualification.

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
