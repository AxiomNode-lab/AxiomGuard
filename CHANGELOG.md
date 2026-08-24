# Changelog

All notable changes to this project are documented here.

## [0.2.0] - Unreleased

### Added

- Provider-aware GitHub and Stripe-style webhook verification.
- Replay protection support for signed Stripe webhook events.
- Secure cookie serialization with `__Host-` / `__Secure-` enforcement, SameSite, Partitioned and Priority options.
- Framework-neutral CORS policy helper with strict HTTP(S) origin validation, credential/wildcard safety, `Origin: null` fail-closed behavior and opt-in Private Network Access.
- HMAC-signed, expiring and optionally session-bound CSRF tokens.
- CSP nonce generation and report-only CSP support.
- Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, optional COEP, Origin-Agent-Cluster, DNS prefetch control and additional defensive HTTP headers.
- Environment types for number, email, port and JSON, plus defaults, numeric ranges and allowed values.
- Explicit dot-path and single-segment wildcard secret redaction.
- Dedicated `/cookies`, `/cors`, and `/csrf` package exports.
- `RESEARCH.md` documenting the competitive review, security rationale, limitations and deliberate non-goals.
- Node.js 24 CI qualification and coverage execution.

### Changed

- Package version advanced to `0.2.0` for a distinct GitHub Packages release.
- CI and publishing workflows use current `actions/checkout@v6` and `actions/setup-node@v6` JavaScript runtimes.
- README reorganized around the expanded security SDK and provider-specific examples.

### Fixed

- Environment URL validation no longer falls through into integer parsing.
- Strict TypeScript narrowing for optional COEP header configuration.

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
- API-key generation, hashing, verification, and safe display masking.
- Fresh webhook verification with timestamp windows and replay-store abstraction.
- In-memory replay store for single-process services.
- CSP builder and framework-neutral security header helpers.
- Subpath package exports for smaller imports.
- Automatic first-time GitHub Packages publishing when a new version lands on `main`.
- GHCR `edge` images from `main`, with semver/release tags reserved for published releases.
- CI across Node.js 20 and 22.
