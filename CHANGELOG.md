# Changelog

All notable changes to this project will be documented here.

## [0.1.0] - Unreleased

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
- In-memory atomic replay store for single-process services.
- CSP builder and framework-neutral security header helpers.
- Subpath package exports for smaller imports.
- Automatic first-time GitHub Packages publishing when a new version lands on `main`.
- GHCR `edge` images from `main`, with release tags reserved for published releases.
- GitHub Packages and GHCR release workflows.
- CI across Node.js 20 and 22.
