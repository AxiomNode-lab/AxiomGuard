# Security Assurance

AxiomGuard is a security SDK, not a complete application security boundary. This document records what is currently verified, what is intentionally out of scope, and what still requires independent evidence.

## Current verification

| Area | Current evidence | Boundary |
| --- | --- | --- |
| Runtime security primitives | Unit and regression tests, TypeScript checks | Application-specific integration remains the caller's responsibility |
| Framework adapters | Express, Fastify, Hono and Fetch integration tests | Framework-specific middleware ordering can still affect behavior |
| Redis stores | CI integration tests against Redis | Deployment topology and Redis availability are external concerns |
| Package surface | Clean-room install, import/require checks, publint and type-shape checks | Registry-side publication is verified by release workflows |
| GitHub Action | Repository action smoke tests, workspace/symlink boundary tests | GitHub-hosted runner behavior remains an external dependency |
| Secret scanner | Regression suite, synthetic positive/negative corpus, self-scan, SARIF validation | Rule-based scanning can have false positives and false negatives; corpus fixtures are synthetic and are not proof of provider-specific completeness |
| SSRF-aware fetch | URL/DNS/redirect/body/timeout regression coverage | Does not eliminate DNS rebinding/TOCTOU; use network egress controls for high-risk workloads |
| Release pipeline | Pinned actions, provenance/version checks, workflow-security regression checks | A third-party security audit has not been completed |

## Security claims

AxiomGuard should be described as providing **security building blocks and defensive guardrails**.

It should not be described as:

- a WAF or firewall;
- a replacement for authentication or authorization;
- a password-hashing system;
- a complete secrets manager;
- complete SSRF prevention;
- DDoS protection;
- a durable transaction/idempotency system;
- a complete SAST or malware scanner.

## Independent assurance

The repository currently has extensive self-review, regression coverage and CI hardening, but **no independent third-party penetration test or security audit is claimed**. Such an audit should be treated as a separate release-readiness milestone rather than implied by the existing test suite.

## 0.7.2 verification priorities

Before publishing 0.7.2, the release candidate should have:

1. consistent package, lockfile and changelog metadata;
2. a green full CI matrix;
3. clean-room package qualification;
4. framework and Redis integration success;
5. container and GitHub Action smoke-test success;
6. a documented scanner evaluation corpus covering every shipped rule with synthetic positives and representative negative cases, plus known limitations;
7. reproducible release provenance and registry read-back verification.

