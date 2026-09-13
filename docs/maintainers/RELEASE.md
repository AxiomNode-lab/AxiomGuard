# Release and registry policy

AxiomGuard publishes immutable package versions. A version is advanced before source intended for a new package release reaches `main`; published versions are never overwritten with different contents.

## Current public line

Source is at the version in `package.json`. As of 2026-09-13 the last version published to npmjs and tagged on GitHub is `0.6.1`; `0.6.2` and `0.6.3` exist only in this changelog and were never released. `0.7.0` is the next release and must be cut by creating the `v0.7.0` GitHub Release from a qualified `main` commit, which triggers the npmjs (Trusted Publishing), GitHub Packages and GHCR workflows. Verify each artifact independently afterwards (`npm view @axiomnode-lab/guard versions`, `gh release view v0.7.0`, `docker pull ghcr.io/axiomnode-lab/axiomguard:0.7.0`).

`0.6.0` should not be presented as the recommended CLI distribution: its GitHub Packages publish succeeded as a library package, but npm 11 removed its CLI mapping during publish normalization. The corrected immutable distribution of that line is `0.6.1`.

## npmjs

npmjs is the primary public install path because it does not require GitHub Packages authentication:

```bash
npm install @axiomnode-lab/guard
```

The first public npmjs publish was performed interactively with account authentication and 2FA. Normal future releases use npm Trusted Publishing/OIDC rather than a long-lived npm write token.

### Trusted Publishing setup

The Trusted Publisher for `@axiomnode-lab/guard` is configured for GitHub Actions with:

- GitHub organization/user: `AxiomNode-lab`
- Repository: `AxiomGuard`
- Workflow filename: `publish-npmjs.yml`
- Allowed action: `npm publish`

The repository does not require a long-lived `NPM_TOKEN` for normal releases. The npmjs workflow keeps `id-token: write`, uses a Trusted-Publishing-capable npm version, checks whether the exact package version already exists, refuses ambiguous registry/network failures, publishes through OIDC only when the version is absent, and reads a newly published version back after publication. Eligible trusted publishes from a public repository receive npm provenance automatically.

The workflow is intentionally enabled directly on `release.published` and manual `workflow_dispatch` events now that Trusted Publishing is configured. A separate repository variable gate is no longer required.

## GitHub Packages

`@axiomnode-lab/guard` is also published to GitHub Packages. A push to `main` runs qualification, checks whether the exact version exists, and publishes only when an explicit registry 404 confirms that it is absent. Authentication, permission, registry, and network failures are not treated as evidence that a version is missing.

GitHub's npm registry requires authentication for npm clients, including public packages, so GitHub Packages is an additional distribution channel rather than the lowest-friction public install path.

## GHCR

Source changes on `main` publish `ghcr.io/axiomnode-lab/axiomguard:edge` plus a commit-SHA tag. GitHub Releases publish semver tags and `latest`.

The release container workflow is configured with:

- `provenance: mode=max`
- `sbom: true`
- non-root runtime execution

A release tag must exactly match `v${package.json version}` before release container tags are emitted.

## Release qualification

Before a version is eligible for a public GitHub Release, the exact source commit should pass:

- Node.js 20, 22 and 24 qualification on Linux; Node 24 on Windows and macOS
- TypeScript type checking, Biome lint and compile-only type tests
- unit/regression tests
- coverage thresholds on Node 22 and 24
- publint and arethetypeswrong package-shape checks
- real packed-tarball clean-room install
- package root/subpath import and TypeScript declaration checks
- installed `axiomguard` CLI shim execution
- package dry-run
- self secret scan
- real Express/Fastify/Hono integration tests
- real node-redis/ioredis integration tests
- non-root/read-only container smoke
- GitHub Action/SARIF smoke
- repository CodeQL default setup

Published artifacts must then be verified independently. Source version alone is never treated as proof that a registry, release, image, SBOM, or provenance artifact exists.

## Cutting a release

1. Advance `package.json` and `package-lock.json` together (`npm version --no-git-tag-version <x.y.z>`).
2. Add the `## [x.y.z]` entry to `CHANGELOG.md` (CI fails without it) and any migration notes to `UPGRADING.md`.
3. Merge only after required qualification passes (`npm run check`, integration jobs, Windows/macOS jobs).
4. Create a GitHub Release whose tag exactly matches the package version (`gh release create vx.y.z --generate-notes`); `.github/release.yml` groups the notes by label.
5. Let npmjs Trusted Publishing and GHCR release workflows run from the release event.
6. Verify every claimed registry/release artifact independently, including `npm view @axiomnode-lab/guard@x.y.z dist.attestations` for provenance.
7. Update the `uses: AxiomNode-lab/AxiomGuard@vx.y.z` example and the container tag in `docs/GITHUB_ACTION.md`/`README.md`.

## Versioning

AxiomGuard follows semantic versioning in intent:

- patch: bug fixes and security hardening without intended incompatible API removals
- minor: backwards-compatible modules, options, adapters or scanner formats
- major: incompatible API or security-default changes

Security behavior can be compatibility-sensitive even when TypeScript signatures do not change. Release notes must call out changed defaults, state/eviction semantics and failure boundaries.
