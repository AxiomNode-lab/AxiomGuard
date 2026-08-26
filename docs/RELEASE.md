# Release and registry policy

AxiomGuard publishes immutable package versions. A version is advanced before source intended for a new package release reaches `main`; published versions are never overwritten with different contents.

## Current public line

The current source/package line is `0.6.1`.

Verified distribution state for 0.6.1:

- GitHub Packages: `@axiomnode-lab/guard@0.6.1` published and read back by the repository workflow.
- npmjs: `@axiomnode-lab/guard@0.6.1` manually bootstrapped as a public package, read back with `npm view`, and installed from `registry.npmjs.org`.
- GHCR edge/commit path: the post-merge container workflow completed successfully.
- GitHub Release/tag: not considered verified until an actual `v0.6.1` release exists and its release-triggered workflows complete.

`0.6.0` should not be presented as the recommended CLI distribution. Its GitHub Packages publish succeeded as a library package, but npm 11 removed its CLI mapping during publish normalization. The corrected immutable distribution is `0.6.1`.

## npmjs

npmjs is the primary public install path because it does not require GitHub Packages authentication:

```bash
npm install @axiomnode-lab/guard
```

The first public npmjs publish was performed interactively with account authentication and 2FA. Normal future releases should use npm Trusted Publishing/OIDC rather than a long-lived npm write token.

### Trusted Publishing setup

After the package exists on npmjs:

1. Open the package settings for `@axiomnode-lab/guard` on npmjs.
2. Add a Trusted Publisher using GitHub Actions with:
   - GitHub organization/user: `AxiomNode-lab`
   - Repository: `AxiomGuard`
   - Workflow filename: `publish-npmjs.yml`
   - Allowed action: `npm publish`
3. In GitHub repository settings create repository variable `NPMJS_PUBLISH=true`.
4. Do not add `NPM_TOKEN` for normal releases.
5. Keep `id-token: write` on the npmjs workflow.

The workflow uses a Trusted-Publishing-capable npm version, checks whether the exact package version already exists, refuses ambiguous registry/network failures, publishes through OIDC, and reads the version back after publication. Eligible trusted publishes from a public repository receive npm provenance automatically.

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

- Node.js 20, 22 and 24 qualification
- TypeScript type checking
- unit/regression tests
- Node 24 coverage
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

## 0.6.1 release completion

The remaining completion sequence for 0.6.1 is:

1. Keep npmjs `@axiomnode-lab/guard@0.6.1` as the public package of record for the 0.6 line.
2. Configure the npm Trusted Publisher for `publish-npmjs.yml`.
3. Set GitHub repository variable `NPMJS_PUBLISH=true`.
4. Create GitHub Release/tag `v0.6.1` from the qualified `main` commit.
5. Confirm the release-triggered npmjs workflow detects 0.6.1 already exists and exits successfully without attempting a divergent republish.
6. Confirm the release-triggered GHCR workflow emits `0.6.1`, `0.6`, and `latest` tags and completes with SBOM/provenance enabled.
7. Verify the immutable GitHub Action reference `AxiomNode-lab/AxiomGuard@v0.6.1` before documenting it as the production example.
8. Update README release wording only after the GitHub Release and release-triggered artifact checks are confirmed.

## Later versions

1. Advance `package.json` and `package-lock.json` together.
2. Update the changelog and release notes.
3. Merge only after required qualification passes.
4. Create a GitHub Release whose tag exactly matches the package version.
5. Let npmjs Trusted Publishing and GHCR release workflows run from the release event.
6. Verify every claimed registry/release artifact independently.

## Versioning

AxiomGuard follows semantic versioning in intent:

- patch: bug fixes and security hardening without intended incompatible API removals
- minor: backwards-compatible modules, options, adapters or scanner formats
- major: incompatible API or security-default changes

Security behavior can be compatibility-sensitive even when TypeScript signatures do not change. Release notes must call out changed defaults, state/eviction semantics and failure boundaries.
