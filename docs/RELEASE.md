# Release and registry policy

AxiomGuard publishes immutable package versions. A version is advanced before source intended for a new package release reaches `main`; published versions are never overwritten with different contents.

## GitHub Packages

`@axiomnode-lab/guard` is configured for GitHub Packages. A push to `main` runs qualification, checks whether the exact version exists, and publishes only when an explicit registry 404 confirms that it is absent. Authentication, permission, registry, and network failures are not treated as evidence that a version is missing. The workflow can also be run manually for retry/diagnostics and reads a newly published version back before reporting success.

GitHub's npm registry requires authentication even for public packages. It is an additional distribution channel, not the lowest-friction public install path.

## GHCR

Source changes on `main` publish `ghcr.io/axiomnode-lab/axiomguard:edge` plus a commit-SHA tag. GitHub Releases publish semver tags and `latest`, with SBOM and provenance enabled in the container build.

A release tag must exactly match `v${package.json version}` before release container tags are emitted.

## npmjs: first public publish

The public npmjs package must exist before its Trusted Publisher can be attached. For the first public release only:

1. Create or verify an npm organization named `axiomnode-lab`. The organization name owns the `@axiomnode-lab` scope.
2. Ensure the publishing npm account is a member with permission to publish public packages and has 2FA enabled. The bootstrap procedure prefers interactive 2FA rather than a long-lived automation token.
3. Use the exact qualified release commit. Run `npm ci`, `npm run typecheck`, `npm test`, `npm run test:package`, and `npm pack --dry-run`.
4. Authenticate interactively to `https://registry.npmjs.org`.
5. Publish exactly once with `npm publish --registry=https://registry.npmjs.org --access public` and complete the npm 2FA challenge.
6. Verify the exact package version with `npm view @axiomnode-lab/guard@<version> version --registry=https://registry.npmjs.org`.
7. From a separate clean directory with no custom npm scope registry, install that exact version and smoke-test root plus subpath imports.

Do not create a long-lived automation token just to bootstrap Trusted Publishing. Never paste an npm token or OTP into an issue, pull request, repository file, CI log, or chat.

## npmjs: Trusted Publishing after bootstrap

After the package exists on npmjs:

1. Open the package settings for `@axiomnode-lab/guard` on npmjs.
2. Add a Trusted Publisher using GitHub Actions with:
   - GitHub organization/user: `AxiomNode-lab`
   - Repository: `AxiomGuard`
   - Workflow filename: `publish-npmjs.yml`
   - Allowed action: `npm publish`
3. In GitHub repository settings, create repository variable `NPMJS_PUBLISH=true`.
4. Do not add `NPM_TOKEN` for normal releases. The workflow uses OIDC with `id-token: write` and npm Trusted Publishing.
5. Publish GitHub Releases only with a tag exactly matching `v${package.json version}`.

The workflow uses Node 24 and a Trusted-Publishing-capable npm version, checks whether the exact version already exists, refuses ambiguous registry failures, publishes through OIDC, and reads the version back after publication. Eligible GitHub Actions trusted publishes from a public repository receive npm provenance automatically.

## Verified 0.5.1 channel status

The `0.5.1` source line was merged to `main`, its CI qualification completed successfully, and the GitHub Packages workflow published and read back `@axiomnode-lab/guard@0.5.1`. A clean authenticated consumer install from GitHub Packages was also verified manually. These facts do **not** imply that npmjs or a GitHub Release/tag exists.

As of the 0.6.0 preparation branch, the GitHub Releases collection is still empty. Documentation therefore keeps `@main` only as a pre-release GitHub Action example until an immutable release ref is independently verified.

## 0.6.0 release sequence

`0.6.0` adds backward-compatible API-protection modules and provider integrations, so it is a minor release rather than another 0.5.x patch.

1. Merge the 0.6.0 PR only after Node 20/22/24 CI, clean-room tarball qualification, real framework/Redis integration tests, container smoke, Action/SARIF smoke, self scan, and CodeQL pass.
2. Confirm the `main` push **Publish npm package** workflow publishes or verifies `@axiomnode-lab/guard@0.6.0` in GitHub Packages.
3. Confirm the `main` push container workflow publishes/verifies the `edge`/commit image path without claiming a semver release tag.
4. If npmjs has not yet been bootstrapped, perform the one-time interactive public publish using the exact qualified `0.6.0` commit, then independently install `@axiomnode-lab/guard@0.6.0` from `registry.npmjs.org`.
5. Configure npm Trusted Publishing and `NPMJS_PUBLISH=true` after the npmjs package exists.
6. Create GitHub Release/tag `v0.6.0` only from the same qualified `main` commit.
7. Verify GitHub Packages, npmjs (if enabled), GHCR semver/latest artifacts, SBOM/provenance, and the `v0.6.0` GitHub Action reference before changing documentation from pre-release wording.

## Later versions

1. Advance `package.json` and `package-lock.json` together.
2. Update the changelog and release notes.
3. Merge only after required qualification passes.
4. Create a GitHub Release whose tag exactly matches the package version.
5. Verify every claimed registry/release artifact independently.

## Versioning

AxiomGuard follows semantic versioning in intent:

- patch: bug fixes and security hardening without intended incompatible API removals
- minor: backwards-compatible modules, options, adapters or scanner formats
- major: incompatible API or security-default changes

Security behavior can be compatibility-sensitive even when TypeScript signatures do not change. Release notes must call out changed defaults, state/eviction semantics and failure boundaries.
