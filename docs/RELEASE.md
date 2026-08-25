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
2. Ensure the publishing npm account is a member with permission to publish public packages and has 2FA enabled. Current npm policy requires 2FA for direct publishing unless a suitable granular bypass-2FA token is used; the bootstrap procedure intentionally prefers interactive 2FA.
3. Use the exact release commit after CI is green. Run `npm ci`, `npm run typecheck`, `npm test`, `npm run test:package`, and `npm pack --dry-run`.
4. Authenticate interactively to `https://registry.npmjs.org`.
5. Publish exactly once with `npm publish --registry=https://registry.npmjs.org --access public` and complete the npm 2FA challenge.
6. Verify `npm view @axiomnode-lab/guard@0.5.1 version --registry=https://registry.npmjs.org` returns `0.5.1`.
7. From a separate clean directory with no custom npm scope registry, run `npm install @axiomnode-lab/guard@0.5.1` and smoke-test an import.

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

The workflow installs npm 11.5.1 or later on Node 24, meeting the current npm Trusted Publishing minimums. It checks whether the exact version already exists, refuses ambiguous registry failures, publishes through OIDC, and reads the version back after publication. Eligible GitHub Actions trusted publishes from a public repository receive npm provenance automatically.

## 0.5.1 release sequence

`0.5.0` was prepared in source but no `v0.5.0` Git ref or GitHub Release was published. Security and release-hardening fixes therefore advance the release candidate to `0.5.1` rather than mutating the prepared 0.5.0 line.

1. Merge the 0.5.1 release-hardening PR only after CI, real framework/Redis integration tests, clean-room tarball qualification, CodeQL, and the self scan pass.
2. Confirm the `main` push **Publish npm package** workflow publishes or verifies `@axiomnode-lab/guard@0.5.1` in GitHub Packages.
3. Perform the one-time interactive npmjs publish described above and independently install `@axiomnode-lab/guard@0.5.1` from the public npm registry.
4. Configure npm Trusted Publishing and set the GitHub repository variable `NPMJS_PUBLISH=true`.
5. Create GitHub Release/tag `v0.5.1` from the qualified `main` commit.
6. Verify GitHub Packages, npmjs, GHCR semver/latest tags, SBOM/provenance, and the `v0.5.1` GitHub Action reference before changing documentation from pre-release wording.

## Later versions

1. Advance `package.json` and `package-lock.json` together.
2. Update the changelog and release notes.
3. Merge only after required qualification passes.
4. Create a GitHub Release whose tag exactly matches the package version, for example `v0.6.0`.
5. Verify every claimed registry/release artifact independently.

## Versioning

AxiomGuard follows semantic versioning in intent:

- patch: bug fixes and security hardening without intended incompatible API removals
- minor: backwards-compatible modules, options, adapters or scanner formats
- major: incompatible API or security-default changes

Security behavior can be compatibility-sensitive even when TypeScript signatures do not change. Release notes must call out changed defaults, state/eviction semantics and failure boundaries.
