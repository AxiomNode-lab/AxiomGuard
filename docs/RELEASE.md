# Release and registry policy

AxiomGuard publishes immutable package versions. A version is advanced before source intended for a new package release reaches `main`.

## GitHub Packages

`@axiomnode-lab/guard` is configured for GitHub Packages. A push to `main` runs type checking and tests, checks whether the version exists, and publishes only when it is new. The workflow can also be run manually for retry/diagnostics.

GitHub's npm registry requires authentication even for public packages. It is an additional distribution channel, not the lowest-friction public install path.

## GHCR

Source changes on `main` publish `ghcr.io/axiomnode-lab/axiomguard:edge` plus a commit-SHA tag. GitHub Releases publish semver tags and `latest`, with SBOM and provenance enabled in the container build.

A release tag must exactly match `v${package.json version}` before release container tags are emitted.

## npmjs: first public publish

The public npmjs package must exist before npm Trusted Publishing can be configured. For the first release only:

1. Create or verify an npm organization named `axiomnode-lab`. The organization name owns the `@axiomnode-lab` scope.
2. Ensure the publishing npm account is a member with permission to publish public packages and has 2FA enabled.
3. From a clean checkout of the release commit, run `npm ci`, `npm run typecheck`, `npm test`, and `npm pack --dry-run`.
4. Authenticate interactively to `https://registry.npmjs.org`.
5. Publish exactly once with `npm publish --registry=https://registry.npmjs.org --access public` and complete the npm 2FA challenge.
6. Verify `npm view @axiomnode-lab/guard@0.5.0 version --registry=https://registry.npmjs.org` returns `0.5.0`.

Do not create a long-lived automation token just to bootstrap Trusted Publishing. The first publish is intentionally interactive.

## npmjs: trusted publishing after bootstrap

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

The release workflow checks whether the version already exists before publishing and reads the exact version back from npmjs after a new publish. npm Trusted Publishing automatically emits provenance for eligible public packages built from public repositories.

## Release sequence

For `0.5.0` bootstrap:

1. Merge the release-preparation PR after CI passes.
2. Verify or manually run **Publish npm package** for GitHub Packages.
3. Perform the one-time interactive npmjs publish described above.
4. Configure npm Trusted Publishing and set `NPMJS_PUBLISH=true`.
5. Create GitHub Release `v0.5.0` from `main`.
6. Verify GitHub Packages, npmjs, GHCR semver/latest tags, and the `v0.5.0` GitHub Action reference.

For later versions:

1. Advance `package.json` and `package-lock.json` together.
2. Update the changelog and release notes.
3. Merge only after CI passes.
4. Create a GitHub Release whose tag exactly matches the package version, for example `v0.6.0`.
5. Verify all registries and release artifacts.

## Versioning

AxiomGuard follows semantic versioning in intent:

- patch: bug fixes without intended API changes
- minor: backwards-compatible modules, options, adapters or scanner formats
- major: incompatible API or security-default changes

Security behavior can be compatibility-sensitive even when TypeScript signatures do not change. Release notes must call out changed defaults and failure boundaries.
