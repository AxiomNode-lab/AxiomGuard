# Release and registry policy

AxiomGuard publishes immutable package versions. A version is advanced before source intended for a new package release reaches `main`.

## GitHub Packages

`@axiomnode-lab/guard` is configured for GitHub Packages. A push to `main` runs type checking and tests, checks whether the version exists, and publishes only when it is new.

## GHCR

Source changes on `main` publish `ghcr.io/axiomnode-lab/axiomguard:edge` plus a commit-SHA tag. GitHub Releases publish semver tags and `latest`, with SBOM and provenance enabled in the container build.

## npmjs

The repository includes an npmjs release workflow but it is disabled by default. Enable it only after the npm scope/package is ready:

1. Create or verify the `@axiomnode-lab` npm scope and package ownership.
2. Prefer npm Trusted Publishing for `AxiomNode-lab/AxiomGuard` and workflow `publish-npmjs.yml`.
3. Set repository variable `NPMJS_PUBLISH=true`.
4. If Trusted Publishing is not configured yet, provide an automation-capable `NPM_TOKEN` secret and rotate/revoke it after migration to OIDC.
5. Publish a GitHub Release matching the package version.

The workflow requests `id-token: write` and publishes with provenance. Release builds do not use the npm dependency cache.

## Versioning

AxiomGuard follows semantic versioning in intent:

- patch: bug fixes without intended API changes
- minor: backwards-compatible modules, options, adapters or scanner formats
- major: incompatible API or security-default changes

Security behavior can be compatibility-sensitive even when TypeScript signatures do not change. Release notes must call out changed defaults and failure boundaries.
