# GitHub Packages visibility and organization display

AxiomGuard publishes two package types:

- npm: `@axiomnode-lab/guard` through GitHub Packages
- container: `ghcr.io/axiomnode-lab/axiomguard`

GitHub's npm registry and Container registry use granular package permissions. A newly created package can be private even when the source repository is public. Package visibility is managed on the package itself, not by `package.json` alone.

## Make the package appear publicly on the organization

1. Open the `AxiomNode-lab` organization on GitHub.
2. Open **Packages**.
3. Open `guard` for npm or `axiomguard` for the container.
4. Open **Package settings**.
5. Confirm the package is connected to repository `AxiomNode-lab/AxiomGuard`. If it is not, use **Connect repository** and select `AxiomGuard`.
6. Under **Danger Zone → Change visibility**, choose **Public** if the package is intended for public use.
7. Confirm the visibility change. GitHub warns that a public package cannot simply be changed back to private.

For a private organization package, owners and explicitly authorized teams can still see it. Public visibility is what makes the package appear to unauthenticated visitors and on the organization's public package surface.

## Organization package creation policy

If a first publish fails before a package exists, check:

**Organization → Settings → Packages → Package creation**

Enable the package visibility type you intend to create. The repository workflow already requests `packages: write` and publishes with the repository-scoped `GITHUB_TOKEN`.

## Verify publication

The package workflow validates source, tests and then publishes a new immutable version. After publication, open the organization Packages page and verify the exact version. If the package is absent, inspect **Actions → Publish npm package** before changing visibility: visibility settings cannot fix a package that was never published.

## Repository linking

The npm package metadata contains the `AxiomNode-lab/AxiomGuard` repository URL. The container build also carries OCI source metadata so GitHub can associate the image with its source. Package settings remain the authoritative place to verify the link and access inheritance.
