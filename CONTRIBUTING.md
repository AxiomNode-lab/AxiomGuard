# Contributing

Contributions are welcome when they keep the package small, auditable and security-focused.

## Development setup

```bash
nvm use            # Node 24 (see .nvmrc); 20 and 22 are also supported
npm ci
npm run check      # typecheck + lint + unit tests + type tests
```

Useful commands:

| Command | What it does |
| --- | --- |
| `npm test` | build, then `node --test` (unit tests in `tests/*.test.mjs`) |
| `npm run test:coverage` | the same with V8 coverage (thresholds are enforced in CI on Node 22+) |
| `npm run test:types` | compile-only type assertions in `tests/types/*.test-d.ts` |
| `npm run lint` / `npm run lint:fix` | Biome (lint only; formatting is not enforced yet) |
| `npm run test:package` | pack the tarball, install it in a clean directory and exercise imports, `require()`, types and the CLI |
| `npm run test:integration:frameworks` | real Express/Fastify/Hono; first run `npm install --no-save --package-lock=false express@5.2.1 fastify@5.12.1 hono@4.13.4` |
| `npm run test:integration:redis` | real node-redis/ioredis; needs `docker run --rm -p 6379:6379 redis:8-alpine` and `npm install --no-save --package-lock=false redis@6.2.1 ioredis@6.0.0` |
| `npm run scan:self` | run the secret scanner over this repository |
| `node examples/<name>.mjs` | runnable examples (see `examples/README.md`) |

## Before opening a PR

1. Add or update tests for behaviour changes. Security fixes need a test that fails without the fix.
2. Run `npm run check`. CI also runs the integration jobs, Windows/macOS and package-shape checks.
3. Avoid new runtime dependencies. The package has none and that is a feature.
4. Do not add payload collections, offensive automation, or claims that are not covered by tests.
5. Document security assumptions and failure modes for new security-sensitive helpers (JSDoc on the export, a paragraph in `docs/`, and `THREAT_MODEL.md` when a new abuse case is covered).
6. If a default becomes stricter or an API changes shape, add a migration note to `UPGRADING.md` and an entry under the next version in `CHANGELOG.md`.
7. Never commit secret-shaped fixtures. Build them from fragments in tests (see `tests/cli.test.mjs`) so `npm run scan:self` stays clean.

## Style

Two-space indentation, single quotes, semicolons, trailing commas, explicit return types on exported functions. Prefer small pure functions and typed error classes with stable `code`s over string matching. Operator misconfiguration should throw at construction time; client-controlled input must never throw.

## Commit messages and releases

Use a short imperative subject and a body that explains *why*. Releases are cut from `main` by a GitHub Release whose tag matches `package.json`; see [docs/RELEASE.md](docs/RELEASE.md).

For vulnerability reports, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
