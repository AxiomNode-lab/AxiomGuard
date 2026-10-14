# Examples

Each file is self-contained and runs against the built package (`npm run build` first, or `npm ci` in a checkout):

```bash
node examples/express-api.mjs        # needs: npm install --no-save express
node examples/webhooks.mjs
node examples/safe-fetch.mjs
node examples/idempotent-endpoint.mjs
node examples/edge-runtime.mjs
bash examples/scanner.sh
```

The examples import from `../dist/index.js`; in your own project replace that with `@axiomnode-lab/guard` or a subpath such as `@axiomnode-lab/guard/webhooks`.

## GitHub Actions workflow example

- [AxiomGuard AI/CI report workflow](workflows/axiomguard-ai-ci.yml) — copy into your repository's `.github/workflows/` directory. This example pins the `v0.8.0-beta.2` prerelease for its AI/CI-safe JSON report output; for the stable `v0.7.1` action, use [the stable GitHub Action guide](../docs/GITHUB_ACTION.md).
