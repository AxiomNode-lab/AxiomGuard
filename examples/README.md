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
