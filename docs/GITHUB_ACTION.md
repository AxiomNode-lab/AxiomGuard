# GitHub Action

The repository can be used directly as a composite GitHub Action. It scans the checked-out workspace and writes SARIF 2.1.0 without including matched credential values.

> **Pinning:** use an existing release tag or an immutable commit SHA in production. The example below uses the currently published `v0.7.1` release. For unreleased changes, pin the exact commit you have reviewed rather than using a moving branch. The composite action builds the scanner from source with `npm ci` on every run, so the runner needs Node.js on `PATH` and network access to npm.

```yaml
name: AxiomGuard
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - id: axiomguard
        uses: AxiomNode-lab/AxiomGuard@v0.7.1
        with:
          path: .
          fail-on-findings: 'true'
          annotations: 'true'
      - name: Upload SARIF
        if: always() && steps.axiomguard.outputs.sarif != ''
        uses: github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9 # v4.37.0
        with:
          sarif_file: ${{ steps.axiomguard.outputs.sarif }}
          category: axiomguard-secrets
```

`security-events: write` is needed only for uploading results to GitHub code scanning. The scan itself requires read-only repository contents.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Workspace-relative directory to scan |
| `fail-on-findings` | `true` | Exit the action with failure when new, non-baselined findings exist |
| `config` | empty | Optional repository-relative `.axiomguard.json` path |
| `baseline` | empty | Optional repository-relative baseline path |
| `annotations` | `true` | Emit GitHub warning annotations without credential values |

When `config` is empty, AxiomGuard looks for `.axiomguard.json` in the scan root. When `baseline` is empty, it uses the config baseline or `.axiomguard-baseline.json` when present.

## Outputs

| Output | Meaning |
| --- | --- |
| `sarif` | Absolute path to the generated SARIF file |
| `exit-code` | Scanner status before `fail-on-findings` handling (`0`, `1`, or `2`) |

## Audit-first rollout

For an existing repository with known findings, start in audit mode rather than adding broad exclusions:

```yaml
- id: axiomguard
  uses: AxiomNode-lab/AxiomGuard@v0.7.1
  with:
    path: .
    fail-on-findings: 'false'
    annotations: 'true'
```

Review the results, create a baseline only for accepted existing findings, commit that baseline, then switch `fail-on-findings` back to `true`. Baselines use non-secret fingerprints; moved or newly introduced findings become visible again.

## Running the container instead

The published image scans a mounted workspace without Node.js on the runner. The example below uses the published `0.7.1` image; production consumers can pin the same tag or an immutable digest:

```bash
docker run --rm -v "$PWD:/workspace:ro" ghcr.io/axiomnode-lab/axiomguard:0.7.1 scan /workspace --sarif --output /tmp/axiomguard.sarif
```
