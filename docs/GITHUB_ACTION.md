# GitHub Action

The repository can be used directly as a composite GitHub Action. It scans the checked-out workspace and writes SARIF 2.1.0 without including matched credential values.

> **Pinning:** use a release tag (`@v0.7.0`) or an immutable commit SHA in production. `@main` is for evaluation only. Note that the action can only be consumed by other repositories once this repository is public; the composite action builds the scanner from source with `npm ci` on every run, so a runner needs Node.js on `PATH`.

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
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
      - id: axiomguard
        uses: AxiomNode-lab/AxiomGuard@v0.7.0
        with:
          path: .
          fail-on-findings: 'true'
          annotations: 'true'
      - name: Upload SARIF
        if: always() && steps.axiomguard.outputs.sarif != ''
        uses: github/codeql-action/upload-sarif@v4
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
  uses: AxiomNode-lab/AxiomGuard@v0.7.0
  with:
    path: .
    fail-on-findings: 'false'
    annotations: 'true'
```

Review the results, create a baseline only for accepted existing findings, commit that baseline, then switch `fail-on-findings` back to `true`. Baselines use non-secret fingerprints; moved or newly introduced findings become visible again.

After a release is published, replace `@main` with the release tag or immutable release commit SHA. Do not infer that a version string in `package.json` creates a usable GitHub Action tag; the Git ref must exist separately.

## Inputs and outputs

| Input | Default | Notes |
| --- | --- | --- |
| `path` | `.` | Directory (or file) to scan; relative to the workspace or absolute |
| `fail-on-findings` | `'true'` | When `'false'` the scanner runs with `--no-fail` and annotations become warnings |
| `config` | | `.axiomguard.json` path, relative to the workspace or absolute |
| `baseline` | | baseline path, relative to the workspace or absolute |
| `annotations` | `'true'` | emit `::error`/`::warning` workflow annotations (never the matched value) |

Outputs: `sarif` is the absolute SARIF path (empty when the scanner failed to run), `exit-code` is `0`, `1` or `2`. Guard the upload step with `if: always() && steps.axiomguard.outputs.sarif != ''`.

## Running the container instead

The published image scans a mounted workspace without Node.js on the runner:

```bash
docker run --rm -v "$PWD:/workspace:ro" ghcr.io/axiomnode-lab/axiomguard:0.7.0 scan /workspace --sarif --output /tmp/axiomguard.sarif
```
