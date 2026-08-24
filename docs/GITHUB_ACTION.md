# GitHub Action

The repository can be used directly as a composite GitHub Action. It scans the checked-out workspace and always writes SARIF 2.1.0 without including matched credential values.

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
      - uses: actions/checkout@v6
      - id: axiomguard
        uses: AxiomNode-lab/AxiomGuard@v0.3.0
        with:
          path: .
          fail-on-findings: 'true'
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
| `fail-on-findings` | `true` | Exit the action with failure when findings exist |

## Outputs

| Output | Meaning |
| --- | --- |
| `sarif` | Absolute path to the generated SARIF file |
| `exit-code` | Scanner status before `fail-on-findings` handling (`0`, `1`, or `2`) |

For an audit-only rollout, set `fail-on-findings: 'false'` and upload SARIF first. Tighten the gate after reviewing false positives in the target repository.
