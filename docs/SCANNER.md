# Scanner configuration, baselines and CI

AxiomGuard's repository scanner is intentionally conservative. Version 0.4 adds a configuration file, deterministic non-secret fingerprints, baselines and GitHub annotations so teams can adopt the scanner without permanently ignoring new findings.

## Configuration

Place `.axiomguard.json` at the scan root:

```json
{
  "version": 1,
  "ignoreDirectories": [".git", "node_modules", "dist", "coverage", ".axiomguard"],
  "ignoreFiles": ["docs/fixtures/**", "testdata/*.txt"],
  "maxFileBytes": 1000000,
  "baseline": ".axiomguard-baseline.json"
}
```

`ignoreFiles` supports `*`, `**`, and `?` over repository-relative paths. Keep exclusions narrow. Do not exclude broad source trees just to make CI green.

## Baselines

Create a baseline after manually reviewing existing findings:

```bash
axiomguard scan . --write-baseline .axiomguard-baseline.json
```

A baseline stores only SHA-256 fingerprints derived from rule, repository-relative file path and line number. It does not store or hash the detected credential value. This is intentionally conservative: moving a finding to another line makes it visible again and forces re-review.

Normal scans automatically load `.axiomguard-baseline.json` when present:

```bash
axiomguard scan .
```

Or select another file:

```bash
axiomguard scan . --baseline security/accepted-findings.json
```

A baseline is not an allowlist for a secret. If a finding is a real credential, rotate/revoke it and remove it from the repository instead of baselining it.

## GitHub annotations

```bash
axiomguard scan . --github-annotations --no-fail
```

Annotations contain the rule, file, line and a short fingerprint only. The matched value is never placed in workflow output.

## SARIF

```bash
axiomguard scan . --sarif --output axiomguard.sarif
```

SARIF results include `partialFingerprints` so code-scanning systems can correlate findings without receiving the matched credential value.
