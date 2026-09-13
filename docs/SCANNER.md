# Scanner configuration, baselines and CI

AxiomGuard's repository scanner is intentionally conservative: every rule is a provider-shaped prefix with enough trailing entropy to stay quiet on ordinary code. `axiomguard rules` lists the current rules and their severities. Configuration, deterministic non-secret fingerprints, baselines and GitHub annotations let teams adopt the scanner without permanently ignoring new findings.

## What is scanned

Text files by extension (source, config, infrastructure, notebooks, CSV), `.env*` files, key material (`.pem`, `.key`, `.asc`, `id_rsa`, `id_ed25519`, …) and extensionless configuration such as `Dockerfile`, `Makefile`, `.npmrc`, `.netrc` and `.pypirc`. Files containing NUL bytes, files over `maxFileBytes` (1 MB) and symbolic links are skipped. `.gitignore` is not consulted; `.git`, `node_modules`, `dist`, `build`, `coverage`, `vendor`, `venv`, `target` and similar directories are ignored by default (`ignoreDirectories` replaces the list). A single file can be scanned as well as a directory.

The `sensitive-env-value` rule matches `NAME=value` and `NAME: value` lines whose name contains `PASSWORD`, `SECRET`, `API_KEY`, `TOKEN` or `PRIVATE_KEY` (with any prefix or suffix, in `.env`, YAML, compose, Dockerfile `ENV`/`ARG` and `export` forms). Placeholders (`changeme`, `<your-key>`, `${VAR}`, `%VAR%`, `{{ x }}`, `xxxx`), and values that are plain words such as TypeScript type annotations, are ignored.

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

`ignoreFiles` supports `*`, `**` (`**/x` also matches a top-level `x`) and `?` over repository-relative paths; `--exclude <glob>` adds patterns from the command line. Keep exclusions narrow. Do not exclude broad source trees just to make CI green.

Output goes to stdout in every format (`--format text|json|sarif`, or `--json`/`--sarif`); diagnostics and `--github-annotations` go to stderr so `--json` output stays parseable. Exit codes are `0` (no new findings), `1` (new findings, unless `--no-fail`) and `2` (error).

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

Annotations are emitted on stderr as `::error` (or `::warning` with `--no-fail`) and contain the rule, file, line and a short fingerprint only. The matched value is never placed in workflow output.

## SARIF

```bash
axiomguard scan . --sarif --output axiomguard.sarif
```

SARIF results include `partialFingerprints`, rule severities (`error` for key material and provider tokens, `warning` for env values and webhook URLs), the tool `semanticVersion` and a `SRCROOT` base id so code-scanning systems can correlate findings without receiving the matched credential value.
