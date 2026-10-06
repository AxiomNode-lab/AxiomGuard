# CORE-001 — Potential committed secret material

## Rule metadata

- Stable ID: `CORE-001`
- Category: `secrets`
- Detector: `core.secret-scanner`
- Applicability: universal; no stack identifier is required
- Default severity: `high`, with deterministic category-specific mapping
- Confidence: `high` for every finding

## Detection behavior

`CORE-001` uses the same authoritative secret-pattern catalog and line inspector as the legacy `scanSecrets()` API. It calls the controlled rule context once to list eligible repository files, reads each eligible text file once, and tests each line against the narrow legacy patterns. It does not execute repository code, access unrestricted filesystem paths, perform network requests, or use an LLM.

The rule represents all legacy secret categories under one generalized rule ID. Examples include private-key material, provider tokens, webhook URLs, connection-string passwords, and sensitive environment values. Placeholder values and public provider identifiers remain subject to the legacy scanner's existing exclusions.

## Severity and confidence

Severity maps as follows:

- `private-key` → `critical`
- every other legacy `error` category → `high`
- every legacy `warning` category → `medium`

This mapping is deterministic triage guidance, not proof that a credential is active or exploitable. Confidence remains separately set to `high` because the legacy patterns intentionally favor narrow credential shapes over broad heuristics.

## Evidence and identity

Each finding emits one evidence item:

```json
{
  "kind": "secret-pattern",
  "summary": "A secret-shaped value was detected; the matched value is intentionally omitted.",
  "attributes": {
    "secretType": "legacy-rule-name",
    "matchedValueIncluded": false
  }
}
```

The location contains the repository-relative file and matching line; `endLine` equals `startLine`. Evidence does not duplicate source location data.

The fingerprint is the existing SHA-256 location identity derived from legacy rule name, repository-relative file, and line. It does not contain or hash the matched value. The stable finding ID is `CORE-001:<legacy fingerprint>`.

## Impact

If active, committed credential material may allow unauthorized access, impersonation, signing, decryption, or use of provider resources. The precise impact depends on the credential category and its permissions. A finding does not claim the value is active or that the entire application is insecure.

## False-positive considerations

The scanner uses provider-shaped prefixes, key headers, and constrained credential-like values to reduce noise. Test data or expired credentials can still match. Review the file and category without copying the value into logs, tickets, or scan output. Do not assume a match is harmless merely because it appears in a test fixture or historical commit.

## Remediation

- Private key: remove it from version control, revoke or replace it, remove it from repository history where required, and use an approved secret store.
- Provider token or webhook: revoke or rotate it, remove it from repository history where required, and load it through server-side secret management.
- Connection-string password: rotate the credential and move the connection string to protected server-side configuration.
- Sensitive environment value: remove the real value, keep only a placeholder in example files, rotate it if committed, and use deployment secret storage.

## Tests

Focused tests verify pack registration, orchestration, identity and fingerprint reuse, category severity mapping, high confidence, locations, evidence redaction, deterministic ordering, placeholders, public-key exclusions, ignores, size limits, binary and symbolic-link handling, legacy baselines, SARIF safety, and public package exports. Credential-shaped fixtures are assembled from safe fragments at runtime.

## Secret-handling guarantee

The rule never places the matched substring, source line, surrounding snippet, credential value, private-key body, or a digest of secret content into findings, evidence, fingerprints, errors, logs, or serialized scan results. Repository contents remain local and are never sent to a network service or LLM.
