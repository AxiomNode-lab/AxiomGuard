# Scanner architecture

## Current implementation

AxiomGuard's implemented scanner is the deterministic secret scanner in `src/scanner.ts`. It scans individual files or directory trees, skips symbolic links and unsupported or oversized files, applies narrowly scoped secret rules, supports ignore paths and baselines, and emits secret-safe findings, JSON, SARIF, and GitHub annotations. Its fingerprints remain based on the existing rule, repository-relative file, and line-number algorithm.

The existing `SecretFinding`, `SecretScanOptions`, `SecretScanBaseline`, `SecretScannerConfig`, and `SecretRuleInfo` types and the `scanSecrets`, `listSecretRules`, `createFindingFingerprint`, and `findingsToSarif` functions remain public. Keeping these APIs available avoids a breaking release and ensures that current CLI, JSON, and SARIF behavior does not change while generalized scanning is developed.

## Generalized scanner contracts

`src/scanner/contracts.ts` defines contracts for future repository scanners. It does not implement a generalized rule engine, stack detection, specialized rule packs, or risk scoring.

A `NormalizedFinding` gives downstream consumers a stable shape: finding and rule identifiers, severity, confidence, human-readable title and description, optional source location, structured evidence, impact, remediation, detector identity, and fingerprint. Detectors are responsible for producing every required field and for ensuring identifiers and fingerprints are deterministic.

Evidence is machine-generated, structured, JSON-serializable, and intentionally minimal. Evidence attributes describe non-sensitive facts such as a configuration key and its state. They must never contain matched secret values, raw credentials, private keys, access tokens, or unredacted sensitive source snippets. The normalized contract does not replace the secret scanner's stronger guarantee that matched values never enter its findings or output.

Severity and confidence are independent. Severity describes potential impact (`critical`, `high`, `medium`, `low`, or `info`); confidence describes how strongly the evidence supports the finding (`high`, `medium`, or `low`). Detectors must not use one as a substitute for the other.

`ScanVersionMetadata` records engine, ruleset, and schema versions so persisted results can be interpreted later. `SCAN_SCHEMA_VERSION` identifies the serialized generalized result schema. Schema changes should remain backward compatible within a major version; incompatible shape changes require a new major schema version. Engine and ruleset versions are supplied by the future scanner implementation because they evolve independently of the schema.

## Future boundaries

Future rule packs may consume a `ScanContext` and produce normalized findings, but their execution model is intentionally deferred. They must remain deterministic, secret-safe, independent of an LLM, and must not execute repository code. Stack detection, rule orchestration, filesystem policy, and scoring will be introduced only in later work with their own tests and threat-model review.

AxiomGuard remains the open-source Security Engine, SDK, and CLI. User accounts, SaaS authentication, organizations, subscriptions, billing, dashboards, customer management, hosted databases, queues, workers, GitHub application user interfaces, and AI conversations belong in a separate future AxiomGuard Cloud repository, not here.
