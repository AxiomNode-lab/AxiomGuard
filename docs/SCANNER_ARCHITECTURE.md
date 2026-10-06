# Scanner architecture

## Current implementation

AxiomGuard's implemented scanner is the deterministic secret scanner in `src/scanner.ts`. It scans individual files or directory trees, skips symbolic links and unsupported or oversized files, applies narrowly scoped secret rules, supports ignore paths and baselines, and emits secret-safe findings, JSON, SARIF, and GitHub annotations. Its fingerprints remain based on the existing rule, repository-relative file, and line-number algorithm.

The existing `SecretFinding`, `SecretScanOptions`, `SecretScanBaseline`, `SecretScannerConfig`, and `SecretRuleInfo` types and the `scanSecrets`, `listSecretRules`, `createFindingFingerprint`, and `findingsToSarif` functions remain public. Keeping these APIs available avoids a breaking release and ensures that current CLI, JSON, and SARIF behavior does not change while generalized scanning is developed.

## Generalized scanner contracts

`src/scanner/contracts.ts` defines the persisted result types and the generalized rule and pack contracts. `NormalizedFinding` gives downstream consumers a stable shape: finding and rule identifiers, severity, confidence, human-readable title and description, optional source location, structured evidence, impact, remediation, detector identity, and fingerprint. Every detector must produce every required field and deterministic identifiers and fingerprints.

A `SecurityRule` combines stable metadata with a deterministic `detect` function. Metadata includes the rule ID, category, default severity and confidence, applicable stack IDs, impact, remediation, detector identity, and optional references. Severity and confidence on every returned finding are still explicit and may differ from metadata defaults. A `SecurityPack` groups versioned rules under a stable pack ID and may declare its own stack applicability. No real Core, Next.js, Supabase, Stripe, or AI-related pack is implemented yet.

Evidence is machine-generated, structured, JSON-serializable, and intentionally minimal. Evidence attributes describe non-sensitive facts such as a configuration key and its state. They must never contain matched secret values, raw credentials, private keys, access tokens, or unredacted sensitive source snippets. The normalized contract does not replace the secret scanner's stronger guarantee that matched values never enter its findings or output.

Severity and confidence are independent. Severity describes potential impact (`critical`, `high`, `medium`, `low`, or `info`); confidence describes how strongly the evidence supports the finding (`high`, `medium`, or `low`). Detectors must not use one as a substitute for the other.

`ScanVersionMetadata` records engine, ruleset, and schema versions so persisted results can be interpreted later. `SCAN_SCHEMA_VERSION` identifies the serialized generalized result schema. Schema changes should remain backward compatible within a major version; incompatible shape changes require a new major schema version. Callers supply explicit engine and ruleset versions because they evolve independently of the schema; the runtime never derives a ruleset version from the clock.

## Registry and deterministic orchestration

Each `SecurityPackRegistry` instance owns its state; there is no process-global registry. Registration validates IDs, semantic pack versions, metadata, references, and detector functions. Duplicate pack IDs and duplicate rule IDs across packs are rejected. Registered definitions and returned lists are frozen, and packs and rules are listed in stable ID order.

`scanRepository` accepts either one registry or an explicit pack list. Omitting `packIds` considers every registered pack; passing an empty array runs no packs; and unknown requested IDs fail. A pack or rule without stack restrictions is applicable to every scan. A restricted pack or rule runs only when its declared identifiers intersect caller-provided `detectedStackIds`. Explicit selection never bypasses those restrictions. The runtime does not infer stacks from filenames; stack detection remains deferred.

Rules execute sequentially in pack-ID and rule-ID order. A rule exception fails the scan with `ScannerError` code `RULE_EXECUTION_FAILED` and identifies the responsible pack and rule without copying the original error message. Partial findings are not returned as a successful result. Every finding is structurally validated, including relative source paths, line ranges, evidence, JSON-safe finite values, rule and detector identity, severity, confidence, and required text fields.

Final findings are ordered by severity (`critical`, `high`, `medium`, `low`, `info`), then rule ID, file, start line, fingerprint, and finding ID. `ScanResult` records explicit engine and ruleset versions plus `SCAN_SCHEMA_VERSION`. Its persisted `ScanContext` contains only JSON data: a repository-neutral target (`.`), sorted detector IDs, executed pack IDs, and provided stack IDs.

## Controlled repository access

`RepositoryScanContext` is runtime-only and is never stored in `ScanResult`. It exposes only sorted eligible file metadata and on-demand text reads by normalized repository-relative path. Absolute paths, traversal, backslashes, symbolic links, unsupported file types, binary files, ignored files, and oversized files are rejected or skipped. Default ignored directories match the legacy scanner; callers may provide explicit ignore directories and glob-style file ignores. Enumeration and binary checks use bounded concurrency, while complete file contents are read only when a rule requests a file.

Repository processing is static and deterministic. The context cannot execute commands, install packages, run repository code, perform network requests, or expose its filesystem root. File contents are not placed in scan results or error messages.

## Implemented and deferred boundaries

The generalized contracts, registry, safe repository context, validation, and orchestration foundation are implemented. The Core Security Pack provides `CORE-001`, which adapts the authoritative legacy secret catalog and line matcher into normalized findings while preserving legacy output. Both paths reuse the existing location-based fingerprint; the generalized path does not apply legacy baselines.

Additional Core rules, specialized packs, stack detection, generalized SARIF and CLI output, semantic fingerprints, generalized baselines, and risk scoring remain deferred. Rules must remain deterministic, secret-safe, and independent of an LLM. The existing legacy secret scanner, its fingerprints, baseline format, JSON, SARIF, CLI behavior, and exports remain unchanged.

AxiomGuard remains the open-source Security Engine, SDK, and CLI. User accounts, SaaS authentication, organizations, subscriptions, billing, dashboards, customer management, hosted databases, queues, workers, GitHub application user interfaces, and AI conversations belong in a separate future AxiomGuard Cloud repository, not here.
