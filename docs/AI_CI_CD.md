# AI and CI/CD Integration

AxiomGuard is designed to be deterministic security infrastructure that can be called by CI/CD systems and AI coding agents without giving those agents access to detected secret values.

The integration is intentionally model-agnostic: AxiomGuard does not require an OpenAI, Anthropic, Gemini or other AI SDK. It produces a stable, machine-readable security report that an agent can inspect and act on.

## 1. Install with the package manager you already use

### Library installation

```bash
npm install @axiomnode-lab/guard
pnpm add @axiomnode-lab/guard
yarn add @axiomnode-lab/guard
bun add @axiomnode-lab/guard
```

For the beta channel:

```bash
npm install @axiomnode-lab/guard@beta
pnpm add @axiomnode-lab/guard@beta
yarn add @axiomnode-lab/guard@beta
bun add @axiomnode-lab/guard@beta
```

### Run the CLI without adding it to your project

```bash
npx @axiomnode-lab/guard@beta scan .
pnpm dlx @axiomnode-lab/guard@beta scan .
yarn dlx @axiomnode-lab/guard@beta scan .
bunx @axiomnode-lab/guard@beta scan .
npm exec --yes @axiomnode-lab/guard@beta -- scan .
```

Use the package name for one-off execution. The installed executable is still named `axiomguard`.

## 2. CI/AI-safe mode

Use:

```bash
axiomguard ci .
```

This is equivalent to a scan with the `agent` output format.

For an AI coding agent or CI orchestrator that needs to keep the pipeline running while it evaluates findings:

```bash
axiomguard ci . --no-fail --output axiomguard-agent.json
```

The command exits with:

- `0` when no new findings are present
- `1` when new findings are present
- `2` when the scanner could not execute

The report never contains the matched secret value.

## 3. Agent report format

The agent report is JSON with a stable top-level shape:

```json
{
  "schemaVersion": "1",
  "tool": {
    "name": "AxiomGuard",
    "version": "0.8.0-beta.2"
  },
  "mode": "ci-agent",
  "target": ".",
  "ok": false,
  "status": "fail",
  "exitCode": 1,
  "summary": {
    "findings": 1,
    "errors": 1,
    "warnings": 0
  },
  "findings": [
    {
      "file": "config.example",
      "line": 12,
      "rule": "github-token",
      "fingerprint": "…",
      "severity": "error",
      "description": "A GitHub token-shaped credential appears to be committed.",
      "remediation": "Revoke or rotate the GitHub credential, remove it from source control, and use the CI/CD secret store."
    }
  ],
  "instructions": [
    "Never request, print, or transmit matched secret values; this report intentionally contains metadata only.",
    "Treat error-severity findings as release-blocking unless a human reviewer has established that the fixture is non-secret.",
    "Never baseline a real credential. Rotate or revoke it first, then remove it from source control.",
    "After remediation, run the same scan again and require a clean result before release."
  ]
}
```

The fingerprint is deterministic and does not contain the detected value.

## 4. Use the library directly

AI agents and CI/CD control planes can call the same functionality without spawning a process:

```ts
import { scanForAgent } from '@axiomnode-lab/guard/agent';

const report = await scanForAgent(process.cwd());

if (!report.ok) {
  // Give the AI only the report metadata.
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.exitCode;
}
```

Or build a report from an existing scan:

```ts
import {
  createAgentSecurityReport,
  scanSecrets,
} from '@axiomnode-lab/guard';

const findings = await scanSecrets('.');
const report = createAgentSecurityReport(findings, '.');
```

This allows an AI-enabled CI service to keep AxiomGuard as the deterministic security layer while the model handles explanation and remediation planning.

## 5. Recommended AI workflow

Use this sequence:

```text
checkout
  ↓
install dependencies
  ↓
AxiomGuard scan
  ↓
agent-safe JSON report
  ↓
AI reviews metadata
  ↓
human-approved remediation
  ↓
AxiomGuard scan again
  ↓
tests / build
  ↓
release
```

The AI should not receive raw environment files, credentials, tokens, private keys or complete secret-bearing log output just to explain a finding.

## 6. GitHub Actions

The existing AxiomGuard GitHub Action continues to generate SARIF for code scanning. It can also expose the agent-safe report for a later AI step.

Example:

```yaml
- name: AxiomGuard
  id: axiomguard
  uses: AxiomNode-lab/AxiomGuard@v0.8.0-beta.2
  with:
    fail-on-findings: 'true'

- name: Review security findings
  if: always()
  run: |
    cat "${{ steps.axiomguard.outputs.agent-report }}"
```

For production, pin an immutable reviewed commit or release tag according to your repository policy.

## 7. GitLab CI

A generic GitLab job can keep the security report as an artifact:

```yaml
security:scan:
  image: node:24
  script:
    - npm install --no-save @axiomnode-lab/guard@beta
    - npx axiomguard ci . --no-fail --output axiomguard-agent.json
  artifacts:
    when: always
    paths:
      - axiomguard-agent.json
```

Use a pinned version rather than `@beta` in a production release pipeline when reproducibility matters.

## 8. Make the AI fail safely

A useful agent policy is:

```text
1. Read the AxiomGuard report.
2. Never ask for the matched value.
3. Treat error findings as release blockers.
4. Treat warning findings as review items.
5. Do not create a baseline for a real credential.
6. Suggest rotation/revocation before removal when the finding may be live.
7. Apply the smallest safe source change.
8. Run AxiomGuard again.
9. Proceed only after the relevant findings are gone or explicitly reviewed.
```

## 9. What AxiomGuard gives the AI

The report provides:

- exact file and line
- rule name
- severity
- deterministic fingerprint
- safe rule description
- deterministic remediation guidance
- overall pass/fail state
- counts suitable for CI gates

It intentionally does not provide:

- the detected secret value
- a tokenized copy of the secret
- decrypted environment files
- credentials extracted from the repository

This boundary is important because an AI assistant with repository access can otherwise turn a security scanner into a secret-disclosure mechanism.

## 10. AI does not replace application security

AxiomGuard can be the deterministic gate around an AI-assisted CI/CD workflow. It does not automatically decide:

- whether a credential is actually live
- whether a business action is authorized
- whether a model output is safe
- whether a document contains prompt injection
- whether an application has a network-layer egress policy
- whether a vulnerability in a dependency is exploitable

Those decisions still require application, infrastructure and human controls.

## 11. Package manager summary

| Goal | npm | pnpm | Yarn | Bun |
|---|---|---|---|---|
| Install library | `npm install` | `pnpm add` | `yarn add` | `bun add` |
| One-off CLI | `npx` | `pnpm dlx` | `yarn dlx` | `bunx` |
| CI/AI report | `npx @axiomnode-lab/guard@beta ci .` | `pnpm dlx @axiomnode-lab/guard@beta ci .` | `yarn dlx @axiomnode-lab/guard@beta ci .` | `bunx @axiomnode-lab/guard@beta ci .` |
