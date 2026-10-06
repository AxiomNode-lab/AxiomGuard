// Compile-only generalized scanner assertions. Run via `npm run test:types`.
import {
  SecurityPackRegistry,
  type NormalizedFinding,
  type RuleExecutionContext,
  type SecurityPack,
  type SecurityRule,
} from '../../dist/index.js';
import type { SecurityRule as ScannerEntryRule } from '../../dist/scanner.js';

const finding: NormalizedFinding = {
  findingId: 'example/rule:finding',
  ruleId: 'example/rule',
  severity: 'medium',
  confidence: 'high',
  title: 'Example finding',
  description: 'A deterministic condition was found.',
  evidence: [{ kind: 'configuration-state', summary: 'A setting is enabled.', attributes: { enabled: true } }],
  impact: 'The intended control may not apply.',
  remediation: 'Disable the setting.',
  detectorId: 'example-detector',
  fingerprint: 'example-fingerprint',
};

const rule: SecurityRule = {
  id: 'example/rule',
  title: 'Example rule',
  description: 'Detects a deterministic condition.',
  category: 'configuration',
  severity: 'medium',
  confidence: 'high',
  applicableStacks: [],
  impact: 'The intended control may not apply.',
  remediation: 'Disable the setting.',
  detectorId: 'example-detector',
  detect: async (context) => {
    const files = await context.listFiles();
    return files.length === 0 ? [] : [finding];
  },
};

const scannerEntryRule: ScannerEntryRule = rule;

const pack: SecurityPack = {
  id: 'example',
  name: 'Example pack',
  version: '1.0.0',
  description: 'Test-only rules.',
  rules: [rule],
};

const registry = new SecurityPackRegistry([pack]);

// @ts-expect-error detect is required by the SecurityRule contract.
const ruleWithoutDetector: SecurityRule = {
  id: 'example/incomplete',
  title: 'Incomplete rule',
  description: 'Missing its detector.',
  category: 'configuration',
  severity: 'low',
  confidence: 'low',
  applicableStacks: [],
  impact: 'Unknown.',
  remediation: 'Add a detector.',
  detectorId: 'example-detector',
};

// @ts-expect-error pack version is required.
const packWithoutVersion: SecurityPack = {
  id: 'incomplete',
  name: 'Incomplete pack',
  description: 'Missing its version.',
  rules: [rule],
};

declare const context: RuleExecutionContext;
// @ts-expect-error the controlled context does not expose its filesystem root.
context.root;
// @ts-expect-error rule detectors must return normalized findings.
const invalidRule: SecurityRule = { ...rule, detect: () => ['not-a-finding'] };

void [scannerEntryRule, registry, ruleWithoutDetector, packWithoutVersion, invalidRule];
