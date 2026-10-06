// Compile-only contract assertions. Run via `npm run test:types`.
import {
  SCAN_SCHEMA_VERSION,
  type FindingConfidence,
  type NormalizedFinding,
  type ScanResult,
  type SecuritySeverity,
} from '../../dist/index.js';
import type { NormalizedFinding as ScannerEntryFinding } from '../../dist/scanner.js';

const severity: SecuritySeverity = 'critical';
const confidence: FindingConfidence = 'high';

// @ts-expect-error severity does not include arbitrary labels.
const invalidSeverity: SecuritySeverity = 'error';
// @ts-expect-error confidence and severity are separate concepts.
const invalidConfidence: FindingConfidence = 'critical';

const finding: NormalizedFinding = {
  findingId: 'finding-example-1',
  ruleId: 'example/insecure-setting',
  severity: 'medium',
  confidence: 'high',
  title: 'Insecure setting enabled',
  description: 'A security-relevant setting is enabled.',
  location: { file: 'config/example.json', startLine: 4 },
  evidence: [
    {
      kind: 'configuration-state',
      summary: 'The setting is enabled.',
      attributes: { setting: 'allowInsecure', enabled: true },
    },
  ],
  impact: 'Requests may bypass the intended control.',
  remediation: 'Disable the setting.',
  detectorId: 'example-detector',
  fingerprint: 'example-fingerprint',
};

const scannerEntryFinding: ScannerEntryFinding = finding;

// @ts-expect-error required normalized fields cannot be omitted.
const incompleteFinding: NormalizedFinding = {
  findingId: 'finding-example-2',
  ruleId: 'example/incomplete',
  severity: 'low',
  confidence: 'low',
};

const result: ScanResult = {
  versions: {
    engineVersion: '0.7.2',
    rulesetVersion: '2026.10.0',
    schemaVersion: SCAN_SCHEMA_VERSION,
  },
  context: { target: '.', detectorIds: ['example-detector'] },
  findings: [finding],
};

void [severity, confidence, invalidSeverity, invalidConfidence, scannerEntryFinding, incompleteFinding, result];
