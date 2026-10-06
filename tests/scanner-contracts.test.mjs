import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SCAN_SCHEMA_VERSION,
  createFindingFingerprint,
  findingsToSarif,
  listSecretRules,
  scanSecrets,
} from '../dist/index.js';
import * as scanner from '../dist/scanner.js';

test('generalized scanner constants are available from root and scanner entry points', () => {
  assert.equal(SCAN_SCHEMA_VERSION, '1.0.0');
  assert.equal(scanner.SCAN_SCHEMA_VERSION, SCAN_SCHEMA_VERSION);
});

test('a normalized finding and scan result serialize without secret values', () => {
  const result = {
    versions: {
      engineVersion: '0.7.2',
      rulesetVersion: '2026.10.0',
      schemaVersion: SCAN_SCHEMA_VERSION,
    },
    context: {
      target: '.',
      detectorIds: ['example-detector'],
    },
    findings: [
      {
        findingId: 'finding-example-1',
        ruleId: 'example/insecure-setting',
        severity: 'medium',
        confidence: 'high',
        title: 'Insecure setting enabled',
        description: 'A security-relevant setting is enabled.',
        location: { file: 'config/example.json', startLine: 4, endLine: 4 },
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
      },
    ],
  };

  const serialized = JSON.stringify(result);
  assert.deepEqual(JSON.parse(serialized), result);
  assert.doesNotMatch(serialized, /credential|private key|access token/i);
});

test('legacy secret scanner values remain exported', () => {
  assert.equal(typeof scanSecrets, 'function');
  assert.equal(typeof listSecretRules, 'function');
  assert.equal(typeof createFindingFingerprint, 'function');
  assert.equal(typeof findingsToSarif, 'function');
});
