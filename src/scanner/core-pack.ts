import type { NormalizedFinding, RuleExecutionContext, SecurityPack, SecurityRule, SecuritySeverity } from './contracts.js';
import { getInternalSecretRule, inspectSecretText, type SecretRuleDefinition } from './secret-detection.js';

export const CORE_SECURITY_PACK_VERSION = '1.0.0' as const;

const CORE_SECRET_RULE_ID = 'CORE-001';
const CORE_SECRET_DETECTOR_ID = 'core.secret-scanner';

function mapSecretSeverity(rule: SecretRuleDefinition): SecuritySeverity {
  if (rule.name === 'private-key') return 'critical';
  return rule.severity === 'error' ? 'high' : 'medium';
}

function normalizeSecretFinding(
  finding: { readonly file: string; readonly line: number; readonly rule: string; readonly fingerprint: string },
  definition: SecretRuleDefinition,
): NormalizedFinding {
  return {
    findingId: `${CORE_SECRET_RULE_ID}:${finding.fingerprint}`,
    ruleId: CORE_SECRET_RULE_ID,
    severity: mapSecretSeverity(definition),
    confidence: 'high',
    title: definition.findingTitle,
    description: definition.findingDescription,
    location: { file: finding.file, startLine: finding.line, endLine: finding.line },
    evidence: [{
      kind: 'secret-pattern',
      summary: 'A secret-shaped value was detected; the matched value is intentionally omitted.',
      attributes: { secretType: finding.rule, matchedValueIncluded: false },
    }],
    impact: definition.impact,
    remediation: definition.remediation,
    detectorId: CORE_SECRET_DETECTOR_ID,
    fingerprint: finding.fingerprint,
  };
}

async function detectCommittedSecrets(context: RuleExecutionContext): Promise<readonly NormalizedFinding[]> {
  const files = await context.listFiles();
  const findings: NormalizedFinding[] = [];
  for (const file of files) {
    const content = await context.readTextFile(file.path);
    for (const finding of inspectSecretText(file.path, content)) {
      const definition = getInternalSecretRule(finding.rule);
      if (definition !== undefined) findings.push(normalizeSecretFinding(finding, definition));
    }
  }
  return findings;
}

function createCoreSecretRule(): SecurityRule {
  return {
    id: CORE_SECRET_RULE_ID,
    title: 'Potential committed secret material',
    description: 'Detects narrow secret-shaped credential patterns while intentionally omitting matched values.',
    category: 'secrets',
    severity: 'high',
    confidence: 'high',
    applicableStacks: [],
    impact: 'If active, a committed credential may allow unauthorized access to protected systems or provider resources.',
    remediation: 'Remove the credential, revoke or rotate it, remove it from repository history where required, and use approved server-side secret management.',
    detectorId: CORE_SECRET_DETECTOR_ID,
    references: ['https://github.com/AxiomNode-lab/AxiomGuard/blob/main/docs/rules/CORE-001.md'],
    detect: detectCommittedSecrets,
  };
}

export function createCoreSecurityPack(): SecurityPack {
  return {
    id: 'core',
    name: 'Core Security',
    version: CORE_SECURITY_PACK_VERSION,
    description: 'Deterministic security checks applicable to most repositories.',
    applicableStacks: [],
    rules: [createCoreSecretRule()],
  };
}
