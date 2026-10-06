import { createRequire } from 'node:module';
import {
  listSecretRules,
  scanSecrets,
  type SecretFinding,
  type SecretRuleInfo,
  type SecretScanOptions,
  type SecretSeverity,
} from './scanner.js';

export interface AgentSecurityFinding extends SecretFinding {
  severity: SecretSeverity;
  description: string;
  remediation: string;
}

export interface AgentSecurityReport {
  schemaVersion: '1';
  tool: {
    name: 'AxiomGuard';
    version: string;
  };
  mode: 'ci-agent';
  target: string;
  ok: boolean;
  status: 'pass' | 'fail';
  exitCode: 0 | 1;
  summary: {
    findings: number;
    errors: number;
    warnings: number;
  };
  findings: AgentSecurityFinding[];
  instructions: string[];
}

export interface AgentSecurityReportOptions {
  version?: string;
}

const VERSION = ((): string => {
  try {
    const pkg = createRequire(import.meta.url)('../package.json') as { version?: string };
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

const REMEDIATION_BY_RULE: Readonly<Record<string, string>> = {
  'private-key': 'Remove the key material from the repository and rotate or revoke the credential before the change is released.',
  'github-token': 'Revoke or rotate the GitHub credential, remove it from source control, and use the CI/CD secret store.',
  'gitlab-token': 'Revoke or rotate the GitLab credential, remove it from source control, and use the CI/CD secret store.',
  'aws-access-key': 'Deactivate or rotate the AWS credential, remove it from source control, and use the CI/CD secret store.',
  'stripe-live-secret': 'Rotate or revoke the live Stripe credential, remove it from source control, and use the CI/CD secret store.',
  'slack-token': 'Rotate or revoke the Slack credential, remove it from source control, and use the CI/CD secret store.',
  'slack-webhook-url': 'Rotate the Slack webhook if it is real, then move it to the CI/CD secret store instead of committing it.',
  'openai-api-key': 'Rotate or revoke the OpenAI credential, remove it from source control, and use the CI/CD secret store.',
  'anthropic-api-key': 'Rotate or revoke the Anthropic credential, remove it from source control, and use the CI/CD secret store.',
  'google-api-key': 'Rotate or revoke the Google credential, remove it from source control, and use the CI/CD secret store.',
  'npm-token': 'Revoke or rotate the npm credential, remove it from source control, and use the CI/CD secret store.',
  'sendgrid-api-key': 'Rotate or revoke the SendGrid credential, remove it from source control, and use the CI/CD secret store.',
  'huggingface-token': 'Rotate or revoke the Hugging Face credential, remove it from source control, and use the CI/CD secret store.',
  'digitalocean-token': 'Rotate or revoke the DigitalOcean credential, remove it from source control, and use the CI/CD secret store.',
  'shopify-token': 'Rotate or revoke the Shopify credential, remove it from source control, and use the CI/CD secret store.',
  'pypi-token': 'Revoke or rotate the PyPI credential, remove it from source control, and use the CI/CD secret store.',
  'vault-token': 'Revoke or rotate the Vault credential, remove it from source control, and use the CI/CD secret store.',
  'age-secret-key': 'Remove the encryption secret key from source control and rotate or replace the affected key material.',
  'telegram-bot-token': 'Rotate the Telegram bot token and move it to the CI/CD secret store.',
  'connection-string-password': 'Remove the embedded password from the connection string and source it from the CI/CD secret store.',
  'sensitive-env-value': 'Review the value. For a real secret, rotate it and move it to the CI/CD secret store; for documentation or a fixture, replace it with a clear placeholder.',
};

const FALLBACK_REMEDIATION = 'Review the finding and remove any real credential from source control before release. Never expose the matched value to an AI agent or CI log.';

function ruleInfoByName(): ReadonlyMap<string, SecretRuleInfo> {
  return new Map(listSecretRules().map((rule) => [rule.name, rule]));
}

function toAgentFinding(finding: SecretFinding, rules: ReadonlyMap<string, SecretRuleInfo>): AgentSecurityFinding {
  const rule = rules.get(finding.rule);
  return {
    ...finding,
    severity: rule?.severity ?? 'warning',
    description: rule?.description ?? 'Potential secret detected.',
    remediation: REMEDIATION_BY_RULE[finding.rule] ?? FALLBACK_REMEDIATION,
  };
}

export function createAgentSecurityReport(
  findings: readonly SecretFinding[],
  target = '.',
  options: AgentSecurityReportOptions = {},
): AgentSecurityReport {
  const rules = ruleInfoByName();
  const enriched = findings.map((finding) => toAgentFinding(finding, rules));
  const errors = enriched.filter((finding) => finding.severity === 'error').length;
  const warnings = enriched.length - errors;
  const ok = enriched.length === 0;

  return {
    schemaVersion: '1',
    tool: { name: 'AxiomGuard', version: options.version ?? VERSION },
    mode: 'ci-agent',
    target,
    ok,
    status: ok ? 'pass' : 'fail',
    exitCode: ok ? 0 : 1,
    summary: {
      findings: enriched.length,
      errors,
      warnings,
    },
    findings: enriched,
    instructions: [
      'Never request, print, or transmit matched secret values; this report intentionally contains metadata only.',
      'Treat error-severity findings as release-blocking unless a human reviewer has established that the fixture is non-secret.',
      'Never baseline a real credential. Rotate or revoke it first, then remove it from source control.',
      'After remediation, run the same scan again and require a clean result before release.',
    ],
  };
}

export async function scanForAgent(target: string, options: SecretScanOptions = {}): Promise<AgentSecurityReport> {
  const findings = await scanSecrets(target, options);
  return createAgentSecurityReport(findings, target);
}
