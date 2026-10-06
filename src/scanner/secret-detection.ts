import { createHash } from 'node:crypto';
import { normalizePathSeparators } from './file-policy.js';

export type LegacySecretSeverity = 'error' | 'warning';

export interface SecretRuleDefinition {
  readonly name: string;
  readonly description: string;
  readonly severity: LegacySecretSeverity;
  readonly findingTitle: string;
  readonly findingDescription: string;
  readonly impact: string;
  readonly remediation: string;
  readonly pattern: RegExp;
}

export interface InternalSecretFinding {
  readonly file: string;
  readonly line: number;
  readonly rule: string;
  readonly fingerprint: string;
}

interface ProviderRuleOptions {
  name: string;
  label: string;
  description: string;
  severity: LegacySecretSeverity;
  pattern: RegExp;
}

function providerRule(options: ProviderRuleOptions): SecretRuleDefinition {
  return Object.freeze({
    name: options.name,
    description: options.description,
    severity: options.severity,
    findingTitle: `Potential committed ${options.label}`,
    findingDescription: `A ${options.label} secret-shaped credential was detected. The matched value is intentionally omitted.`,
    impact: 'If active, this credential may allow unauthorized access to the associated provider account or resources.',
    remediation: 'Revoke or rotate the credential, remove it from repository history where required, and load it through server-side secret management.',
    pattern: options.pattern,
  });
}

const PLACEHOLDER_WORD = String.raw`(?:changeme|change-me|example|placeholder|dummy|sample|your[_-]?[a-z0-9_-]+|<[^>]+>|\*{3,}|x{4,}|undefined|null|none|true|false)`;
const PLACEHOLDER_PREFIX = String.raw`(?:\$|%[A-Za-z_]|\{\{|<)`;
const NOT_PLACEHOLDER = String.raw`(?!$|["']?${PLACEHOLDER_WORD}["']?\s*$|["']?${PLACEHOLDER_PREFIX})`;
const CREDENTIAL_VALUE = String.raw`(?:["'][^"']{6,}["']|(?=[^\s"',;]*[0-9!@#$%^&*+/=~_-])[^\s"',;]{6,})`;

const SECRET_RULES: readonly SecretRuleDefinition[] = Object.freeze([
  Object.freeze({
    name: 'private-key',
    severity: 'error',
    description: 'Private key material appears to be committed.',
    findingTitle: 'Potential committed private key',
    findingDescription: 'Private-key-shaped material was detected. The matched value and key body are intentionally omitted.',
    impact: 'If active, the key may allow impersonation, decryption, signing, or unauthorized access to protected systems.',
    remediation: 'Remove the key from version control, revoke or replace it, remove it from repository history where required, and use an approved secret store.',
    pattern: /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----/,
  }),
  providerRule({ name: 'github-token', label: 'GitHub token', severity: 'error', description: 'A GitHub token-shaped credential appears to be committed.', pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/ }),
  providerRule({ name: 'gitlab-token', label: 'GitLab token', severity: 'error', description: 'A GitLab token-shaped credential appears to be committed.', pattern: /\bgl(?:pat|rt|dt|ptt|soat|oas)-[A-Za-z0-9_-]{20,}\b/ }),
  providerRule({ name: 'aws-access-key', label: 'AWS access key identifier', severity: 'error', description: 'An AWS access key identifier appears to be committed.', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/ }),
  providerRule({ name: 'stripe-live-secret', label: 'Stripe live-mode key', severity: 'error', description: 'A Stripe live-mode secret or restricted API key appears to be committed.', pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/ }),
  providerRule({ name: 'slack-token', label: 'Slack token', severity: 'error', description: 'A Slack bot, user, app-level or refresh token appears to be committed.', pattern: /\bxox(?:[bpasr]|e\.xox[bp])-[A-Za-z0-9-]{20,}\b/ }),
  providerRule({ name: 'slack-webhook-url', label: 'Slack webhook URL', severity: 'warning', description: 'A Slack incoming-webhook URL appears to be committed.', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/ }),
  providerRule({ name: 'openai-api-key', label: 'OpenAI API key', severity: 'error', description: 'An OpenAI API key appears to be committed.', pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20}T3BlbkFJ[A-Za-z0-9_-]{20}\b|\bsk-proj-[A-Za-z0-9_-]{60,}\b/ }),
  providerRule({ name: 'anthropic-api-key', label: 'Anthropic API key', severity: 'error', description: 'An Anthropic API key appears to be committed.', pattern: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/ }),
  providerRule({ name: 'google-api-key', label: 'Google API key', severity: 'warning', description: 'A Google API key appears to be committed.', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ }),
  providerRule({ name: 'npm-token', label: 'npm token', severity: 'error', description: 'An npm access token appears to be committed.', pattern: /\bnpm_[A-Za-z0-9]{36}\b/ }),
  providerRule({ name: 'sendgrid-api-key', label: 'SendGrid API key', severity: 'error', description: 'A SendGrid API key appears to be committed.', pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ }),
  providerRule({ name: 'huggingface-token', label: 'Hugging Face token', severity: 'error', description: 'A Hugging Face access token appears to be committed.', pattern: /\bhf_[A-Za-z0-9]{34}\b/ }),
  providerRule({ name: 'digitalocean-token', label: 'DigitalOcean token', severity: 'error', description: 'A DigitalOcean API token appears to be committed.', pattern: /\bdo[opr]_v1_[a-f0-9]{64}\b/ }),
  providerRule({ name: 'shopify-token', label: 'Shopify token', severity: 'error', description: 'A Shopify access token appears to be committed.', pattern: /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/ }),
  providerRule({ name: 'pypi-token', label: 'PyPI token', severity: 'error', description: 'A PyPI upload token appears to be committed.', pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/ }),
  providerRule({ name: 'vault-token', label: 'HashiCorp Vault token', severity: 'error', description: 'A HashiCorp Vault token appears to be committed.', pattern: /\bhv[sb]\.[A-Za-z0-9_-]{24,}\b/ }),
  providerRule({ name: 'age-secret-key', label: 'age secret key', severity: 'error', description: 'An age encryption secret key appears to be committed.', pattern: /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/ }),
  providerRule({ name: 'telegram-bot-token', label: 'Telegram bot token', severity: 'warning', description: 'A Telegram bot token appears to be committed.', pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/ }),
  Object.freeze({
    name: 'connection-string-password',
    severity: 'warning',
    description: 'A database or broker URL with an embedded password appears to be committed.',
    findingTitle: 'Potential password in a connection string',
    findingDescription: 'A connection string containing a secret-shaped password was detected. The password and source line are intentionally omitted.',
    impact: 'If active, the credential may allow unauthorized access to the referenced database, broker, or service.',
    remediation: 'Rotate the credential, remove the connection string from repository history where required, and move it to protected server-side configuration.',
    pattern: new RegExp(String.raw`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|clickhouse):\/\/[^:/\s@]+:(?!${PLACEHOLDER_WORD}@|${PLACEHOLDER_PREFIX})[^@/\s]{8,}@`, 'i'),
  }),
  Object.freeze({
    name: 'sensitive-env-value',
    severity: 'warning',
    description: 'A sensitive environment variable appears to contain a non-placeholder value.',
    findingTitle: 'Potential committed sensitive environment value',
    findingDescription: 'A sensitive environment variable appears to contain a credential-like value. The variable value and source line are intentionally omitted.',
    impact: 'If the value is active, it may expose access to an application, provider, or protected service.',
    remediation: 'Remove the real value, retain only a placeholder in example files, rotate the credential if it was committed, and use deployment secret storage.',
    pattern: new RegExp(String.raw`^\s*(?:export\s+|ENV\s+|ARG\s+|-\s*)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_?KEY|TOKEN|PRIVATE_KEY)(?:_[A-Z0-9]+)*\s*[=:]\s*${NOT_PLACEHOLDER}${CREDENTIAL_VALUE}`, 'i'),
  }),
]);

const SECRET_RULES_BY_NAME = new Map(SECRET_RULES.map((rule) => [rule.name, rule]));

export function listInternalSecretRules(): readonly SecretRuleDefinition[] {
  return SECRET_RULES;
}

export function getInternalSecretRule(name: string): SecretRuleDefinition | undefined {
  return SECRET_RULES_BY_NAME.get(name);
}

export function createLegacySecretFingerprint(rule: string, file: string, line: number): string {
  if (!rule || !file || !Number.isInteger(line) || line < 1) throw new TypeError('fingerprint requires rule, file and a positive line number');
  return createHash('sha256').update(`axiomguard:v1\0${rule}\0${normalizePathSeparators(file)}\0${line}`).digest('hex');
}

export function inspectSecretText(file: string, content: string): InternalSecretFinding[] {
  const findings: InternalSecretFinding[] = [];
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    if (line.length === 0) continue;
    for (const rule of SECRET_RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(line)) {
        const lineNumber = index + 1;
        findings.push({ file, line: lineNumber, rule: rule.name, fingerprint: createLegacySecretFingerprint(rule.name, file, lineNumber) });
      }
    }
  }
  return findings;
}
