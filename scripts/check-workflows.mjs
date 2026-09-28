import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const root = process.cwd();
const workflowDir = path.join(root, '.github', 'workflows');
const entries = (await readdir(workflowDir)).filter((name) => /\\.(?:yml|yaml)$/.test(name)).sort();

const violations = [];

for (const name of entries) {
  const file = path.join(workflowDir, name);
  const lines = (await readFile(file, 'utf8')).split(/\\r?\\n/);
  let runIndent = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const indent = line.match(/^\\s*/)?.[0].length ?? 0;
    const trimmed = line.trim();

    if (runIndent !== null && trimmed && indent <= runIndent) runIndent = null;

    if (/^\\s*run:\\s*\\|/.test(line)) {
      runIndent = indent + 2;
      continue;
    }

    if (runIndent !== null) {
      if (/\\$\\{\\{\\s*github\\.event\\./.test(line)) {
        violations.push(`${name}:${index + 1} interpolates github.event.* directly inside a shell run block`);
      }
      if (/\\$\\{\\{\\s*github\\.(?:head_ref|base_ref|ref_name)\\b/.test(line)) {
        violations.push(`${name}:${index + 1} interpolates an untrusted branch/ref context directly inside a shell run block`);
      }
    }

    if (/\\buses:\\s+[^.#][^\\s]*@/.test(line)) {
      const match = line.match(/\\buses:\\s+([^\\s]+)/);
      const target = match?.[1] ?? '';
      if (target && !target.startsWith('./') && !/@[0-9a-f]{40}$/i.test(target)) {
        violations.push(`${name}:${index + 1} uses a mutable external action ref: ${target}`);
      }
    }

    if (/\\buses:\\s+actions\\/checkout@/i.test(line)) {
      const following = lines.slice(index + 1, index + 6).join('\\n');
      if (!/persist-credentials:\\s*false/.test(following)) {
        violations.push(`${name}:${index + 1} actions/checkout is missing persist-credentials: false`);
      }
    }
  }
}

const workflowText = await Promise.all(entries.map((name) => readFile(path.join(workflowDir, name), 'utf8')));
for (let i = 0; i < entries.length; i += 1) {
  if (/^\\s*pull_request_target\\s*:/m.test(workflowText[i])) {
    violations.push(`${entries[i]} uses pull_request_target; review whether untrusted code can reach privileged steps`);
  }
}

if (violations.length > 0) {
  for (const violation of violations) console.error(`[workflow-security] ${violation}`);
  process.exit(1);
}

console.log(`Workflow security checks passed for ${entries.length} workflow file(s).`);
