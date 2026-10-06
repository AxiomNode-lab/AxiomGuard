import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const root = process.cwd();
const workflowDir = path.join(root, '.github', 'workflows');
const entries = (await readdir(workflowDir)).filter((name) => /\.(?:yml|yaml)$/.test(name)).sort();

const violations = [];

for (const name of entries) {
  const file = path.join(workflowDir, name);
  const lines = (await readFile(file, 'utf8')).split(/\r?\n/);
  let runIndent = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const indent = line.match(/^\s*/)?.[0].length ?? 0;
    const trimmed = line.trim();

    if (runIndent !== null && trimmed && indent <= runIndent) runIndent = null;

    if (/^\s*(?:-\s*)?run:\s*[|>]/.test(line)) {
      runIndent = indent + 2;
      continue;
    }

    const inlineRun = line.match(/^\s*(?:-\s*)?run:\s+(?![|>])(.+)$/);
    if (inlineRun && /\$\{\{\s*github\.(?:event\.|head_ref|base_ref|ref_name)\b/.test(inlineRun[1])) {
      violations.push(`${name}:${index + 1} interpolates untrusted github context directly inside an inline shell run`);
    }

    if (runIndent !== null) {
      if (/\$\{\{\s*github\.event\./.test(line)) {
        violations.push(`${name}:${index + 1} interpolates github.event.* directly inside a shell run block`);
      }
      if (/\$\{\{\s*github\.(?:head_ref|base_ref|ref_name)\b/.test(line)) {
        violations.push(`${name}:${index + 1} interpolates an untrusted branch/ref context directly inside a shell run block`);
      }
    }

    const usesMatch = line.match(/^\s*(?:-\s*)?uses:\s+([^\s#]+)/);
    if (usesMatch) {
      const target = usesMatch[1] ?? '';
      if (!target.startsWith('./')) {
        const at = target.lastIndexOf('@');
        const ref = at >= 0 ? target.slice(at + 1) : '';
        const pinnedAction = /^[0-9a-f]{40}$/i.test(ref);
        const pinnedDockerImage = target.startsWith('docker://') && /^sha256:[0-9a-f]{64}$/i.test(ref);
        if (!pinnedAction && !pinnedDockerImage) {
          violations.push(`${name}:${index + 1} uses a mutable external action ref: ${target}`);
        }
      }
    }
    if (/\buses:\s+actions\/checkout@/i.test(line)) {
      const following = lines.slice(index + 1, index + 21).join('\n');
      if (!/persist-credentials:\s*false/.test(following)) {
        violations.push(`${name}:${index + 1} actions/checkout is missing persist-credentials: false`);
      }
    }
  }
}

const workflowText = await Promise.all(entries.map((name) => readFile(path.join(workflowDir, name), 'utf8')));

const workflowByName = new Map(entries.map((name, index) => [name, workflowText[index] ?? '']));
const npmPublishWorkflow = workflowByName.get('publish-npmjs.yml');
if (npmPublishWorkflow) {
  if (!npmPublishWorkflow.includes('npm install --global npm@11.21.0')) {
    violations.push('publish-npmjs.yml must use npm 11.21.0+ for OIDC prerelease dist-tag support');
  }
  if (!npmPublishWorkflow.includes('--tag "${{ steps.version.outputs.dist-tag }}"')) {
    violations.push('publish-npmjs.yml must publish with the computed dist-tag');
  }
  if (!npmPublishWorkflow.includes('DIST_TAG: ${{ steps.version.outputs.dist-tag }}')) {
    violations.push('publish-npmjs.yml must carry the dist-tag output into the verification step');
  }
  if (!npmPublishWorkflow.includes('scripts/check-release-tag.mjs')) {
    violations.push('publish-npmjs.yml must validate release tag prerelease metadata');
  }
}

const packagePublishWorkflow = workflowByName.get('publish-package.yml');
if (packagePublishWorkflow) {
  if (!packagePublishWorkflow.includes('npm publish --ignore-scripts --tag "$DIST_TAG"')) {
    violations.push('publish-package.yml must keep prerelease publication on the beta dist-tag');
  }
  if (!packagePublishWorkflow.includes('DIST_TAG: ${{ steps.version.outputs.dist-tag }}')) {
    violations.push('publish-package.yml must carry the dist-tag output into the publish step');
  }
  if (!packagePublishWorkflow.includes('dist-tags.${DIST_TAG}')) {
    violations.push('publish-package.yml must verify the computed dist-tag points to the published version');
  }
  const packageVerifyStep = packagePublishWorkflow
    .split('- name: Verify package version in GitHub Packages', 2)[1]
    ?.split('\\n      - name:', 1)[0] ?? '';
  if (!packageVerifyStep.includes('DIST_TAG: ${{ steps.version.outputs.dist-tag }}')) {
    violations.push('publish-package.yml verification step must receive the computed dist-tag');
  }
  if (!packagePublishWorkflow.includes('scripts/check-release-tag.mjs')) {
    violations.push('publish-package.yml must validate release tag prerelease metadata');
  }
}

const containerPublishWorkflow = workflowByName.get('publish-container.yml');
if (containerPublishWorkflow) {
  if (!containerPublishWorkflow.includes("type=semver,pattern={{major}}.{{minor}},enable=${{ github.event_name == 'release' && github.event.release.prerelease == false }}")) {
    violations.push('publish-container.yml must not create major.minor tags for prerelease releases');
  }
  if (!containerPublishWorkflow.includes("type=raw,value=latest,enable=${{ github.event_name == 'release' && github.event.release.prerelease == false }}")) {
    violations.push('publish-container.yml must not move latest for prerelease releases');
  }
  if (!containerPublishWorkflow.includes('scripts/check-release-tag.mjs')) {
    violations.push('publish-container.yml must validate release tag prerelease metadata');
  }
}
for (let i = 0; i < entries.length; i += 1) {
  if (/^\s*pull_request_target\s*:/m.test(workflowText[i])) {
    violations.push(`${entries[i]} uses pull_request_target; review whether untrusted code can reach privileged steps`);
  }
}

if (violations.length > 0) {
  for (const violation of violations) console.error(`[workflow-security] ${violation}`);
  process.exit(1);
}

console.log(`Workflow security checks passed for ${entries.length} workflow file(s).`);
