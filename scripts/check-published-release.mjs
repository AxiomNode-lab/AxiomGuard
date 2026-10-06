import { readFile } from 'node:fs/promises';

const packageJson = JSON.parse(await readFile('package.json', 'utf8'));
const lockfile = JSON.parse(await readFile('package-lock.json', 'utf8'));
const changelog = await readFile('CHANGELOG.md', 'utf8');

const version = packageJson.version;
const lockRootVersion = lockfile.packages?.['']?.version;
const headingPattern = /^## \[(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\](?: - (.+))?$/gm;
const headings = [...changelog.matchAll(headingPattern)];
const failures = [];

if (!version) failures.push('package.json has no version');
if (lockRootVersion !== version) failures.push(`package-lock.json root package version is ${lockRootVersion ?? 'missing'}, expected ${version}`);
if (headings[0]?.[1] !== version) failures.push(`CHANGELOG.md first version entry is ${headings[0]?.[1] ?? 'missing'}, expected ${version}`);

const versionDate = headings.find((heading) => heading[1] === version)?.[2];
if (!versionDate || !/^\\d{4}-\\d{2}-\\d{2}$/.test(versionDate)) {
  failures.push(`CHANGELOG.md entry for ${version} must use a YYYY-MM-DD release date before publication`);
}

if (failures.length) {
  for (const failure of failures) console.error(`[published-release-check] ${failure}`);
  process.exit(1);
}

console.log(`Published release metadata is valid for ${version} (${versionDate}).`);
