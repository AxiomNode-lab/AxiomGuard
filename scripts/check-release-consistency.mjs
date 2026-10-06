import { readFile } from 'node:fs/promises';

const packageJson = JSON.parse(await readFile('package.json', 'utf8'));
const lockfile = JSON.parse(await readFile('package-lock.json', 'utf8'));
const changelog = await readFile('CHANGELOG.md', 'utf8');

const version = packageJson.version;
const lockRootVersion = lockfile.packages?.['']?.version;
const lockTopLevelVersion = lockfile.version === 3 ? lockfile.version && lockfile.packages?.['']?.version : lockfile.version;
const changelogHeading = `## [${version}]`;

const failures = [];
if (!version) failures.push('package.json has no version');
if (lockRootVersion !== version) failures.push(`package-lock.json root package version is ${lockRootVersion ?? 'missing'}, expected ${version}`);
if (!changelog.includes(changelogHeading)) failures.push(`CHANGELOG.md has no entry for ${version}`);

if (failures.length) {
  for (const failure of failures) console.error(`[release-consistency] ${failure}`);
  process.exit(1);
}

console.log(`Release metadata is consistent for ${version}.`);
