const tag = process.env.RELEASE_TAG ?? '';
const releasePrerelease = process.env.RELEASE_PRERELEASE === 'true';

const match = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/.exec(tag);
if (!match) {
  console.error(`[release-tag] invalid release tag: ${tag || '<missing>'}`);
  process.exit(1);
}

const tagPrerelease = tag.includes('-');
if (tagPrerelease !== releasePrerelease) {
  console.error(`[release-tag] release prerelease flag does not match tag ${tag}`);
  process.exit(1);
}

console.log(`Release tag metadata is valid for ${tag} (prerelease=${releasePrerelease}).`);
