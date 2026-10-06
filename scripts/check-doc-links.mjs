import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const root = process.cwd();
const ignored = new Set(['.git', 'node_modules', 'dist', 'coverage', 'build', '.next']);

async function walk(current) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (ignored.has(entry.name)) continue;
    const full = path.join(current, entry.name);
    if (entry.isDirectory()) files.push(...await walk(full));
    else if (entry.isFile() && /\.md$/i.test(entry.name)) files.push(full);
  }
  return files;
}

function isExternal(target) {
  return /^(?:[a-z][a-z0-9+.-]*:|#)/i.test(target);
}

const markdownFiles = await walk(root);
const failures = [];

for (const file of markdownFiles) {
  const source = await readFile(file, 'utf8');
  const withoutCode = source.replace(/```[\s\S]*?```/g, '');
  const re = /!?\[[^]]*\]\(([^)\s]+)(?:\s+['"][^)]*['"])?\)/g;
  for (const match of withoutCode.matchAll(re)) {
    const target = match[1] ?? '';
    if (!target || isExternal(target)) continue;
    const clean = target.split('#', 1)[0].split('?', 1)[0];
    if (!clean) continue;
    const resolved = path.resolve(path.dirname(file), clean);
    try { await stat(resolved); }
    catch { failures.push(`${path.relative(root, file).split(path.sep).join('/')} -> ${target}`); }
  }
}

if (failures.length) {
  for (const failure of failures) console.error(`[docs-links] broken internal link: ${failure}`);
  process.exit(1);
}

console.log(`Documentation link checks passed for ${markdownFiles.length} Markdown file(s).`);