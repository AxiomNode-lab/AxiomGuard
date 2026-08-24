import path from 'node:path';

export function safePath(baseDirectory: string, candidate: string): string {
  const base = path.resolve(baseDirectory);
  const resolved = path.resolve(base, candidate);
  const relative = path.relative(base, resolved);

  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
    return resolved;
  }
  throw new Error('Path escapes the allowed base directory');
}

export function sanitizeFilename(input: string, maxLength = 180): string {
  if (!Number.isInteger(maxLength) || maxLength < 16) throw new RangeError('maxLength must be at least 16');

  let name = path.basename(input)
    .normalize('NFKC')
    .replace(/[<>:"/\\|?*\u0000-\u001F]/g, '_')
    .replace(/\s+/g, ' ')
    .replace(/[. ]+$/g, '')
    .trim();

  if (!name || name === '.' || name === '..') name = 'file';
  const windowsReserved = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;
  if (windowsReserved.test(name)) name = `_${name}`;

  if (name.length > maxLength) {
    const extension = path.extname(name);
    const stem = path.basename(name, extension);
    const keep = Math.max(1, maxLength - extension.length);
    name = `${stem.slice(0, keep)}${extension.slice(0, Math.max(0, maxLength - keep))}`;
  }
  return name;
}
