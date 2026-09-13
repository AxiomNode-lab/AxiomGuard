import path from 'node:path';

export interface SanitizeFilenameOptions {
  /** Maximum length in UTF-8 bytes. Default: 180 (POSIX NAME_MAX is 255). */
  maxBytes?: number;
  /** Keep a leading dot (hidden files such as `.htaccess`). Default: false, leading dots become `_`. */
  allowLeadingDot?: boolean;
  /** Replacement for the original name when nothing usable remains. Default: `file`. */
  fallback?: string;
}

/**
 * Resolve `candidate` inside `baseDirectory` and throw if the result escapes
 * it. Symbolic links are not resolved; call `fs.realpath` on the result when
 * the base directory may contain links that point outside it.
 */
export function safePath(baseDirectory: string, candidate: string): string {
  if (typeof candidate !== 'string' || candidate.includes('\0')) throw new Error('Path contains a NUL byte');
  const base = path.resolve(baseDirectory);
  const resolved = path.resolve(base, candidate);
  const relative = path.relative(base, resolved);

  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
    return resolved;
  }
  throw new Error('Path escapes the allowed base directory');
}

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;

/** Cut a string to at most `maxBytes` UTF-8 bytes without splitting a code point. */
function truncateBytes(value: string, maxBytes: number): string {
  if (Buffer.byteLength(value, 'utf8') <= maxBytes) return value;
  let output = '';
  let used = 0;
  for (const char of value) {
    const size = Buffer.byteLength(char, 'utf8');
    if (used + size > maxBytes) break;
    output += char;
    used += size;
  }
  return output;
}

/**
 * Turn untrusted input into a single safe filename component: strips path
 * separators, control and invisible format characters, Windows-reserved
 * names, trailing dots/spaces and, by default, leading dots. Length is
 * enforced in bytes so the result never exceeds filesystem limits or splits a
 * multi-byte character.
 */
export function sanitizeFilename(input: string, options: SanitizeFilenameOptions | number = {}): string {
  const resolved = typeof options === 'number' ? { maxBytes: options } : options;
  const maxBytes = resolved.maxBytes ?? 180;
  if (!Number.isInteger(maxBytes) || maxBytes < 16 || maxBytes > 255) throw new RangeError('maxBytes must be an integer between 16 and 255');
  const fallback = resolved.fallback ?? 'file';
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(fallback)) throw new TypeError('fallback must be 1-32 alphanumeric, dash or underscore characters');

  let name = path.win32.basename(path.posix.basename(String(input)))
    .normalize('NFKC')
    // Control, DEL, C1 and Unicode format characters are exactly what we strip.
    .replace(/[<>:"/\\|?*\u0000-\u001f\u007f-\u009f]|\p{Cf}/gu, '_')
    .replace(/\s+/g, ' ')
    .replace(/[. ]+$/g, '')
    .trim();

  if (!resolved.allowLeadingDot) name = name.replace(/^\.+/, (dots) => '_'.repeat(dots.length));
  if (!name || name === '.' || name === '..' || /^_+$/.test(name)) name = fallback;
  if (WINDOWS_RESERVED.test(name)) name = `_${name}`;

  if (Buffer.byteLength(name, 'utf8') > maxBytes) {
    const extension = path.extname(name);
    const stem = path.basename(name, extension);
    const extensionBytes = Buffer.byteLength(extension, 'utf8');
    const keepExtension = extensionBytes <= Math.floor(maxBytes / 2) ? extension : '';
    const stemBudget = maxBytes - Buffer.byteLength(keepExtension, 'utf8');
    name = `${truncateBytes(stem, Math.max(1, stemBudget)) || fallback}${keepExtension}`.replace(/[. ]+$/g, '') || fallback;
  }
  return name;
}
