import { lstat, open, readFile, readdir } from 'node:fs/promises';
import type { Dirent, Stats } from 'node:fs';
import path from 'node:path';
import type { RepositoryFile, RuleExecutionContext } from './contracts.js';
import { ScannerError } from './errors.js';
import {
  DEFAULT_FILESYSTEM_CONCURRENCY,
  DEFAULT_IGNORE_DIRECTORIES,
  DEFAULT_MAX_FILE_BYTES,
  compareStrings,
  globToRegExp,
  isSupportedTextPath,
  mapWithConcurrency,
  normalizePathSeparators,
} from './file-policy.js';

export interface RepositoryScanContextOptions {
  target: string;
  detectedStackIds?: readonly string[];
  ignoreDirectories?: readonly string[];
  ignoreFiles?: readonly string[];
  maxFileBytes?: number;
  concurrency?: number;
  signal?: AbortSignal;
}

const STABLE_ID_PATTERN = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/;

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new ScannerError('SCAN_ABORTED', 'Repository scan was aborted.');
}

function validatePositiveInteger(value: number, label: string, maximum?: number): void {
  if (!Number.isInteger(value) || value < 1 || (maximum !== undefined && value > maximum)) {
    throw new ScannerError('INVALID_SCAN_OPTIONS', `${label} must be a positive integer${maximum === undefined ? '' : ` no greater than ${maximum}`}.`);
  }
}

function normalizeRequestedPath(relativePath: string): string {
  if (typeof relativePath !== 'string' || relativePath.length === 0 || relativePath.includes('\0') || relativePath.includes('\\')) {
    throw new ScannerError('INVALID_FILE_PATH', 'Repository file path must be a normalized relative path.');
  }
  if (path.posix.isAbsolute(relativePath) || path.win32.isAbsolute(relativePath)) {
    throw new ScannerError('INVALID_FILE_PATH', 'Absolute repository file paths are not allowed.');
  }
  const segments = relativePath.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..') || path.posix.normalize(relativePath) !== relativePath) {
    throw new ScannerError('INVALID_FILE_PATH', 'Repository file path traversal is not allowed.');
  }
  return relativePath;
}

function validateStringList(values: readonly string[], label: string, stableIds = false): void {
  if (values.some((value) => typeof value !== 'string' || value.length === 0 || (stableIds && !STABLE_ID_PATTERN.test(value)))) {
    throw new ScannerError('INVALID_SCAN_OPTIONS', `${label} must contain ${stableIds ? 'stable identifiers' : 'non-empty strings'}.`);
  }
}

async function hasNullByte(filePath: string): Promise<boolean> {
  const handle = await open(filePath, 'r');
  try {
    const buffer = Buffer.allocUnsafe(8192);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).includes(0);
  } finally {
    await handle.close();
  }
}

export class RepositoryScanContext implements RuleExecutionContext {
  readonly detectedStackIds: readonly string[];
  readonly signal?: AbortSignal;
  readonly #root: string;
  readonly #ignoredDirectories: ReadonlySet<string>;
  readonly #ignoredFiles: readonly RegExp[];
  readonly #maxFileBytes: number;
  readonly #concurrency: number;
  #filesPromise?: Promise<readonly RepositoryFile[]>;

  private constructor(root: string, options: RepositoryScanContextOptions) {
    this.#root = root;
    this.detectedStackIds = Object.freeze([...new Set(options.detectedStackIds ?? [])].sort(compareStrings));
    this.#ignoredDirectories = new Set(options.ignoreDirectories ?? DEFAULT_IGNORE_DIRECTORIES);
    this.#ignoredFiles = (options.ignoreFiles ?? []).map(globToRegExp);
    this.#maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.#concurrency = options.concurrency ?? DEFAULT_FILESYSTEM_CONCURRENCY;
    if (options.signal !== undefined) this.signal = options.signal;
  }

  static async create(options: RepositoryScanContextOptions): Promise<RepositoryScanContext> {
    if (typeof options.target !== 'string' || options.target.trim().length === 0) {
      throw new ScannerError('INVALID_SCAN_TARGET', 'Scan target must be a non-empty directory path.');
    }
    validatePositiveInteger(options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES, 'maxFileBytes');
    validatePositiveInteger(options.concurrency ?? DEFAULT_FILESYSTEM_CONCURRENCY, 'concurrency', 256);
    validateStringList(options.detectedStackIds ?? [], 'detectedStackIds', true);
    validateStringList(options.ignoreDirectories ?? DEFAULT_IGNORE_DIRECTORIES, 'ignoreDirectories');
    validateStringList(options.ignoreFiles ?? [], 'ignoreFiles');
    throwIfAborted(options.signal);

    const root = path.resolve(options.target);
    let stat: Stats;
    try {
      stat = await lstat(root);
    } catch {
      throw new ScannerError('INVALID_SCAN_TARGET', 'Scan target could not be accessed.');
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new ScannerError('INVALID_SCAN_TARGET', 'Scan target must be a directory and not a symbolic link.');
    }
    return new RepositoryScanContext(root, options);
  }

  listFiles(): Promise<readonly RepositoryFile[]> {
    this.#filesPromise ??= this.#collectFiles();
    return this.#filesPromise;
  }

  async readTextFile(relativePath: string): Promise<string> {
    throwIfAborted(this.signal);
    const normalized = normalizeRequestedPath(relativePath);
    if (!isSupportedTextPath(normalized) || this.#isIgnoredPath(normalized)) {
      throw new ScannerError('FILE_NOT_ELIGIBLE', `Repository file "${normalized}" is not eligible for scanning.`);
    }
    const absolute = path.join(this.#root, ...normalized.split('/'));
    await this.#assertSafeFile(normalized, absolute);
    let content: string;
    try {
      content = await readFile(absolute, 'utf8');
    } catch {
      throw new ScannerError('REPOSITORY_ACCESS_FAILED', `Repository file "${normalized}" could not be read.`);
    }
    throwIfAborted(this.signal);
    if (content.includes('\0')) throw new ScannerError('FILE_NOT_ELIGIBLE', `Repository file "${normalized}" is binary.`);
    return content;
  }

  async #collectFiles(): Promise<readonly RepositoryFile[]> {
    const candidates: Array<{ path: string; absolute: string }> = [];
    await this.#walk(this.#root, '', candidates);
    const inspected = await mapWithConcurrency(candidates, this.#concurrency, async (candidate): Promise<RepositoryFile | undefined> => {
      throwIfAborted(this.signal);
      try {
        const stat = await lstat(candidate.absolute);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > this.#maxFileBytes || await hasNullByte(candidate.absolute)) return undefined;
        return Object.freeze({ path: candidate.path, size: stat.size });
      } catch (error) {
        if (error instanceof ScannerError) throw error;
        throw new ScannerError('REPOSITORY_ACCESS_FAILED', `Repository file "${candidate.path}" could not be inspected.`);
      }
    });
    return Object.freeze(inspected.filter((file): file is RepositoryFile => file !== undefined).sort((left, right) => compareStrings(left.path, right.path)));
  }

  async #walk(directory: string, relativeDirectory: string, candidates: Array<{ path: string; absolute: string }>): Promise<void> {
    throwIfAborted(this.signal);
    let entries: Dirent[];
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      throw new ScannerError('REPOSITORY_ACCESS_FAILED', 'A repository directory could not be enumerated.');
    }
    entries.sort((left, right) => compareStrings(left.name, right.name));
    for (const entry of entries) {
      throwIfAborted(this.signal);
      if (entry.isSymbolicLink()) continue;
      const relativePath = relativeDirectory === '' ? entry.name : `${relativeDirectory}/${entry.name}`;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!this.#ignoredDirectories.has(entry.name)) await this.#walk(absolute, relativePath, candidates);
      } else if (entry.isFile() && isSupportedTextPath(relativePath) && !this.#isIgnoredFile(relativePath)) {
        candidates.push({ path: normalizePathSeparators(relativePath), absolute });
      }
    }
  }

  #isIgnoredFile(relativePath: string): boolean {
    return this.#ignoredFiles.some((pattern) => pattern.test(relativePath));
  }

  #isIgnoredPath(relativePath: string): boolean {
    const segments = relativePath.split('/');
    return segments.slice(0, -1).some((segment) => this.#ignoredDirectories.has(segment)) || this.#isIgnoredFile(relativePath);
  }

  async #assertSafeFile(relativePath: string, absolute: string): Promise<void> {
    let current = this.#root;
    const segments = relativePath.split('/');
    for (let index = 0; index < segments.length; index += 1) {
      current = path.join(current, segments[index]!);
      let stat: Stats;
      try {
        stat = await lstat(current);
      } catch {
        throw new ScannerError('FILE_NOT_ELIGIBLE', `Repository file "${relativePath}" could not be accessed.`);
      }
      if (stat.isSymbolicLink()) throw new ScannerError('FILE_NOT_ELIGIBLE', `Repository file "${relativePath}" uses a symbolic link.`);
      if (index < segments.length - 1 && !stat.isDirectory()) throw new ScannerError('FILE_NOT_ELIGIBLE', `Repository file "${relativePath}" could not be accessed.`);
      if (index === segments.length - 1 && (!stat.isFile() || stat.size > this.#maxFileBytes)) {
        throw new ScannerError('FILE_NOT_ELIGIBLE', `Repository file "${relativePath}" is not eligible for scanning.`);
      }
    }
    if (absolute !== current) throw new ScannerError('INVALID_FILE_PATH', 'Repository file path could not be normalized safely.');
  }
}

export function createRepositoryScanContext(options: RepositoryScanContextOptions): Promise<RepositoryScanContext> {
  return RepositoryScanContext.create(options);
}
