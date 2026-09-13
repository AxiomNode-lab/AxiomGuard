import { assertSafeResolvedUrl, type SafeUrlOptions } from './web.js';

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const SENSITIVE_REDIRECT_HEADERS = ['authorization', 'cookie', 'proxy-authorization', 'x-api-key', 'x-auth-token'] as const;
const FORBIDDEN_AUTHORITY_HEADERS = new Set(['host', 'connection', 'transfer-encoding', 'content-length', 'upgrade']);

export type SafeFetchErrorCode =
  | 'timeout'
  | 'aborted'
  | 'too-many-redirects'
  | 'body-replay'
  | 'insecure-downgrade'
  | 'response-too-large'
  | 'forbidden-header'
  | 'invalid-redirect'
  | 'no-fetch';

/** Error thrown by `safeFetch` for policy decisions. `code` is stable; messages may change. */
export class SafeFetchError extends Error {
  readonly code: SafeFetchErrorCode;
  /** Status of the redirect response that triggered the error, when relevant. */
  readonly status: number | undefined;
  /** Validated redirect target, when relevant. */
  readonly location: string | undefined;

  constructor(code: SafeFetchErrorCode, message: string, details: { status?: number; location?: string } = {}) {
    super(message);
    this.name = 'SafeFetchError';
    this.code = code;
    this.status = details.status;
    this.location = details.location;
  }
}

export interface SafeFetchOptions extends SafeUrlOptions, Omit<RequestInit, 'redirect' | 'signal'> {
  /** Maximum number of redirects followed after re-validating every target. Default: 3. */
  maxRedirects?: number;
  /** Total timeout for the complete redirect chain and response body. Default: 10 seconds. */
  timeoutMs?: number;
  /** Optional caller cancellation signal. Also cancels a response body that is still streaming. */
  signal?: AbortSignal;
  /** Remove credential-bearing headers when an allowed redirect changes origin. Default: true. */
  stripSensitiveHeadersOnCrossOriginRedirect?: boolean;
  /** Follow an https -> http redirect. Default: false (the redirect is rejected). */
  allowInsecureRedirectDowngrade?: boolean;
  /**
   * `follow` (default) follows validated redirects; `manual` validates the first
   * redirect target and returns the 3xx response untouched so the caller can
   * decide, which is the safe way to handle redirected writes.
   */
  redirect?: 'follow' | 'manual';
  /** Abort the response body once it exceeds this many bytes. Default: unlimited. */
  maxResponseBytes?: number;
  /** Injectable fetch implementation for testing or controlled runtimes. */
  fetchImpl?: typeof fetch;
}

function validateSafeFetchOptions(options: SafeFetchOptions): void {
  const maxRedirects = options.maxRedirects ?? 3;
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > 10) {
    throw new RangeError('maxRedirects must be an integer between 0 and 10');
  }

  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new RangeError('timeoutMs must be an integer between 1 and 120000');
  }

  if (options.maxResponseBytes !== undefined && (!Number.isInteger(options.maxResponseBytes) || options.maxResponseBytes < 1)) {
    throw new RangeError('maxResponseBytes must be a positive integer');
  }
  if (options.redirect !== undefined && options.redirect !== 'follow' && options.redirect !== 'manual') {
    throw new TypeError("redirect must be 'follow' or 'manual'");
  }
}

function validateRequestHeaders(headers: Headers): void {
  for (const name of headers.keys()) {
    if (FORBIDDEN_AUTHORITY_HEADERS.has(name.toLowerCase())) {
      throw new SafeFetchError('forbidden-header', `safeFetch does not allow overriding transport header: ${name}`);
    }
  }
}

function shouldRewriteRedirectToGet(status: number, method: string): boolean {
  if (status === 303 && method !== 'HEAD') return true;
  return (status === 301 || status === 302) && method === 'POST';
}

function stripCrossOriginCredentials(headers: Headers): void {
  for (const header of SENSITIVE_REDIRECT_HEADERS) headers.delete(header);
}

async function cancelResponseBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Best-effort cleanup only. A redirect target is validated independently.
  }
}

/**
 * Wrap the response body so the timeout/caller signal keep applying while it
 * streams and so an oversized body is aborted instead of buffered.
 */
function guardResponse(response: Response, signal: AbortSignal, maxResponseBytes: number | undefined, cleanup: () => void): Response {
  if (!response.body) {
    cleanup();
    return response;
  }
  const reader = response.body.getReader();
  let received = 0;
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      let result: ReadableStreamReadResult<Uint8Array>;
      try {
        result = await reader.read();
      } catch (error) {
        cleanup();
        // Surface the timeout as the typed error rather than undici's generic AbortError.
        throw signal.aborted && signal.reason instanceof SafeFetchError ? signal.reason : error;
      }
      if (result.done) {
        cleanup();
        controller.close();
        return;
      }
      received += result.value.byteLength;
      if (maxResponseBytes !== undefined && received > maxResponseBytes) {
        const error = new SafeFetchError('response-too-large', `safeFetch response exceeded maxResponseBytes (${maxResponseBytes})`);
        await reader.cancel(error).catch(() => undefined);
        cleanup();
        throw error;
      }
      controller.enqueue(result.value);
    },
    async cancel(reason) {
      cleanup();
      await reader.cancel(reason).catch(() => undefined);
    },
  });
  const guarded = new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
  Object.defineProperties(guarded, {
    url: { value: response.url, configurable: true, enumerable: true },
    redirected: { value: response.redirected, configurable: true, enumerable: true },
    type: { value: response.type, configurable: true, enumerable: true },
  });
  return guarded;
}

/**
 * Fetch a public HTTP(S) resource while applying AxiomGuard URL checks before
 * the first request and before every followed redirect.
 *
 * This reduces common SSRF and credential-forwarding mistakes but cannot pin
 * DNS resolution to the connection used by the underlying fetch transport.
 * High-risk environments still need egress/network controls.
 */
export async function safeFetch(input: string | URL, options: SafeFetchOptions = {}): Promise<Response> {
  validateSafeFetchOptions(options);

  const {
    protocols,
    allowedHosts,
    allowCredentials,
    dangerouslyAllowPrivateTargets,
    maxRedirects = 3,
    timeoutMs = 10_000,
    stripSensitiveHeadersOnCrossOriginRedirect = true,
    allowInsecureRedirectDowngrade = false,
    redirect = 'follow',
    maxResponseBytes,
    fetchImpl,
    signal: callerSignal,
    method: initialMethod,
    headers: initialHeaders,
    body: initialBody,
    ...requestInit
  } = options;

  const urlOptions: SafeUrlOptions = {
    ...(protocols ? { protocols } : {}),
    ...(allowedHosts ? { allowedHosts } : {}),
    ...(allowCredentials !== undefined ? { allowCredentials } : {}),
    ...(dangerouslyAllowPrivateTargets !== undefined ? { dangerouslyAllowPrivateTargets } : {}),
  };

  const fetcher = fetchImpl ?? globalThis.fetch;
  if (typeof fetcher !== 'function') throw new SafeFetchError('no-fetch', 'safeFetch requires a Fetch API implementation');

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new SafeFetchError('timeout', `safeFetch timed out after ${timeoutMs}ms`)), timeoutMs);
  timeout.unref?.();

  const relayAbort = (): void => controller.abort(callerSignal?.reason);
  if (callerSignal?.aborted) relayAbort();
  else callerSignal?.addEventListener('abort', relayAbort, { once: true });

  let settled = false;
  const cleanup = (): void => {
    if (settled) return;
    settled = true;
    clearTimeout(timeout);
    callerSignal?.removeEventListener('abort', relayAbort);
  };

  try {
    let currentUrl = await assertSafeResolvedUrl(input, urlOptions);
    let method = (initialMethod ?? 'GET').toUpperCase();
    let body = initialBody;
    let headers = new Headers(initialHeaders);
    validateRequestHeaders(headers);

    for (let redirects = 0; ; redirects += 1) {
      const init: RequestInit = {
        ...requestInit,
        method,
        headers,
        redirect: 'manual',
        signal: controller.signal,
      };
      if (body !== undefined) init.body = body;

      const response = await fetcher(currentUrl, init);
      if (!REDIRECT_STATUSES.has(response.status)) return guardResponse(response, controller.signal, maxResponseBytes, cleanup);

      const location = response.headers.get('location');
      if (!location) return guardResponse(response, controller.signal, maxResponseBytes, cleanup);

      try {
        let nextCandidate: URL;
        try {
          nextCandidate = new URL(location, currentUrl);
        } catch {
          throw new SafeFetchError('invalid-redirect', 'safeFetch received an unparsable Location header', { status: response.status });
        }
        const nextUrl = await assertSafeResolvedUrl(nextCandidate, urlOptions);
        if (redirect === 'manual') return guardResponse(response, controller.signal, maxResponseBytes, cleanup);
        if (redirects >= maxRedirects) {
          throw new SafeFetchError('too-many-redirects', `safeFetch exceeded maxRedirects (${maxRedirects})`, { status: response.status, location: nextUrl.href });
        }
        if (currentUrl.protocol === 'https:' && nextUrl.protocol === 'http:' && !allowInsecureRedirectDowngrade) {
          throw new SafeFetchError('insecure-downgrade', 'safeFetch refuses to follow a redirect from https to http', { status: response.status, location: nextUrl.href });
        }
        const originChanged = nextUrl.origin !== currentUrl.origin;

        if (originChanged && stripSensitiveHeadersOnCrossOriginRedirect) {
          headers = new Headers(headers);
          stripCrossOriginCredentials(headers);
        }

        if (shouldRewriteRedirectToGet(response.status, method)) {
          method = 'GET';
          body = undefined;
          headers = new Headers(headers);
          headers.delete('content-type');
        } else if (body !== undefined) {
          throw new SafeFetchError('body-replay', 'safeFetch refuses to replay a request body across a redirect; handle the redirect explicitly', { status: response.status, location: nextUrl.href });
        }
        currentUrl = nextUrl;
      } finally {
        if (redirect !== 'manual') await cancelResponseBody(response);
      }
    }
  } catch (error) {
    cleanup();
    if (controller.signal.aborted && controller.signal.reason instanceof SafeFetchError) throw controller.signal.reason;
    throw error;
  }
}
