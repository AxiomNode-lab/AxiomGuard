import { createSecurityHeaders, type SecurityHeadersOptions } from './headers.js';

export type SecurityPresetName = 'api' | 'web' | 'isolated';

const PRESETS: Record<SecurityPresetName, SecurityHeadersOptions> = {
  api: {
    contentSecurityPolicy: false,
    hsts: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    crossOriginEmbedderPolicy: false,
  },
  web: {
    contentSecurityPolicy: {
      'default-src': ["'self'"],
      'base-uri': ["'self'"],
      'frame-ancestors': ["'none'"],
      'object-src': ["'none'"],
      'script-src': ["'self'"],
    },
    hsts: false,
    crossOriginOpenerPolicy: 'same-origin',
    crossOriginResourcePolicy: 'same-origin',
  },
  isolated: {
    contentSecurityPolicy: {
      'default-src': ["'self'"],
      'base-uri': ["'self'"],
      'frame-ancestors': ["'none'"],
      'object-src': ["'none'"],
      'script-src': ["'self'"],
    },
    hsts: false,
    crossOriginOpenerPolicy: 'same-origin',
    crossOriginResourcePolicy: 'same-origin',
    crossOriginEmbedderPolicy: 'require-corp',
  },
};

function clonePreset(options: SecurityHeadersOptions): SecurityHeadersOptions {
  const csp = options.contentSecurityPolicy;
  if (csp && typeof csp === 'object') {
    const cloned = Object.fromEntries(Object.entries(csp).map(([key, value]) => [key, Array.isArray(value) ? [...value] : value]));
    return { ...options, contentSecurityPolicy: cloned };
  }
  return { ...options };
}

export function getSecurityHeaderPreset(name: SecurityPresetName): SecurityHeadersOptions {
  return clonePreset(PRESETS[name]);
}

export function createPresetSecurityHeaders(name: SecurityPresetName, overrides: SecurityHeadersOptions = {}): Record<string, string> {
  const preset = getSecurityHeaderPreset(name);
  return createSecurityHeaders({ ...preset, ...overrides });
}
