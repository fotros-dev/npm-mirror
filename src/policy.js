// Pure decision logic. No I/O in this file: everything here is a function of its arguments.

import { createHash, timingSafeEqual } from 'node:crypto';

const NAME = /^(?:@[a-zA-Z0-9-~][a-zA-Z0-9-._~]*\/)?[a-zA-Z0-9-~][a-zA-Z0-9-._~]*$/;
const MAX_NAME_LENGTH = 214;

export const ABBREVIATED_ACCEPT = 'application/vnd.npm.install-v1+json';

/**
 * Split a raw request path on the literal "/-/". Nothing is decoded here.
 * @returns {{ name: string, file: string | null } | null}
 */
export function parsePath(pathname) {
  const i = pathname.indexOf('/-/');
  if (i === -1) return { name: pathname.slice(1), file: null };
  const file = pathname.slice(i + 3);
  if (file === '' || file.includes('/')) return null;
  return { name: pathname.slice(1, i), file };
}

/** Decode exactly once, then validate. Returns null on any failure. */
function decodeOnce(raw) {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/** @returns {string | null} the canonical package name, or null if invalid */
export function normalizeName(raw) {
  const name = decodeOnce(raw);
  if (name === null || name.length > MAX_NAME_LENGTH || !NAME.test(name)) return null;
  return name;
}

/** @returns {string | null} the tarball filename, or null if invalid */
export function normalizeFilename(raw) {
  const file = decodeOnce(raw);
  if (file === null || file.length > 255) return null;
  if (file.startsWith('.') || file.includes('/') || file.includes('\\') || file.includes('\0')) return null;
  if (!file.endsWith('.tgz')) return null;
  return file;
}

/** @returns {'private' | 'proxied'} */
export function classify(name, privateScopes) {
  for (const scope of privateScopes) {
    if (name.startsWith(scope + '/')) return 'private';
  }
  return 'proxied';
}

export function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Find the token record matching an `Authorization: Bearer <token>` header.
 * @returns {{ id: string, user: string, access: string } | null}
 */
export function findToken(header, tokens) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return null;
  const secret = header.slice(7).trim();
  if (secret === '') return null;
  const presented = Buffer.from(hashToken(secret), 'hex');
  let match = null;
  for (const t of tokens) {
    const stored = Buffer.from(t.sha256, 'hex');
    if (stored.length === presented.length && timingSafeEqual(stored, presented)) match = t;
  }
  return match;
}

/**
 * 401 means "we don't know who you are", 403 means "we do and the answer is no".
 * The realm is checked before the token so a proxied PUT is always 403.
 * @returns {{ ok: true } | { ok: false, status: 401 | 403, error: string }}
 */
export function authorize(method, realm, token) {
  const read = method === 'GET' || method === 'HEAD';
  if (realm === 'proxied') {
    if (read) return { ok: true };
    return { ok: false, status: 403, error: 'cannot publish to a proxied (public) package name' };
  }
  if (!token) return { ok: false, status: 401, error: 'authentication required' };
  if (read) return { ok: true };
  if (method === 'PUT' && token.access === 'write') return { ok: true };
  return { ok: false, status: 403, error: 'token does not have write access' };
}

/**
 * What to do with a proxied packument request.
 * @param {'fresh' | 'stale' | 'negative' | 'none'} cacheState
 * @param {boolean} breakerOpen
 */
export function decide(cacheState, breakerOpen) {
  switch (cacheState) {
    case 'fresh':
      return 'serve-cached';
    case 'stale':
      return breakerOpen ? 'serve-stale' : 'revalidate';
    case 'negative':
      return 'not-found';
    default:
      // Never 404 here: "upstream unreachable" is not "package doesn't exist".
      return breakerOpen ? 'unavailable' : 'fetch';
  }
}

const HASH_BYTES = { sha512: 64, sha1: 20 };

/**
 * Parse an SRI integrity string (or a legacy hex sha1 shasum) into something safe to build a
 * path from. Prefers sha512. Returns null unless the hash is well-formed.
 * @returns {{ algo: 'sha512' | 'sha1', hex: string } | null}
 */
export function parseIntegrity(integrity, shasum) {
  const found = {};
  for (const part of String(integrity ?? '').split(/\s+/)) {
    const m = /^(sha512|sha1)-([A-Za-z0-9+/]+={0,2})$/.exec(part);
    if (!m) continue;
    const bytes = Buffer.from(m[2], 'base64');
    if (bytes.length === HASH_BYTES[m[1]]) found[m[1]] ??= bytes.toString('hex');
  }
  if (found.sha512) return { algo: 'sha512', hex: found.sha512 };
  if (found.sha1) return { algo: 'sha1', hex: found.sha1 };
  if (typeof shasum === 'string' && /^[0-9a-f]{40}$/.test(shasum)) return { algo: 'sha1', hex: shasum };
  return null;
}

const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function isValidVersion(v) {
  return typeof v === 'string' && v.length <= 256 && VERSION.test(v);
}
