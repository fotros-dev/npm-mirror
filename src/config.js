import { existsSync, readFileSync, openSync, writeSync, fsyncSync, closeSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const DATA_DIR = join(ROOT, 'data');
export const CONFIG_PATH = join(ROOT, 'config.json');

const SCOPE = /^@[a-z0-9-~][a-z0-9-._~]*$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;

// Tunables only. baseUrl and privateScopes have no default on purpose: a deployment that forgot
// them must fail at startup instead of silently running with someone else's values.
const DEFAULTS = {
  listen: { host: '127.0.0.1', port: 4873 },
  upstream: { url: 'https://registry.npmjs.org' },
  ttl: { packumentSeconds: 300, negativeSeconds: 60 },
  breaker: { threshold: 5, openMs: 30000, maxOpenMs: 300000 },
  timeouts: { packumentMs: 3000, tarballHeadersMs: 30000 },
  bodyLimitBytes: 104857600,
};

export class ConfigError extends Error {}

/** Read config.json as written on disk. It is optional: {} if absent. */
export function readRawConfig() {
  if (!existsSync(CONFIG_PATH)) return {};
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
  } catch (err) {
    throw new ConfigError(`${CONFIG_PATH} is not valid JSON: ${err.message}`);
  }
}

/** Write config.json atomically (used by the token commands). */
export function writeRawConfig(raw) {
  const tmp = join(ROOT, `.config.${randomUUID()}.tmp`);
  const fd = openSync(tmp, 'w', 0o600);
  try {
    writeSync(fd, JSON.stringify(raw, null, 2) + '\n');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, CONFIG_PATH);
}

/** Load, apply defaults, validate. Throws ConfigError with a readable message. */
export function loadConfig() {
  const raw = readRawConfig();
  const config = { ...DEFAULTS, ...raw };
  for (const key of ['listen', 'upstream', 'ttl', 'breaker', 'timeouts']) {
    config[key] = { ...DEFAULTS[key], ...raw[key] };
  }

  // Environment overrides config.json. Nothing loads a .env file: whoever starts us exports these.
  const env = process.env;
  if (env.BASE_URL) config.baseUrl = env.BASE_URL;
  if (env.LISTEN_HOST) config.listen.host = env.LISTEN_HOST;
  if (env.UPSTREAM_URL) config.upstream.url = env.UPSTREAM_URL;
  if (env.PRIVATE_SCOPES) config.privateScopes = env.PRIVATE_SCOPES.split(',').map((s) => s.trim()).filter(Boolean);
  if (env.PORT) {
    config.listen.port = Number(env.PORT);
    if (!Number.isInteger(config.listen.port) || config.listen.port < 1 || config.listen.port > 65535) {
      throw new ConfigError(`PORT must be a TCP port number, got ${JSON.stringify(env.PORT)}`);
    }
  }

  if (typeof config.baseUrl !== 'string' || config.baseUrl.trim() === '') {
    throw new ConfigError('"baseUrl" is required: set BASE_URL or "baseUrl" in config.json (e.g. "http://localhost:4873")');
  }
  config.baseUrl = config.baseUrl.trim().replace(/\/+$/, '');

  if (!Array.isArray(config.privateScopes) || config.privateScopes.length === 0) {
    throw new ConfigError('"privateScopes" is required: set PRIVATE_SCOPES (e.g. "@fotros-internal") or "privateScopes" in config.json');
  }
  for (const scope of config.privateScopes) {
    if (typeof scope !== 'string' || !SCOPE.test(scope)) {
      throw new ConfigError(`invalid private scope ${JSON.stringify(scope)} (expected "@name")`);
    }
  }

  config.upstream.url = String(config.upstream.url).replace(/\/+$/, '');
  config.tokens = [...(Array.isArray(config.tokens) ? config.tokens : []), ...parseTokensEnv(env.TOKENS)];
  for (const t of config.tokens) {
    if (typeof t?.user !== 'string' || !['read', 'write'].includes(t.access) || !SHA256_HEX.test(t.sha256 ?? '')) {
      throw new ConfigError(`invalid token entry for ${JSON.stringify(t?.user ?? t?.id)}: needs user, access read|write, sha256 (64 hex chars)`);
    }
  }
  return config;
}

/**
 * TOKENS="user:access:sha256hex,user2:read:sha256hex". Hashes, not tokens: the plaintext never
 * has to exist on the server. `node src/main.js token env --user <u> --access <a>` makes one.
 */
function parseTokensEnv(value) {
  if (!value) return [];
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) => {
      const [user, access, sha256, ...extra] = entry.split(':');
      if (!user || extra.length > 0) throw new ConfigError(`TOKENS: malformed entry ${JSON.stringify(entry.slice(0, 20) + '…')} (expected user:access:sha256)`);
      return { id: `env:${user}`, user, access, sha256 };
    });
}
