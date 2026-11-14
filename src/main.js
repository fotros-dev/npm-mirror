#!/usr/bin/env node
// CLI entry: serve | token | warm

import { randomBytes } from 'node:crypto';
import { unwatchFile, watchFile } from 'node:fs';
import { join } from 'node:path';
import { CONFIG_PATH, ConfigError, DATA_DIR, loadConfig, readRawConfig, writeRawConfig } from './config.js';
import { log } from './log.js';
import { hashToken } from './policy.js';
import { createPrivate } from './private.js';
import { createProxy } from './proxy.js';
import { createServer } from './server.js';
import { Store } from './store.js';
import { createUpstream } from './upstream.js';
import { warm } from './warm.js';

const USAGE = `usage:
  node src/main.js [serve]          (serve is the default, e.g. under pm2)
  node src/main.js token create --user <name> --access <read|write>   (stored in config.json)
  node src/main.js token env --user <name> --access <read|write>      (prints a TOKENS entry, stores nothing)
  node src/main.js token list
  node src/main.js token revoke <id>
  node src/main.js warm <package-lock.json> [more...]`;

function fail(message) {
  console.error(message);
  process.exit(1);
}

async function openStores() {
  // Separate trees, separate instances: wiping the cache can never touch private packages.
  const privateStore = new Store(join(DATA_DIR, 'private'));
  const cacheStore = new Store(join(DATA_DIR, 'cache'));
  await privateStore.init();
  await cacheStore.init();
  return { privateStore, cacheStore };
}

async function serve() {
  const config = loadConfig();
  const { privateStore, cacheStore } = await openStores();
  const upstream = createUpstream(config);
  const server = createServer({
    config,
    privateHandler: createPrivate({ config, store: privateStore }),
    proxyHandler: createProxy({ config, store: cacheStore, upstream }),
  });

  // Pick up tokens created/revoked while running, without a restart.
  watchFile(CONFIG_PATH, { interval: 2000 }, () => {
    try {
      config.tokens = loadConfig().tokens;
      log.info('tokens reloaded', { count: config.tokens.length });
    } catch (err) {
      log.error('config reload failed; keeping previous tokens', { err });
    }
  });

  server.listen(config.listen.port, config.listen.host, () => {
    log.info('listening', {
      host: config.listen.host,
      port: config.listen.port,
      baseUrl: config.baseUrl,
      upstream: config.upstream.url,
      privateScopes: config.privateScopes,
      tokens: config.tokens.length,
    });
    if (config.tokens.length === 0) {
      log.warn('no tokens configured: publishing and reading private packages are denied for everyone');
    }
  });

  let stopping = false;
  const shutdown = (signal) => {
    if (stopping) process.exit(1);
    stopping = true;
    log.info('shutting down', { signal });
    unwatchFile(CONFIG_PATH);
    // Give destroyed responses a moment to emit 'close' (and log) before forcing exit; the
    // force is needed because idle upstream keep-alive sockets can hold the event loop open.
    server.close(() => setTimeout(() => process.exit(0), 100).unref());
    server.closeIdleConnections();
    setTimeout(() => server.closeAllConnections(), 10_000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

function token(args) {
  const [sub, ...rest] = args;
  const raw = readRawConfig();
  raw.tokens ??= [];

  if (sub === 'create' || sub === 'env') {
    const opts = {};
    for (let i = 0; i < rest.length; i += 2) opts[rest[i].replace(/^--/, '')] = rest[i + 1];
    if (!opts.user || !/^[A-Za-z0-9._-]+$/.test(opts.user)) fail(`token ${sub}: --user is required (letters, digits, . _ -)`);
    const access = opts.access ?? 'read';
    if (access !== 'read' && access !== 'write') fail(`token ${sub}: --access must be "read" or "write"`);

    const secret = randomBytes(32).toString('base64url');
    if (sub === 'env') {
      console.log(`token for ${opts.user} (${access}). Give it to the user; it is not stored anywhere:\n\n${secret}\n`);
      console.log(`add this entry to TOKENS (comma-separated):\n\n${opts.user}:${access}:${hashToken(secret)}\n`);
      return;
    }
    const id = randomBytes(4).toString('hex');
    raw.tokens.push({ id, user: opts.user, access, sha256: hashToken(secret), createdAt: new Date().toISOString() });
    writeRawConfig(raw);
    console.log(`created token ${id} for ${opts.user} (${access}). It will not be shown again:\n\n${secret}\n`);
    return;
  }
  if (sub === 'list') {
    console.log('tokens in config.json (TOKENS from the environment are not listed):');
    for (const t of raw.tokens) console.log(`${t.id}  ${t.user}  ${t.access}  ${t.createdAt ?? ''}`);
    if (raw.tokens.length === 0) console.log('(no tokens)');
    return;
  }
  if (sub === 'revoke') {
    const id = rest[0];
    const before = raw.tokens.length;
    raw.tokens = raw.tokens.filter((t) => t.id !== id);
    if (raw.tokens.length === before) fail(`no token with id ${id}`);
    writeRawConfig(raw);
    console.log(`revoked ${id}`);
    return;
  }
  fail(USAGE);
}

async function warmCommand(files) {
  if (files.length === 0) fail(USAGE);
  const config = loadConfig();
  const { cacheStore } = await openStores();
  const proxy = createProxy({ config, store: cacheStore, upstream: createUpstream(config) });
  const counts = await warm(files, { config, proxy });
  console.log(
    `warm: ${counts.fetched} fetched, ${counts.cached} already cached, ${counts.failed} failed, ` +
      `${counts.skippedPrivate} private skipped, ${counts.skippedNonRegistry} non-registry skipped`,
  );
  if (counts.failed > 0) process.exitCode = 1;
}

const [command = 'serve', ...args] = process.argv.slice(2);
try {
  if (command === 'serve') await serve();
  else if (command === 'token') token(args);
  else if (command === 'warm') await warmCommand(args);
  else fail(USAGE);
} catch (err) {
  if (err instanceof ConfigError) fail(err.message);
  throw err;
}
