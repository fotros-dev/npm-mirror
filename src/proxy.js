// Public packages: served from data/cache, filled from upstream. Everything here is disposable.

import { promisify } from 'node:util';
import { gzip as gzipCb } from 'node:zlib';
import { log } from './log.js';
import { ABBREVIATED_ACCEPT, decide, parseIntegrity } from './policy.js';
import { IntegrityError, blobRel } from './store.js';
import { HttpError, sendFile } from './server.js';
import { UpstreamUnavailable, singleFlight } from './upstream.js';

const gzip = promisify(gzipCb);

const CONTENT_TYPE = { abbreviated: ABBREVIATED_ACCEPT, full: 'application/json' };

/**
 * @param {{ config: object, store: import('./store.js').Store, upstream: ReturnType<import('./upstream.js').createUpstream> }} deps
 */
export function createProxy({ config, store, upstream }) {
  const ttlMs = config.ttl.packumentSeconds * 1000;
  const negativeTtlMs = config.ttl.negativeSeconds * 1000;
  const dir = (name) => `packuments/${name}`;
  const negativeRel = (name) => `negative/${name}.json`;

  function updateJson(name, file, update) {
    return store.lock(name, async () => {
      const rel = `${dir(name)}/${file}`;
      await store.writeFile(rel, JSON.stringify(update((await store.readJson(rel)) ?? {})));
    });
  }

  async function cacheState(name, kind) {
    const meta = (await store.readJson(`${dir(name)}/meta.json`))?.[kind];
    // Tarball URLs are baked in at write time: an entry written under another baseUrl is a miss.
    if (meta?.baseUrl === config.baseUrl && (await store.stat(`${dir(name)}/${kind}.json.gz`))) {
      return { state: Date.now() - meta.fetchedAt < ttlMs ? 'fresh' : 'stale', meta };
    }
    const negative = await store.readJson(negativeRel(name));
    if (negative && negative.expiresAt > Date.now()) return { state: 'negative' };
    return { state: 'none' };
  }

  /** Point every version's tarball at us. integrity/shasum are left untouched. */
  function rewriteTarballs(doc, name) {
    for (const v of Object.values(doc.versions ?? {})) {
      const tarball = v?.dist?.tarball;
      if (typeof tarball !== 'string' || !tarball.includes('/-/')) continue;
      const filename = tarball.split('/-/')[1];
      v.dist.tarball = `${config.baseUrl}/${name}/-/${filename}`;
    }
  }

  async function storePackument(name, kind, etag, body) {
    let doc;
    try {
      doc = JSON.parse(body.toString('utf8'));
    } catch (err) {
      throw new UpstreamUnavailable(`upstream sent invalid JSON for ${name}`, { cause: err });
    }
    rewriteTarballs(doc, name);
    const json = Buffer.from(JSON.stringify(doc));

    // Remember filename -> integrity so tarball requests don't have to parse the packument.
    const index = {};
    for (const v of Object.values(doc.versions ?? {})) {
      const tarball = v?.dist?.tarball;
      if (typeof tarball !== 'string' || !tarball.includes('/-/')) continue;
      index[tarball.split('/-/')[1]] = { integrity: v.dist.integrity, shasum: v.dist.shasum };
    }

    // Data files before meta.json: a crash in between looks like a miss, not a dangling pointer.
    await store.writeFile(`${dir(name)}/${kind}.json`, json);
    await store.writeFile(`${dir(name)}/${kind}.json.gz`, await gzip(json));
    await updateJson(name, 'tarballs.json', (old) => ({ ...old, ...index }));
    await updateJson(name, 'meta.json', (meta) => ({ ...meta, [kind]: { etag, fetchedAt: Date.now(), baseUrl: config.baseUrl } }));
    await store.remove(negativeRel(name));
  }

  /**
   * Fetch (or revalidate) a packument from upstream and update the cache.
   * @returns {Promise<'stored' | 'not-modified' | 'not-found' | 'other'>}
   */
  function refresh(name, kind, etag) {
    return singleFlight(`packument:${kind}:${name}`, async () => {
      const r = await upstream.fetchPackument(name, kind, etag);
      if (r.status === 200) {
        await storePackument(name, kind, r.etag, r.body);
        return 'stored';
      }
      if (r.status === 304) {
        await updateJson(name, 'meta.json', (meta) => ({ ...meta, [kind]: { ...meta[kind], fetchedAt: Date.now() } }));
        return 'not-modified';
      }
      if (r.status === 404) {
        // Only an explicit 404 from a healthy upstream is cached as "doesn't exist".
        if (!etag) await store.writeFile(negativeRel(name), JSON.stringify({ expiresAt: Date.now() + negativeTtlMs }));
        return 'not-found';
      }
      log.warn('unexpected upstream status for packument', { pkg: name, kind, status: r.status });
      return 'other';
    });
  }

  /**
   * Make sure a packument is available locally, following the decide() table.
   * @returns {Promise<{ outcome: 'ok' | 'not-found' | 'unavailable', xcache: string, decision: string, cacheState: string }>}
   */
  async function resolvePackument(name, kind, { forceRevalidate = false } = {}) {
    const { state, meta } = await cacheState(name, kind);
    let decision = decide(state, upstream.packuments.isOpen());
    if (forceRevalidate && decision === 'serve-cached') decision = 'revalidate';
    const result = (outcome, xcache) => ({ outcome, xcache, decision, cacheState: state });

    if (decision === 'serve-cached') return result('ok', 'HIT');
    if (decision === 'serve-stale') return result('ok', 'STALE');
    if (decision === 'not-found') return result('not-found', 'HIT');
    if (decision === 'unavailable') return result('unavailable', 'MISS');

    const revalidating = decision === 'revalidate';
    let r;
    try {
      r = await refresh(name, kind, revalidating ? meta.etag : undefined);
    } catch (err) {
      if (!(err instanceof UpstreamUnavailable)) throw err;
      log.warn('upstream unavailable', { pkg: name, kind, decision, err: err.message });
      return revalidating ? result('ok', 'STALE') : result('unavailable', 'MISS');
    }

    if (r === 'stored') return result('ok', revalidating ? 'REVALIDATED' : 'MISS');
    if (r === 'not-modified') return result('ok', 'REVALIDATED');
    if (revalidating) {
      // Breaking everyone's installs over a transient 404 is worse than serving a stale copy.
      if (r === 'not-found') log.error('upstream returned 404 for a cached package; serving stale copy', { pkg: name, kind });
      return result('ok', 'STALE');
    }
    return r === 'not-found' ? result('not-found', 'MISS') : result('unavailable', 'MISS');
  }

  function unavailable(breaker) {
    return new HttpError(503, 'upstream registry unavailable and not cached', {
      'retry-after': String(breaker.isOpen() ? breaker.retryAfterSeconds() : 5),
    });
  }

  async function servePackument(req, res, name, ctx) {
    const kind = (req.headers.accept ?? '').includes(ABBREVIATED_ACCEPT) ? 'abbreviated' : 'full';
    const r = await resolvePackument(name, kind);
    Object.assign(ctx, { kind, decision: r.decision, cacheState: r.cacheState });
    res.setHeader('x-cache', r.xcache);
    res.setHeader('vary', 'Accept, Accept-Encoding');
    if (r.outcome === 'not-found') throw new HttpError(404, 'not found');
    if (r.outcome === 'unavailable') throw unavailable(upstream.packuments);

    const gz = /\bgzip\b/.test(req.headers['accept-encoding'] ?? '');
    const headers = { 'content-type': CONTENT_TYPE[kind] };
    if (gz) headers['content-encoding'] = 'gzip';
    const sent = await sendFile(req, res, store.path(`${dir(name)}/${kind}.json${gz ? '.gz' : ''}`), headers);
    if (!sent) throw new HttpError(503, 'cache entry disappeared, retry', { 'retry-after': '1' });
  }

  async function lookupTarball(name, filename) {
    const entry = (await store.readJson(`${dir(name)}/tarballs.json`))?.[filename];
    return entry ? { entry, parsed: parseIntegrity(entry.integrity, entry.shasum) } : null;
  }

  /**
   * Make sure a tarball blob is on disk, downloading and verifying it if needed.
   * @returns {Promise<{ outcome: 'ok' | 'not-found' | 'unavailable' | 'bad-gateway', xcache: string, decision: string, rel?: string, integrity?: string }>}
   */
  async function ensureTarball(name, filename) {
    let found = await lookupTarball(name, filename);
    if (!found) {
      // Unknown filename: load the packument (or refresh it once — a new version may exist).
      let p = await resolvePackument(name, 'abbreviated');
      if (p.outcome !== 'ok') return { ...p, decision: 'packument-' + p.outcome };
      found = await lookupTarball(name, filename);
      if (!found && p.xcache === 'HIT') {
        p = await resolvePackument(name, 'abbreviated', { forceRevalidate: true });
        found = await lookupTarball(name, filename);
      }
      if (!found) return { outcome: 'not-found', xcache: 'MISS', decision: 'not-in-packument' };
    }
    if (!found.parsed) return { outcome: 'bad-gateway', xcache: 'MISS', decision: 'no-integrity' };

    const rel = blobRel(found.parsed);
    const integrity = found.entry.integrity ?? `sha1:${found.entry.shasum}`;
    if (await store.stat(rel)) return { outcome: 'ok', xcache: 'HIT', decision: 'serve-cached', rel, integrity };
    if (upstream.tarballs.isOpen()) return { outcome: 'unavailable', xcache: 'MISS', decision: 'unavailable' };

    try {
      const r = await singleFlight(`tarball:${rel}`, () =>
        upstream.fetchTarball(name, filename, (body) => store.putBlobStream(body, found.parsed)),
      );
      if (r.status === 404) return { outcome: 'not-found', xcache: 'MISS', decision: 'fetch' };
      if (r.status !== 200) {
        log.warn('unexpected upstream status for tarball', { pkg: name, file: filename, status: r.status });
        return { outcome: 'bad-gateway', xcache: 'MISS', decision: 'fetch' };
      }
    } catch (err) {
      if (err instanceof IntegrityError) {
        log.error('tarball failed integrity check; not stored', { pkg: name, file: filename, err: err.message });
        return { outcome: 'bad-gateway', xcache: 'MISS', decision: 'fetch' };
      }
      if (err instanceof UpstreamUnavailable) {
        log.warn('upstream unavailable', { pkg: name, file: filename, err: err.message });
        return { outcome: 'unavailable', xcache: 'MISS', decision: 'fetch' };
      }
      throw err;
    }
    return { outcome: 'ok', xcache: 'MISS', decision: 'fetch', rel, integrity };
  }

  async function serveTarball(req, res, name, filename, ctx) {
    const r = await ensureTarball(name, filename);
    ctx.decision = r.decision;
    res.setHeader('x-cache', r.xcache);
    if (r.outcome === 'not-found') throw new HttpError(404, 'not found');
    if (r.outcome === 'unavailable') throw unavailable(upstream.tarballs);
    if (r.outcome === 'bad-gateway') throw new HttpError(502, 'upstream tarball could not be verified');

    // Already gzipped: no Content-Encoding, never re-compressed.
    const sent = await sendFile(req, res, store.path(r.rel), { 'content-type': 'application/octet-stream' });
    if (!sent) throw new HttpError(503, 'cache entry disappeared, retry', { 'retry-after': '1' });
  }

  return { servePackument, serveTarball, resolvePackument, ensureTarball };
}
