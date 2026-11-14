// Pre-fetch everything in one or more package-lock.json files, so the cache can serve those
// projects when npm is unreachable.

import { readFile } from 'node:fs/promises';
import { log } from './log.js';
import { classify, normalizeFilename, normalizeName, parseIntegrity } from './policy.js';

const CONCURRENCY = 8;

/** Yield { name, resolved, integrity } for every registry tarball in a lockfile (v1, v2, v3). */
function* lockfileEntries(lock) {
  if (lock.packages) {
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (path === '' || entry.link || entry.inBundle || !entry.resolved) continue;
      const name = entry.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      yield { name, resolved: entry.resolved, integrity: entry.integrity };
    }
    return;
  }
  // lockfileVersion 1: nested "dependencies"
  function* walk(deps) {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      if (entry.resolved && !entry.bundled) yield { name, resolved: entry.resolved, integrity: entry.integrity };
      yield* walk(entry.dependencies);
    }
  }
  yield* walk(lock.dependencies);
}

/**
 * @param {string[]} files
 * @param {{ config: object, proxy: ReturnType<import('./proxy.js').createProxy> }} deps
 */
export async function warm(files, { config, proxy }) {
  const work = new Map();
  const counts = { fetched: 0, cached: 0, skippedPrivate: 0, skippedNonRegistry: 0, failed: 0 };

  for (const file of files) {
    const lock = JSON.parse(await readFile(file, 'utf8'));
    for (const e of lockfileEntries(lock)) {
      const name = normalizeName(e.name);
      const filename = e.resolved.includes('/-/') ? normalizeFilename(e.resolved.split('/-/').pop()) : null;
      if (!name || !filename || !/^https?:\/\//.test(e.resolved)) {
        counts.skippedNonRegistry++;
        continue;
      }
      if (classify(name, config.privateScopes) === 'private') {
        counts.skippedPrivate++;
        continue;
      }
      work.set(`${name}/-/${filename}`, { name, filename, integrity: e.integrity });
    }
  }

  log.info('warm start', { files, tarballs: work.size });
  const queue = [...work.values()];
  let done = 0;

  async function worker() {
    for (let item = queue.shift(); item; item = queue.shift()) {
      const p = await proxy.resolvePackument(item.name, 'abbreviated');
      const r = p.outcome === 'ok' ? await proxy.ensureTarball(item.name, item.filename) : p;
      const expected = parseIntegrity(item.integrity);
      const actual = r.outcome === 'ok' ? parseIntegrity(r.integrity) : null;

      if (r.outcome !== 'ok') {
        counts.failed++;
        log.error('warm failed', { pkg: item.name, file: item.filename, outcome: r.outcome, decision: r.decision });
      } else if (expected && actual && expected.algo === actual.algo && expected.hex !== actual.hex) {
        counts.failed++;
        log.error('warm: lockfile integrity differs from registry', { pkg: item.name, file: item.filename, lockfile: item.integrity, registry: r.integrity });
      } else if (r.xcache === 'HIT') {
        counts.cached++;
      } else {
        counts.fetched++;
      }
      if (++done % 100 === 0) log.info('warm progress', { done, total: work.size });
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  log.info('warm done', counts);
  return counts;
}
