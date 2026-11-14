// Filesystem storage for one tree (data/private or data/cache). Every write is atomic:
// tmp file -> fsync -> close -> rename. tmp/ lives inside the tree so rename stays on one filesystem.

import { createHash, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, rm, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export class IntegrityError extends Error {}

/** 'sha512-<base64>' for a buffer. */
export function sha512Integrity(buf) {
  return 'sha512-' + createHash('sha512').update(buf).digest('base64');
}

/** Relative path of a blob, from a parsed integrity ({ algo, hex } from policy.parseIntegrity). */
export function blobRel({ algo, hex }) {
  return `blobs/${algo}/${hex.slice(0, 2)}/${hex}/data`;
}

export class Store {
  constructor(root) {
    this.root = root;
    this.tmpDir = join(root, 'tmp');
    this.locks = new Map();
  }

  async init() {
    await mkdir(this.tmpDir, { recursive: true });
    // Remove temp files left by a crash. Only old ones: `warm` may share this tree with a
    // running server whose in-flight writes must not be deleted.
    const cutoff = Date.now() - 60 * 60 * 1000;
    for (const entry of await readdir(this.tmpDir)) {
      const p = join(this.tmpDir, entry);
      const s = await stat(p).catch(() => null);
      if (s && s.mtimeMs < cutoff) await rm(p, { force: true });
    }
  }

  /** Callers pass only validated names/filenames, so joining is safe. */
  path(rel) {
    return join(this.root, rel);
  }

  async stat(rel) {
    try {
      return await stat(this.path(rel));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  async readJson(rel) {
    try {
      return JSON.parse(await readFile(this.path(rel), 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  async remove(rel) {
    await rm(this.path(rel), { force: true });
  }

  /**
   * Write via a temp file. `writer(fileHandle)` fills it; the file is fsynced before rename.
   * If `beforeRename` throws, nothing is stored.
   */
  async #atomic(rel, writer, beforeRename) {
    const dest = this.path(rel);
    const tmp = join(this.tmpDir, randomUUID());
    await mkdir(this.tmpDir, { recursive: true }); // the cache tree may be deleted while we run
    let fh = await open(tmp, 'wx', 0o644);
    try {
      await writer(fh);
      await fh.sync();
      await fh.close();
      fh = null;
      if (beforeRename) beforeRename();
      await mkdir(dirname(dest), { recursive: true });
      await rename(tmp, dest);
    } catch (err) {
      if (fh) await fh.close().catch(() => {});
      await rm(tmp, { force: true });
      throw err;
    }
  }

  writeFile(rel, data) {
    return this.#atomic(rel, (fh) => fh.writeFile(data));
  }

  /** Store a buffer as a content-addressed blob. Returns its sha512 integrity string. */
  async putBlob(buf) {
    const hex = createHash('sha512').update(buf).digest('hex');
    await this.writeFile(blobRel({ algo: 'sha512', hex }), buf);
    return 'sha512-' + Buffer.from(hex, 'hex').toString('base64');
  }

  /**
   * Stream bytes into a blob, verifying the hash before it becomes visible. On mismatch
   * nothing is stored and IntegrityError is thrown.
   * @param {AsyncIterable<Uint8Array>} source
   * @param {{ algo: string, hex: string }} expected
   */
  putBlobStream(source, expected) {
    const hash = createHash(expected.algo);
    let bytes = 0;
    return this.#atomic(
      blobRel(expected),
      async (fh) => {
        for await (const chunk of source) {
          hash.update(chunk);
          bytes += chunk.length;
          await fh.write(chunk);
        }
      },
      () => {
        const actual = hash.digest('hex');
        if (actual !== expected.hex) {
          throw new IntegrityError(`integrity mismatch: expected ${expected.algo}:${expected.hex.slice(0, 16)}…, got ${actual.slice(0, 16)}… (${bytes} bytes)`);
        }
      },
    );
  }

  /** Serialize read-modify-write sequences on the same key (in-process only). */
  lock(key, fn) {
    const prev = this.locks.get(key) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => {});
    this.locks.set(key, tail);
    tail.then(() => {
      if (this.locks.get(key) === tail) this.locks.delete(key);
    });
    return run;
  }
}
