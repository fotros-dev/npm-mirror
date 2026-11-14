// Private packages: we are the source of truth. This module deliberately has no access to the
// upstream client — it is neither imported nor passed in — so a private name can never leak
// to public npm.

import { createHash } from 'node:crypto';
import { log } from './log.js';
import { isValidVersion, parseIntegrity } from './policy.js';
import { blobRel } from './store.js';
import { HttpError, readBody, sendFile, sendJson } from './server.js';

/**
 * @param {{ config: object, store: import('./store.js').Store }} deps
 */
export function createPrivate({ config, store }) {
  const packumentRel = (name) => `packuments/${name}/local.json`;

  async function servePackument(req, res, name, ctx) {
    ctx.decision = 'serve-local';
    res.setHeader('x-cache', 'LOCAL');
    const sent = await sendFile(req, res, store.path(packumentRel(name)), {
      'content-type': 'application/json',
      vary: 'Accept',
    });
    if (!sent) throw new HttpError(404, 'not found');
  }

  async function serveTarball(req, res, name, file, ctx) {
    ctx.decision = 'serve-local';
    res.setHeader('x-cache', 'LOCAL');
    const doc = await store.readJson(packumentRel(name));
    const version = Object.values(doc?.versions ?? {}).find((v) => v.dist?.tarball?.endsWith(`/-/${file}`));
    if (!version) throw new HttpError(404, 'not found');

    const parsed = parseIntegrity(version.dist.integrity);
    if (!parsed) throw new Error(`stored integrity for ${name}@${version.version} is invalid`);
    const sent = await sendFile(req, res, store.path(blobRel(parsed)), { 'content-type': 'application/octet-stream' });
    if (!sent) {
      log.error('private tarball missing from disk', { pkg: name, version: version.version, integrity: version.dist.integrity });
      throw new HttpError(500, 'tarball missing from storage');
    }
  }

  async function publish(req, res, name, token, ctx) {
    ctx.decision = 'publish';
    const body = await readBody(req, config.bodyLimitBytes);

    let incoming;
    try {
      incoming = JSON.parse(body.toString('utf8'));
    } catch {
      throw new HttpError(400, 'body is not valid JSON');
    }
    if (incoming?.name !== name) throw new HttpError(400, 'package name in body does not match URL');

    const versions = Object.keys(incoming.versions ?? {});
    if (versions.length !== 1) throw new HttpError(400, 'publish must contain exactly one version');
    const version = versions[0];
    const manifest = incoming.versions[version];
    if (!isValidVersion(version) || manifest?.version !== version || manifest.name !== name) {
      throw new HttpError(400, 'invalid version manifest');
    }

    const attachments = Object.values(incoming._attachments ?? {});
    if (attachments.length !== 1 || typeof attachments[0]?.data !== 'string') {
      throw new HttpError(400, 'publish must contain exactly one tarball attachment');
    }
    const tarball = Buffer.from(attachments[0].data, 'base64');
    if (tarball.length === 0) throw new HttpError(400, 'tarball attachment is empty');

    const integrity = 'sha512-' + createHash('sha512').update(tarball).digest('base64');
    const shasum = createHash('sha1').update(tarball).digest('hex');
    if (manifest.dist?.integrity && manifest.dist.integrity !== integrity) {
      throw new HttpError(400, 'dist.integrity does not match the attached tarball');
    }

    await store.lock(name, async () => {
      const stored = (await store.readJson(packumentRel(name))) ?? {
        _id: name,
        name,
        'dist-tags': {},
        versions: {},
        time: { created: new Date().toISOString() },
      };
      // Immutability is what makes caching tarballs forever safe.
      if (stored.versions[version]) throw new HttpError(403, `cannot publish over existing version ${version}`);

      // Tarball first, packument second: a crash in between leaves only an orphan blob.
      await store.putBlob(tarball);

      const filename = `${name.split('/')[1]}-${version}.tgz`;
      manifest.dist = { ...manifest.dist, integrity, shasum, tarball: `${config.baseUrl}/${name}/-/${filename}` };
      const now = new Date().toISOString();

      stored.versions[version] = manifest;
      Object.assign(stored['dist-tags'], incoming['dist-tags']);
      stored.description = manifest.description;
      stored.readme = manifest.readme ?? incoming.readme;
      stored.license = manifest.license;
      stored.time = { ...stored.time, modified: now, [version]: now };
      // _attachments is transport only and is never stored.

      await store.writeFile(packumentRel(name), JSON.stringify(stored));
    });

    log.info('publish', {
      user: token.user,
      pkg: name,
      version,
      integrity,
      postinstall: Boolean(manifest.scripts?.postinstall),
    });
    sendJson(res, 201, { ok: true });
  }

  return { servePackument, serveTarball, publish };
}
