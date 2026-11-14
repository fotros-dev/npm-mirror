// HTTP server: routing and the request pipeline (parse -> normalize -> classify -> authorize ->
// resolve). Realm handlers are passed in; this file never talks to upstream itself.

import http from 'node:http';
import { open } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { randomBytes } from 'node:crypto';
import { log } from './log.js';
import { authorize, classify, findToken, normalizeFilename, normalizeName, parsePath } from './policy.js';

export class HttpError extends Error {
  constructor(status, message, headers = {}) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

export function sendJson(res, status, body, headers = {}) {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { ...headers, 'content-type': 'application/json', 'content-length': data.length });
  res.end(res.req.method === 'HEAD' ? undefined : data);
}

/**
 * Stream a file with Content-Length. Returns false if the file does not exist.
 * The size comes from the opened handle, so a concurrent rename can't make it lie.
 */
export async function sendFile(req, res, path, headers) {
  let fh;
  try {
    fh = await open(path, 'r');
  } catch (err) {
    if (err.code === 'ENOENT') return false;
    throw err;
  }
  let stream;
  try {
    const { size } = await fh.stat();
    res.writeHead(200, { ...headers, 'content-length': size });
    if (req.method === 'HEAD') {
      res.end();
      return true;
    }
    stream = fh.createReadStream(); // the stream now owns (and closes) the handle
  } finally {
    if (!stream) await fh.close();
  }
  try {
    await pipeline(stream, res);
  } catch (err) {
    // npm cancels requests all the time; pipeline has already destroyed the file stream.
    if (err.code !== 'ERR_STREAM_PREMATURE_CLOSE') throw err;
  }
  return true;
}

/** Read a request body, counting real bytes against `limit` (Content-Length is not trusted). */
export async function readBody(req, limit) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > limit) throw new HttpError(413, `request body exceeds ${limit} bytes`, { connection: 'close' });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function countBytes(res) {
  const counter = { bytes: 0 };
  const { write, end } = res;
  const add = (chunk, encoding) => {
    if (chunk && typeof chunk !== 'function') {
      counter.bytes += typeof chunk === 'string' ? Buffer.byteLength(chunk, typeof encoding === 'string' ? encoding : 'utf8') : chunk.length;
    }
  };
  res.write = function (chunk, encoding, cb) {
    add(chunk, encoding);
    return write.call(this, chunk, encoding, cb);
  };
  res.end = function (chunk, encoding, cb) {
    add(chunk, encoding);
    return end.call(this, chunk, encoding, cb);
  };
  return counter;
}

/**
 * @param {{ config: object, privateHandler: object, proxyHandler: object }} deps
 */
export function createServer({ config, privateHandler, proxyHandler }) {
  async function handle(req, res, ctx) {
    const method = req.method;
    const pathname = req.url.split('?')[0]; // raw: no URL parsing, no decoding

    if (pathname === '/-/ping') return sendJson(res, 200, {});
    if (pathname === '/-/whoami') {
      const token = findToken(req.headers.authorization, config.tokens);
      if (!token) throw new HttpError(401, 'authentication required', { 'www-authenticate': 'Bearer' });
      ctx.user = token.user;
      return sendJson(res, 200, { username: token.user });
    }
    if (pathname.startsWith('/-/') || pathname === '/') throw new HttpError(404, 'not found');

    // 1. Parse
    const parsed = parsePath(pathname);
    if (!parsed) throw new HttpError(400, 'invalid tarball path');

    // 2. Normalize
    const name = normalizeName(parsed.name);
    if (!name) throw new HttpError(400, 'invalid package name');
    let file = null;
    if (parsed.file !== null) {
      file = normalizeFilename(parsed.file);
      if (!file) throw new HttpError(400, 'invalid tarball filename');
    }
    ctx.pkg = name;
    if (file) ctx.file = file;

    const isRead = method === 'GET' || method === 'HEAD';
    if (!isRead && !(method === 'PUT' && file === null)) throw new HttpError(404, 'not found');

    // 3. Classify
    const realm = classify(name, config.privateScopes);
    ctx.realm = realm;

    // 4. Authorize
    const token = findToken(req.headers.authorization, config.tokens);
    if (token) ctx.user = token.user;
    const verdict = authorize(method, realm, token);
    if (!verdict.ok) {
      throw new HttpError(verdict.status, verdict.error, verdict.status === 401 ? { 'www-authenticate': 'Bearer' } : {});
    }

    // 5. Resolve
    if (realm === 'private') {
      if (method === 'PUT') return privateHandler.publish(req, res, name, token, ctx);
      if (file) return privateHandler.serveTarball(req, res, name, file, ctx);
      return privateHandler.servePackument(req, res, name, ctx);
    }
    if (file) return proxyHandler.serveTarball(req, res, name, file, ctx);
    return proxyHandler.servePackument(req, res, name, ctx);
  }

  const server = http.createServer((req, res) => {
    const started = performance.now();
    const ctx = { reqId: randomBytes(4).toString('hex'), method: req.method, path: req.url };
    const counter = countBytes(res);
    res.setHeader('x-cache', 'MISS');

    // 'close' fires after 'finish' and also when the client aborts, so every request is logged.
    res.on('close', () => {
      log.info('request', {
        ...ctx,
        status: res.statusCode,
        durationMs: Math.round(performance.now() - started),
        bytes: counter.bytes,
        ...(!res.writableFinished && { aborted: true }),
      });
    });

    handle(req, res, ctx).catch((err) => {
      if (err instanceof HttpError) {
        if (!res.headersSent) return sendJson(res, err.status, { error: err.message }, err.headers);
        return res.destroy();
      }
      log.error('unhandled error', { reqId: ctx.reqId, err });
      if (!res.headersSent) sendJson(res, 500, { error: 'internal server error' });
      else res.destroy(); // mid-stream: the status line is gone, so cut the connection
    });
  });

  server.headersTimeout = 10_000;
  server.requestTimeout = 60_000;
  server.keepAliveTimeout = 30_000;
  return server;
}
