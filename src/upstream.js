// Upstream (public npm) client: explicit timeouts, one circuit breaker per kind of request,
// and single-flight de-duplication of concurrent identical requests.

import { log } from './log.js';
import { ABBREVIATED_ACCEPT } from './policy.js';

/** Upstream is unreachable or unhealthy: "don't know", never "doesn't exist". */
export class UpstreamUnavailable extends Error {}

const USER_AGENT = 'npm-mirror (+node ' + process.version + ')';
/** Abort a response body that stops delivering bytes for this long. */
const BODY_IDLE_MS = 30_000;

class Breaker {
  constructor(name, { threshold, openMs, maxOpenMs }) {
    this.name = name;
    this.threshold = threshold;
    this.baseOpenMs = openMs;
    this.maxOpenMs = maxOpenMs;
    this.openMs = openMs;
    this.state = 'closed';
    this.failures = 0;
    this.openUntil = 0;
    this.probing = false;
  }

  #transition(to, extra = {}) {
    log.warn('breaker state change', { breaker: this.name, from: this.state, to, ...extra });
    this.state = to;
  }

  #refresh() {
    if (this.state === 'open' && Date.now() >= this.openUntil) this.#transition('half-open');
  }

  /** True if a request made right now would be rejected without touching the network. */
  isOpen() {
    this.#refresh();
    return this.state === 'open' || (this.state === 'half-open' && this.probing);
  }

  retryAfterSeconds() {
    return Math.max(1, Math.ceil((this.openUntil - Date.now()) / 1000));
  }

  /** Claim permission to make a request. In half-open, exactly one caller gets through. */
  tryAcquire() {
    this.#refresh();
    if (this.state === 'closed') return true;
    if (this.state === 'half-open' && !this.probing) {
      this.probing = true;
      return true;
    }
    return false;
  }

  success() {
    this.failures = 0;
    this.probing = false;
    this.openMs = this.baseOpenMs;
    if (this.state !== 'closed') this.#transition('closed');
  }

  failure(err) {
    this.probing = false;
    if (this.state === 'half-open') {
      this.openMs = Math.min(this.openMs * 2, this.maxOpenMs);
      this.#open(err);
    } else if (this.state === 'closed' && ++this.failures >= this.threshold) {
      this.#open(err);
    }
  }

  #open(err) {
    this.openUntil = Date.now() + this.openMs;
    this.#transition('open', { failures: this.failures, openMs: this.openMs, lastError: err?.message });
  }
}

const inflight = new Map();

/** Run fn once per key at a time; concurrent callers with the same key share the result. */
export function singleFlight(key, fn) {
  let p = inflight.get(key);
  if (!p) {
    p = Promise.resolve()
      .then(fn)
      .finally(() => inflight.delete(key));
    inflight.set(key, p);
  }
  return p;
}

/** Wrap a fetch body: abort if idle too long, and remember whether the network failed. */
async function* guardedBody(body, controller, outcome) {
  if (!body) return;
  let timer;
  const arm = () => {
    clearTimeout(timer);
    timer = setTimeout(() => controller.abort(new Error(`response body idle for ${BODY_IDLE_MS}ms`)), BODY_IDLE_MS);
  };
  try {
    arm();
    for await (const chunk of body) {
      arm();
      yield chunk;
    }
  } catch (err) {
    outcome.networkError = err;
    throw new UpstreamUnavailable(`reading upstream body failed: ${err.message}`, { cause: err });
  } finally {
    clearTimeout(timer);
  }
}

export function createUpstream(config) {
  const base = config.upstream.url;
  const packuments = new Breaker('packuments', config.breaker);
  const tarballs = new Breaker('tarballs', config.breaker);

  /**
   * One upstream request through a breaker. `headersMs` bounds the time to response headers.
   * 5xx/429/network errors count as breaker failures; anything else (incl. 404) is success.
   * `consume(res, body)` reads the response; its return value is returned.
   */
  async function request(breaker, url, headers, headersMs, consume) {
    if (!breaker.tryAcquire()) throw new UpstreamUnavailable(`${breaker.name} circuit is open`);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error(`no response headers within ${headersMs}ms`)), headersMs);
    const started = performance.now();
    let res;
    try {
      res = await fetch(url, { headers: { 'user-agent': USER_AGENT, ...headers }, signal: controller.signal });
      log.info('upstream request', { url, status: res.status, headersMs: Math.round(performance.now() - started) });
    } catch (err) {
      const reason = controller.signal.aborted ? controller.signal.reason : err;
      log.warn('upstream request failed', { url, err: reason.message });
      breaker.failure(reason);
      throw new UpstreamUnavailable(`GET ${url} failed: ${reason.message}${err.cause ? ` (${err.cause.code ?? err.cause.message})` : ''}`, { cause: err });
    } finally {
      clearTimeout(timer);
    }

    if (res.status >= 500 || res.status === 429) {
      res.body?.cancel().catch(() => {});
      const err = new UpstreamUnavailable(`GET ${url} returned ${res.status}`);
      breaker.failure(err);
      throw err;
    }

    const outcome = { networkError: null };
    try {
      return await consume(res, guardedBody(res.body, controller, outcome));
    } finally {
      res.body?.cancel().catch(() => {});
      if (outcome.networkError) breaker.failure(outcome.networkError);
      else breaker.success();
    }
  }

  /**
   * @param {'abbreviated' | 'full'} kind
   * @returns {Promise<{ status: number, etag?: string, body?: Buffer }>}
   */
  function fetchPackument(name, kind, etag) {
    const url = `${base}/${name.replace('/', '%2f')}`;
    const headers = {
      accept: kind === 'abbreviated' ? ABBREVIATED_ACCEPT : 'application/json',
      'accept-encoding': 'gzip',
    };
    if (etag) headers['if-none-match'] = etag;
    return request(packuments, url, headers, config.timeouts.packumentMs, async (res, body) => {
      if (res.status !== 200) return { status: res.status };
      const chunks = [];
      for await (const chunk of body) chunks.push(chunk);
      return { status: 200, etag: res.headers.get('etag') ?? undefined, body: Buffer.concat(chunks) };
    });
  }

  /**
   * Download a tarball and hand its body to `sink` (which verifies + stores it).
   * @returns {Promise<{ status: number }>}
   */
  function fetchTarball(name, filename, sink) {
    const url = `${base}/${name}/-/${filename}`;
    // identity: fetch would transparently gunzip a gzip Content-Encoding and break the hash.
    const headers = { accept: '*/*', 'accept-encoding': 'identity' };
    return request(tarballs, url, headers, config.timeouts.tarballHeadersMs, async (res, body) => {
      if (res.status !== 200) return { status: res.status };
      await sink(body);
      return { status: 200 };
    });
  }

  return { packuments, tarballs, fetchPackument, fetchTarball };
}
