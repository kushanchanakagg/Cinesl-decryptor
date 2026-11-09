
import CryptoJS from 'crypto-js';
import { UA } from './../http.js';
import { base64ToB64url, b64urlToBase64 } from './../util.js';
import { relayTarget } from './../proxy.js';

const API_BASE = 'https://web.nxsha.app';
const NX_ORIGIN = 'https://web.nxsha.app';
const NX_REFERER = 'https://web.nxsha.app/';

// Passphrase used by the nxsha web client to encrypt/decrypt the `q` query and
// the `_hash` response payload (CryptoJS AES, OpenSSL "Salted__" format).
// Nxsha rotates this without notice: when it changes, /api/servers still
// returns HTTP 200 but every payload fails to decrypt with "Malformed UTF-8
// data". `refreshKeyThrottled()` re-reads the current value from the site's JS
// bundles.
const DEFAULT_KEY = '082b3ead9d74d2171f312110057b6faf906c2c8b800424ae944f963d31b109d0';
let KEY = DEFAULT_KEY;

const TAG = '[nxsha]';
const CONCURRENCY = 3;
const SERVER_TIMEOUT = 12000;
const KEY_SCAN_LIMIT = 40;
const KEY_SCAN_TIMEOUT = 8000;
const VERIFY_LIMIT = 10;
const VERIFY_CONCURRENCY = 4;
const VERIFY_TIMEOUT = 6000;

// nxsha sits behind Cloudflare and intermittently answers /api/servers with
// 403 (WAF/rate-limit after a burst) even for a valid encrypted payload. The
// same request succeeds moments later, so retry with backoff instead of
// failing the whole extraction (and losing the server list to vixsrc).
const API_RETRIES = 2;
const RETRY_BASE_MS = 500;
const RETRYABLE_STATUS = new Set([403, 408, 425, 429, 500, 502, 503, 504]);

// Tried in order on retries: full browser-ish headers, then bare, then JSON.
const API_HEADER_PROFILES = [
  {
    'User-Agent': UA,
    Accept: '*/*',
    Referer: NX_REFERER,
    Origin: NX_ORIGIN,
  },
  { 'User-Agent': UA, Accept: '*/*' },
  { 'User-Agent': UA, Accept: 'application/json' },
];

// Sources that need a browser session / private cookie we can't supply.
const UNSUPPORTED_SCRAPERS = new Set(['showbox-online']);

// nxsha reports HLS variants as "m3u8" or "hls" depending on the scraper.
const HLS_TYPES = new Set(['m3u8', 'hls']);

function log(...args) {
  console.log(TAG, ...args);
}

function warn(...args) {
  console.warn(TAG, ...args);
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }

    const onAbort = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };

    const timer = setTimeout(() => {
      signal?.removeEventListener?.('abort', onAbort);
      resolve();
    }, ms);

    signal?.addEventListener?.('abort', onAbort, { once: true });
  });
}

function encodeData(obj) {
  const payload = {
    ...obj,
    _req_ts: Date.now(),
    _req_salt: Math.random().toString(36).slice(2, 12),
  };

  return base64ToB64url(
    CryptoJS.AES.encrypt(JSON.stringify(payload), KEY).toString()
  );
}

function decodeData(str) {
  if (!str) {
    throw new Error('Missing encrypted _hash');
  }

  let text;

  try {
    text = CryptoJS.AES
      .decrypt(b64urlToBase64(str), KEY)
      .toString(CryptoJS.enc.Utf8);
  } catch (err) {
    throw new Error('AES decryption failed: ' + err.message);
  }

  if (!text) {
    throw new Error('AES returned empty plaintext');
  }

  let obj;

  try {
    obj = JSON.parse(text);
  } catch {
    throw new Error('Decrypted response is not valid JSON');
  }

  delete obj._req_ts;
  delete obj._req_salt;

  return obj;
}

// ---------------------------------------------------------------------------
// AES key discovery
//
// The player ships its passphrase inside a lazily-imported JS chunk. We walk
// the chunk graph starting from the embed page, follow nested
// `static/chunks/*.js` imports, and take the 64-hex literal from the module
// that talks to CryptoJS. Only runs when decryption fails, so the happy path
// costs nothing.
// ---------------------------------------------------------------------------

function looksLikeCryptoModule(text) {
  return /AES\.(?:encrypt|decrypt)/.test(text);
}

function extractKey(text) {
  const m = text.match(/["']([0-9a-f]{64})["']/i);
  return m ? m[1] : null;
}

function collectChunkPaths(html) {
  return [
    ...new Set(
      [...html.matchAll(/\/_next\/static\/chunks\/[A-Za-z0-9_.-]+\.js/g)].map(
        (m) => m[0]
      )
    ),
  ];
}

async function scanForKey(entryUrl) {
  const queue = [];
  const seen = new Set();

  try {
    const res = await fetch(entryUrl, {
      headers: { 'User-Agent': UA, Accept: 'text/html' },
      signal: AbortSignal.timeout(KEY_SCAN_TIMEOUT),
    });
    const html = await res.text();
    queue.push(...collectChunkPaths(html).map((p) => API_BASE + p));
  } catch (err) {
    warn('Key scan: could not load embed page:', err?.message || err);
    return null;
  }

  while (queue.length && seen.size < KEY_SCAN_LIMIT) {
    const url = queue.shift();

    if (seen.has(url)) continue;
    seen.add(url);

    let text;

    try {
      const res = await fetch(url, {
        headers: { 'User-Agent': UA, Accept: '*/*' },
        signal: AbortSignal.timeout(KEY_SCAN_TIMEOUT),
      });
      if (!res.ok) continue;
      text = await res.text();
    } catch {
      continue;
    }

    // Follow the lazy-import graph: player chunks name further chunks.
    for (const m of text.matchAll(/static\/chunks\/[A-Za-z0-9_.-]+\.js/g)) {
      queue.push(API_BASE + '/_next/' + m[0]);
    }

    if (!looksLikeCryptoModule(text)) continue;

    const key = extractKey(text);

    if (key) {
      log('Key scan: found passphrase in', url.split('/').pop());
      return key;
    }
  }

  warn('Key scan: no passphrase found after', seen.size, 'chunks');
  return null;
}

let keyRefreshPromise = null;
let keyRefreshCooldownUntil = 0;
let targetHint = { tmdbId: '1', type: 'movie' };

function refreshKeyThrottled() {
  const now = Date.now();

  if (keyRefreshPromise) return keyRefreshPromise;
  if (now < keyRefreshCooldownUntil) return Promise.resolve(null);

  keyRefreshCooldownUntil = now + 60000;

  const entry = `${API_BASE}/embed/${targetHint.type || 'movie'}/${
    targetHint.tmdbId || '1'
  }`;

  log('Decrypt failed with cached key, scanning', entry);

  keyRefreshPromise = scanForKey(entry)
    .then((key) => {
      if (key) KEY = key;
      return key;
    })
    .catch(() => null)
    .finally(() => {
      keyRefreshPromise = null;
    });

  return keyRefreshPromise;
}

function parseInput(input) {
  const raw = String(input || '').trim();

  let tmdbId = null;
  let type = 'movie';
  let season = '1';
  let episode = '1';

  const numMatch = raw.match(/^(\d+)$/);

  if (numMatch) {
    tmdbId = numMatch[1];
  } else {
    let u;

    try {
      u = new URL(raw);
    } catch {
      throw new Error('Unrecognized NXsha/TMDB input: ' + raw);
    }

    if (u.hostname.includes('themoviedb.org')) {
      const m = u.pathname.match(
        /\/(movie|tv)\/(\d+)(?:\/season\/(\d+)\/episode\/(\d+))?/
      );

      if (!m) {
        throw new Error('Could not parse TMDB URL: ' + raw);
      }

      type = m[1];
      tmdbId = m[2];

      if (m[3]) season = m[3];
      if (m[4]) episode = m[4];
    } else {
      throw new Error(
        'Unsupported host for NXsha extractor: ' + u.hostname
      );
    }
  }

  if (!tmdbId) {
    throw new Error('No TMDB ID found');
  }

  return { tmdbId, type, season, episode };
}

async function apiGet(path, query, signal) {
  let lastErr;

  for (let attempt = 0; attempt <= API_RETRIES; attempt++) {
    if (attempt > 0) {
      const wait = RETRY_BASE_MS * 2 ** (attempt - 1) + Math.random() * 250;

      log(path, `retry ${attempt}/${API_RETRIES} in ${Math.round(wait)}ms`);

      await sleep(wait, signal);
    }

    const headers =
      API_HEADER_PROFILES[attempt % API_HEADER_PROFILES.length];

    try {
      return await apiGetOnce(path, query, signal, headers);
    } catch (err) {
      lastErr = err;

      const aborted =
        signal?.aborted ||
        err?.name === 'AbortError' ||
        err?.name === 'TimeoutError';

      if (aborted) throw err;

      // Parse/decrypt failures aren't transient — retrying just re-hits the
      // API with the same (already key-refreshed) payload.
      if (err?.retryable === false) throw err;

      if (err?.status !== undefined && !RETRYABLE_STATUS.has(err.status)) {
        throw err;
      }

      warn(path, 'attempt', attempt + 1, 'failed:', err?.message || err);
    }
  }

  throw lastErr;
}

async function apiGetOnce(path, query, signal, headers) {
  const url = `${API_BASE}${path}?q=${encodeURIComponent(query)}`;

  log('Request:', path);

  const res = await fetch(url, {
    signal,
    headers,
  });

  log(path, 'HTTP:', res.status);

  const raw = await res.text();

  if (!res.ok) {
    const err = new Error(
      `${path} HTTP ${res.status}: ${raw.slice(0, 300)}`
    );

    err.status = res.status;

    throw err;
  }

  let json;

  try {
    json = JSON.parse(raw);
  } catch {
    const err = new Error(`${path}: Invalid JSON response`);

    err.retryable = false;

    throw err;
  }

  if (!json || !json._hash) {
    const err = new Error(
      `${path}: Missing _hash. Response keys: ${
        Object.keys(json || {}).join(', ')
      }`
    );

    err.retryable = false;

    throw err;
  }

  let decoded;

  try {
    decoded = decodeData(json._hash);
  } catch (err) {
    warn(path, 'Decrypt failed:', err?.message || err);

    const fresh = await refreshKeyThrottled();

    if (!fresh) {
      err.retryable = false;
      throw err;
    }

    decoded = decodeData(json._hash);
  }

  log(path, 'Decryption successful');
  log(path, 'Decoded keys:', Object.keys(decoded));

  return decoded;
}

function pickSource(sources) {
  if (!Array.isArray(sources)) {
    return null;
  }

  log('Received source count:', sources.length);

  const usable = sources.filter((s) => s && s.url && !s.isEmbed);

  const hls = usable.find((s) =>
    HLS_TYPES.has(String(s.type || '').toLowerCase())
  );

  if (hls) {
    return { source: hls, kind: 'm3u8' };
  }

  const mp4 = usable.find(
    (s) => String(s.type || '').toLowerCase() === 'mp4'
  );

  if (mp4) {
    return { source: mp4, kind: 'mp4' };
  }

  return null;
}

function buildProxyParts(chosen) {
  const headers = chosen.source.headers || {};

  const referer = headers.Referer || '';
  const extra = {};

  for (const [key, value] of Object.entries(headers)) {
    extra[key.toLowerCase()] = value;
  }

  return { referer, extra };
}

// Cheap reachability probe used to order servers. Returns:
//   true  – playlist/media fetched
//   false – definitive upstream refusal (4xx/5xx, block page)
//   null  – timeout / transport error (unknown; don't blacklist)
async function probeSource(entry) {
  const headers = {
    'User-Agent': UA,
    Accept: '*/*',
    // Range keeps mp4/mkv probes from pulling the whole file and makes CDNs
    // answer with headers immediately (200 for text, 206 for media).
    Range: 'bytes=0-1023',
    Referer: entry.referer || NX_REFERER,
    Origin: (entry.headers && entry.headers.origin) || NX_ORIGIN,
  };

  const drop = (res) => res.body?.cancel?.().catch(() => {});

  try {
    // If this host is relay-routed, probe through the relay too — otherwise
    // relay-only sources would be ranked as "failed" and pushed to the bottom.
    const relay = relayTarget(entry.url);

    const res = await fetch(relay ? relay.url : entry.url, {
      headers: relay ? { ...headers, ...relay.headers } : headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(VERIFY_TIMEOUT),
    });

    if (res.status !== 200 && res.status !== 206) {
      await drop(res);
      return false;
    }

    if (entry.type === 'mp4') {
      await drop(res);
      return true;
    }

    const reader = res.body?.getReader();

    if (!reader) {
      await drop(res);
      return /mpegurl/i.test(res.headers.get('content-type') || '') || res.ok;
    }

    const { value } = await reader.read();

    try {
      await reader.cancel();
    } catch {
      /* already closed */
    }

    const head = value ? new TextDecoder().decode(value.subarray(0, 512)) : '';

    if (/^#EXTM3U/i.test(head.trim())) return true;

    return /mpegurl/i.test(res.headers.get('content-type') || '');
  } catch {
    return null;
  }
}

async function pool(items, limit, worker) {
  const results = new Array(items.length);

  let index = 0;

  async function next() {
    while (true) {
      const idx = index++;

      if (idx >= items.length) {
        return;
      }

      results[idx] = await worker(items[idx], idx);
    }
  }

  await Promise.all(
    Array.from(
      { length: Math.min(limit, items.length) },
      () => next()
    )
  );

  return results;
}

export async function extract(embedUrl, _label) {
  const { tmdbId, type, season, episode } = parseInput(embedUrl);

  targetHint = { tmdbId, type };

  log('================================');
  log('Starting extraction');
  log('TMDB ID:', tmdbId);
  log('Type:', type);
  log('Season:', season);
  log('Episode:', episode);

  // Step 1: Discover servers

  const serversRes = await apiGet(
    '/api/servers',
    encodeData({
      tmdbId,
      type,
      imdb_id: '',
      season,
      episode,
      method: 'stream',
    })
  );

  const servers = (Array.isArray(serversRes?.servers)
    ? serversRes.servers
    : []
  ).filter(
    (s) =>
      s &&
      s.web_support !== false &&
      s.isDisable !== true &&
      !UNSUPPORTED_SCRAPERS.has(s.scraper)
  );

  log('Server count:', servers.length);

  if (!servers.length) {
    log('Servers response:', serversRes);
    throw new Error('NXsha returned no servers');
  }

  // Step 2: Extract individual server sources

  const withSources = await pool(
    servers,
    CONCURRENCY,
    async (server, index) => {
      const serverName =
        server.name || server.scraper || server.id || `server-${index}`;

      log(`Trying server ${index + 1}/${servers.length}:`, serverName);

      try {
        const srcRes = await apiGet(
          '/api/sources',
          encodeData({
            provider: server.scraper || server.id,
            tmdbId,
            imdb_id: '',
            type,
            season,
            episode,
            ex_lang: false,
            method: 'stream',
          }),
          AbortSignal.timeout(SERVER_TIMEOUT)
        );

        const chosen = pickSource(srcRes?.sources);

        if (!chosen) {
          warn(serverName, 'No supported playable source');
          return null;
        }

        const { referer, extra } = buildProxyParts(chosen);

        // Most nxsha CDNs (nitro/wts.itsnitrox.tech, castvid/*.workers.dev, …)
        // reject server-side fetches unless Referer/Origin look like the site.
        // Results: none=403, nxsha=200, any-other-origin=403. The API returns
        // an empty headers map for those scrapers, so default to nxsha's
        // origin whenever the source doesn't dictate its own.
        const proxyReferer = referer || NX_REFERER;

        const proxyExtra = {
          ...extra,
          // Origin must be scheme+host only: a trailing slash makes
          // *.workers.dev sources (CastVid) answer 403.
          origin: extra.origin || NX_ORIGIN,
        };

        log(
          serverName,
          'SUCCESS:',
          chosen.kind,
          chosen.source.quality || chosen.source.label || 'Unknown quality'
        );

        return {
          name: serverName,
          type: chosen.kind,
          url: chosen.source.url,
          referer: proxyReferer,
          headers: proxyExtra,
          quality:
            chosen.source.quality ||
            chosen.source.label ||
            '',
        };

      } catch (err) {
        warn(
          serverName,
          'FAILED:',
          err?.message || String(err)
        );

        return null;
      }
    }
  );

  // Step 3: Filter playable sources

  const playable = withSources.filter(Boolean);

  log('================================');
  log('Total servers:', servers.length);
  log('Playable sources:', playable.length);

  if (!playable.length) {
    throw new Error(
      `NXsha: No playable sources found across ${servers.length} servers. Check individual server logs.`
    );
  }

  // Step 3b: Probe sources and put the ones we can actually reach first.
  //
  // A CDN accepting headers is not the same as a CDN accepting *us*: from
  // Cloudflare Worker egress several scrapers answer 403/404 (Nitro, Prvibd,
  // CastVid, AwsPly, Ophm), while on a home IP/VPS the same URL returns 200.
  // nxsha lists Nitro first, so without this the player's default source is
  // the one most likely to fail. Probe cheaply, order verified → unknown →
  // failed, and keep everything (probes can lie).

  const probed = playable.slice(0, VERIFY_LIMIT);
  const verdicts = await pool(probed, VERIFY_CONCURRENCY, probeSource);

  const state = new Map();
  probed.forEach((entry, i) => state.set(entry, verdicts[i]));

  // Verified HLS first (adaptive quality), then verified mp4, keeping the
  // rest of the order intact.
  const verified = playable.filter((s) => state.get(s) === true);
  verified.sort((a, b) => (a.type === 'mp4' ? 1 : 0) - (b.type === 'mp4' ? 1 : 0));

  const ordered = [
    ...verified,
    ...playable.filter((s) => !state.has(s)),
    ...playable.filter((s) => state.get(s) === null),
    ...playable.filter((s) => state.get(s) === false),
  ].map((s) => ({ ...s, ok: state.get(s) }));

  log(
    'Reachable:',
    ordered.filter((s) => s.ok === true).map((s) => s.name).join(', ') || 'none'
  );

  // Step 4: Select primary source

  const top = ordered[0];

  log('Selected server:', top.name);
  log('Selected type:', top.type);
  log('================================');

  return {
    m3u8: top.url,
    referer: top.referer,
    headers: top.headers,
    host: 'nxsha',
    finalUrl: embedUrl,
    type: top.type,
    servers: ordered,
  };
}
