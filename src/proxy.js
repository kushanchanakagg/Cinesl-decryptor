import { UA } from './http.js';
import { toB64url, fromB64url } from './util.js';

const EXTRA_HEADER_ALLOWLIST = new Set([
  'accept',
  'accept-language',
  'origin',
  'user-agent',
  'referer',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
]);

// Optional outbound relay (relay/relay.php). Some CDNs answer 403 to
// Cloudflare Worker egress but 200 to an ordinary hosting IP; routing only
// those hosts through the relay keeps everything else direct.
let RELAY = null;

function envValue(env, name) {
  if (env && env[name]) return String(env[name]).trim();
  if (typeof process !== 'undefined' && process.env && process.env[name]) {
    return String(process.env[name]).trim();
  }
  return '';
}

export function setRelayConfig(env) {
  const url = envValue(env, 'PROXY_RELAY_URL');

  if (!url) {
    RELAY = null;
    return null;
  }

  const hosts = envValue(env, 'PROXY_RELAY_HOSTS')
    .split(',')
    .map((h) => h.trim().toLowerCase().replace(/^\./, ''))
    .filter(Boolean);

  RELAY = { url, key: envValue(env, 'PROXY_RELAY_KEY'), hosts };

  return RELAY;
}

export function getRelayConfig() {
  return RELAY;
}

// Returns { url, headers } when the target should go through the relay.
export function relayTarget(target) {
  if (!RELAY) return null;

  let host;

  try {
    host = new URL(target).hostname.toLowerCase();
  } catch {
    return null;
  }

  if (
    RELAY.hosts.length &&
    !RELAY.hosts.some((h) => host === h || host.endsWith('.' + h))
  ) {
    return null;
  }

  const u = new URL(RELAY.url);
  u.searchParams.set('url', target);

  return {
    url: u.toString(),
    headers: RELAY.key ? { 'x-relay-key': RELAY.key } : {},
  };
}

export function encodeExtraHeaders(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const clean = {};
  for (const [k, v] of Object.entries(obj)) {
    if (EXTRA_HEADER_ALLOWLIST.has(k.toLowerCase()) && typeof v === 'string') {
      clean[k.toLowerCase()] = v;
    }
  }
  if (!Object.keys(clean).length) return null;
  return toB64url(JSON.stringify(clean));
}

export function decodeExtraHeaders(token) {
  if (!token) return {};
  try {
    const obj = JSON.parse(fromB64url(token));
    const clean = {};
    for (const [k, v] of Object.entries(obj)) {
      if (EXTRA_HEADER_ALLOWLIST.has(k.toLowerCase()) && typeof v === 'string') {
        clean[k.toLowerCase()] = v;
      }
    }
    return clean;
  } catch {
    return {};
  }
}

export function encodeProxyUrl(target, referer, proxyBase, extra) {
  const params = new URLSearchParams();
  params.set('url', target);
  if (referer) params.set('referer', referer);
  const h = encodeExtraHeaders(extra);
  if (h) params.set('headers', h);
  const path = `/proxy?${params}`;
  // No base ⇒ root-relative link, which hls.js resolves against the playlist
  // URL we served. Used for playlist rewriting so a TLS-terminating reverse
  // proxy can never turn the links into http:// (mixed content).
  return proxyBase ? new URL(path, proxyBase).toString() : path;
}

function isM3u8ContentType(contentType) {
  return !!contentType && /mpegurl/i.test(contentType);
}

export function isPlaylist(text, contentType) {
  if (isM3u8ContentType(contentType)) return true;
  return /^#EXTM3U/i.test(text.slice(0, 1024).trim());
}

export function isPlaylistTarget(target, contentType) {
  if (isM3u8ContentType(contentType)) return true;
  try {
    return /\.m3u8$/i.test(new URL(target).pathname);
  } catch {
    return false;
  }
}

export function rewritePlaylist(playlistText, baseUrl, referer, proxyBase, extra) {
  const base = new URL('.', baseUrl);
  return playlistText
    .split('\n')
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return line;
      if (/^#EXT-X-(MAP|KEY|MEDIA):/i.test(trimmed)) {
        return line.replace(/(URI=")([^"]+)(")/g, (_m, pre, uri, post) => {
          const abs = resolve(uri, base);
          return pre + encodeProxyUrl(abs, referer, proxyBase, extra) + post;
        });
      }
      if (trimmed.startsWith('#')) return line;
      const abs = resolve(trimmed, base);
      return encodeProxyUrl(abs, referer, proxyBase, extra);
    })
    .join('\n');
}

function resolve(target, base) {
  try {
    return new URL(target, base).toString();
  } catch {
    return target;
  }
}

const REFERERLESS_HOSTS = [/\.googleusercontent\.com$/i, /googleapis\.com$/i];

function shouldDropReferer(target) {
  try {
    const host = new URL(target).hostname;
    return REFERERLESS_HOSTS.some((re) => re.test(host));
  } catch {
    return false;
  }
}

export function needsDeprefix(target) {
  return shouldDropReferer(target);
}

const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47];

export function stripFakePrefix(buf) {
  if (buf.length < 4) return buf;
  const looksPng = PNG_MAGIC.every((b, i) => buf[i] === b);
  if (!looksPng) return buf;
  const limit = Math.min(buf.length - 376, 8192);
  for (let start = 0; start < limit; start++) {
    if (
      buf[start] === 0x47 &&
      buf[start + 188] === 0x47 &&
      buf[start + 376] === 0x47
    ) {
      return buf.subarray(start);
    }
  }
  return buf;
}

export async function fetchThrough(target, referer, { range, origin, useReferer, extraHeaders, signal } = {}) {
  if (useReferer === undefined) {
    useReferer = Boolean(referer) && !shouldDropReferer(target);
  }

  // Lower-case names throughout: `Origin` and `origin` are the same header on
  // the wire, and sending both (referer-derived + explicit) makes undici/Workers
  // merge them into `https://a, https://b` — which CDNs answer 403 to.
  const headers = {
    'user-agent': UA,
    accept: '*/*',
  };

  if (useReferer) {
    headers.referer = referer;
    headers.origin = referer;
  }

  if (origin) headers.origin = origin;

  for (const [key, value] of Object.entries(extraHeaders || {})) {
    if (typeof value !== 'string' || !value) continue;
    headers[key.toLowerCase()] = value;
  }

  if (range) headers.range = range;

  const relay = relayTarget(target);

  if (relay) {
    Object.assign(headers, relay.headers);
  }

  const res = await fetch(relay ? relay.url : target, {
    redirect: 'follow',
    headers,
    signal,
  });

  return {
    res,
    status: res.status,
    contentType: res.headers.get('content-type') || '',
    contentLength: res.headers.get('content-length') || '',
    contentRange: res.headers.get('content-range') || '',
    acceptRanges: res.headers.get('accept-ranges') || '',
  };
}
