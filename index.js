import { Hono } from 'hono';
import { extract } from './src/extractors/index.js';
import {
  encodeProxyUrl,
  decodeExtraHeaders,
  isPlaylistTarget,
  isPlaylist,
  rewritePlaylist,
  fetchThrough,
  needsDeprefix,
  stripFakePrefix,
} from './src/proxy.js';

const app = new Hono();
const PORT = process.env.PORT || 3030;

function firstHeaderValue(value) {
  return String(value || '').split(',')[0].trim();
}

// Public origin of the request as the *browser* sees it.
//
// Reverse proxies (Bot-Hosting, Render, Fly, nginx, Caddy…) terminate TLS and
// forward plain HTTP, so `c.req.url` is `http://…` even though the page is on
// `https://…`. Building proxy URLs from that origin makes the player XHR
// `http://…/proxy` from an https page, which browsers block as mixed content.
export function publicOrigin(c) {
  const url = new URL(c.req.url);

  const forwarded = c.req.header('forwarded') || '';
  const fProto = /(?:^|;)\s*proto=("?)([^;"]+)\1/i.exec(forwarded)?.[2];
  const fHost = /(?:^|;)\s*host=("?)([^;"]+)\1/i.exec(forwarded)?.[2];

  // The page that calls us knows the real scheme/host even when the proxy
  // forgets to forward it (fetch POSTs always carry Origin; sub-resource XHR
  // carries Referer).
  let browserUrl;
  try {
    browserUrl = new URL(
      firstHeaderValue(c.req.header('origin')) ||
        firstHeaderValue(c.req.header('referer')) ||
        ''
    );
  } catch {
    browserUrl = undefined;
  }

  const proto =
    firstHeaderValue(c.req.header('x-forwarded-proto')) ||
    fProto ||
    browserUrl?.protocol.replace(':', '') ||
    '';

  const host =
    firstHeaderValue(c.req.header('x-forwarded-host')) ||
    fHost ||
    browserUrl?.host ||
    firstHeaderValue(c.req.header('host'));

  if (proto === 'https' || proto === 'http') url.protocol = proto + ':';

  if (host) {
    // Set hostname and port separately: assigning `.host` keeps the old port
    // when the forwarded host has none (e.g. ...:3030 → https://host:3030).
    try {
      const parsed = new URL(`${url.protocol}//${host}`);
      url.hostname = parsed.hostname;
      url.port = parsed.port;
    } catch {
      /* ignore malformed forwarded host */
    }
  }

  return url.origin;
}

app.post('/api/extract', async (c) => {
  let body;
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }
  const url = body.url;
  if (!url) {
    return c.json({ error: 'missing "url" in request body' }, 400);
  }

  try {
    const target = /^\d+$/.test(url.trim())
      ? 'https://www.themoviedb.org/movie/' + url.trim()
      : url;
    const result = await extract(target);
    const proxyBase = publicOrigin(c);
    const proxyUrl = encodeProxyUrl(result.m3u8, result.referer, proxyBase, result.headers);

    const servers = Array.isArray(result.servers)
      ? result.servers.map((s) => ({
          name: s.name,
          type: s.type,
          quality: s.quality || '',
          // true/false/null from the reachability probe; absent for extractors
          // that don't probe.
          ...(s.ok === undefined ? {} : { ok: s.ok }),
          proxyUrl: encodeProxyUrl(s.url, s.referer, proxyBase, s.headers),
        }))
      : undefined;

    return c.json({
      url: result.m3u8,
      referer: result.referer,
      type: result.type,
      proxyUrl,
      ...(servers ? { servers } : {}),
    });
  } catch (err) {
    return c.json({ error: String(err.message || err) }, 502);
  }
});

app.get('/proxy', async (c) => {
  const target = c.req.query('url');
  const referer = c.req.query('referer') || '';
  const range = c.req.header('range');
  const extraHeaders = decodeExtraHeaders(c.req.query('headers') || '');

  if (!target) {
    return c.json({ error: 'missing "url" query param' }, 400);
  }

  try {
    const deprefix = needsDeprefix(target);
    const useReferer = referer && !deprefix;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000);

    const { res, status, contentType, contentLength, contentRange, acceptRanges } =
      await fetchThrough(target, referer, {
        range: deprefix ? undefined : range,
        useReferer,
        extraHeaders,
        signal: controller.signal,
      });
    clearTimeout(timeout);

    if (isPlaylistTarget(target, contentType)) {
      const text = await res.text();
      if (!isPlaylist(text, contentType)) {
        console.warn(
          '[proxy] non-playlist upstream:',
          new URL(target).hostname,
          res.status,
          contentType,
          JSON.stringify(text.slice(0, 160))
        );
        return new Response(
          `Upstream returned HTTP ${res.status}${
            contentType ? ' ' + contentType : ''
          } instead of a playlist (block page or dead source). Try another server.`,
          { status: 502, headers: { 'content-type': 'text/plain', 'access-control-allow-origin': '*' } }
        );
      }
      // Root-relative links (`/proxy?...`): hls.js resolves them against this
      // response's URL, so they always inherit the correct scheme (no mixed
      // content behind a TLS-terminating proxy).
      const rewritten = rewritePlaylist(text, target, referer, '', extraHeaders);
      return new Response(rewritten, {
        status: 200,
        headers: {
          'content-type': 'application/vnd.apple.mpegurl',
          'cache-control': 'public, max-age=30',
          'access-control-allow-origin': '*',
        },
      });
    }

    if (deprefix) {
      const clean = stripFakePrefix(new Uint8Array(await res.arrayBuffer()));
      return new Response(clean, {
        status: 200,
        headers: {
          'content-type': 'video/mp2t',
          'content-length': String(clean.byteLength),
          'access-control-allow-origin': '*',
          'cache-control': 'no-store',
        },
      });
    }

    const headers = {
      'content-type': contentType || 'application/octet-stream',
      'access-control-allow-origin': '*',
      'cache-control': 'no-store',
    };
    if (contentLength) headers['content-length'] = contentLength;
    if (contentRange) headers['content-range'] = contentRange;
    if (acceptRanges) headers['accept-ranges'] = acceptRanges;

    const body = res.body ?? new Uint8Array(await res.arrayBuffer());
    return new Response(body, { status, headers });
  } catch (err) {
    return c.json({ error: String(err.message || err) }, 502);
  }
});

app.get('/health', (c) => c.json({ ok: true }));

const STATIC_TYPES = {
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.html': 'text/html',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function resolveAssetPath(p) {
  if (!p || p === '/') return '/player.html';
  let f = p.startsWith('/') ? p.slice(1) : p;
  if (!f.includes('.')) f += '.html';
  return '/' + f;
}

const CACHE_MAX_AGE = {
  '.html': 300,
  '.js': 86400,
  '.css': 86400,
  '.png': 86400,
  '.ico': 86400,
};

app.all('*', async (c) => {
  const env = c.env;
  const path = resolveAssetPath(c.req.path);

  if (env && env.ASSETS) {
    const url = new URL(path, c.req.url);
    return env.ASSETS.fetch(new Request(url, c.req.raw));
  }

  try {
    const { readFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const filePath = join(process.cwd(), 'public', path.replace(/^\//, ''));
    const body = readFileSync(filePath);
    const ext = path.slice(path.lastIndexOf('.'));
    const maxAge = CACHE_MAX_AGE[ext] || 0;
    return new Response(body, {
      headers: {
        'content-type': STATIC_TYPES[ext] || 'application/octet-stream',
        'cache-control': maxAge ? `public, max-age=${maxAge}` : 'no-store',
        'access-control-allow-origin': '*',
      },
    });
  } catch {
    return c.json({ error: 'not found' }, 404);
  }
});

export default { fetch: app.fetch };

if (typeof process !== 'undefined' && process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  const { serve } = await import('@hono/node-server');
  serve({ fetch: app.fetch, port: PORT });
  console.log(`Decryptor running on http://localhost:${PORT}`);
}
