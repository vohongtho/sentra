// Minimal HTTP layer on node:http: routing, JSON bodies with limits, static files, security headers,
// correlation IDs, rate limiting and uniform error responses.
import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { AppError } from '../util.mjs';
import { log, als } from '../log.mjs';

export class Router {
  constructor() { this.routes = []; }
  add(method, pattern, handler, opts = {}) {
    const keys = []; const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
    this.routes.push({ method, re, keys, handler, opts });
  }
  get(p, h, o) { this.add('GET', p, h, o); } post(p, h, o) { this.add('POST', p, h, o); }
  put(p, h, o) { this.add('PUT', p, h, o); } patch(p, h, o) { this.add('PATCH', p, h, o); } delete(p, h, o) { this.add('DELETE', p, h, o); }
  match(method, pathname) {
    let allowed = false;
    for (const r of this.routes) {
      const m = r.re.exec(pathname); if (!m) continue;
      if (r.method !== method) { allowed = true; continue; }
      return { route: r, params: Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])])) };
    }
    return allowed ? { methodNotAllowed: true } : null;
  }
}

export async function readBody(req, limit) {
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > limit) throw new AppError(413, 'PAYLOAD_TOO_LARGE', `Request body exceeds ${limit} bytes.`); chunks.push(c); }
  return Buffer.concat(chunks);
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon', '.md': 'text/markdown; charset=utf-8', '.yml': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8' };
export const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};

// In-memory token bucket per key. Not distributed: documented limitation for multi-instance deployments.
const buckets = new Map();
function rateLimited(key, perMinute) {
  const now = Date.now(); let b = buckets.get(key);
  if (!b) { b = { tokens: perMinute, at: now }; buckets.set(key, b); }
  b.tokens = Math.min(perMinute, b.tokens + ((now - b.at) / 60000) * perMinute); b.at = now;
  if (b.tokens < 1) return true; b.tokens -= 1; return false;
}

export function createServer(app, router, { publicDir, authenticate }) {
  return http.createServer((req, res) => {
    const correlationId = (req.headers['x-request-id'] && /^[\w-]{8,64}$/.test(req.headers['x-request-id'])) ? req.headers['x-request-id'] : randomUUID();
    als.run({ correlationId }, () => handle(req, res, correlationId).catch(e => log.error('unhandled', { error: String(e?.stack || e) })));
  });

  async function handle(req, res, correlationId) {
    const started = Date.now();
    const url = new URL(req.url, app.cfg.appOrigin);
    let ctx = null;
    const send = (status, body, headers = {}) => {
      if (res.headersSent) return;
      const isBuf = Buffer.isBuffer(body) || typeof body === 'string';
      res.writeHead(status, { ...SECURITY_HEADERS, 'X-Request-Id': correlationId, ...(isBuf ? {} : { 'Content-Type': 'application/json; charset=utf-8' }), 'Cache-Control': 'no-store', ...headers });
      res.end(isBuf ? body : JSON.stringify(body));
    };
    try {
      if (!url.pathname.startsWith('/api/')) return await serveStatic(url.pathname, publicDir, send);
      const ip = req.socket.remoteAddress || 'unknown';
      if (rateLimited('ip:' + ip, app.cfg.rateLimitPerMinute)) throw new AppError(429, 'RATE_LIMITED', 'Too many requests. Retry shortly.');
      const m = router.match(req.method, url.pathname);
      if (!m) throw new AppError(404, 'NOT_FOUND', 'Unknown API route.');
      if (m.methodNotAllowed) throw new AppError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed.');
      const { route, params } = m;
      const limit = route.opts.maxBody || 1024 * 1024;
      const raw = ['GET', 'HEAD', 'DELETE'].includes(req.method) ? Buffer.alloc(0) : await readBody(req, limit);
      let body = {};
      const ctype = req.headers['content-type'] || '';
      if (raw.length && ctype.includes('application/json') && !route.opts.rawBody) {
        try { body = JSON.parse(raw.toString('utf8')); } catch { throw new AppError(400, 'INVALID_JSON', 'Request body is not valid JSON.'); }
      }
      ctx = await authenticate(req, url, route.opts, { correlationId, body });
      const r = await route.handler({ req, url, params, body, raw, query: Object.fromEntries(url.searchParams), ctx, app });
      if (r instanceof Reply) return send(r.status, r.body, r.headers);
      send(r === undefined ? 204 : 200, r === undefined ? '' : r);
    } catch (e) {
      if (e instanceof AppError) {
        send(e.status, { error: e.code, message: e.message, ...(e.details ? { details: e.details } : {}), request_id: correlationId }, e.headers || {});
      } else {
        log.error('request_failed', { path: url.pathname, method: req.method, error: String(e?.stack || e) });
        send(500, { error: 'INTERNAL_ERROR', message: 'The request failed. No simulated result was generated.', request_id: correlationId });
      }
    } finally {
      await ctx?.db?.release?.().catch?.(() => {});
      if (url.pathname.startsWith('/api/')) log.info('http', { method: req.method, path: url.pathname, status: res.statusCode, ms: Date.now() - started });
    }
  }
}

export class Reply { constructor(status, body, headers = {}) { this.status = status; this.body = body; this.headers = headers; } }
export const reply = (status, body, headers) => new Reply(status, body, headers);

async function serveStatic(pathname, publicDir, send) {
  let rel = decodeURIComponent(pathname);
  if (rel === '/' || !path.extname(rel)) rel = '/index.html';
  const file = path.normalize(path.join(publicDir, rel));
  if (!file.startsWith(path.normalize(publicDir) + path.sep)) return send(403, 'Forbidden', { 'Content-Type': 'text/plain' });
  try {
    const st = await stat(file); if (!st.isFile()) throw new Error();
    const ext = path.extname(file);
    return send(200, await readFile(file), { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': ext === '.html' ? 'no-store' : 'no-cache' });
  } catch { return send(404, 'Not found', { 'Content-Type': 'text/plain' }); }
}
