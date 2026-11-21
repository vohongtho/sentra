// Outbound HTTP for user-configured URLs (webhooks, connectors): HTTPS only, DNS-resolved address checks against
// private/loopback/link-local/metadata ranges, no redirects, bounded timeouts and response sizes.
import dns from 'node:dns/promises';
import net from 'node:net';
import { AppError } from '../util.mjs';

function ipv4Private(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}
export function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) return ipv4Private(ip);
  const s = ip.toLowerCase();
  if (s === '::1' || s === '::') return true;
  if (s.startsWith('fc') || s.startsWith('fd') || s.startsWith('fe80')) return true;
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s); if (m) return ipv4Private(m[1]);
  return false;
}
export async function assertSafeUrl(raw, { allowPrivate = false, allowHttp = false } = {}) {
  let u; try { u = new URL(raw); } catch { throw new AppError(400, 'URL_INVALID', 'Invalid URL.'); }
  if (u.username || u.password) throw new AppError(400, 'URL_INVALID', 'Credentials in URLs are not allowed; use a secret reference.');
  if (u.protocol !== 'https:' && !(allowHttp && u.protocol === 'http:')) throw new AppError(400, 'URL_INVALID', 'Only HTTPS destinations are allowed.');
  if (!allowPrivate) {
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const addrs = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true }).catch(() => { throw new AppError(400, 'URL_UNRESOLVABLE', `Cannot resolve ${host}.`); })).map(a => a.address);
    if (!addrs.length || addrs.some(isPrivateAddress)) throw new AppError(400, 'URL_BLOCKED', 'Destination resolves to a private, loopback, link-local or metadata address.');
  }
  return u;
}
export async function safeFetch(raw, init = {}, { allowPrivate = false, allowHttp = false, timeoutMs = 10000, maxBytes = 2_000_000 } = {}) {
  const u = await assertSafeUrl(raw, { allowPrivate, allowHttp });
  const res = await fetch(u, { ...init, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  if (res.status >= 300 && res.status < 400) throw new AppError(502, 'REDIRECT_BLOCKED', `Destination attempted a redirect (${res.status}); redirects are not followed.`);
  const reader = res.body?.getReader(); let size = 0; const chunks = [];
  if (reader) for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > maxBytes) { reader.cancel(); throw new AppError(502, 'RESPONSE_TOO_LARGE', 'Response exceeded size limit.'); } chunks.push(value); }
  const text = Buffer.concat(chunks).toString('utf8');
  return { status: res.status, ok: res.ok, headers: Object.fromEntries(res.headers), text, json: () => JSON.parse(text) };
}
