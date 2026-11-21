// Structured JSON logs with correlation IDs. Secret-looking keys and token shapes are redacted.
import { AsyncLocalStorage } from 'node:async_hooks';
export const als = new AsyncLocalStorage();
const SECRET_KEYS = /(secret|password|passwd|token|authorization|api[_-]?key|cookie|sealed|private[_-]?key)/i;
export function redactText(s) {
  return String(s)
    .replace(/\b(sk-[A-Za-z0-9_-]{4})[A-Za-z0-9_-]{8,}/g, '$1…[redacted]')
    .replace(/\b(ghp_|gho_|github_pat_|glpat-|xox[abps]-)[A-Za-z0-9_-]{6,}/g, '$1…[redacted]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, 'AKIA…[redacted]')
    .replace(/(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)/g, '$1[redacted]$2')
    .replace(/\b(stk_[A-Za-z0-9]{4})[A-Za-z0-9_-]{8,}/g, '$1…[redacted]')
    .replace(/((?:password|passwd|secret|api_key|apikey|token)\s*[=:]\s*)["']?[^\s"',;]{4,}/gi, '$1[redacted]');
}
export function redact(value, depth = 0) {
  if (depth > 8 || value == null) return value;
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(v => redact(v, depth + 1));
  if (typeof value === 'object') {
    const o = {};
    for (const [k, v] of Object.entries(value)) o[k] = SECRET_KEYS.test(k) && typeof v !== 'object' ? '[redacted]' : redact(v, depth + 1);
    return o;
  }
  return value;
}
let quiet = process.env.SENTRA_LOG_QUIET === '1';
export function setQuiet(q) { quiet = q; }
function emit(level, event, data) {
  if (quiet && level !== 'error') return;
  const ctx = als.getStore() || {};
  const line = { ts: new Date().toISOString(), level, event, correlation_id: ctx.correlationId, ...redact(data || {}) };
  (level === 'error' ? process.stderr : process.stdout).write(JSON.stringify(line) + '\n');
}
export const log = {
  info: (e, d) => emit('info', e, d),
  warn: (e, d) => emit('warn', e, d),
  error: (e, d) => emit('error', e, d),
};
export const correlationId = () => als.getStore()?.correlationId;
