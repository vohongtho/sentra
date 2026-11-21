import { randomBytes, createHash } from 'node:crypto';
export const id = (prefix) => `${prefix}_${randomBytes(10).toString('base64url').replace(/[-_]/g, 'x')}`;
export const sha256 = (v) => createHash('sha256').update(v).digest('hex');
export class AppError extends Error {
  constructor(status, code, message, details) { super(message); this.status = status; this.code = code; this.details = details; }
}
export const badRequest = (msg, details) => new AppError(400, 'VALIDATION_ERROR', msg, details);
export const notFound = (what = 'Resource') => new AppError(404, 'NOT_FOUND', `${what} not found or not accessible.`);
export const forbidden = (msg = 'You do not have permission for this action.') => new AppError(403, 'FORBIDDEN', msg);
export const conflict = (msg) => new AppError(409, 'CONFLICT', msg);
export function stableStringify(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  return '{' + Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => JSON.stringify(k) + ':' + stableStringify(v[k])).join(',') + '}';
}
export function need(obj, fields) {
  const missing = fields.filter(f => obj?.[f] == null || obj[f] === '');
  if (missing.length) throw badRequest(`Missing required field(s): ${missing.join(', ')}`, { missing });
}
export function oneOf(value, allowed, field) {
  if (!allowed.includes(value)) throw badRequest(`${field} must be one of: ${allowed.join(', ')}`);
  return value;
}
export const sleep = (ms) => new Promise(r => setTimeout(r, ms));
// Prevent spreadsheet formula injection in CSV exports.
export function csvCell(v) {
  let s = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
export const toCsv = (rows, cols) => [cols.join(','), ...rows.map(r => cols.map(c => csvCell(r[c])).join(','))].join('\n') + '\n';
export const clampInt = (v, d, min, max) => { const n = Number.parseInt(v, 10); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : d; };
