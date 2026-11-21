// AES-256-GCM sealing for stored credentials and server-side OIDC tokens.
// Master key: SENTRA_MASTER_KEY (32 bytes, base64). Without it (development only) an ephemeral per-process key
// is generated and /api/health reports sealed values as non-durable across restarts.
import { randomBytes, createCipheriv, createDecipheriv, createHash, timingSafeEqual, createHmac } from 'node:crypto';
let KEY = null; let ephemeral = true;
export function initCrypto(cfg) {
  if (cfg.masterKey) {
    const raw = Buffer.from(cfg.masterKey, 'base64');
    if (raw.length !== 32) throw new Error('SENTRA_MASTER_KEY must be 32 bytes, base64-encoded.');
    KEY = raw; ephemeral = false;
  } else if (!KEY) { KEY = randomBytes(32); ephemeral = true; }
}
export const sealDurable = () => !ephemeral;
export function seal(plaintext, purpose) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', KEY, iv); c.setAAD(Buffer.from(purpose));
  const ct = Buffer.concat([c.update(String(plaintext), 'utf8'), c.final()]);
  return ['v1', iv.toString('base64url'), ct.toString('base64url'), c.getAuthTag().toString('base64url')].join('.');
}
export function unseal(sealed, purpose) {
  const [v, iv, ct, tag] = String(sealed).split('.');
  if (v !== 'v1') throw new Error('Unsupported sealed format');
  const d = createDecipheriv('aes-256-gcm', KEY, Buffer.from(iv, 'base64url'));
  d.setAAD(Buffer.from(purpose)); d.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
}
export const hashToken = (t) => createHash('sha256').update(String(t)).digest('hex');
export function safeEqual(a, b) { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); }
export const hmacHex = (key, data) => createHmac('sha256', key).update(data).digest('hex');
export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');
