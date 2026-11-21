// Encrypted credential store. Values are sealed with the master key and never returned by any API,
// written to logs, evidence, exports or model inputs. Only metadata and a fingerprint are visible.
import { id, badRequest, notFound } from '../util.mjs';
import { seal, unseal, hashToken } from '../crypto.mjs';

export async function putSecret(db, orgId, rawName, value, createdBy, { derived = !!rawName && /^(channel|connection)\//.test(rawName) } = {}) {
  // Names derived from user-chosen connection/channel names are normalized; names typed by a user are validated as-is.
  const name = derived ? String(rawName).replace(/[^\w.\-:/]+/g, '-').slice(0, 100) : rawName;
  if (!name || !/^[\w.\-:/]{1,100}$/.test(name)) throw badRequest('Secret name must be 1-100 chars [A-Za-z0-9_.-:/].');
  if (value == null || value === '') throw badRequest('Secret value is required.');
  const v = typeof value === 'string' ? value : JSON.stringify(value);
  if (v.length > 16384) throw badRequest('Secret value too large.');
  const sealed = seal(v, `secret:${orgId}:${name}`);
  const fingerprint = hashToken(v).slice(0, 8);
  const existing = await db.one('SELECT id FROM secrets WHERE org_id=$1 AND name=$2', [orgId, name]);
  if (existing) { await db.query('UPDATE secrets SET sealed=$2, fingerprint=$3, rotated_at=now() WHERE id=$1', [existing.id, sealed, fingerprint]); return { id: existing.id, name, fingerprint, rotated: true }; }
  const sid = id('sec');
  await db.query('INSERT INTO secrets (id, org_id, name, sealed, fingerprint, created_by) VALUES ($1,$2,$3,$4,$5,$6)', [sid, orgId, name, sealed, fingerprint, createdBy]);
  return { id: sid, name, fingerprint, rotated: false };
}
export async function getSecretValue(db, orgId, secretId) {
  const s = await db.one('SELECT * FROM secrets WHERE id=$1 AND org_id=$2', [secretId, orgId]);
  if (!s) throw notFound('Secret');
  return unseal(s.sealed, `secret:${orgId}:${s.name}`);
}
export async function listSecrets(db, orgId) {
  return db.query('SELECT id, name, fingerprint, created_by, rotated_at, created_at FROM secrets WHERE org_id=$1 ORDER BY name', [orgId]);
}
