// Append-only audit trail with a per-organization hash chain (tamper evidence, not tamper proof).
import { id, sha256, stableStringify } from './util.mjs';
import { redact } from './log.mjs';

export function actorOf(ctx) {
  if (!ctx) return { id: 'system', type: 'system' };
  if (ctx.actorType === 'ci') return { id: ctx.ciToken?.id, type: 'ci' };
  if (ctx.actorType === 'agent') return { id: ctx.agentRunId, type: 'agent' };
  if (ctx.actorType === 'system') return { id: ctx.systemActor || 'system', type: 'system' };
  return { id: ctx.identity?.id, type: 'user' };
}

export async function audit(db, ctx, action, { targetType = null, targetId = null, projectId = null, data = {} } = {}) {
  const orgId = ctx?.orgId || null;
  const actor = actorOf(ctx);
  const doInsert = async (t) => {
    if (t.kind === 'postgres') await t.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['audit:' + (orgId || 'global')]);
    const prev = await t.one('SELECT hash FROM audit_events WHERE org_id IS NOT DISTINCT FROM $1 ORDER BY seq DESC LIMIT 1', [orgId]);
    const row = { id: id('aud'), org_id: orgId, project_id: projectId, actor_id: actor.id, actor_type: actor.type, action, target_type: targetType, target_id: targetId, data: redact(data), correlation_id: ctx?.correlationId || null, created_at: new Date().toISOString() };
    const hash = sha256((prev?.hash || 'genesis') + stableStringify(row));
    await t.query(`INSERT INTO audit_events (id, org_id, project_id, actor_id, actor_type, action, target_type, target_id, data, correlation_id, prev_hash, hash, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, [row.id, orgId, projectId, actor.id, actor.type, action, targetType, targetId, row.data, row.correlation_id, prev?.hash || null, hash, row.created_at]);
    return row.id;
  };
  return db.tx ? db.tx(doInsert) : doInsert(db);
}

/** Verify the hash chain for an organization; returns the first broken sequence number or null. */
export async function verifyAuditChain(db, orgId) {
  // Archived periods (retention) leave an anchor: verification continues from the last archived hash.
  const anchor = await db.one('SELECT through_seq, last_hash FROM audit_archives WHERE org_id=$1 ORDER BY through_seq DESC LIMIT 1', [orgId]);
  const rows = await db.query('SELECT * FROM audit_events WHERE org_id=$1 AND seq > $2 ORDER BY seq', [orgId, anchor?.through_seq || 0]);
  let prev = anchor?.last_hash || null;
  for (const r of rows) {
    const row = { id: r.id, org_id: r.org_id, project_id: r.project_id, actor_id: r.actor_id, actor_type: r.actor_type, action: r.action, target_type: r.target_type, target_id: r.target_id, data: r.data, correlation_id: r.correlation_id, created_at: new Date(r.created_at).toISOString() };
    const expect = sha256((prev || 'genesis') + stableStringify(row));
    if (r.prev_hash !== prev || r.hash !== expect) return { ok: false, broken_at: r.seq, checked: rows.length };
    prev = r.hash;
  }
  return { ok: true, checked: rows.length, anchored_at_seq: anchor?.through_seq || null };
}
