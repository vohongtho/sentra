// Retention enforcement per organization (settings.retention_days, minimum 30).
// Deletes expired operational records and superseded inventory snapshots; archives whole audit periods to object
// storage before deleting them, recording the last archived hash so chain verification continues from that anchor.
// Never deleted: findings, evidence, finding events, advisories, current/latest inventory, open alerts.
import { id } from '../util.mjs';

export async function runRetention(app, orgId) {
  const db = app.db;
  const org = await db.one('SELECT settings FROM organizations WHERE id=$1', [orgId]);
  const days = Math.max(30, Number(org?.settings?.retention_days) || 730);
  const cutoff = new Date(Date.now() - days * 86400_000).toISOString();
  const n = {};
  const del = async (k, sql, params = []) => { n[k] = (await db.query(sql, params)).length; };
  await del('notifications', `DELETE FROM notifications WHERE org_id=$1 AND created_at < $2 RETURNING id`, [orgId, cutoff]);
  await del('deliveries', `DELETE FROM deliveries WHERE org_id=$1 AND updated_at < $2 AND status IN ('accepted','delivered','dead','suppressed','failed') RETURNING id`, [orgId, cutoff]);
  await del('resolved_alerts', `DELETE FROM alerts WHERE org_id=$1 AND state='resolved' AND updated_at < $2 RETURNING id`, [orgId, cutoff]);
  await del('jobs', `DELETE FROM jobs WHERE org_id=$1 AND status IN ('succeeded','cancelled','dead') AND finished_at < $2 RETURNING id`, [orgId, cutoff]);
  await del('outbox', `DELETE FROM outbox WHERE org_id=$1 AND processed_at < $2 RETURNING id`, [orgId, cutoff]);
  await del('report_runs', `DELETE FROM report_runs WHERE org_id=$1 AND created_at < $2 RETURNING id`, [orgId, cutoff]);
  await del('tool_executions', `DELETE FROM tool_executions WHERE investigation_id IN (SELECT id FROM investigations WHERE org_id=$1 AND finished_at < $2) RETURNING id`, [orgId, cutoff]);
  // Superseded snapshots: older than cutoff, not the latest for their artifact/asset/source, and not backing a current deployment.
  await del('snapshots', `DELETE FROM inventory_snapshots s WHERE s.org_id=$1 AND s.created_at < $2
      AND s.id <> (SELECT x.id FROM inventory_snapshots x WHERE x.project_id=s.project_id AND x.artifact_id IS NOT DISTINCT FROM s.artifact_id AND x.asset_id IS NOT DISTINCT FROM s.asset_id AND x.source=s.source ORDER BY x.created_at DESC LIMIT 1)
      AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.is_current AND d.artifact_id=s.artifact_id) RETURNING s.id`, [orgId, cutoff]);
  // Audit: archive everything older than the cutoff as one period.
  const old = await db.query('SELECT * FROM audit_events WHERE org_id=$1 AND created_at < $2 ORDER BY seq', [orgId, cutoff]);
  n.audit_archived = 0;
  if (old.length) {
    const last = old[old.length - 1];
    const key = await app.objects.put(`${orgId}/audit-archive/${old[0].seq}-${last.seq}.json`, Buffer.from(JSON.stringify({ org_id: orgId, from_seq: old[0].seq, through_seq: last.seq, last_hash: last.hash, events: old })), 'application/json');
    await db.tx(async (t) => {
      await t.query('INSERT INTO audit_archives (id, org_id, through_seq, last_hash, event_count, object_key) VALUES ($1,$2,$3,$4,$5,$6)', [id('arc'), orgId, last.seq, last.hash, old.length, key]);
      await t.query('DELETE FROM audit_events WHERE org_id=$1 AND seq <= $2', [orgId, last.seq]);
    });
    n.audit_archived = old.length;
  }
  await db.query(`DELETE FROM sessions WHERE (revoked_at IS NOT NULL OR expires_at < now()) AND created_at < now() - interval '7 days'`);
  await db.query(`DELETE FROM webhook_receipts WHERE received_at < $1`, [cutoff]);
  return { retention_days: days, cutoff, deleted: n };
}
