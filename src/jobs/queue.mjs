// Durable PostgreSQL-backed job queue: leases, fencing tokens, idempotency keys, bounded retries with jitter,
// dead-letter state, cancellation and checkpoints. Workers are at-least-once; handlers must be idempotent.
import { id } from '../util.mjs';
import { correlationId } from '../log.mjs';

export async function enqueue(db, { type, payload = {}, orgId = null, projectId = null, idempotencyKey = null, runAfter = null, maxAttempts = 5, priority = 100, scheduleId = null, scheduledFor = null, createdBy = null }) {
  const jid = id('job');
  const rows = await db.query(`INSERT INTO jobs (id, org_id, project_id, type, payload, idempotency_key, run_after, max_attempts, priority, schedule_id, scheduled_for, correlation_id, created_by)
    VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7, now()),$8,$9,$10,$11,$12,$13) ON CONFLICT (idempotency_key) DO NOTHING RETURNING *`,
    [jid, orgId, projectId, type, payload, idempotencyKey, runAfter, maxAttempts, priority, scheduleId, scheduledFor, correlationId() || null, createdBy]);
  if (rows[0]) return { job: rows[0], created: true };
  return { job: await db.one('SELECT * FROM jobs WHERE idempotency_key=$1', [idempotencyKey]), created: false };
}

export async function claim(db, workerId, leaseSeconds = 120, types = null) {
  const rows = await db.query(`UPDATE jobs SET status='running', lease_owner=$1, lease_expires_at=now() + ($2 || ' seconds')::interval,
      fence=fence+1, attempts=attempts+1, started_at=COALESCE(started_at, now())
    WHERE id = (SELECT id FROM jobs WHERE ((status='queued' AND run_after <= now()) OR (status='running' AND lease_expires_at < now()))
      AND NOT cancel_requested ${types ? 'AND type = ANY($3)' : ''} ORDER BY priority, run_after FOR UPDATE SKIP LOCKED LIMIT 1)
    RETURNING *`, types ? [workerId, String(leaseSeconds), types] : [workerId, String(leaseSeconds)]);
  return rows[0] || null;
}

export async function extendLease(db, job, leaseSeconds = 120) {
  const r = await db.query(`UPDATE jobs SET lease_expires_at=now() + ($3 || ' seconds')::interval WHERE id=$1 AND fence=$2 AND status='running' RETURNING id`, [job.id, job.fence, String(leaseSeconds)]);
  return r.length > 0;
}
export async function saveCheckpoint(db, job, checkpoint) {
  const r = await db.query('UPDATE jobs SET checkpoint=$3 WHERE id=$1 AND fence=$2 RETURNING id', [job.id, job.fence, checkpoint]);
  if (!r.length) throw new LeaseLostError();
}
export class LeaseLostError extends Error { constructor() { super('Lease lost (fencing token superseded)'); } }

export async function complete(db, job, result = {}) {
  const r = await db.query(`UPDATE jobs SET status='succeeded', result=$3, finished_at=now(), lease_owner=NULL, lease_expires_at=NULL, last_error=NULL WHERE id=$1 AND fence=$2 RETURNING id`, [job.id, job.fence, result]);
  return r.length > 0;
}
export function backoffMs(attempt, base = 2000, cap = 300000) {
  const exp = Math.min(cap, base * 2 ** Math.max(0, attempt - 1));
  return Math.floor(exp / 2 + Math.random() * (exp / 2)); // equal jitter
}
export async function fail(db, job, error, { retryable = true } = {}) {
  const dead = !retryable || job.attempts >= job.max_attempts;
  await db.query(`UPDATE jobs SET status=$3, last_error=$4, run_after=now() + ($5 || ' milliseconds')::interval, lease_owner=NULL, lease_expires_at=NULL,
    finished_at=CASE WHEN $3='dead' THEN now() ELSE NULL END WHERE id=$1 AND fence=$2`,
  [job.id, job.fence, dead ? 'dead' : 'queued', String(error?.message || error).slice(0, 2000), String(dead ? 0 : backoffMs(job.attempts))]);
  return dead ? 'dead' : 'retry';
}
export async function cancelled(db, job) {
  await db.query(`UPDATE jobs SET status='cancelled', finished_at=now(), lease_owner=NULL, lease_expires_at=NULL WHERE id=$1 AND fence=$2`, [job.id, job.fence]);
}
export async function requestCancel(db, jobId, orgId) {
  const r = await db.query(`UPDATE jobs SET cancel_requested=true, status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,
    finished_at=CASE WHEN status='queued' THEN now() ELSE finished_at END WHERE id=$1 AND org_id IS NOT DISTINCT FROM $2 AND status IN ('queued','running') RETURNING *`, [jobId, orgId]);
  return r[0] || null;
}
export async function replay(db, jobId, orgId) {
  const r = await db.query(`UPDATE jobs SET status='queued', attempts=0, run_after=now(), last_error=NULL, cancel_requested=false, finished_at=NULL WHERE id=$1 AND org_id IS NOT DISTINCT FROM $2 AND status IN ('dead','failed','cancelled') RETURNING *`, [jobId, orgId]);
  return r[0] || null;
}
export async function isCancelRequested(db, jobId) { return !!(await db.one('SELECT cancel_requested FROM jobs WHERE id=$1', [jobId]))?.cancel_requested; }
export async function queueStats(db, orgId = null) {
  const rows = await db.query(`SELECT type, status, count(*)::int AS n FROM jobs WHERE ($1::text IS NULL OR org_id=$1) GROUP BY type, status`, [orgId]);
  const oldest = await db.one(`SELECT EXTRACT(EPOCH FROM (now() - min(run_after)))::int AS lag_s FROM jobs WHERE status='queued' AND run_after <= now() AND ($1::text IS NULL OR org_id=$1)`, [orgId]);
  return { by_type_status: rows, oldest_ready_lag_s: oldest?.lag_s ?? 0, dead_letter: rows.filter(r => r.status === 'dead').reduce((s, r) => s + r.n, 0) };
}
