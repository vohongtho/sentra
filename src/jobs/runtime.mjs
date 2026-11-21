// Worker loop, outbox dispatcher and scheduler. Browser sessions never drive execution.
import { claim, complete, fail, cancelled, saveCheckpoint, extendLease, enqueue, isCancelRequested, LeaseLostError } from './queue.mjs';
import { nextOccurrence, occurrencesBetween } from '../domain/timezone.mjs';
import { log, als } from '../log.mjs';
import { id } from '../util.mjs';

const handlers = new Map();
const subscribers = new Map();
export const registerHandler = (type, fn, opts = {}) => handlers.set(type, { fn, ...opts });
export const subscribe = (eventType, fn) => { if (!subscribers.has(eventType)) subscribers.set(eventType, []); subscribers.get(eventType).push(fn); };
export const handlerTypes = () => [...handlers.keys()];

export class RetryableError extends Error {}
export class PermanentError extends Error {}

/** Insert a domain event into the outbox inside the caller's transaction. */
export async function emit(db, orgId, eventType, payload) {
  await db.query('INSERT INTO outbox (org_id, event_type, payload) VALUES ($1,$2,$3)', [orgId, eventType, payload]);
}

export async function runOneJob(app, workerId = 'inline') {
  const { db } = app;
  const job = await claim(db, workerId, 120);
  if (!job) return null;
  const h = handlers.get(job.type);
  return als.run({ correlationId: job.correlation_id || job.id }, async () => {
    if (!h) { await fail(db, job, `No handler for job type ${job.type}`, { retryable: false }); return job; }
    const started = Date.now();
    const timer = setInterval(() => extendLease(db, job).catch(() => {}), 30000);
    try {
      const helpers = {
        checkpoint: (c) => saveCheckpoint(db, job, c),
        isCancelled: () => isCancelRequested(db, job.id),
        heartbeat: () => extendLease(db, job),
      };
      const result = await h.fn(app, job, helpers);
      if (result === 'cancelled') { await cancelled(db, job); log.info('job_cancelled', { job_id: job.id, type: job.type }); }
      else {
        await complete(db, job, result || {});
        if (job.schedule_id) await db.query('UPDATE schedules SET last_success_at=now() WHERE id=$1', [job.schedule_id]);
        log.info('job_succeeded', { job_id: job.id, type: job.type, ms: Date.now() - started });
      }
    } catch (e) {
      if (e instanceof LeaseLostError) { log.warn('job_lease_lost', { job_id: job.id }); return job; }
      const outcome = await fail(db, job, e, { retryable: !(e instanceof PermanentError) });
      log.warn('job_failed', { job_id: job.id, type: job.type, attempt: job.attempts, outcome, error: String(e?.message || e) });
      if (outcome === 'dead') await emit(db, job.org_id, 'job.dead_lettered', { job_id: job.id, type: job.type, error: String(e?.message || e) }).catch(() => {});
    } finally { clearInterval(timer); }
    return job;
  });
}

export async function dispatchOutbox(app, limit = 50) {
  const { db } = app;
  const events = await db.query('SELECT * FROM outbox WHERE processed_at IS NULL AND attempts < 10 ORDER BY id LIMIT $1', [limit]);
  for (const ev of events) {
    try {
      for (const fn of subscribers.get(ev.event_type) || []) await fn(app, ev);
      for (const fn of subscribers.get('*') || []) await fn(app, ev);
      await db.query('UPDATE outbox SET processed_at=now() WHERE id=$1', [ev.id]);
    } catch (e) {
      log.warn('outbox_dispatch_failed', { event_id: ev.id, type: ev.event_type, error: String(e?.message || e) });
      await db.query('UPDATE outbox SET attempts=attempts+1, last_error=$2 WHERE id=$1', [ev.id, String(e?.message || e).slice(0, 1000)]);
    }
  }
  return events.length;
}

const GRACE_MS = 5 * 60 * 1000;
/** Materialize due schedule occurrences into durable jobs. Occurrence id = schedule id + original UTC time. */
export async function schedulerTick(app, now = new Date()) {
  const { db } = app;
  const due = await db.query('SELECT * FROM schedules WHERE NOT paused AND archived_at IS NULL AND next_run_at <= $1 ORDER BY next_run_at LIMIT 100', [now.toISOString()]);
  let created = 0;
  for (const s of due) {
    const spec = { frequency: s.frequency, local_time: s.local_time, weekday: s.weekday, timezone: s.timezone };
    const first = new Date(s.next_run_at);
    const occ = [first, ...occurrencesBetween(spec, first, now)];
    let toRun;
    const latest = occ[occ.length - 1];
    if (s.missed_run_policy === 'run_all') toRun = occ;
    else if (s.missed_run_policy === 'run_once') toRun = [latest];
    else toRun = occ.filter(o => now - o <= GRACE_MS); // skip: only on-time occurrences
    const skipped = occ.filter(o => !toRun.includes(o));
    if (s.overlap_policy === 'skip') {
      const active = await db.one(`SELECT id FROM jobs WHERE schedule_id=$1 AND status IN ('queued','running') LIMIT 1`, [s.id]);
      if (active) { skipped.push(...toRun); toRun = []; }
    }
    for (const o of toRun) {
      const r = await enqueue(db, { type: s.job_type, orgId: s.org_id, projectId: s.project_id, payload: { ...s.params, schedule_id: s.id, scheduled_for: o.toISOString(), timeout_s: s.timeout_s }, idempotencyKey: `sched:${s.id}:${o.toISOString()}`, scheduleId: s.id, scheduledFor: o.toISOString(), maxAttempts: Math.max(1, s.retry_budget + 1) });
      if (r.created) created++;
    }
    if (skipped.length) await emit(db, s.org_id, 'schedule.occurrences_skipped', { schedule_id: s.id, occurrences: skipped.map(d => d.toISOString()), policy: s.missed_run_policy, overlap: s.overlap_policy });
    const next = nextOccurrence(spec, now);
    await db.query('UPDATE schedules SET next_run_at=$2, last_attempt_at=$3 WHERE id=$1', [s.id, next.toISOString(), now.toISOString()]);
  }
  await db.query(`INSERT INTO system_heartbeats (component, beat_at, info) VALUES ('scheduler', now(), $1) ON CONFLICT (component) DO UPDATE SET beat_at=now(), info=$1`, [{ due: due.length, created }]);
  return { due: due.length, created };
}

/** Process everything currently runnable (used by tests, the demo script and "drain" admin action). */
export async function drain(app, { maxJobs = 500, now } = {}) {
  let n = 0;
  for (let i = 0; i < maxJobs; i++) {
    const ev = await dispatchOutbox(app);
    const job = await runOneJob(app, 'drain');
    if (job) n++;
    if (!job && !ev) break;
  }
  return n;
}

export function startBackground(app) {
  const workerId = 'worker:' + id('w').slice(2);
  let stopped = false; const timers = [];
  const loop = async (fn, ms, name) => {
    while (!stopped) {
      try { await fn(); } catch (e) { log.error('background_loop_error', { loop: name, error: String(e?.stack || e) }); }
      await new Promise(r => timers.push(setTimeout(r, ms)));
    }
  };
  if (app.cfg.runWorkers) {
    loop(async () => { let n = 0; while (!stopped && n < 20 && (await runOneJob(app, workerId))) n++; await app.db.query(`INSERT INTO system_heartbeats (component, beat_at) VALUES ($1, now()) ON CONFLICT (component) DO UPDATE SET beat_at=now()`, [workerId]); }, app.cfg.workerPollMs, 'worker');
    loop(() => dispatchOutbox(app), app.cfg.workerPollMs, 'outbox');
  }
  if (app.cfg.runScheduler) loop(() => schedulerTick(app), 15000, 'scheduler');
  return () => { stopped = true; timers.forEach(clearTimeout); };
}
