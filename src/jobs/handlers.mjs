// Job handlers and outbox subscriptions (the event-driven backbone).
import { registerHandler, subscribe, PermanentError } from './runtime.mjs';
import { enqueue } from './queue.mjs';
import { processIngestion } from '../services/ingestion.mjs';
import { assessProject, verifyFinding, normName } from '../services/matching.mjs';
import { deliverJob, escalateJob, handleEventForAlerts, slaEvaluationJob } from '../services/alerts.mjs';
import { createTicket, syncTicketsOnVerified } from '../services/tickets.mjs';
import { runInvestigation, createInvestigation } from '../ai/agents.mjs';
import { syncConnection, testConnection, CONNECTORS } from '../connectors/index.mjs';
import { generateDailyReport } from '../services/reports.mjs';
import { runRetention } from '../services/retention.mjs';

export function registerAll() {
  registerHandler('process_ingestion', (app, job) => processIngestion(app, job.payload.ingestion_id));
  registerHandler('assess_project', (app, job) => assessProject(app, job.payload.project_id, { reason: job.payload.reason, advisoryId: job.payload.advisory_id || null }));
  registerHandler('reassess_advisory', async (app, job) => {
    const { advisory_id, reason } = job.payload;
    const pkgs = await app.db.query('SELECT DISTINCT ecosystem, package_name FROM affected_ranges WHERE advisory_id=$1', [advisory_id]);
    const projects = new Set();
    for (const p of pkgs) for (const r of await app.db.query(`SELECT DISTINCT o.project_id FROM observations o JOIN components c ON c.id=o.component_id WHERE c.ecosystem=$1 AND (c.name=$2 OR ($1='pypi' AND lower(replace(replace(c.name,'_','-'),'.','-'))=$2))`, [p.ecosystem, normName(p.ecosystem, p.package_name)])) projects.add(r.project_id);
    for (const r of await app.db.query('SELECT DISTINCT project_id FROM findings WHERE advisory_id=$1', [advisory_id])) projects.add(r.project_id);
    const out = {};
    for (const pid of projects) out[pid] = await assessProject(app, pid, { reason: `${reason} (${advisory_id})`, advisoryId: advisory_id });
    return { projects: projects.size, results: out };
  });
  registerHandler('verify_finding', (app, job) => verifyFinding(app, job.payload.finding_id));
  registerHandler('deliver', (app, job) => deliverJob(app, job));
  registerHandler('escalate_alert', (app, job) => escalateJob(app, job));
  registerHandler('unsnooze_alert', async (app, job) => { await app.db.query(`UPDATE alerts SET state='open', snoozed_until=NULL, updated_at=now() WHERE id=$1 AND state='snoozed' AND snoozed_until <= now() + interval '5 seconds'`, [job.payload.alert_id]); return {}; });
  registerHandler('create_ticket', async (app, job) => { const r = await createTicket(app, { findingId: job.payload.finding_id, provider: job.payload.provider, connectionId: job.payload.connection_id, actor: job.payload.actor || 'rule' }); return { ticket_id: r.ticket.id, duplicate: r.duplicate }; });
  registerHandler('sync_tickets_verified', async (app, job) => ({ closed: await syncTicketsOnVerified(app, job.payload.finding_id) }));
  registerHandler('run_investigation', (app, job, helpers) => runInvestigation(app, job, helpers));
  registerHandler('auto_investigate', async (app, job) => {
    const inv = await createInvestigation(app, { orgId: job.org_id, actorType: 'system', systemActor: 'system:alert-rule', orgRole: 'org_admin', projectRoles: new Map(), db: app.db, identity: null }, { workflow: job.payload.workflow, findingId: job.payload.finding_id });
    return { investigation_id: inv.id };
  });
  registerHandler('connector_sync', async (app, job, helpers) => {
    const conn = await app.db.one('SELECT * FROM connections WHERE id=$1', [job.payload.connection_id]);
    if (!conn) throw new PermanentError('Connection removed.');
    return syncConnection(app, conn, helpers);
  });
  // ---- scheduled job families
  const forKinds = (kinds) => async (app, job, helpers) => {
    const conns = await app.db.query(`SELECT * FROM connections WHERE org_id=$1 AND kind = ANY($2) AND status NOT IN ('disabled','disconnected') AND ($3::text IS NULL OR project_id=$3 OR project_id IS NULL)`, [job.org_id, kinds, job.project_id]);
    const results = {}; const errors = [];
    for (const c of conns) { try { results[c.name] = await syncConnection(app, c, helpers); } catch (e) { errors.push(`${c.name}: ${e.message}`); } }
    if (errors.length && errors.length === conns.length) throw new Error(errors.join('; '));
    return { results, errors };
  };
  registerHandler('advisory_sync', forKinds(['osv', 'kev', 'epss']));
  registerHandler('stack_collection', forKinds(['github', 'aws', 'dependency_track']));
  registerHandler('connector_health', async (app, job) => {
    const conns = await app.db.query(`SELECT * FROM connections WHERE org_id=$1 AND status NOT IN ('disabled','disconnected')`, [job.org_id]);
    const out = {};
    for (const c of conns) { if (!CONNECTORS[c.kind]?.test) continue; out[c.name] = await testConnection(app, c); if (!out[c.name].ok) await app.db.query(`INSERT INTO outbox (org_id, event_type, payload) VALUES ($1,'connector.failed',$2)`, [c.org_id, { connection_id: c.id, connection_name: c.name, project_id: c.project_id, summary: `Health check failed for ${c.name}: ${out[c.name].error}` }]); }
    // freshness: sources past their threshold mark observations stale
    for (const c of conns) { const hrs = c.config?.freshness_hours; if (hrs && c.last_success_at && Date.now() - new Date(c.last_success_at) > hrs * 3600_000) { await app.db.query(`UPDATE observations SET stale=true WHERE source=$1 AND NOT stale`, [`connector:${c.id}`]); await app.db.query(`INSERT INTO outbox (org_id, event_type, payload) VALUES ($1,'inventory.stale',$2)`, [c.org_id, { connection_id: c.id, project_id: c.project_id, summary: `${c.name} exceeded freshness threshold (${hrs}h).` }]); } }
    return out;
  });
  registerHandler('inventory_reassessment', async (app, job) => {
    const projects = await app.db.query(`SELECT id FROM projects WHERE org_id=$1 AND archived_at IS NULL AND ($2::text IS NULL OR id=$2)`, [job.org_id, job.project_id]);
    const out = {}; for (const p of projects) out[p.id] = await assessProject(app, p.id, { reason: 'scheduled_reassessment' }); return out;
  });
  registerHandler('verification', async (app, job) => {
    const fs = await app.db.query(`SELECT id FROM findings WHERE org_id=$1 AND status IN ('verification_pending','deployed') AND ($2::text IS NULL OR project_id=$2)`, [job.org_id, job.project_id]);
    const out = {}; for (const f of fs) out[f.id] = await verifyFinding(app, f.id); return out;
  });
  registerHandler('retention', (app, job) => runRetention(app, job.org_id));
  registerHandler('sla_evaluation', (app, job) => slaEvaluationJob(app, job));
  registerHandler('daily_report', (app, job) => generateDailyReport(app, { orgId: job.org_id, language: job.payload.language || 'vi', timezone: job.payload.timezone || 'Asia/Ho_Chi_Minh', scheduledFor: job.scheduled_for || new Date().toISOString(), scheduleId: job.schedule_id, jobId: job.id }));

  // ---- event subscriptions
  subscribe('inventory.updated', (app, ev) => enqueue(app.db, { type: 'assess_project', orgId: ev.org_id, projectId: ev.payload.project_id, payload: { project_id: ev.payload.project_id, reason: 'inventory.updated' }, idempotencyKey: `assess:${ev.payload.project_id}:${ev.id}` }));
  subscribe('deployment.recorded', (app, ev) => enqueue(app.db, { type: 'assess_project', orgId: ev.org_id, projectId: ev.payload.project_id, payload: { project_id: ev.payload.project_id, reason: 'deployment.recorded' }, idempotencyKey: `assess:${ev.payload.project_id}:${ev.id}`, priority: 20 }));
  subscribe('advisory.updated', (app, ev) => enqueue(app.db, { type: 'reassess_advisory', orgId: ev.org_id, payload: { advisory_id: ev.payload.advisory_id, reason: ev.payload.reason }, idempotencyKey: `reassess:${ev.payload.advisory_id}:${ev.id}`, priority: 20 }));
  subscribe('remediation.verified', (app, ev) => enqueue(app.db, { type: 'sync_tickets_verified', orgId: ev.org_id, payload: { finding_id: ev.payload.finding_id }, idempotencyKey: `tsync:${ev.payload.finding_id}:${ev.id}` }));
  subscribe('*', handleEventForAlerts);
}
