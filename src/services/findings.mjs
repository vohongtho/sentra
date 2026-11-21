// Finding queries and human workflow actions. Every action is authorized per project and audited.
import { id, badRequest, notFound, forbidden, conflict, clampInt, toCsv } from '../util.mjs';
import { canTransition, REQUIRES_REASON, STATUSES, APPLICABILITY } from '../domain/policy.mjs';
import { accessibleProjectIds, requireProject, projectPermissions, orgWide } from '../authz.mjs';
import { audit } from '../audit.mjs';
import { emit } from '../jobs/runtime.mjs';

const SORTS = { priority: 'f.priority ASC, f.sla_due_at ASC NULLS LAST', due: 'f.sla_due_at ASC NULLS LAST', newest: 'f.first_seen_at DESC', updated: 'f.updated_at DESC' };
const CLOSED = ['verified_fixed', 'false_positive', 'accepted_risk'];

export async function listFindings(db, ctx, q = {}) {
  const ids = await accessibleProjectIds(ctx);
  const where = ['f.org_id=$1', 'f.project_id = ANY($2)']; const params = [ctx.orgId, q.project_id ? ids.filter(i => i === q.project_id) : ids];
  const add = (sql, v) => { params.push(v); where.push(sql.replace('?', '$' + params.length)); };
  if (q.status === 'open' || !q.status) add('NOT (f.status = ANY(?))', CLOSED); else if (q.status === 'closed') add('f.status = ANY(?)', CLOSED); else if (q.status !== 'all') add('f.status = ?', q.status);
  if (q.priority) add('f.priority = ANY(?)', String(q.priority).split(','));
  if (q.applicability) add('f.applicability = ANY(?)', String(q.applicability).split(','));
  if (q.exploitation) add('f.exploitation = ANY(?)', String(q.exploitation).split(','));
  if (q.environment) add('e.key = ?', q.environment);
  if (q.production === 'true') where.push('e.is_production');
  if (q.ecosystem) add('c.ecosystem = ?', q.ecosystem);
  if (q.advisory_id) add('(f.advisory_id = ? OR f.advisory_id IN (SELECT advisory_id FROM advisory_aliases WHERE alias = $' + (params.length) + '))', q.advisory_id);
  if (q.root_cause) add('f.root_cause_key = ?', q.root_cause);
  if (q.campaign_id) add('f.campaign_id = ?', q.campaign_id);
  if (q.overdue === 'true') where.push(`f.sla_due_at < now() AND NOT (f.status = ANY(ARRAY['verified_fixed','false_positive','accepted_risk']))`);
  if (q.q) add(`(f.advisory_id ILIKE ? OR c.name ILIKE $${params.length} OR a.title ILIKE $${params.length})`, `%${String(q.q).slice(0, 100)}%`);
  const limit = clampInt(q.limit, 50, 1, 500), offset = clampInt(q.offset, 0, 0, 1_000_000);
  const sql = `FROM findings f JOIN components c ON c.id=f.component_id JOIN advisories a ON a.id=f.advisory_id JOIN projects p ON p.id=f.project_id LEFT JOIN environments e ON e.id=f.environment_id LEFT JOIN services s ON s.id=f.service_id LEFT JOIN identities i ON i.id=COALESCE(f.owner_identity_id, p.owner_identity_id) WHERE ${where.join(' AND ')}`;
  const total = (await db.one(`SELECT count(*)::int AS n ${sql}`, params)).n;
  const rows = await db.query(`SELECT f.id, f.project_id, p.key AS project_key, p.name AS project_name, f.advisory_id, a.title AS advisory_title, a.is_synthetic, c.name AS package, c.ecosystem, f.observed_version, f.fixed_version, f.severity, f.applicability, f.exploitation, f.priority, f.status, f.verification_status,
      e.key AS environment, e.is_production, s.key AS service, f.asset_id, f.sla_due_at, f.first_seen_at, f.updated_at, i.display_name AS owner, f.root_cause_key, f.campaign_id ${sql} ORDER BY ${SORTS[q.sort] || SORTS.priority} LIMIT ${limit} OFFSET ${offset}`, params);
  return { total, limit, offset, items: rows };
}

export async function exportFindingsCsv(db, ctx, q) {
  const { items } = await listFindings(db, ctx, { ...q, limit: 500 });
  for (const pid of new Set(items.map(i => i.project_id))) await requireProject(ctx, pid, 'export');
  await audit(db, ctx, 'findings.export', { data: { count: items.length, filters: q } });
  return toCsv(items, ['id', 'project_key', 'service', 'environment', 'advisory_id', 'package', 'ecosystem', 'observed_version', 'fixed_version', 'severity', 'applicability', 'exploitation', 'priority', 'status', 'verification_status', 'sla_due_at', 'owner']);
}

export async function getFinding(db, ctx, findingId) {
  const f = await db.one(`SELECT f.*, p.key AS project_key, p.name AS project_name, c.purl, c.name AS package, c.ecosystem, c.kind AS component_kind, a.title AS advisory_title, a.summary AS advisory_summary, a.cvss_vector, a.cvss_score, a.is_synthetic, a.current_revision AS advisory_revision, a.references_json, a.prerequisites, a.mitigations,
      e.key AS environment, e.is_production, e.timezone, s.key AS service, art.digest, art.commit_sha, d.deployed_at, i.display_name AS owner, i.email AS owner_email, t.name AS team
    FROM findings f JOIN projects p ON p.id=f.project_id JOIN components c ON c.id=f.component_id JOIN advisories a ON a.id=f.advisory_id LEFT JOIN environments e ON e.id=f.environment_id LEFT JOIN services s ON s.id=f.service_id
    LEFT JOIN artifacts art ON art.id=f.artifact_id LEFT JOIN deployments d ON d.id=f.deployment_id LEFT JOIN identities i ON i.id=COALESCE(f.owner_identity_id, p.owner_identity_id) LEFT JOIN teams t ON t.id=f.owner_team_id WHERE f.id=$1 AND f.org_id=$2`, [findingId, ctx.orgId]);
  if (!f) throw notFound('Finding');
  await requireProject(ctx, f.project_id, 'project:read');
  const [evidence, events, tickets, prs, exceptions, signals, related, investigations, alerts] = await Promise.all([
    db.query('SELECT * FROM evidence WHERE finding_id=$1 ORDER BY collected_at', [f.id]),
    db.query(`SELECT fe.*, i.display_name AS actor_name FROM finding_events fe LEFT JOIN identities i ON i.id=fe.actor WHERE fe.finding_id=$1 ORDER BY fe.created_at`, [f.id]),
    db.query('SELECT * FROM tickets WHERE finding_id=$1', [f.id]),
    db.query('SELECT * FROM pull_requests WHERE finding_id=$1 ORDER BY created_at', [f.id]),
    db.query('SELECT * FROM risk_exceptions WHERE finding_id=$1 ORDER BY created_at DESC', [f.id]),
    db.query(`SELECT kind, value, source, observed_at FROM exploit_signals WHERE advisory_id=$1 OR advisory_id IN (SELECT alias FROM advisory_aliases WHERE advisory_id=$1)`, [f.advisory_id]),
    db.query(`SELECT f2.id, p2.key AS project_key, s2.key AS service, e2.key AS environment, f2.status, f2.priority FROM findings f2 JOIN projects p2 ON p2.id=f2.project_id LEFT JOIN services s2 ON s2.id=f2.service_id LEFT JOIN environments e2 ON e2.id=f2.environment_id WHERE f2.root_cause_key=$1 AND f2.id<>$2 AND f2.org_id=$3 AND f2.project_id = ANY($4)`, [f.root_cause_key, f.id, ctx.orgId, await accessibleProjectIds(ctx)]),
    db.query(`SELECT id, workflow, state, created_at, model FROM investigations WHERE inputs->>'finding_id'=$1 ORDER BY created_at DESC`, [f.id]),
    db.query('SELECT id, trigger, state, created_at FROM alerts WHERE finding_id=$1 ORDER BY created_at', [f.id]),
  ]);
  const perms = [...projectPermissions(ctx, f.project_id)];
  return { ...f, evidence, events, tickets, pull_requests: prs, exceptions, signals, related, investigations, alerts, permissions: perms, allowed_transitions: STATUSES.filter(s => canTransition(f.status, s)) };
}

export async function transition(db, ctx, findingId, { to, reason }) {
  if (!STATUSES.includes(to)) throw badRequest('Unknown status.');
  const f = await db.one('SELECT * FROM findings WHERE id=$1 AND org_id=$2', [findingId, ctx.orgId]);
  if (!f) throw notFound('Finding');
  await requireProject(ctx, f.project_id, ['false_positive', 'accepted_risk'].includes(to) ? 'findings:triage' : 'findings:write');
  if (to === 'verified_fixed') throw forbidden('Verified fixed is set only by the verification service after the fixed artifact is observed in the affected environment.');
  if (to === 'accepted_risk') throw badRequest('Use the risk exception flow (scope, approver, rationale, expiry).');
  if (!canTransition(f.status, to)) throw conflict(`Transition ${f.status} → ${to} is not allowed.`);
  if (REQUIRES_REASON.includes(to) && !(reason && reason.trim().length >= 5)) throw badRequest('A reason (≥5 chars) is required for this transition.');
  const now = new Date();
  let pausedSecs = f.sla_paused_seconds, pausedAt = f.sla_paused_at, due = f.sla_due_at;
  if (to === 'paused') pausedAt = now.toISOString();
  if (f.status === 'paused' && f.sla_paused_at) { const s = Math.round((now - new Date(f.sla_paused_at)) / 1000); pausedSecs += s; pausedAt = null; if (due) due = new Date(new Date(due).getTime() + s * 1000).toISOString(); }
  const applicability = to === 'false_positive' ? 'not_affected' : to === 'new' ? 'under_investigation' : f.applicability;
  await db.tx(async (t) => {
    await t.query(`UPDATE findings SET status=$2, status_reason=$3, applicability=$4, applicability_justification=CASE WHEN $2='false_positive' THEN $3 ELSE applicability_justification END, sla_paused_at=$5, sla_paused_seconds=$6, sla_due_at=$7,
      closed_at=CASE WHEN $2='false_positive' THEN now() WHEN $2='new' THEN NULL ELSE closed_at END, verification_status=CASE WHEN $2='new' THEN 'not_started' ELSE verification_status END, updated_at=now() WHERE id=$1`, [f.id, to, reason || null, applicability, pausedAt, pausedSecs, due]);
    await t.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor) VALUES ($1,$2,'status',$3,$4,$5,$6)`, [id('fev'), f.id, f.status, to, reason || null, ctx.identity.id]);
    if (to === 'fix_available') await emit(t, f.org_id, 'fix.available', { finding_id: f.id, project_id: f.project_id });
    await audit(t, ctx, 'finding.transition', { targetType: 'finding', targetId: f.id, projectId: f.project_id, data: { from: f.status, to, reason } });
  });
  return { id: f.id, status: to };
}

export async function assign(db, ctx, findingId, { identity_id, team_id }) {
  const f = await db.one('SELECT * FROM findings WHERE id=$1 AND org_id=$2', [findingId, ctx.orgId]);
  if (!f) throw notFound('Finding');
  await requireProject(ctx, f.project_id, 'findings:write');
  if (identity_id) { const ok = await db.one(`SELECT 1 FROM memberships WHERE identity_id=$1 AND org_id=$2`, [identity_id, ctx.orgId]); if (!ok) throw badRequest('Assignee is not a member of this organization.'); }
  await db.query(`UPDATE findings SET owner_identity_id=$2, owner_team_id=COALESCE($3, owner_team_id), status=CASE WHEN status IN ('new','triaged') THEN 'assigned' ELSE status END, updated_at=now() WHERE id=$1`, [f.id, identity_id || null, team_id || null]);
  await db.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor) VALUES ($1,$2,'assignment',$3,$4,'Owner changed',$5)`, [id('fev'), f.id, f.owner_identity_id, identity_id, ctx.identity.id]);
  await audit(db, ctx, 'finding.assign', { targetType: 'finding', targetId: f.id, projectId: f.project_id, data: { identity_id, team_id } });
  return { ok: true };
}

export async function comment(db, ctx, findingId, text) {
  const f = await db.one('SELECT * FROM findings WHERE id=$1 AND org_id=$2', [findingId, ctx.orgId]);
  if (!f) throw notFound('Finding');
  await requireProject(ctx, f.project_id, 'findings:write');
  if (!text || text.length > 4000) throw badRequest('Comment must be 1-4000 chars.');
  await db.query(`INSERT INTO finding_events (id, finding_id, kind, reason, actor) VALUES ($1,$2,'comment',$3,$4)`, [id('fev'), f.id, text, ctx.identity.id]);
  return { ok: true };
}

/** Risk exceptions: scope, approver, rationale, expiry and re-evaluation triggers. Requester cannot self-approve. */
export async function requestException(db, ctx, findingId, { kind = 'accepted_risk', rationale, expires_at, scope = {} }) {
  const f = await db.one('SELECT * FROM findings WHERE id=$1 AND org_id=$2', [findingId, ctx.orgId]);
  if (!f) throw notFound('Finding');
  await requireProject(ctx, f.project_id, 'exceptions:request');
  if (!['accepted_risk', 'gate_exception'].includes(kind)) throw badRequest('kind must be accepted_risk or gate_exception.');
  if (!rationale || rationale.length < 20) throw badRequest('Rationale must be at least 20 characters.');
  const exp = new Date(expires_at); if (isNaN(exp) || exp < new Date() || exp - new Date() > 365 * 86400000) throw badRequest('Expiry must be in the future and within 365 days.');
  const eid = id('exc');
  await db.query(`INSERT INTO risk_exceptions (id, org_id, project_id, finding_id, advisory_id, kind, scope, rationale, requested_by, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [eid, ctx.orgId, f.project_id, f.id, f.advisory_id, kind, { environment_id: f.environment_id, service_id: f.service_id, ...scope }, rationale, ctx.identity.id, exp.toISOString()]);
  await db.query(`INSERT INTO finding_events (id, finding_id, kind, to_value, reason, actor) VALUES ($1,$2,'exception','requested',$3,$4)`, [id('fev'), f.id, rationale, ctx.identity.id]);
  await audit(db, ctx, 'exception.requested', { targetType: 'risk_exception', targetId: eid, projectId: f.project_id, data: { kind, expires_at } });
  return { id: eid, status: 'pending_approval' };
}
export async function decideException(db, ctx, exceptionId, { decision }) {
  const e = await db.one('SELECT * FROM risk_exceptions WHERE id=$1 AND org_id=$2', [exceptionId, ctx.orgId]);
  if (!e || e.approved_by || e.revoked_at) throw notFound('Pending exception');
  await requireProject(ctx, e.project_id, 'exceptions:approve');
  if (e.requested_by === ctx.identity.id) throw forbidden('Requester cannot approve their own exception.');
  if (decision === 'approve') {
    await db.query('UPDATE risk_exceptions SET approved_by=$2 WHERE id=$1', [e.id, ctx.identity.id]);
    if (e.kind === 'accepted_risk' && e.finding_id) {
      const f = await db.one('SELECT status FROM findings WHERE id=$1', [e.finding_id]);
      await db.query(`UPDATE findings SET status='accepted_risk', status_reason=$2, closed_at=now(), updated_at=now() WHERE id=$1`, [e.finding_id, `Risk accepted until ${new Date(e.expires_at).toISOString().slice(0, 10)}: ${e.rationale}`]);
      await db.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor) VALUES ($1,$2,'status',$3,'accepted_risk',$4,$5)`, [id('fev'), e.finding_id, f.status, `Exception ${e.id} approved; expires ${e.expires_at}`, ctx.identity.id]);
    }
  } else await db.query('UPDATE risk_exceptions SET revoked_at=now() WHERE id=$1', [e.id]);
  await audit(db, ctx, `exception.${decision === 'approve' ? 'approved' : 'rejected'}`, { targetType: 'risk_exception', targetId: e.id, projectId: e.project_id });
  return { id: e.id, decision };
}

export async function bulk(db, ctx, { ids = [], action, to, reason, identity_id }) {
  if (!Array.isArray(ids) || !ids.length || ids.length > 200) throw badRequest('Provide 1-200 finding ids.');
  const results = [];
  for (const fid of ids) {
    try {
      if (action === 'transition') results.push({ id: fid, ok: true, ...(await transition(db, ctx, fid, { to, reason })) });
      else if (action === 'assign') { await assign(db, ctx, fid, { identity_id }); results.push({ id: fid, ok: true }); }
      else throw badRequest('Unknown bulk action.');
    } catch (e) { results.push({ id: fid, ok: false, error: e.message }); }
  }
  return { results, succeeded: results.filter(r => r.ok).length, failed: results.filter(r => !r.ok).length };
}
export { orgWide };
