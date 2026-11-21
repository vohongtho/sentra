// Alert rules → stable alerts → per-channel deliveries (outbox-driven jobs with retries, jitter, dead-letter).
// Routing rule, delivery channel and delivery attempt are separate records.
import { id, notFound, badRequest, AppError } from '../util.mjs';
import { enqueue } from '../jobs/queue.mjs';
import { emit, RetryableError } from '../jobs/runtime.mjs';
import { sendViaChannel, DeliveryError } from '../notify/senders.mjs';
import { localParts, formatLocal } from '../domain/timezone.mjs';
import { audit } from '../audit.mjs';
import { log } from '../log.mjs';

export const TRIGGERS = ['finding.created', 'finding.priority_changed', 'finding.exploitation_changed', 'deployment.newly_affected', 'fix.available', 'sla.approaching', 'sla.breached', 'verification.failed', 'verification.contradicted', 'remediation.verified', 'inventory.stale', 'connector.failed', 'job.dead_lettered', 'delivery.dead_lettered'];
const PRI = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };

function inQuietHours(qh, now = new Date()) {
  if (!qh?.start || !qh?.end || !qh?.timezone) return null;
  const l = localParts(now, qh.timezone); const cur = l.hour * 60 + l.minute;
  const [sh, sm] = qh.start.split(':').map(Number), [eh, em] = qh.end.split(':').map(Number);
  const s = sh * 60 + sm, e = eh * 60 + em;
  const inside = s <= e ? cur >= s && cur < e : cur >= s || cur < e;
  if (!inside) return null;
  const minutesLeft = (e - cur + 1440) % 1440 || 1440;
  return new Date(now.getTime() + minutesLeft * 60000);
}

async function findingContext(db, findingId) {
  return db.one(`SELECT f.*, p.name AS project_name, p.key AS project_key, p.org_id, p.owner_identity_id AS project_owner, s.key AS service_key, e.key AS env_key, e.is_production, e.timezone AS env_tz,
      a.title AS advisory_title, a.is_synthetic, c.name AS component_name, art.digest, i.display_name AS owner_name, i.email AS owner_email
    FROM findings f JOIN projects p ON p.id=f.project_id JOIN advisories a ON a.id=f.advisory_id JOIN components c ON c.id=f.component_id
    LEFT JOIN services s ON s.id=f.service_id LEFT JOIN environments e ON e.id=f.environment_id LEFT JOIN artifacts art ON art.id=f.artifact_id
    LEFT JOIN identities i ON i.id=COALESCE(f.owner_identity_id, p.owner_identity_id) WHERE f.id=$1`, [findingId]);
}

function ruleMatches(rule, trigger, f, payload) {
  if (!rule.enabled || !(rule.triggers || []).includes(trigger)) return false;
  if (rule.project_id && rule.project_id !== (f?.project_id || payload.project_id)) return false;
  if (!f) return true;
  const c = rule.conditions || {};
  if (c.production_only && !f.is_production) return false;
  if (c.environments?.length && !c.environments.includes(f.env_key)) return false;
  if (c.min_priority && PRI[f.priority] > PRI[c.min_priority]) return false;
  if (c.applicability?.length && !c.applicability.includes(f.applicability)) return false;
  if (c.exploitation?.length && !c.exploitation.includes(f.exploitation)) return false;
  if (trigger === 'finding.priority_changed' && !payload.increased) return false;
  if (['false_positive', 'accepted_risk', 'verified_fixed'].includes(f.status) && !['remediation.verified'].includes(trigger)) return false;
  return true;
}

function alertBody(app, f, trigger, payload, evidenceTop) {
  if (!f) return { title: `${trigger}: ${payload.summary || payload.connection_name || payload.type || ''}`.trim(), body: { text: payload.summary || JSON.stringify(payload).slice(0, 500), link: `${app.cfg.appOrigin}/#/ops/jobs` } };
  const titleBy = { 'finding.created': 'New affected finding', 'finding.priority_changed': `Priority increased to ${f.priority}`, 'finding.exploitation_changed': `Exploitation update: ${f.exploitation}`, 'sla.breached': 'SLA breached', 'sla.approaching': 'SLA due within 24h', 'verification.failed': 'Fix verification failed', 'verification.contradicted': 'Contradictory evidence reopened finding', 'deployment.newly_affected': 'Newly affected deployment', 'fix.available': 'Fix available', 'remediation.verified': 'Remediation verified' };
  const factors = (f.priority_explanation || []).filter(x => x.points > 0).map(x => `${x.factor}=${x.value}`).join(', ');
  return {
    title: `${f.is_synthetic ? '[SYNTHETIC] ' : ''}${titleBy[trigger] || trigger} — ${f.advisory_id} in ${f.component_name} (${f.project_key}/${f.service_key || 'asset'}/${f.env_key || '-'})`,
    body: {
      project: f.project_name, service: f.service_key, environment: f.env_key, deployment: f.digest ? `artifact ${f.digest}` : null,
      observed_version: f.observed_version || 'unknown', fixed_version: f.fixed_version, exploitation: f.exploitation, priority: f.priority, applicability: f.applicability,
      why: `${f.priority} because ${factors || 'policy defaults'}.`, evidence: evidenceTop,
      action: f.fixed_version ? `Upgrade ${f.component_name} to ${f.fixed_version} or later, redeploy to ${f.env_key}; closure happens only after the deployed artifact is verified.` : 'No verified fixed release recorded; review vendor guidance and mitigations, and run an impact investigation.',
      owner: f.owner_name ? `${f.owner_name}${f.owner_email ? ' <' + f.owner_email + '>' : ''}` : 'Unassigned', due: f.sla_due_at ? formatLocal(new Date(f.sla_due_at), f.env_tz || 'UTC') + ` (${f.env_tz || 'UTC'})` : 'No SLA',
      link: `${app.cfg.appOrigin}/#/findings/${f.id}`,
    },
  };
}

export async function handleEventForAlerts(app, ev) {
  const trigger = ev.event_type;
  if (!TRIGGERS.includes(trigger)) return;
  const p = ev.payload || {};
  const db = app.db;
  const f = p.finding_id ? await findingContext(db, p.finding_id) : null;
  const orgId = f?.org_id || ev.org_id;
  if (!orgId) return;
  const rules = await db.query('SELECT * FROM alert_rules WHERE org_id=$1 AND enabled', [orgId]);
  for (const rule of rules) {
    if (!ruleMatches(rule, trigger, f, p)) continue;
    const discriminator = trigger === 'finding.priority_changed' ? f.priority : trigger === 'finding.exploitation_changed' ? f.exploitation : trigger === 'connector.failed' ? p.connection_id : trigger === 'job.dead_lettered' ? p.job_id : trigger === 'delivery.dead_lettered' ? p.delivery_id : trigger === 'verification.contradicted' ? ev.id : '';
    const dedupeKey = `${rule.id}|${trigger}|${p.finding_id || p.connection_id || p.project_id || '-'}|${discriminator}`;
    await createAlert(app, { rule, trigger, f, payload: p, dedupeKey, orgId });
  }
}

export async function createAlert(app, { rule, trigger, f, payload, dedupeKey, orgId }) {
  const db = app.db;
  const evidenceTop = f ? (await db.query(`SELECT summary FROM evidence WHERE finding_id=$1 AND stance='supporting' ORDER BY collected_at LIMIT 2`, [f.id])).map(e => e.summary).join(' | ') : null;
  const msg = alertBody(app, f, trigger, payload, evidenceTop);
  const res = await db.tx(async (t) => {
    const existing = await t.one('SELECT * FROM alerts WHERE org_id=$1 AND dedupe_key=$2', [orgId, dedupeKey]);
    if (existing) { await t.query('UPDATE alerts SET occurrences=occurrences+1, updated_at=now() WHERE id=$1', [existing.id]); return { alert: existing, created: false }; }
    const aid = id('alt');
    const alert = (await t.query(`INSERT INTO alerts (id, org_id, project_id, rule_id, dedupe_key, trigger, finding_id, title, body, priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [aid, orgId, f?.project_id || payload.project_id || null, rule.id, dedupeKey, trigger, f?.id || null, msg.title, msg.body, f?.priority || null]))[0];
    const recipients = await resolveRecipients(t, rule, f);
    for (const action of rule.actions || []) {
      if (action.type === 'notify') {
        const ch = await t.one('SELECT * FROM channels WHERE id=$1 AND org_id=$2 AND enabled', [action.channel_id, orgId]);
        if (!ch) continue;
        const critical = f && ['P0', 'P1'].includes(f.priority);
        const heldUntil = rule.critical_bypass && critical ? null : inQuietHours(rule.quiet_hours);
        const groupAt = rule.grouping_window_s > 0 ? new Date(Date.now() + rule.grouping_window_s * 1000) : null;
        const runAfter = heldUntil && groupAt ? new Date(Math.max(heldUntil, groupAt)) : heldUntil || groupAt;
        const did = id('dlv');
        await t.query(`INSERT INTO deliveries (id, org_id, alert_id, channel_id, dedupe_key, status, next_attempt_at) VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7, now())) ON CONFLICT (dedupe_key) DO NOTHING`,
          [did, orgId, aid, ch.id, `${aid}|${ch.id}`, heldUntil ? 'held' : 'pending', runAfter?.toISOString() || null]);
        await enqueue(t, { type: 'deliver', orgId, payload: { delivery_id: did, recipients }, idempotencyKey: `deliver:${did}`, runAfter: runAfter?.toISOString() || null, maxAttempts: 6, priority: critical ? 5 : 50 });
      } else if (action.type === 'ticket' && f) {
        await enqueue(t, { type: 'create_ticket', orgId, projectId: f.project_id, payload: { finding_id: f.id, provider: action.provider || 'internal', connection_id: action.connection_id || null }, idempotencyKey: `ticket:${f.id}:${action.provider || 'internal'}:${action.connection_id || ''}` });
      } else if (action.type === 'investigate' && f) {
        await enqueue(t, { type: 'auto_investigate', orgId, projectId: f.project_id, payload: { finding_id: f.id, workflow: action.workflow || 'impact' }, idempotencyKey: `autoinv:${f.id}:${f.advisory_id}` });
      }
    }
    if (rule.escalation?.after_s && rule.escalation?.channel_id) await enqueue(t, { type: 'escalate_alert', orgId, payload: { alert_id: aid, channel_id: rule.escalation.channel_id, recipients }, idempotencyKey: `esc:${aid}`, runAfter: new Date(Date.now() + rule.escalation.after_s * 1000).toISOString() });
    return { alert, created: true };
  });
  if (res.created) log.info('alert_created', { alert_id: res.alert.id, trigger, rule_id: rule.id });
  return res;
}

async function resolveRecipients(db, rule, f) {
  const ids = new Set(rule.route_to?.identity_ids || []);
  if (f && rule.route_to?.project_owner !== false) { const owner = f.owner_identity_id || f.project_owner; if (owner) ids.add(owner); }
  return [...ids];
}

export async function deliverJob(app, job) {
  const db = app.db;
  const d = await db.one('SELECT d.*, a.title, a.body, a.state AS alert_state, a.rule_id, a.priority FROM deliveries d LEFT JOIN alerts a ON a.id=d.alert_id WHERE d.id=$1', [job.payload.delivery_id]);
  if (!d || ['accepted', 'delivered', 'dead', 'suppressed'].includes(d.status)) return { skipped: true };
  if (d.alert_state === 'resolved') { await db.query(`UPDATE deliveries SET status='suppressed', last_error='Alert resolved before delivery', updated_at=now() WHERE id=$1`, [d.id]); return { suppressed: true }; }
  const ch = await db.one('SELECT * FROM channels WHERE id=$1', [d.channel_id]);
  // grouping: include other pending deliveries for the same channel+rule
  const group = d.rule_id ? await db.query(`SELECT d.id, a.title FROM deliveries d JOIN alerts a ON a.id=d.alert_id WHERE d.channel_id=$1 AND a.rule_id=$2 AND d.status IN ('pending','held') AND d.id<>$3 AND d.next_attempt_at <= now() + interval '1 second'`, [d.channel_id, d.rule_id, d.id]) : [];
  const recipients = job.payload.recipients || [];
  const emails = recipients.length ? (await db.query('SELECT email FROM identities WHERE id = ANY($1) AND email IS NOT NULL', [recipients])).map(r => r.email) : [];
  const message = group.length ? { title: `${group.length + 1} grouped alerts`, body: { items: [d.title, ...group.map(g => g.title)], link: d.body?.link }, alertId: d.alert_id, emails, deliveryId: d.id } : { title: d.title, body: d.body, alertId: d.alert_id, emails, deliveryId: d.id, event: 'alert' };
  await db.query(`UPDATE deliveries SET status='sending', attempts=attempts+1, updated_at=now() WHERE id=$1`, [d.id]);
  try {
    const receipt = await sendViaChannel(app, ch, message, { recipients });
    const ids = [d.id, ...group.map(g => g.id)];
    await db.query(`UPDATE deliveries SET status=$2, provider_receipt=$3, last_error=NULL, updated_at=now() WHERE id = ANY($1)`, [ids, receipt.status === 'delivered' ? 'delivered' : 'accepted', { ...receipt, grouped_with: ids.length > 1 ? ids : undefined }]);
    return { receipt };
  } catch (e) {
    const retryable = e instanceof DeliveryError ? e.retryable : true;
    const exhausted = job.attempts >= job.max_attempts;
    await db.query(`UPDATE deliveries SET status=$2, last_error=$3, updated_at=now() WHERE id=$1`, [d.id, !retryable || exhausted ? 'dead' : 'failed', String(e.message).slice(0, 500)]);
    if (!retryable || exhausted) { await emit(db, d.org_id, 'delivery.dead_lettered', { delivery_id: d.id, channel_id: ch.id, summary: `Delivery to ${ch.name} failed: ${e.message}` }); return { dead: true, error: e.message }; }
    throw new RetryableError(e.message);
  }
}

export async function escalateJob(app, job) {
  const db = app.db; const { alert_id, channel_id, recipients } = job.payload;
  const a = await db.one('SELECT * FROM alerts WHERE id=$1', [alert_id]);
  if (!a || a.state !== 'open') return { skipped: 'acknowledged_or_resolved' };
  const did = id('dlv');
  await db.query(`INSERT INTO deliveries (id, org_id, alert_id, channel_id, dedupe_key) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (dedupe_key) DO NOTHING`, [did, a.org_id, a.id, channel_id, `${a.id}|${channel_id}|escalation`]);
  await db.query('UPDATE alerts SET escalated_at=now() WHERE id=$1', [a.id]);
  await enqueue(db, { type: 'deliver', orgId: a.org_id, payload: { delivery_id: did, recipients }, idempotencyKey: `deliver:${did}` });
  return { escalated: true };
}

export async function alertAction(app, ctx, alertId, action, { until, reason } = {}) {
  const db = app.db;
  const a = await db.one('SELECT * FROM alerts WHERE id=$1 AND org_id=$2', [alertId, ctx.orgId]);
  if (!a) throw notFound('Alert');
  if (a.project_id) { const { requireProject } = await import('../authz.mjs'); await requireProject(ctx, a.project_id, 'findings:write'); }
  const next = { acknowledge: 'acknowledged', snooze: 'snoozed', resolve: 'resolved', reopen: 'open' }[action];
  if (!next) throw badRequest('Unknown action.');
  if (action === 'snooze') {
    const t = new Date(until); if (isNaN(t) || t < new Date() || t - new Date() > 30 * 86400_000) throw badRequest('Snooze requires an expiry within 30 days.');
    await db.query(`UPDATE alerts SET state='snoozed', snoozed_until=$2, updated_at=now() WHERE id=$1`, [a.id, t.toISOString()]);
    await enqueue(db, { type: 'unsnooze_alert', orgId: a.org_id, payload: { alert_id: a.id }, idempotencyKey: `unsnooze:${a.id}:${t.toISOString()}`, runAfter: t.toISOString() });
  } else {
    await db.query(`UPDATE alerts SET state=$2, acknowledged_by=CASE WHEN $2='acknowledged' THEN $3 ELSE acknowledged_by END, acknowledged_at=CASE WHEN $2='acknowledged' THEN now() ELSE acknowledged_at END, snoozed_until=NULL, updated_at=now() WHERE id=$1`, [a.id, next, ctx.identity.id]);
  }
  await audit(db, ctx, `alert.${action}`, { targetType: 'alert', targetId: a.id, projectId: a.project_id, data: { reason, until } });
  return db.one('SELECT * FROM alerts WHERE id=$1', [a.id]);
}

/** Authorized, real test send. Never fabricates success. */
export async function testChannel(app, ctx, channelId) {
  const ch = await app.db.one('SELECT * FROM channels WHERE id=$1 AND org_id=$2', [channelId, ctx.orgId]);
  if (!ch) throw notFound('Channel');
  const did = id('dlv');
  await app.db.query(`INSERT INTO deliveries (id, org_id, channel_id, dedupe_key, status, is_test, attempts) VALUES ($1,$2,$3,$4,'sending',true,1)`, [did, ctx.orgId, ch.id, `test|${did}`]);
  try {
    const receipt = await sendViaChannel(app, ch, { title: 'Sentra test notification', body: { text: `Test message requested by ${ctx.identity.display_name || ctx.identity.email} at ${new Date().toISOString()}. No finding is attached.` }, emails: ctx.identity.email ? [ctx.identity.email] : [], deliveryId: did, event: 'test' }, { recipients: [ctx.identity.id] });
    await app.db.query(`UPDATE deliveries SET status=$2, provider_receipt=$3 WHERE id=$1`, [did, receipt.status === 'delivered' ? 'delivered' : 'accepted', receipt]);
    await audit(app.db, ctx, 'channel.test', { targetType: 'channel', targetId: ch.id, data: { outcome: receipt.status } });
    return { delivery_id: did, outcome: receipt.status, receipt };
  } catch (e) {
    await app.db.query(`UPDATE deliveries SET status='failed', last_error=$2 WHERE id=$1`, [did, e.message]);
    await audit(app.db, ctx, 'channel.test', { targetType: 'channel', targetId: ch.id, data: { outcome: 'failed', error: e.message } });
    throw new AppError(502, 'DELIVERY_FAILED', `Test delivery failed: ${e.message}`, { delivery_id: did });
  }
}

export async function slaEvaluationJob(app, job) {
  const db = app.db;
  const orgFilter = job.org_id;
  const breached = await db.query(`SELECT id, project_id, org_id FROM findings WHERE status NOT IN ('verified_fixed','false_positive','accepted_risk','paused') AND sla_due_at < now() AND ($1::text IS NULL OR org_id=$1)`, [orgFilter]);
  const soon = await db.query(`SELECT id, project_id, org_id FROM findings WHERE status NOT IN ('verified_fixed','false_positive','accepted_risk','paused') AND sla_due_at BETWEEN now() AND now() + interval '24 hours' AND ($1::text IS NULL OR org_id=$1)`, [orgFilter]);
  for (const f of breached) await emit(db, f.org_id, 'sla.breached', { finding_id: f.id, project_id: f.project_id });
  for (const f of soon) await emit(db, f.org_id, 'sla.approaching', { finding_id: f.id, project_id: f.project_id });
  // exceptions expiring => re-open review
  const expired = await db.query(`SELECT e.*, f.status FROM risk_exceptions e JOIN findings f ON f.id=e.finding_id WHERE e.expires_at < now() AND e.revoked_at IS NULL AND f.status='accepted_risk' AND ($1::text IS NULL OR e.org_id=$1)`, [orgFilter]);
  for (const e of expired) {
    await db.query(`UPDATE findings SET status='new', status_reason='Risk acceptance expired', closed_at=NULL, updated_at=now() WHERE id=$1`, [e.finding_id]);
    await db.query(`UPDATE risk_exceptions SET revoked_at=now() WHERE id=$1`, [e.id]);
    await db.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor) VALUES ($1,$2,'status','accepted_risk','new','Risk acceptance expired','system')`, [id('fev'), e.finding_id]);
  }
  return { breached: breached.length, approaching: soon.length, expired_exceptions: expired.length };
}
