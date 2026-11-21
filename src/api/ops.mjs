// Operations API: alerting, channels, routing rules, schedules, jobs, deliveries, connections, reports, CI tokens,
// versioned CI contracts (/api/v1), webhooks, health/readiness/metrics.
import { id, badRequest, notFound, need, oneOf, clampInt, AppError } from '../util.mjs';
import { requireOrg, requireProject, accessibleProjectIds, hasOrgPerm } from '../authz.mjs';
import { audit } from '../audit.mjs';
import { putSecret } from '../services/secrets.mjs';
import { alertAction, testChannel, TRIGGERS } from '../services/alerts.mjs';
import { enqueue, requestCancel, replay, queueStats } from '../jobs/queue.mjs';
import { nextOccurrence, isValidTimeZone } from '../domain/timezone.mjs';
import { connectorCatalog, testConnection, disconnect, CONNECTORS } from '../connectors/index.mjs';
import { acceptSbom, getIngestion, recordDeployment, getEvaluation } from '../services/ingestion.mjs';
import { handleGithubWebhook } from '../services/tickets.mjs';
import { randomToken, hashToken, sealDurable } from '../crypto.mjs';
import { reply } from '../http/server.mjs';
import { assertSafeUrl } from '../notify/safe-fetch.mjs';
import { markOnboarding } from './core.mjs';

const JOB_TYPES = ['advisory_sync', 'inventory_reassessment', 'stack_collection', 'connector_health', 'verification', 'daily_report', 'sla_evaluation', 'retention'];

async function scopeCheck(ctx, projectId, perm) { if (projectId) return requireProject(ctx, projectId, perm); requireOrg(ctx, perm); return null; }

export function registerOps(r) {
  // ---------------- alerts
  r.get('/api/alerts', async ({ ctx, query }) => {
    const ids = await accessibleProjectIds(ctx);
    return ctx.db.query(`SELECT a.*, p.key AS project, (SELECT json_agg(json_build_object('id', d.id, 'channel', c.name, 'kind', c.kind, 'status', d.status, 'attempts', d.attempts, 'last_error', d.last_error, 'receipt', d.provider_receipt, 'updated_at', d.updated_at)) FROM deliveries d JOIN channels c ON c.id=d.channel_id WHERE d.alert_id=a.id) AS deliveries
      FROM alerts a LEFT JOIN projects p ON p.id=a.project_id WHERE a.org_id=$1 AND (a.project_id IS NULL OR a.project_id = ANY($2)) AND ($3::text IS NULL OR a.state=$3) ORDER BY a.created_at DESC LIMIT $4`, [ctx.orgId, ids, query.state || null, clampInt(query.limit, 100, 1, 500)]);
  });
  for (const action of ['acknowledge', 'snooze', 'resolve', 'reopen']) r.post(`/api/alerts/:id/${action}`, async ({ ctx, params, body, app }) => alertAction(app, ctx, params.id, action, body));

  // ---------------- channels (secrets stay server-side)
  r.get('/api/channels', async ({ ctx }) => ctx.db.query(`SELECT c.id, c.kind, c.name, c.project_id, c.config, c.enabled, c.created_at, s.name AS secret_name, s.fingerprint FROM channels c LEFT JOIN secrets s ON s.id=c.secret_id WHERE c.org_id=$1 ORDER BY c.name`, [ctx.orgId]));
  r.post('/api/channels', async ({ ctx, body, app }) => {
    await scopeCheck(ctx, body.project_id, 'alerts:manage'); need(body, ['kind', 'name']);
    oneOf(body.kind, ['in_app', 'email', 'slack', 'teams', 'webhook', 'siem'], 'kind');
    const config = {};
    if (body.kind === 'email') { config.to = (body.to || []).filter(e => /^[^@\s]+@[^@\s]+$/.test(e)).slice(0, 50); for (const k of ['smtp_host', 'smtp_port', 'smtp_secure', 'smtp_user', 'from']) if (body[k] != null) config[k] = body[k]; }
    let secretId = null;
    if (['slack', 'teams', 'webhook'].includes(body.kind)) {
      need(body, ['url']);
      await assertSafeUrl(body.url, { allowPrivate: app.cfg.allowPrivateWebhookTargets, allowHttp: app.cfg.allowPrivateWebhookTargets });
      const signing = body.kind === 'webhook' ? randomToken(32) : undefined;
      const s = await putSecret(ctx.db, ctx.orgId, `channel/${body.name}/${id('k')}`, { url: body.url, signing_key: signing }, ctx.identity.id);
      secretId = s.id; config.url_host = new URL(body.url).host;
      if (signing) config.signing = 'HMAC-SHA256 over "<timestamp>.<body>" in X-Sentra-Signature (v1=); timestamp in X-Sentra-Timestamp. Signing key shown once at creation.';
      body._signing = signing;
    }
    if (body.kind === 'siem') {
      need(body, ['url', 'collector_token']);
      await assertSafeUrl(body.url, { allowPrivate: app.cfg.allowPrivateWebhookTargets, allowHttp: app.cfg.allowPrivateWebhookTargets });
      config.format = oneOf(body.format || 'splunk_hec', ['splunk_hec', 'json'], 'format'); config.url_host = new URL(body.url).host;
      if (body.index) config.index = String(body.index).slice(0, 80);
      if (body.sourcetype) config.sourcetype = String(body.sourcetype).slice(0, 80);
      secretId = (await putSecret(ctx.db, ctx.orgId, `channel/${body.name}/${id('k')}`, { url: body.url, token: body.collector_token }, ctx.identity.id)).id;
    }
    if (body.kind === 'email' && body.smtp_password) secretId = (await putSecret(ctx.db, ctx.orgId, `channel/${body.name}/smtp`, body.smtp_password, ctx.identity.id)).id;
    const cid = id('chn');
    await ctx.db.query('INSERT INTO channels (id, org_id, project_id, kind, name, config, secret_id) VALUES ($1,$2,$3,$4,$5,$6,$7)', [cid, ctx.orgId, body.project_id || null, body.kind, body.name, config, secretId]);
    await audit(ctx.db, ctx, 'channel.created', { targetType: 'channel', targetId: cid, projectId: body.project_id || null, data: { kind: body.kind, name: body.name, host: config.url_host } });
    return { id: cid, ...(body._signing ? { signing_key: body._signing, signing_key_note: 'Store this now; it is not shown again.' } : {}) };
  });
  r.patch('/api/channels/:id', async ({ ctx, params, body }) => {
    const ch = await ctx.db.one('SELECT * FROM channels WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!ch) throw notFound('Channel');
    await scopeCheck(ctx, ch.project_id, 'alerts:manage');
    await ctx.db.query('UPDATE channels SET enabled=COALESCE($2, enabled), name=COALESCE($3, name) WHERE id=$1', [ch.id, body.enabled ?? null, body.name || null]);
    await audit(ctx.db, ctx, 'channel.updated', { targetType: 'channel', targetId: ch.id, data: body });
    return { ok: true };
  });
  r.post('/api/channels/:id/test', async ({ ctx, params, app }) => { const ch = await ctx.db.one('SELECT project_id FROM channels WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!ch) throw notFound('Channel'); await scopeCheck(ctx, ch.project_id, 'alerts:manage'); return testChannel(app, ctx, params.id); });

  // ---------------- alert rules
  r.get('/api/alert-rules', async ({ ctx }) => ({ triggers: TRIGGERS, rules: await ctx.db.query('SELECT r.*, p.key AS project FROM alert_rules r LEFT JOIN projects p ON p.id=r.project_id WHERE r.org_id=$1 ORDER BY r.created_at', [ctx.orgId]) }));
  r.post('/api/alert-rules', async ({ ctx, body }) => {
    await scopeCheck(ctx, body.project_id, 'alerts:manage'); need(body, ['name', 'triggers']);
    const rule = validateRule(body);
    for (const a of rule.actions) if (a.channel_id && !(await ctx.db.one('SELECT 1 FROM channels WHERE id=$1 AND org_id=$2', [a.channel_id, ctx.orgId]))) throw badRequest('Unknown channel.');
    const rid = id('rule');
    await ctx.db.query(`INSERT INTO alert_rules (id, org_id, project_id, name, triggers, conditions, actions, route_to, grouping_window_s, quiet_hours, critical_bypass, escalation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [rid, ctx.orgId, body.project_id || null, body.name, JSON.stringify(rule.triggers), rule.conditions, JSON.stringify(rule.actions), rule.route_to, rule.grouping_window_s, rule.quiet_hours, rule.critical_bypass, rule.escalation]);
    if (body.project_id) await markOnboarding(ctx.db, body.project_id, 'policy');
    await audit(ctx.db, ctx, 'alert_rule.created', { targetType: 'alert_rule', targetId: rid, projectId: body.project_id || null, data: rule });
    return { id: rid };
  });
  r.patch('/api/alert-rules/:id', async ({ ctx, params, body }) => {
    const rule = await ctx.db.one('SELECT * FROM alert_rules WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!rule) throw notFound('Rule');
    await scopeCheck(ctx, rule.project_id, 'alerts:manage');
    await ctx.db.query('UPDATE alert_rules SET enabled=COALESCE($2, enabled) WHERE id=$1', [rule.id, body.enabled ?? null]);
    await audit(ctx.db, ctx, 'alert_rule.updated', { targetType: 'alert_rule', targetId: rule.id, data: body });
    return { ok: true };
  });
  // Dry-run: which open findings would this rule match now? No messages are sent.
  r.post('/api/alert-rules/test', async ({ ctx, body }) => {
    const rule = validateRule({ ...body, name: body.name || 'test' });
    const ids = body.project_id ? [body.project_id] : await accessibleProjectIds(ctx);
    const rows = await ctx.db.query(`SELECT f.id, f.priority, f.applicability, f.exploitation, f.status, e.key AS env_key, e.is_production, p.key AS project, f.advisory_id FROM findings f JOIN projects p ON p.id=f.project_id LEFT JOIN environments e ON e.id=f.environment_id WHERE f.project_id = ANY($1) AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk')`, [ids]);
    const PRI = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 }; const c = rule.conditions;
    const m = rows.filter(f => (!c.production_only || f.is_production) && (!c.environments?.length || c.environments.includes(f.env_key)) && (!c.min_priority || PRI[f.priority] <= PRI[c.min_priority]) && (!c.applicability?.length || c.applicability.includes(f.applicability)) && (!c.exploitation?.length || c.exploitation.includes(f.exploitation)));
    return { dry_run: true, would_match: m.length, sample: m.slice(0, 20), note: 'Dry run against current open findings; no notifications were sent.' };
  });

  // ---------------- schedules
  r.get('/api/schedules', async ({ ctx }) => ({ job_types: JOB_TYPES, schedules: await ctx.db.query(`SELECT s.*, p.key AS project, i.display_name AS owner_name, (SELECT json_agg(x) FROM (SELECT id, status, scheduled_for, attempts, last_error, finished_at FROM jobs j WHERE j.schedule_id=s.id ORDER BY created_at DESC LIMIT 5) x) AS recent_runs FROM schedules s LEFT JOIN projects p ON p.id=s.project_id LEFT JOIN identities i ON i.id=s.owner_identity_id WHERE s.org_id=$1 AND s.archived_at IS NULL ORDER BY s.name`, [ctx.orgId]) }));
  r.post('/api/schedules', async ({ ctx, body }) => {
    await scopeCheck(ctx, body.project_id, 'schedules:manage');
    need(body, ['name', 'job_type', 'timezone', 'frequency', 'local_time']);
    const s = validateSchedule(body);
    const sid = id('sch');
    await ctx.db.query(`INSERT INTO schedules (id, org_id, project_id, name, job_type, owner_identity_id, timezone, frequency, local_time, weekday, params, next_run_at, timeout_s, retry_budget, overlap_policy, missed_run_policy) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [sid, ctx.orgId, body.project_id || null, body.name, s.job_type, ctx.identity.id, s.timezone, s.frequency, s.local_time, s.weekday, s.params, s.next_run_at, s.timeout_s, s.retry_budget, s.overlap_policy, s.missed_run_policy]);
    await audit(ctx.db, ctx, 'schedule.created', { targetType: 'schedule', targetId: sid, projectId: body.project_id || null, data: s });
    return { id: sid, next_run_at: s.next_run_at };
  });
  r.patch('/api/schedules/:id', async ({ ctx, params, body }) => {
    const cur = await ctx.db.one('SELECT * FROM schedules WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!cur) throw notFound('Schedule');
    await scopeCheck(ctx, cur.project_id, 'schedules:manage');
    const s = validateSchedule({ ...cur, ...body, params: body.params ?? cur.params });
    await ctx.db.query(`UPDATE schedules SET name=$2, timezone=$3, frequency=$4, local_time=$5, weekday=$6, params=$7, next_run_at=$8, timeout_s=$9, retry_budget=$10, overlap_policy=$11, missed_run_policy=$12 WHERE id=$1`, [cur.id, body.name || cur.name, s.timezone, s.frequency, s.local_time, s.weekday, s.params, s.next_run_at, s.timeout_s, s.retry_budget, s.overlap_policy, s.missed_run_policy]);
    await audit(ctx.db, ctx, 'schedule.updated', { targetType: 'schedule', targetId: cur.id, data: body });
    return { ok: true, next_run_at: s.next_run_at };
  });
  for (const [action, sql] of [['pause', 'paused=true'], ['resume', 'paused=false'], ['archive', 'archived_at=now()']]) r.post(`/api/schedules/:id/${action}`, async ({ ctx, params }) => {
    const s = await ctx.db.one('SELECT * FROM schedules WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!s) throw notFound('Schedule');
    await scopeCheck(ctx, s.project_id, 'schedules:manage');
    await ctx.db.query(`UPDATE schedules SET ${sql}${action === 'resume' ? ', next_run_at=$2' : ''} WHERE id=$1`, action === 'resume' ? [s.id, nextOccurrence(s).toISOString()] : [s.id]);
    await audit(ctx.db, ctx, `schedule.${action}`, { targetType: 'schedule', targetId: s.id });
    return { ok: true };
  });
  // Run now: persistent job; recurring schedule unchanged unless reset_schedule=true.
  r.post('/api/schedules/:id/run-now', async ({ ctx, params, body }) => {
    const s = await ctx.db.one('SELECT * FROM schedules WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!s) throw notFound('Schedule');
    await scopeCheck(ctx, s.project_id, 'schedules:manage');
    const now = new Date().toISOString();
    const { job } = await enqueue(ctx.db, { type: s.job_type, orgId: s.org_id, projectId: s.project_id, payload: { ...s.params, schedule_id: s.id, run_now: true }, idempotencyKey: `runnow:${s.id}:${now}`, scheduleId: s.id, scheduledFor: now, createdBy: ctx.identity.id, maxAttempts: s.retry_budget + 1 });
    if (body.reset_schedule) await ctx.db.query('UPDATE schedules SET next_run_at=$2 WHERE id=$1', [s.id, nextOccurrence(s, new Date()).toISOString()]);
    await audit(ctx.db, ctx, 'schedule.run_now', { targetType: 'schedule', targetId: s.id, data: { job_id: job.id } });
    return { job_id: job.id };
  });

  // ---------------- jobs & deliveries
  r.get('/api/jobs', async ({ ctx, query }) => {
    requireOrg(ctx, 'org:read');
    return { stats: await queueStats(ctx.db, ctx.orgId), items: await ctx.db.query(`SELECT id, type, status, attempts, max_attempts, run_after, scheduled_for, schedule_id, last_error, created_at, started_at, finished_at, project_id, correlation_id, result FROM jobs WHERE org_id=$1 AND ($2::text IS NULL OR status=$2) AND ($3::text IS NULL OR type=$3) ORDER BY created_at DESC LIMIT $4`, [ctx.orgId, query.status || null, query.type || null, clampInt(query.limit, 100, 1, 500)]) };
  });
  r.post('/api/jobs/:id/cancel', async ({ ctx, params }) => { requireOrg(ctx, 'org:admin'); const j = await requestCancel(ctx.db, params.id, ctx.orgId); if (!j) throw notFound('Active job'); await audit(ctx.db, ctx, 'job.cancel', { targetType: 'job', targetId: j.id }); return j; });
  r.post('/api/jobs/:id/replay', async ({ ctx, params }) => { requireOrg(ctx, 'org:admin'); const j = await replay(ctx.db, params.id, ctx.orgId); if (!j) throw notFound('Dead/failed job'); await audit(ctx.db, ctx, 'job.replay', { targetType: 'job', targetId: j.id }); return j; });
  r.get('/api/deliveries', async ({ ctx, query }) => { requireOrg(ctx, 'org:read'); return ctx.db.query(`SELECT d.*, c.name AS channel, c.kind, a.title FROM deliveries d JOIN channels c ON c.id=d.channel_id LEFT JOIN alerts a ON a.id=d.alert_id WHERE d.org_id=$1 AND ($2::text IS NULL OR d.status=$2) ORDER BY d.updated_at DESC LIMIT 200`, [ctx.orgId, query.status || null]); });
  r.post('/api/deliveries/:id/replay', async ({ ctx, params }) => {
    requireOrg(ctx, 'alerts:manage');
    const d = await ctx.db.one(`SELECT * FROM deliveries WHERE id=$1 AND org_id=$2 AND status IN ('dead','failed')`, [params.id, ctx.orgId]); if (!d) throw notFound('Dead delivery');
    await ctx.db.query(`UPDATE deliveries SET status='pending', last_error=NULL, updated_at=now() WHERE id=$1`, [d.id]);
    const { job } = await enqueue(ctx.db, { type: 'deliver', orgId: ctx.orgId, payload: { delivery_id: d.id, recipients: [] }, idempotencyKey: `deliver:${d.id}:replay:${Date.now()}`, createdBy: ctx.identity.id });
    await audit(ctx.db, ctx, 'delivery.replay', { targetType: 'delivery', targetId: d.id });
    return { job_id: job.id };
  });

  // ---------------- connections
  r.get('/api/connectors', async () => connectorCatalog());
  r.get('/api/connections', async ({ ctx }) => {
    const ids = await accessibleProjectIds(ctx);
    return ctx.db.query(`SELECT c.id, c.kind, c.name, c.project_id, p.key AS project, c.config, c.status, c.last_check_at, c.last_success_at, c.last_error, c.created_at, s.name AS secret_name, s.fingerprint FROM connections c LEFT JOIN projects p ON p.id=c.project_id LEFT JOIN secrets s ON s.id=c.secret_id WHERE c.org_id=$1 AND (c.project_id IS NULL OR c.project_id = ANY($2)) ORDER BY c.name`, [ctx.orgId, ids]);
  });
  r.post('/api/connections', async ({ ctx, body, app }) => {
    await scopeCheck(ctx, body.project_id, 'connections:manage'); need(body, ['kind', 'name']);
    const def = CONNECTORS[body.kind]; if (!def) throw badRequest('Unknown connector kind.');
    const config = { ...(body.config || {}) };
    for (const k of ['api_base', 'feed_url']) if (config[k]) await assertSafeUrl(config[k], { allowPrivate: app.cfg.allowPrivateWebhookTargets, allowHttp: app.cfg.allowPrivateWebhookTargets });
    if (body.kind === 'github') need(config, ['owner', 'repo']);
    if (body.kind === 'azure_devops') need(config, ['organization', 'project']);
    if (body.kind === 'dependency_track') need(config, ['api_base', 'project_uuid']);
    if (body.kind === 'aws') { config.resource_types = (config.resource_types || ['lambda:function']).filter(t => def.resource_types.includes(t)); if (!body.project_id) throw badRequest('AWS connections must be scoped to a project.'); }
    if (config.environment_id && body.project_id) { const e = await ctx.db.one('SELECT id FROM environments WHERE project_id=$1 AND (id=$2 OR key=$2)', [body.project_id, config.environment_id]); if (!e) throw badRequest('Unknown environment.'); config.environment_id = e.id; }
    let secretId = null;
    if (body.secret_value) secretId = (await putSecret(ctx.db, ctx.orgId, `connection/${body.kind}/${body.name}`, body.secret_value, ctx.identity.id)).id;
    else if (body.secret_id) { if (!(await ctx.db.one('SELECT 1 FROM secrets WHERE id=$1 AND org_id=$2', [body.secret_id, ctx.orgId]))) throw badRequest('Unknown secret.'); secretId = body.secret_id; }
    if (def.needsSecret && !secretId) throw badRequest(`${def.label} requires a credential (secret_value or secret_id).`);
    const cid = id('con');
    await ctx.db.query('INSERT INTO connections (id, org_id, project_id, kind, name, config, secret_id, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [cid, ctx.orgId, body.project_id || null, body.kind, body.name, config, secretId, 'degraded']);
    if (body.project_id) await markOnboarding(ctx.db, body.project_id, 'connection', { kind: body.kind });
    await audit(ctx.db, ctx, 'connection.created', { targetType: 'connection', targetId: cid, projectId: body.project_id || null, data: { kind: body.kind, name: body.name } });
    const test = await testConnection(app, await ctx.db.one('SELECT * FROM connections WHERE id=$1', [cid]));
    return { id: cid, test };
  });
  r.post('/api/connections/:id/test', async ({ ctx, params, app }) => { const c = await connOrThrow(ctx, params.id); return testConnection(app, c); });
  r.post('/api/connections/:id/sync', async ({ ctx, params }) => {
    const c = await connOrThrow(ctx, params.id);
    if (['disconnected', 'disabled'].includes(c.status)) throw new AppError(409, 'CONNECTION_DISCONNECTED', 'Reconnect before syncing; a disconnected source cannot produce observations.');
    const { job } = await enqueue(ctx.db, { type: 'connector_sync', orgId: ctx.orgId, projectId: c.project_id, payload: { connection_id: c.id }, idempotencyKey: `csync:${c.id}:${Date.now()}`, createdBy: ctx.identity.id });
    await audit(ctx.db, ctx, 'connection.sync_requested', { targetType: 'connection', targetId: c.id });
    return { job_id: job.id };
  });
  r.post('/api/connections/:id/disconnect', async ({ ctx, params, app }) => { const c = await connOrThrow(ctx, params.id); await disconnect(app, c); await audit(ctx.db, ctx, 'connection.disconnected', { targetType: 'connection', targetId: c.id, projectId: c.project_id }); return { ok: true, note: 'Access stopped; observations from this source are marked stale and history is retained.' }; });
  r.post('/api/connections/:id/reconnect', async ({ ctx, params, app }) => { const c = await connOrThrow(ctx, params.id); await ctx.db.query(`UPDATE connections SET status='degraded' WHERE id=$1`, [c.id]); return testConnection(app, { ...c, status: 'degraded' }); });

  // ---------------- reports
  r.get('/api/reports', async ({ ctx }) => { requireOrg(ctx, 'org:read'); return ctx.db.query('SELECT id, kind, language, period_start, period_end, coverage_status, content, created_at FROM report_runs WHERE org_id=$1 ORDER BY created_at DESC LIMIT 60', [ctx.orgId]); });
  r.get('/api/reports/:id', async ({ ctx, params }) => { requireOrg(ctx, 'org:read'); const rr = await ctx.db.one('SELECT * FROM report_runs WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!rr) throw notFound('Report'); return rr; });

  // ---------------- CI tokens (scoped, expiring, revocable; hash stored only)
  r.get('/api/projects/:id/ci-tokens', async ({ ctx, params }) => { await requireProject(ctx, params.id, 'ci_tokens:manage'); return ctx.db.query('SELECT id, name, prefix, scopes, service_id, expires_at, revoked_at, last_used_at, created_at FROM ci_tokens WHERE project_id=$1 ORDER BY created_at DESC', [params.id]); });
  r.post('/api/projects/:id/ci-tokens', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'ci_tokens:manage'); need(body, ['name']);
    const days = clampInt(body.expires_in_days, 90, 1, 365);
    let serviceId = null; if (body.service_id) { const s = await ctx.db.one('SELECT id FROM services WHERE project_id=$1 AND (id=$2 OR key=$2)', [p.id, body.service_id]); if (!s) throw badRequest('Unknown service.'); serviceId = s.id; }
    const scopes = (body.scopes || ['ingest:sbom', 'deployments:write', 'policy:read']).filter(s => ['ingest:sbom', 'deployments:write', 'policy:read'].includes(s));
    const token = 'stk_' + randomToken(30);
    const tid = id('cit');
    await ctx.db.query(`INSERT INTO ci_tokens (id, org_id, project_id, service_id, name, token_hash, prefix, scopes, expires_at, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now() + ($9 || ' days')::interval, $10)`, [tid, p.org_id, p.id, serviceId, body.name, hashToken(token), token.slice(0, 8), JSON.stringify(scopes), String(days), ctx.identity.id]);
    await audit(ctx.db, ctx, 'ci_token.created', { targetType: 'ci_token', targetId: tid, projectId: p.id, data: { name: body.name, scopes, days } });
    return { id: tid, token, note: 'Store this token in your CI secret manager now. It is not shown again. Do not expose it to fork pull requests.', scopes, expires_in_days: days };
  });
  r.post('/api/ci-tokens/:id/revoke', async ({ ctx, params }) => {
    const t = await ctx.db.one('SELECT * FROM ci_tokens WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!t) throw notFound('Token');
    await requireProject(ctx, t.project_id, 'ci_tokens:manage');
    await ctx.db.query('UPDATE ci_tokens SET revoked_at=now() WHERE id=$1', [t.id]);
    await audit(ctx.db, ctx, 'ci_token.revoked', { targetType: 'ci_token', targetId: t.id, projectId: t.project_id });
    return { ok: true };
  });

  // ---------------- versioned CI contracts
  r.post('/api/v1/ingestions/sbom', async ({ ctx, body, req, app }) => {
    const res = await acceptSbom(app, ctx, { metadata: body.metadata, document: body.document, idempotencyKey: req.headers['idempotency-key'] || body.idempotency_key });
    if (res.duplicate) return reply(200, { ...res.ingestion.receipt, status: res.ingestion.status, duplicate: true });
    return reply(202, res.ingestion.receipt, { Location: res.ingestion.receipt.status_url });
  }, { ci: true, allowSession: true, maxBody: 12 * 1024 * 1024 });
  r.get('/api/v1/ingestions/:id', async ({ ctx, params }) => getIngestion(ctx.db, ctx, params.id), { ci: true, allowSession: true });
  r.post('/api/v1/deployments', async ({ ctx, body, app }) => { const res = await recordDeployment(app, ctx, body); return reply(res.duplicate ? 200 : 201, { deployment_id: res.deployment.id, duplicate: res.duplicate, note: 'Deployment recorded; affected findings in this environment are re-evaluated and verified against the deployed artifact.' }); }, { ci: true, allowSession: true });
  r.get('/api/v1/policy-evaluations/:id', async ({ ctx, params }) => getEvaluation(ctx.db, ctx, params.id), { ci: true, allowSession: true });

  // ---------------- inbound webhooks
  r.post('/api/webhooks/github', async ({ raw, req, app }) => handleGithubWebhook(app, { raw, headers: req.headers }), { public: true, csrfExempt: true, rawBody: true, maxBody: 5 * 1024 * 1024 });

  // ---------------- health / readiness / metrics
  r.get('/api/health', async ({ app }) => ({ status: 'ok', service: 'sentra', version: '1.0.0', environment: app.cfg.environment, database: app.db.kind, object_store: app.objects.kind, auth_mode: app.cfg.authMode, ai_provider: app.cfg.ai.provider, sealed_secrets_durable: sealDurable(), note: 'Liveness only. Use /api/ready for dependency checks.' }), { public: true });
  r.get('/api/ready', async ({ app }) => {
    const checks = {};
    try { await app.db.query('SELECT 1'); checks.database = 'ok'; } catch (e) { checks.database = 'fail'; }
    const hb = await app.db.query('SELECT component, beat_at FROM system_heartbeats').catch(() => []);
    const sched = hb.find(h => h.component === 'scheduler');
    checks.scheduler = !app.cfg.runScheduler ? 'external' : sched && Date.now() - new Date(sched.beat_at) < 90_000 ? 'ok' : 'stale';
    checks.workers = hb.some(h => h.component.startsWith('worker:') && Date.now() - new Date(h.beat_at) < 60_000) ? 'ok' : app.cfg.runWorkers ? 'stale' : 'external';
    checks.keycloak = app.cfg.authMode === 'dev' ? 'dev_mode' : app.cfg.keycloak.issuer ? 'configured' : 'missing';
    checks.secret_sealing = sealDurable() ? 'ok' : 'ephemeral_key';
    const ready = checks.database === 'ok';
    return reply(ready ? 200 : 503, { ready, checks });
  }, { public: true });
  r.get('/api/metrics', async ({ ctx, app }) => {
    requireOrg(ctx, 'org:read');
    const q = await queueStats(app.db, ctx.orgId);
    const outbox = await app.db.one(`SELECT count(*)::int AS pending, COALESCE(EXTRACT(EPOCH FROM (now() - min(created_at)))::int, 0) AS oldest_s FROM outbox WHERE processed_at IS NULL`);
    const deliv = await app.db.query(`SELECT status, count(*)::int AS n FROM deliveries WHERE org_id=$1 AND updated_at > now() - interval '24 hours' GROUP BY status`, [ctx.orgId]);
    const ai = await app.db.one(`SELECT count(*)::int AS runs, COALESCE(sum(cost_usd),0)::float AS cost_usd, count(*) FILTER (WHERE state='failed')::int AS failed FROM investigations WHERE org_id=$1 AND created_at > now() - interval '30 days'`, [ctx.orgId]);
    const lag = await app.db.query(`SELECT name, kind, status, EXTRACT(EPOCH FROM (now() - last_success_at))::int AS seconds_since_success FROM connections WHERE org_id=$1`, [ctx.orgId]);
    const hb = await app.db.query('SELECT component, beat_at FROM system_heartbeats');
    return { queue: q, outbox, deliveries_24h: deliv, ai_30d: ai, connector_lag: lag, heartbeats: hb };
  });
}

async function connOrThrow(ctx, cid) {
  const c = await ctx.db.one('SELECT * FROM connections WHERE id=$1 AND org_id=$2', [cid, ctx.orgId]); if (!c) throw notFound('Connection');
  await scopeCheck(ctx, c.project_id, 'connections:manage');
  return c;
}
function validateRule(b) {
  const triggers = (b.triggers || []).filter(t => TRIGGERS.includes(t)); if (!triggers.length) throw badRequest('At least one valid trigger is required.');
  const c = b.conditions || {};
  if (c.min_priority && !['P0', 'P1', 'P2', 'P3', 'P4'].includes(c.min_priority)) throw badRequest('min_priority invalid.');
  const actions = (b.actions || []).filter(a => ['notify', 'ticket', 'investigate'].includes(a.type));
  if (!actions.length) throw badRequest('At least one action is required.');
  const qh = b.quiet_hours?.start ? { start: b.quiet_hours.start, end: b.quiet_hours.end, timezone: b.quiet_hours.timezone } : null;
  if (qh && (!isValidTimeZone(qh.timezone) || !/^\d{2}:\d{2}$/.test(qh.start) || !/^\d{2}:\d{2}$/.test(qh.end))) throw badRequest('quiet_hours requires start/end HH:MM and an IANA timezone.');
  return { triggers, conditions: { production_only: !!c.production_only, environments: c.environments || [], min_priority: c.min_priority || null, applicability: c.applicability || [], exploitation: c.exploitation || [] }, actions, route_to: { project_owner: b.route_to?.project_owner !== false, identity_ids: b.route_to?.identity_ids || [] }, grouping_window_s: clampInt(b.grouping_window_s, 0, 0, 86400), quiet_hours: qh, critical_bypass: b.critical_bypass !== false, escalation: b.escalation?.after_s && b.escalation?.channel_id ? { after_s: clampInt(b.escalation.after_s, 3600, 60, 604800), channel_id: b.escalation.channel_id } : null };
}
function validateSchedule(b) {
  oneOf(b.job_type, JOB_TYPES, 'job_type'); oneOf(b.frequency, ['hourly', 'daily', 'weekly'], 'frequency');
  if (!isValidTimeZone(b.timezone)) throw badRequest('timezone must be a valid IANA timezone.');
  if (!/^\d{2}:\d{2}$/.test(b.local_time)) throw badRequest('local_time must be HH:MM.');
  const weekday = b.frequency === 'weekly' ? Number(b.weekday) : null;
  if (b.frequency === 'weekly' && !(weekday >= 0 && weekday <= 6)) throw badRequest('Weekly schedules require weekday 0 (Sunday) – 6.');
  const s = { job_type: b.job_type, timezone: b.timezone, frequency: b.frequency, local_time: b.local_time, weekday, params: b.params || {}, timeout_s: clampInt(b.timeout_s, 600, 30, 7200), retry_budget: clampInt(b.retry_budget, 3, 0, 10), overlap_policy: oneOf(b.overlap_policy || 'skip', ['skip', 'queue', 'allow'], 'overlap_policy'), missed_run_policy: oneOf(b.missed_run_policy || 'run_once', ['skip', 'run_once', 'run_all'], 'missed_run_policy') };
  s.next_run_at = nextOccurrence(s, new Date()).toISOString();
  return s;
}
