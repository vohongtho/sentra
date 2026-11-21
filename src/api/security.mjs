// Security API: advisories, findings, investigations, agent policies, campaigns, dashboards, coverage, drift, search.
import { id, badRequest, notFound, need, clampInt, AppError } from '../util.mjs';
import { requireOrg, requireProject, accessibleProjectIds, hasOrgPerm } from '../authz.mjs';
import { audit } from '../audit.mjs';
import { upsertAdvisory, exploitationFor, upsertSignal } from '../services/advisories.mjs';
import { listFindings, getFinding, transition, assign, comment, requestException, decideException, bulk, exportFindingsCsv } from '../services/findings.mjs';
import { createTicket, recordPullRequest } from '../services/tickets.mjs';
import { createInvestigation, approveProposal, WORKFLOWS, effectivePolicy, DEFAULT_AGENT_POLICY, testProvider, orgAiKey, ORG_AI_KEY_SECRET } from '../ai/agents.mjs';
import { putSecret } from '../services/secrets.mjs';
import { TOOL_DEFS, WORKFLOW_TOOLS } from '../ai/tools.mjs';
import { orgCoverage, projectCoverage } from '../services/coverage.mjs';
import { enqueue } from '../jobs/queue.mjs';
import { reply } from '../http/server.mjs';
import { DEFAULT_PRIORITY_POLICY, DEFAULT_SLA_POLICY } from '../domain/policy.mjs';
import { DEFAULT_GATE } from '../services/ingestion.mjs';
import { ECOSYSTEMS } from '../domain/versions.mjs';
import { loadPolicies, savePolicy } from '../services/policies.mjs';
import { projectVex } from '../services/exports.mjs';
import { projectAttackPaths } from '../services/attackpaths.mjs';
import { createDraftPr } from '../services/remediation-pr.mjs';

export function registerSecurity(r) {
  // ---------------- advisories
  r.get('/api/advisories', async ({ ctx, query }) => {
    const limit = clampInt(query.limit, 50, 1, 200), offset = clampInt(query.offset, 0, 0, 1e6);
    const params = [query.q ? `%${query.q}%` : null, query.affecting === 'true' ? await accessibleProjectIds(ctx) : null];
    const rows = await ctx.db.query(`SELECT a.id, a.title, a.severity, a.cvss_score, a.status, a.is_synthetic, a.source, a.published_at, a.modified_at, a.current_revision,
        (SELECT json_agg(alias) FROM advisory_aliases al WHERE al.advisory_id=a.id AND al.alias<>a.id) AS aliases,
        (SELECT count(*)::int FROM findings f WHERE f.advisory_id=a.id AND f.org_id=$3 AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk')) AS open_findings
      FROM advisories a WHERE ($1::text IS NULL OR a.id ILIKE $1 OR a.title ILIKE $1 OR EXISTS (SELECT 1 FROM advisory_aliases al WHERE al.advisory_id=a.id AND al.alias ILIKE $1))
        AND ($2::text[] IS NULL OR EXISTS (SELECT 1 FROM findings f WHERE f.advisory_id=a.id AND f.project_id = ANY($2)))
      ORDER BY a.modified_at DESC NULLS LAST, a.id LIMIT ${limit} OFFSET ${offset}`, [...params, ctx.orgId]);
    return { items: rows, limit, offset };
  });
  r.get('/api/advisories/:id', async ({ ctx, params }) => {
    const a = await ctx.db.one(`SELECT * FROM advisories WHERE id=$1 OR id=(SELECT advisory_id FROM advisory_aliases WHERE alias=$1)`, [params.id]);
    if (!a) throw notFound('Advisory');
    const ids = await accessibleProjectIds(ctx);
    const [ranges, aliases, revisions, exp, findings] = await Promise.all([
      ctx.db.query('SELECT * FROM affected_ranges WHERE advisory_id=$1', [a.id]),
      ctx.db.query('SELECT alias FROM advisory_aliases WHERE advisory_id=$1', [a.id]),
      ctx.db.query('SELECT revision, modified_at, change_summary, created_at FROM advisory_revisions WHERE advisory_id=$1 ORDER BY revision DESC', [a.id]),
      exploitationFor(ctx.db, a.id),
      ctx.db.query(`SELECT f.id, p.key AS project, s.key AS service, e.key AS environment, e.is_production, c.name AS package, f.observed_version, f.priority, f.status, f.applicability FROM findings f JOIN projects p ON p.id=f.project_id JOIN components c ON c.id=f.component_id LEFT JOIN services s ON s.id=f.service_id LEFT JOIN environments e ON e.id=f.environment_id WHERE f.advisory_id=$1 AND f.project_id = ANY($2) ORDER BY f.priority`, [a.id, ids]),
    ]);
    delete a.raw;
    return { ...a, ranges, aliases: aliases.map(x => x.alias), revisions, exploitation: exp, findings };
  });
  // "Investigate this CVE": paste OSV JSON → store → portfolio reassessment → impact list.
  r.post('/api/advisories', async ({ ctx, body }) => {
    requireOrg(ctx, 'advisories:write');
    const osv = body.osv || body;
    const res = await ctx.db.tx(t => upsertAdvisory(t, osv, { source: body.source || 'manual', synthetic: !!body.synthetic, orgId: ctx.orgId }));
    await audit(ctx.db, ctx, 'advisory.ingested', { targetType: 'advisory', targetId: res.advisoryId, data: { revision: res.revision, changed: res.changed, changes: res.changes } });
    return { ...res, note: res.changed ? 'Stored. Deployed inventory is re-evaluated asynchronously; results appear on the advisory page.' : 'Identical to the stored revision; no reassessment.' };
  }, { maxBody: 2 * 1024 * 1024 });
  r.post('/api/advisories/:id/signals', async ({ ctx, params, body }) => {
    requireOrg(ctx, 'advisories:write'); need(body, ['kind']);
    if (!['public_poc', 'vendor_exploited', 'observed_in_env'].includes(body.kind)) throw badRequest('Manual signals: public_poc, vendor_exploited, observed_in_env. KEV/EPSS come from their feeds.');
    if (!body.source_url && body.kind !== 'observed_in_env') throw badRequest('source_url is required for external exploitation claims.');
    const changed = await upsertSignal(ctx.db, params.id, body.kind, { present: true, source_url: body.source_url || null, note: body.note || null, recorded_by: ctx.identity.id }, `manual:${ctx.identity.id}`);
    await audit(ctx.db, ctx, 'advisory.signal_recorded', { targetType: 'advisory', targetId: params.id, data: { kind: body.kind, source_url: body.source_url } });
    return { changed };
  });

  // ---------------- findings
  r.get('/api/findings', async ({ ctx, query }) => listFindings(ctx.db, ctx, query));
  r.get('/api/findings.csv', async ({ ctx, query }) => reply(200, await exportFindingsCsv(ctx.db, ctx, query), { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="sentra-findings.csv"' }));
  r.get('/api/findings/:id', async ({ ctx, params }) => getFinding(ctx.db, ctx, params.id));
  r.post('/api/findings/:id/transition', async ({ ctx, params, body }) => transition(ctx.db, ctx, params.id, body));
  r.post('/api/findings/:id/assign', async ({ ctx, params, body }) => assign(ctx.db, ctx, params.id, body));
  r.post('/api/findings/:id/comments', async ({ ctx, params, body }) => comment(ctx.db, ctx, params.id, body.text));
  r.post('/api/findings/:id/exceptions', async ({ ctx, params, body }) => requestException(ctx.db, ctx, params.id, body));
  r.post('/api/exceptions/:id/decision', async ({ ctx, params, body }) => decideException(ctx.db, ctx, params.id, body));
  r.get('/api/exceptions', async ({ ctx, query }) => ctx.db.query(`SELECT e.*, p.key AS project, i.display_name AS requester FROM risk_exceptions e JOIN projects p ON p.id=e.project_id JOIN identities i ON i.id=e.requested_by WHERE e.org_id=$1 AND e.project_id = ANY($2) AND ($3::text IS NULL OR ($3='pending' AND e.approved_by IS NULL AND e.revoked_at IS NULL)) ORDER BY e.created_at DESC`, [ctx.orgId, await accessibleProjectIds(ctx), query.state || null]));
  r.post('/api/findings/bulk', async ({ ctx, body }) => bulk(ctx.db, ctx, body));
  r.post('/api/findings/:id/tickets', async ({ ctx, params, body, app }) => {
    const f = await ctx.db.one('SELECT * FROM findings WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!f) throw notFound('Finding');
    await requireProject(ctx, f.project_id, 'tickets:write');
    if (body.connection_id && !(await ctx.db.one('SELECT 1 FROM connections WHERE id=$1 AND org_id=$2', [body.connection_id, ctx.orgId]))) throw notFound('Connection');
    const r2 = await createTicket(app, { findingId: f.id, provider: body.provider || 'internal', connectionId: body.connection_id || null, actor: ctx.identity.id });
    await audit(ctx.db, ctx, 'ticket.requested', { targetType: 'finding', targetId: f.id, projectId: f.project_id, data: { provider: body.provider, duplicate: r2.duplicate } });
    return r2;
  });
  r.post('/api/findings/:id/pull-requests', async ({ ctx, params, body, app }) => {
    const f = await ctx.db.one('SELECT * FROM findings WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!f) throw notFound('Finding');
    await requireProject(ctx, f.project_id, 'findings:write');
    if (!['draft', 'open', 'merged', 'closed'].includes(body.state)) throw badRequest('state must be draft|open|merged|closed');
    if (body.url && !/^https:\/\//.test(body.url)) throw badRequest('url must be https');
    const res = await recordPullRequest(app, ctx, f.id, body);
    await audit(ctx.db, ctx, 'finding.pull_request_recorded', { targetType: 'finding', targetId: f.id, projectId: f.project_id, data: body });
    return res;
  });
  r.post('/api/findings/:id/verify', async ({ ctx, params }) => {
    const f = await ctx.db.one('SELECT * FROM findings WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!f) throw notFound('Finding');
    await requireProject(ctx, f.project_id, 'findings:write');
    if (!['deployed', 'verification_pending'].includes(f.status)) throw badRequest('Verification runs when the finding is deployed or verification_pending.');
    const { job } = await enqueue(ctx.db, { type: 'verify_finding', orgId: ctx.orgId, projectId: f.project_id, payload: { finding_id: f.id }, idempotencyKey: `verify:${f.id}:manual:${Date.now()}`, createdBy: ctx.identity.id });
    return { job_id: job.id };
  });

  // ---------------- investigations & copilot
  r.get('/api/investigations', async ({ ctx, query }) => {
    const ids = await accessibleProjectIds(ctx);
    return ctx.db.query(`SELECT i.id, i.workflow, i.state, i.project_id, p.key AS project, i.question, i.inputs->>'finding_id' AS finding_id, i.inputs->>'advisory_id' AS advisory_id, i.provider, i.model, i.cost_usd, i.created_at, i.finished_at, i.result->>'summary' AS summary, i.result->>'applicability' AS applicability
      FROM investigations i LEFT JOIN projects p ON p.id=i.project_id WHERE i.org_id=$1 AND (i.project_id = ANY($2) OR (i.project_id IS NULL AND i.requested_by=$3)) AND ($4::text IS NULL OR i.workflow=$4) ORDER BY i.created_at DESC LIMIT $5`, [ctx.orgId, ids, ctx.identity.id, query.workflow || null, clampInt(query.limit, 50, 1, 200)]);
  });
  r.post('/api/investigations', async ({ ctx, body, app }) => createInvestigation(app, ctx, { workflow: body.workflow, projectId: body.project_id, findingId: body.finding_id, advisoryId: body.advisory_id, question: body.question, files: body.files, evidence: body.evidence }), { maxBody: 4 * 1024 * 1024 });
  r.post('/api/copilot', async ({ ctx, body, app }) => { need(body, ['question']); return createInvestigation(app, ctx, { workflow: 'copilot', projectId: body.project_id || null, question: body.question }); });
  r.get('/api/investigations/:id', async ({ ctx, params }) => {
    const inv = await ctx.db.one('SELECT * FROM investigations WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!inv) throw notFound('Investigation');
    if (inv.project_id) await requireProject(ctx, inv.project_id); else if (inv.requested_by !== ctx.identity.id && !hasOrgPerm(ctx, 'org:read')) throw notFound('Investigation');
    const tools = await ctx.db.query('SELECT seq, tool, input, output_summary, status, duration_ms, created_at FROM tool_executions WHERE investigation_id=$1 ORDER BY seq', [inv.id]);
    delete inv.checkpoint; if (inv.inputs?.files) inv.inputs.files = inv.inputs.files.map(f => ({ name: f.name, bytes: f.content.length }));
    return { ...inv, tool_executions: tools, note: 'Tool action summaries and evidence receipts are shown; private model reasoning is not stored or displayed.' };
  });
  r.get('/api/investigations/:id/tool/:seq', async ({ ctx, params }) => {
    const inv = await ctx.db.one('SELECT project_id, requested_by FROM investigations WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!inv) throw notFound('Investigation');
    if (inv.project_id) await requireProject(ctx, inv.project_id); else if (inv.requested_by !== ctx.identity.id) throw notFound('Investigation');
    return ctx.db.one('SELECT * FROM tool_executions WHERE investigation_id=$1 AND seq=$2', [params.id, Number(params.seq)]);
  });
  r.post('/api/investigations/:id/cancel', async ({ ctx, params }) => {
    const inv = await ctx.db.one('SELECT * FROM investigations WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!inv) throw notFound('Investigation');
    if (inv.project_id) await requireProject(ctx, inv.project_id, 'investigations:run');
    await ctx.db.query(`UPDATE investigations SET cancel_requested=true, state=CASE WHEN state IN ('queued','waiting_evidence') THEN 'cancelled' ELSE state END WHERE id=$1`, [inv.id]);
    await ctx.db.query(`UPDATE jobs SET cancel_requested=true WHERE idempotency_key=$1`, [`inv:${inv.id}`]);
    await audit(ctx.db, ctx, 'investigation.cancel_requested', { targetType: 'investigation', targetId: inv.id, projectId: inv.project_id });
    return { ok: true };
  });
  r.post('/api/investigations/:id/rerun', async ({ ctx, params, body, app }) => {
    const inv = await ctx.db.one('SELECT * FROM investigations WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!inv) throw notFound('Investigation');
    return createInvestigation(app, ctx, { workflow: inv.workflow, projectId: inv.project_id, findingId: inv.inputs?.finding_id, advisoryId: inv.inputs?.advisory_id, question: inv.question, files: body.files || inv.inputs?.files, previousId: inv.id, rerunReason: body.reason || 'manual rerun' });
  });
  r.post('/api/investigations/:id/feedback', async ({ ctx, params, body }) => {
    const inv = await ctx.db.one('SELECT * FROM investigations WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!inv) throw notFound('Investigation');
    if (inv.project_id) await requireProject(ctx, inv.project_id);
    if (!['correct', 'incorrect', 'partially_correct', 'unsupported_claims', 'missed_prerequisite'].includes(body.rating)) throw badRequest('Invalid rating.');
    const fb = [...(inv.reviewer_feedback || []), { by: ctx.identity.id, name: ctx.identity.display_name, rating: body.rating, note: String(body.note || '').slice(0, 2000), at: new Date().toISOString() }];
    await ctx.db.query('UPDATE investigations SET reviewer_feedback=$2 WHERE id=$1', [inv.id, JSON.stringify(fb)]);
    await audit(ctx.db, ctx, 'investigation.feedback', { targetType: 'investigation', targetId: inv.id, projectId: inv.project_id, data: { rating: body.rating } });
    return { ok: true };
  });
  r.post('/api/investigations/:id/proposals', async ({ ctx, params, body, app }) => approveProposal(app, ctx, params.id, body));

  // ---------------- agent control plane
  r.get('/api/agent-policies', async ({ ctx, query }) => {
    const rows = await ctx.db.query('SELECT * FROM agent_policies WHERE org_id=$1 AND ($2::text IS NULL OR project_id=$2 OR project_id IS NULL)', [ctx.orgId, query.project_id || null]);
    const effective = {}; for (const w of WORKFLOWS) effective[w] = await effectivePolicy(ctx.db, ctx.orgId, query.project_id || null, w);
    return { policies: rows, effective, defaults: DEFAULT_AGENT_POLICY, workflows: WORKFLOWS, tools: Object.fromEntries(Object.entries(TOOL_DEFS).map(([k, v]) => [k, v.description])), workflow_tools: WORKFLOW_TOOLS, provider: { configured: ctx.cfg.ai.provider, model: ctx.cfg.ai.model, anthropic_key_configured: !!ctx.cfg.ai.anthropicApiKey || !!(await orgAiKey(ctx.app, ctx.orgId).catch(() => '')), key_source: ctx.cfg.ai.anthropicApiKey ? 'server' : 'organization', effort: ctx.cfg.ai.effort } };
  });
  r.put('/api/agent-policies/:workflow', async ({ ctx, params, body }) => {
    if (!WORKFLOWS.includes(params.workflow)) throw badRequest('Unknown workflow.');
    if (body.project_id) await requireProject(ctx, body.project_id, 'agent_policies:manage'); else requireOrg(ctx, 'agent_policies:manage');
    const d = {};
    if (body.provider !== undefined) { if (!['anthropic', 'offline', null].includes(body.provider)) throw badRequest('provider must be anthropic or offline.'); d.provider = body.provider; }
    if (body.model) { if (!/^claude-[a-z0-9-]+$/.test(body.model)) throw badRequest('Invalid model id.'); d.model = body.model; }
    if (body.max_tool_calls != null) d.max_tool_calls = clampInt(body.max_tool_calls, 24, 1, 100);
    if (body.timeout_s != null) d.timeout_s = clampInt(body.timeout_s, 300, 10, 3600);
    if (body.budget_usd != null) { const b = Number(body.budget_usd); if (!(b > 0 && b <= 100)) throw badRequest('budget_usd must be 0-100.'); d.budget_usd = b; }
    if (body.allowed_data_classes) d.allowed_data_classes = body.allowed_data_classes.filter(c => ['public', 'internal', 'confidential', 'restricted'].includes(c));
    if (body.tools) d.tools = body.tools.filter(t => WORKFLOW_TOOLS[params.workflow].includes(t));
    const existing = await ctx.db.one(`SELECT * FROM agent_policies WHERE org_id=$1 AND COALESCE(project_id,'')=$2 AND workflow=$3`, [ctx.orgId, body.project_id || '', params.workflow]);
    if (existing) await ctx.db.query('UPDATE agent_policies SET definition=$2, version=version+1, updated_by=$3, updated_at=now() WHERE id=$1', [existing.id, { ...existing.definition, ...d }, ctx.identity.id]);
    else await ctx.db.query('INSERT INTO agent_policies (id, org_id, project_id, workflow, definition, updated_by) VALUES ($1,$2,$3,$4,$5,$6)', [id('apol'), ctx.orgId, body.project_id || null, params.workflow, d, ctx.identity.id]);
    await audit(ctx.db, ctx, 'agent_policy.updated', { targetType: 'agent_policy', targetId: params.workflow, projectId: body.project_id || null, data: d });
    return effectivePolicy(ctx.db, ctx.orgId, body.project_id || null, params.workflow);
  });
  // Provider key: stored only through this authenticated, admin-only flow; sealed server-side; never returned.
  r.put('/api/ai/credentials', async ({ ctx, body }) => {
    requireOrg(ctx, 'agent_policies:manage'); need(body, ['api_key']);
    if (!/^sk-ant-[\w-]{20,}$/.test(body.api_key)) throw badRequest('This does not look like an Anthropic API key.');
    const s = await putSecret(ctx.db, ctx.orgId, ORG_AI_KEY_SECRET, body.api_key, ctx.identity.id);
    await audit(ctx.db, ctx, s.rotated ? 'ai.credentials_rotated' : 'ai.credentials_stored', { targetType: 'secret', targetId: s.id, data: { fingerprint: s.fingerprint } });
    return { stored: true, fingerprint: s.fingerprint, note: 'Run the connection test to confirm the provider accepts it.' };
  });
  r.delete('/api/ai/credentials', async ({ ctx }) => { requireOrg(ctx, 'agent_policies:manage'); await ctx.db.query('DELETE FROM secrets WHERE org_id=$1 AND name=$2', [ctx.orgId, ORG_AI_KEY_SECRET]); await audit(ctx.db, ctx, 'ai.credentials_deleted', {}); });
  r.post('/api/ai/test', async ({ ctx, app }) => { requireOrg(ctx, 'agent_policies:manage'); const r2 = await testProvider(app, ctx.orgId); await audit(ctx.db, ctx, 'ai.connection_test', { data: { ok: r2.ok, model: r2.model, error: r2.error } }); return r2; });
  r.get('/api/policies', async ({ ctx, query }) => {
    if (query.project_id) await requireProject(ctx, query.project_id);
    const eff = await loadPolicies(ctx.db, ctx.orgId, query.project_id || null);
    return { priority: DEFAULT_PRIORITY_POLICY, sla: DEFAULT_SLA_POLICY, effective: eff, gate_default: DEFAULT_GATE, stored: await ctx.db.query('SELECT * FROM policies WHERE org_id=$1 ORDER BY kind, version DESC', [ctx.orgId]) };
  });
  for (const kind of ['priority', 'sla']) r.post(`/api/policies/${kind}`, async ({ ctx, body }) => {
    if (body.project_id) await requireProject(ctx, body.project_id, 'project:manage'); else requireOrg(ctx, 'org:admin');
    const res = await savePolicy(ctx.db, ctx, kind, body);
    await audit(ctx.db, ctx, `policy.${kind}_updated`, { targetType: 'policy', targetId: res.id, projectId: body.project_id || null, data: { version: res.version } });
    return { ...res, note: 'New version saved. Affected findings are re-scored asynchronously and record the version they were scored with.' };
  });

  // ---------------- VEX export, attack paths, external findings, draft PRs
  r.get('/api/projects/:id/vex.cdx.json', async ({ ctx, params, query }) => {
    const p = await requireProject(ctx, params.id, 'export');
    const vex = await projectVex(ctx.db, p.id, { environment: query.environment || null });
    await audit(ctx.db, ctx, 'export.vex', { targetType: 'project', targetId: p.id, projectId: p.id, data: { vulnerabilities: vex.vulnerabilities.length, environment: query.environment || null } });
    return reply(200, JSON.stringify(vex, null, 2), { 'Content-Type': 'application/vnd.cyclonedx+json; charset=utf-8', 'Content-Disposition': `attachment; filename="${p.key}-vex.cdx.json"` });
  });
  r.get('/api/projects/:id/attack-paths', async ({ ctx, params }) => { const p = await requireProject(ctx, params.id); return projectAttackPaths(ctx.db, p.id); });
  r.get('/api/projects/:id/external-findings', async ({ ctx, params }) => { const p = await requireProject(ctx, params.id); return ctx.db.query('SELECT x.*, c.name AS connection FROM external_findings x LEFT JOIN connections c ON c.id=x.connection_id WHERE x.project_id=$1 ORDER BY x.seen_at DESC LIMIT 500', [p.id]); });
  r.post('/api/findings/:id/draft-pr', async ({ ctx, params, body, app }) => {
    const f = await ctx.db.one('SELECT project_id FROM findings WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!f) throw notFound('Finding');
    await requireProject(ctx, f.project_id, 'tickets:write');
    need(body, ['connection_id']);
    return createDraftPr(app, ctx, params.id, body);
  });
  r.post('/api/policies/gate', async ({ ctx, body }) => {
    if (body.project_id) await requireProject(ctx, body.project_id, 'project:manage'); else requireOrg(ctx, 'org:admin');
    if (!['observe', 'block_new'].includes(body.mode)) throw badRequest('mode must be observe or block_new');
    if (!['open', 'closed'].includes(body.fail_mode)) throw badRequest('fail_mode must be open or closed (explicit choice required).');
    const def = { mode: body.mode, fail_mode: body.fail_mode, block_on: { min_severity: body.block_on?.min_severity || 'critical', exploitation: body.block_on?.exploitation || ['kev_listed', 'actively_exploited'], only_new: body.block_on?.only_new !== false, require_fix_available: !!body.block_on?.require_fix_available }, timeout_s: clampInt(body.timeout_s, 120, 10, 900) };
    const prev = await ctx.db.one(`SELECT max(version)::int AS v FROM policies WHERE org_id=$1 AND kind='gate' AND project_id IS NOT DISTINCT FROM $2`, [ctx.orgId, body.project_id || null]);
    await ctx.db.query(`UPDATE policies SET active=false WHERE org_id=$1 AND kind='gate' AND project_id IS NOT DISTINCT FROM $2`, [ctx.orgId, body.project_id || null]);
    const pid = id('pol');
    await ctx.db.query(`INSERT INTO policies (id, org_id, project_id, kind, version, definition, created_by) VALUES ($1,$2,$3,'gate',$4,$5,$6)`, [pid, ctx.orgId, body.project_id || null, (prev?.v || 0) + 1, def, ctx.identity.id]);
    if (body.project_id) { const { markOnboarding } = await import('./core.mjs'); await markOnboarding(ctx.db, body.project_id, 'policy'); }
    await audit(ctx.db, ctx, 'policy.gate_updated', { targetType: 'policy', targetId: pid, projectId: body.project_id || null, data: def });
    return { id: pid, version: (prev?.v || 0) + 1, definition: def };
  });

  // ---------------- campaigns
  r.get('/api/campaigns', async ({ ctx }) => {
    const ids = await accessibleProjectIds(ctx);
    const rows = await ctx.db.query(`SELECT c.*, i.display_name AS owner_name,
        (SELECT json_agg(json_build_object('id', f.id, 'project', p.key, 'service', s.key, 'environment', e.key, 'status', f.status, 'priority', f.priority, 'verification', f.verification_status, 'owner', oi.display_name))
         FROM findings f JOIN projects p ON p.id=f.project_id LEFT JOIN services s ON s.id=f.service_id LEFT JOIN environments e ON e.id=f.environment_id LEFT JOIN identities oi ON oi.id=COALESCE(f.owner_identity_id, p.owner_identity_id) WHERE f.campaign_id=c.id AND f.project_id = ANY($2)) AS findings
      FROM campaigns c LEFT JOIN identities i ON i.id=c.owner_identity_id WHERE c.org_id=$1 ORDER BY c.created_at DESC`, [ctx.orgId, ids]);
    return rows.map(c => { const f = c.findings || []; return { ...c, progress: { total: f.length, verified: f.filter(x => x.status === 'verified_fixed').length, in_flight: f.filter(x => ['fix_available', 'deployed', 'verification_pending'].includes(x.status)).length, blocked: f.filter(x => x.status === 'paused').length } }; });
  });
  r.get('/api/campaigns/suggestions', async ({ ctx }) => {
    const ids = await accessibleProjectIds(ctx);
    return ctx.db.query(`SELECT f.root_cause_key, f.advisory_id, c.name AS package, c.ecosystem, max(f.fixed_version) AS fixed_version, count(*)::int AS occurrences, count(DISTINCT f.project_id)::int AS projects, min(f.priority) AS top_priority, json_agg(DISTINCT p.key) AS project_keys
      FROM findings f JOIN components c ON c.id=f.component_id JOIN projects p ON p.id=f.project_id WHERE f.org_id=$1 AND f.project_id = ANY($2) AND f.campaign_id IS NULL AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk')
      GROUP BY f.root_cause_key, f.advisory_id, c.name, c.ecosystem HAVING count(*) > 1 ORDER BY min(f.priority), count(*) DESC LIMIT 50`, [ctx.orgId, ids]);
  });
  r.post('/api/campaigns', async ({ ctx, body }) => {
    requireOrg(ctx, 'campaigns:manage'); need(body, ['name', 'root_cause_key']);
    const ids = await accessibleProjectIds(ctx);
    const cid = id('cmp');
    await ctx.db.tx(async (t) => {
      await t.query(`INSERT INTO campaigns (id, org_id, name, root_cause_key, description, owner_identity_id, plan) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [cid, ctx.orgId, body.name, body.root_cause_key, body.description || null, body.owner_identity_id || ctx.identity.id, body.plan || {}]);
      const n = await t.query(`UPDATE findings SET campaign_id=$1 WHERE org_id=$2 AND root_cause_key=$3 AND project_id = ANY($4) AND status NOT IN ('verified_fixed','false_positive','accepted_risk') RETURNING id`, [cid, ctx.orgId, body.root_cause_key, ids]);
      await audit(t, ctx, 'campaign.created', { targetType: 'campaign', targetId: cid, data: { root_cause_key: body.root_cause_key, findings: n.length } });
    });
    return { id: cid };
  });

  // ---------------- dashboards
  r.get('/api/dashboard/portfolio', async ({ ctx }) => {
    const ids = await accessibleProjectIds(ctx); const db = ctx.db;
    const projects = await db.query(`SELECT p.id, p.key, p.name, p.criticality, p.exposure,
        count(f.id) FILTER (WHERE f.status NOT IN ('verified_fixed','false_positive','accepted_risk'))::int AS open,
        count(f.id) FILTER (WHERE f.priority='P0' AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk'))::int AS p0,
        count(f.id) FILTER (WHERE f.priority='P1' AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk'))::int AS p1,
        count(f.id) FILTER (WHERE f.priority='P2' AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk'))::int AS p2,
        count(f.id) FILTER (WHERE f.exploitation IN ('kev_listed','actively_exploited','observed_in_env') AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk'))::int AS exploited,
        count(f.id) FILTER (WHERE f.sla_due_at < now() AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk','paused'))::int AS overdue,
        count(f.id) FILTER (WHERE f.applicability IN ('unknown','under_investigation') AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk'))::int AS uncertain,
        count(f.id) FILTER (WHERE f.status='verified_fixed')::int AS verified
      FROM projects p LEFT JOIN findings f ON f.project_id=p.id WHERE p.id = ANY($1) GROUP BY p.id ORDER BY p.name`, [ids]);
    const cov = await orgCoverage(db, ids);
    for (const p of projects) { const c = cov.find(x => x.project_id === p.id); p.coverage_ratio = c?.coverage_ratio ?? 0; p.coverage_gaps = c?.gaps.length ?? 0; }
    const trend = await db.query(`SELECT d::date AS day, (SELECT count(*)::int FROM findings f WHERE f.project_id = ANY($1) AND f.first_seen_at::date = d::date) AS opened,
        (SELECT count(*)::int FROM findings f WHERE f.project_id = ANY($1) AND f.closed_at::date = d::date) AS closed FROM generate_series(now() - interval '13 days', now(), interval '1 day') d ORDER BY d`, [ids]);
    const mttr = await db.one(`SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (closed_at - first_seen_at))/3600) AS median_hours, count(*)::int AS n FROM findings WHERE project_id = ANY($1) AND status='verified_fixed' AND closed_at IS NOT NULL`, [ids]);
    const ack = await db.one(`SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (acknowledged_at - created_at))/60) AS median_minutes, count(*)::int AS n FROM alerts WHERE org_id=$1 AND acknowledged_at IS NOT NULL AND (project_id IS NULL OR project_id = ANY($2))`, [ctx.orgId, ids]);
    const connectors = await db.query(`SELECT kind, name, status, last_success_at, last_error FROM connections WHERE org_id=$1 AND (project_id IS NULL OR project_id = ANY($2))`, [ctx.orgId, ids]);
    const totals = projects.reduce((t, p) => { for (const k of ['open', 'p0', 'p1', 'exploited', 'overdue', 'uncertain', 'verified']) t[k] = (t[k] || 0) + p[k]; return t; }, {});
    return { totals, projects, trend, metrics: { remediation_median_hours: { value: mttr?.median_hours ?? null, population: `verified_fixed findings (n=${mttr?.n || 0}); first_seen → verified closure` }, ack_median_minutes: { value: ack?.median_minutes ?? null, population: `acknowledged alerts (n=${ack?.n || 0}); alert created → acknowledged` } }, connectors, generated_at: new Date().toISOString(), note: 'Every number links to its records. No single opaque risk score is computed.' };
  });
  r.get('/api/coverage', async ({ ctx }) => orgCoverage(ctx.db, await accessibleProjectIds(ctx)));
  r.get('/api/drift', async ({ ctx, query }) => {
    const ids = await accessibleProjectIds(ctx);
    const pid = query.project_id && ids.includes(query.project_id) ? query.project_id : null;
    if (!pid) throw badRequest('project_id required.');
    const db = ctx.db;
    const services = await db.query('SELECT id, key FROM services WHERE project_id=$1', [pid]);
    const envs = await db.query('SELECT id, key, is_production FROM environments WHERE project_id=$1 ORDER BY is_production DESC', [pid]);
    const declared = await db.query(`SELECT c.ecosystem, c.name, c.version FROM observations o JOIN components c ON c.id=o.component_id WHERE o.snapshot_id=(SELECT id FROM inventory_snapshots WHERE project_id=$1 AND collection_method IN ('repository_scan','discovery_upload') ORDER BY created_at DESC LIMIT 1)`, [pid]);
    const out = [];
    for (const s of services) {
      const latestBuild = await db.one(`SELECT a.digest, a.commit_sha, a.created_at, (SELECT id FROM inventory_snapshots x WHERE x.artifact_id=a.id ORDER BY created_at DESC LIMIT 1) AS snap FROM artifacts a WHERE a.service_id=$1 ORDER BY a.created_at DESC LIMIT 1`, [s.id]);
      const buildComps = latestBuild?.snap ? await db.query('SELECT c.ecosystem, c.name, c.version FROM observations o JOIN components c ON c.id=o.component_id WHERE o.snapshot_id=$1', [latestBuild.snap]) : [];
      const perEnv = [];
      for (const e of envs) {
        const dep = await db.one(`SELECT a.digest, d.deployed_at, (SELECT id FROM inventory_snapshots x WHERE x.artifact_id=a.id ORDER BY created_at DESC LIMIT 1) AS snap FROM deployments d JOIN artifacts a ON a.id=d.artifact_id WHERE d.service_id=$1 AND d.environment_id=$2 AND d.is_current`, [s.id, e.id]);
        const depComps = dep?.snap ? await db.query('SELECT c.ecosystem, c.name, c.version FROM observations o JOIN components c ON c.id=o.component_id WHERE o.snapshot_id=$1', [dep.snap]) : [];
        const runtime = await db.query(`SELECT c.ecosystem, c.name, c.version, a.name AS asset FROM asset_projects ap JOIN assets a ON a.id=ap.asset_id JOIN LATERAL (SELECT id FROM inventory_snapshots WHERE asset_id=a.id ORDER BY created_at DESC LIMIT 1) sn ON true JOIN observations o ON o.snapshot_id=sn.id JOIN components c ON c.id=o.component_id WHERE ap.project_id=$1 AND ap.environment_id=$2`, [pid, e.id]);
        perEnv.push({ environment: e.key, is_production: e.is_production, deployed_digest: dep?.digest || null, deployed_at: dep?.deployed_at || null, behind_latest_build: !!(dep && latestBuild && dep.digest !== latestBuild.digest), comps: depComps, runtime });
      }
      const names = new Set([...declared, ...buildComps, ...perEnv.flatMap(p => [...p.comps, ...p.runtime])].map(c => `${c.ecosystem}:${c.name}`));
      const rows = [];
      for (const n of names) {
        const pick = (list) => list.find(c => `${c.ecosystem}:${c.name}` === n)?.version ?? null;
        const row = { component: n, declared: pick(declared), build: pick(buildComps), environments: Object.fromEntries(perEnv.map(p => [p.environment, { deployed: pick(p.comps), observed: pick(p.runtime) }])) };
        const vals = [row.build, ...Object.values(row.environments).flatMap(v => [v.deployed, v.observed])].filter(v => v != null);
        row.drift = new Set(vals).size > 1 || (row.declared && row.build && !String(row.build).includes(String(row.declared).replace(/^[~^>=<v ]+/, '')));
        if (row.drift) rows.push(row);
      }
      out.push({ service: s.key, latest_build: latestBuild ? { digest: latestBuild.digest, commit: latestBuild.commit_sha, at: latestBuild.created_at } : null, environments: perEnv.map(({ comps, runtime, ...rest }) => rest), drift: rows.slice(0, 100) });
    }
    return { project_id: pid, services: out, legend: 'declared = repository manifest; build = latest SBOM; deployed = SBOM of the artifact currently deployed; observed = runtime/asset observation.' };
  });
  r.get('/api/search', async ({ ctx, query }) => {
    const q = String(query.q || '').trim(); if (q.length < 2) return { projects: [], findings: [], advisories: [], components: [] };
    const ids = await accessibleProjectIds(ctx); const like = `%${q}%`;
    const [projects, findings, advisories, components] = await Promise.all([
      ctx.db.query('SELECT id, key, name FROM projects WHERE id = ANY($1) AND (key ILIKE $2 OR name ILIKE $2) LIMIT 8', [ids, like]),
      ctx.db.query(`SELECT f.id, f.advisory_id, c.name AS package, p.key AS project, f.priority FROM findings f JOIN components c ON c.id=f.component_id JOIN projects p ON p.id=f.project_id WHERE f.project_id = ANY($1) AND (f.advisory_id ILIKE $2 OR c.name ILIKE $2) LIMIT 8`, [ids, like]),
      ctx.db.query(`SELECT DISTINCT a.id, a.title, a.severity FROM advisories a LEFT JOIN advisory_aliases al ON al.advisory_id=a.id WHERE a.id ILIKE $1 OR al.alias ILIKE $1 OR a.title ILIKE $1 LIMIT 8`, [like]),
      ctx.db.query(`SELECT DISTINCT c.id, c.name, c.version, c.ecosystem FROM components c JOIN observations o ON o.component_id=c.id WHERE o.project_id = ANY($1) AND c.name ILIKE $2 LIMIT 8`, [ids, like]),
    ]);
    return { projects, findings, advisories, components };
  });
  r.get('/api/coverage-matrix', async () => ({ ecosystems: Object.entries(ECOSYSTEMS).map(([k, v]) => ({ key: k, label: v.label, comparator: v.comparator, osv: v.osv, sbom_ingestion: 'CycloneDX/SPDX via purl', lockfile_discovery: { npm: 'package-lock.json', composer: 'composer.lock', pypi: 'requirements.txt (pinned only)', go: 'go.mod', maven: 'pom.xml (declared, properties resolved)', rubygems: 'Gemfile.lock', cargo: 'Cargo.lock' }[k] || 'not supported', status: ['generic', 'cpan', 'conan', 'cran'].includes(k) ? 'partial' : 'implemented' })), unsupported: ['XLSX import', 'Gradle lockfiles', 'NuGet packages.lock.json', 'yarn.lock/pnpm-lock.yaml (use CycloneDX from the build)', 'SAST reachability'] }));
}
