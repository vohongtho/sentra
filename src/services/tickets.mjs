// Remediation tickets: GitHub Issues, Azure DevOps work items (PBI), or internal tickets.
// Stable external IDs + idempotency keys prevent duplicates; last_sync_origin prevents sync loops.
// A ticket becoming Done never verifies a finding.
import { id, notFound, AppError } from '../util.mjs';
import { safeFetch } from '../notify/safe-fetch.mjs';
import { getSecretValue } from './secrets.mjs';
import { audit } from '../audit.mjs';
import { emit, RetryableError, PermanentError } from '../jobs/runtime.mjs';
import { hmacHex, safeEqual } from '../crypto.mjs';
import { CLOSED_STATUSES } from '../domain/policy.mjs';

const STATE_MAP = {
  github: { open: 'open', closed: 'done' },
  azure_devops: { New: 'open', Approved: 'open', Committed: 'in_progress', Active: 'in_progress', Done: 'done', Removed: 'cancelled', Closed: 'done', Resolved: 'done' },
};

async function ticketBody(db, appOrigin, f) {
  const ev = await db.query(`SELECT summary FROM evidence WHERE finding_id=$1 ORDER BY collected_at LIMIT 5`, [f.id]);
  return [
    `Sentra finding ${f.id}${f.is_synthetic ? ' (SYNTHETIC demonstration data)' : ''}`,
    `Advisory: ${f.advisory_id} — ${f.advisory_title || ''}`,
    `Component: ${f.component_name} ${f.observed_version || '(version unknown)'} → fixed: ${f.fixed_version || 'unknown'}`,
    `Scope: ${f.project_key} / ${f.service_key || 'asset'} / ${f.env_key || '-'}`,
    `Priority: ${f.priority} · Applicability: ${f.applicability} · Exploitation: ${f.exploitation}`,
    `SLA due: ${f.sla_due_at ? new Date(f.sla_due_at).toISOString() : 'n/a'}`,
    '', 'Evidence:', ...ev.map(e => `- ${e.summary}`), '',
    `Details: ${appOrigin}/#/findings/${f.id}`,
    '', 'Closing this ticket does not close the finding. Sentra closes it only after the fixed artifact is verified in the affected environment.',
    `Sentra-Finding: ${f.id}`,
  ].join('\n');
}

async function adapterFor(app, conn) {
  const cfg = conn?.config || {};
  const token = conn?.secret_id ? await getSecretValue(app.db, conn.org_id, conn.secret_id) : null;
  const net = { allowPrivate: app.cfg.allowPrivateWebhookTargets, allowHttp: app.cfg.allowPrivateWebhookTargets };
  if (conn.kind === 'github') {
    const base = cfg.api_base || 'https://api.github.com';
    const h = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json', 'User-Agent': 'Sentra' };
    return {
      async create(title, body) {
        const r = await safeFetch(`${base}/repos/${cfg.owner}/${cfg.repo}/issues`, { method: 'POST', headers: h, body: JSON.stringify({ title, body, labels: cfg.labels || ['security', 'sentra'] }) }, net);
        if (r.status === 429 || r.status >= 500) throw new RetryableError(`GitHub ${r.status}`);
        if (!r.ok) throw new PermanentError(`GitHub rejected issue: ${r.status} ${r.text.slice(0, 200)}`);
        const j = r.json(); return { external_id: String(j.number), url: j.html_url, state: j.state };
      },
      async close(extId) {
        const r = await safeFetch(`${base}/repos/${cfg.owner}/${cfg.repo}/issues/${extId}`, { method: 'PATCH', headers: h, body: JSON.stringify({ state: 'closed', state_reason: 'completed' }) }, net);
        if (!r.ok) throw new RetryableError(`GitHub close failed ${r.status}`); return 'closed';
      },
      async test() { const r = await safeFetch(`${base}/repos/${cfg.owner}/${cfg.repo}`, { headers: h }, net); return { ok: r.ok, status: r.status }; },
    };
  }
  if (conn.kind === 'azure_devops') {
    const base = cfg.api_base || `https://dev.azure.com/${encodeURIComponent(cfg.organization)}`;
    const h = { Authorization: 'Basic ' + Buffer.from(':' + token).toString('base64'), 'Content-Type': 'application/json-patch+json' };
    const type = encodeURIComponent(cfg.work_item_type || 'Product Backlog Item');
    return {
      async create(title, body) {
        const patch = [{ op: 'add', path: '/fields/System.Title', value: title }, { op: 'add', path: '/fields/System.Description', value: body.replace(/\n/g, '<br>') }, { op: 'add', path: '/fields/System.Tags', value: 'security; sentra' }];
        if (cfg.area_path) patch.push({ op: 'add', path: '/fields/System.AreaPath', value: cfg.area_path });
        const r = await safeFetch(`${base}/${encodeURIComponent(cfg.project)}/_apis/wit/workitems/$${type}?api-version=7.1`, { method: 'POST', headers: h, body: JSON.stringify(patch) }, net);
        if (r.status === 429 || r.status >= 500) throw new RetryableError(`Azure DevOps ${r.status}`);
        if (!r.ok) throw new PermanentError(`Azure DevOps rejected work item: ${r.status} ${r.text.slice(0, 200)}`);
        const j = r.json(); return { external_id: String(j.id), url: j._links?.html?.href || j.url, state: j.fields?.['System.State'] };
      },
      async close(extId) {
        const r = await safeFetch(`${base}/${encodeURIComponent(cfg.project)}/_apis/wit/workitems/${extId}?api-version=7.1`, { method: 'PATCH', headers: h, body: JSON.stringify([{ op: 'add', path: '/fields/System.State', value: cfg.done_state || 'Done' }]) }, net);
        if (!r.ok) throw new RetryableError(`Azure DevOps close failed ${r.status}`); return 'Done';
      },
      async test() { const r = await safeFetch(`${base}/_apis/projects/${encodeURIComponent(cfg.project)}?api-version=7.1`, { headers: { Authorization: h.Authorization } }, net); return { ok: r.ok, status: r.status }; },
    };
  }
  throw new PermanentError(`No ticket adapter for ${conn.kind}`);
}
export { adapterFor };

export async function createTicket(app, { findingId, provider = 'internal', connectionId = null, actor = null }) {
  const db = app.db;
  const f = await db.one(`SELECT f.*, a.title AS advisory_title, a.is_synthetic, c.name AS component_name, p.key AS project_key, s.key AS service_key, e.key AS env_key FROM findings f JOIN advisories a ON a.id=f.advisory_id JOIN components c ON c.id=f.component_id JOIN projects p ON p.id=f.project_id LEFT JOIN services s ON s.id=f.service_id LEFT JOIN environments e ON e.id=f.environment_id WHERE f.id=$1`, [findingId]);
  if (!f) throw notFound('Finding');
  const key = `${findingId}|${provider}|${connectionId || ''}`;
  const existing = await db.one('SELECT * FROM tickets WHERE idempotency_key=$1', [key]);
  if (existing?.external_id) return { ticket: existing, duplicate: true };
  const tid = existing?.id || id('tkt');
  if (!existing) await db.query(`INSERT INTO tickets (id, org_id, project_id, finding_id, provider, connection_id, idempotency_key, mapped_state, last_sync_origin) VALUES ($1,$2,$3,$4,$5,$6,$7,'open','sentra')`, [tid, f.org_id, f.project_id, f.id, provider, connectionId, key]);
  const title = `[${f.priority}] ${f.advisory_id}: ${f.component_name} ${f.observed_version || ''} in ${f.project_key}/${f.service_key || 'asset'}/${f.env_key || '-'}`.slice(0, 240);
  const body = await ticketBody(db, app.cfg.appOrigin, f);
  let result;
  if (provider === 'internal') result = { external_id: 'SNT-' + tid.slice(-8).toUpperCase(), url: `${app.cfg.appOrigin}/#/findings/${f.id}`, state: 'open' };
  else {
    const conn = await db.one('SELECT * FROM connections WHERE id=$1 AND org_id=$2', [connectionId, f.org_id]);
    if (!conn || conn.status === 'disabled') throw new PermanentError('Ticket connection unavailable.');
    result = await (await adapterFor(app, conn)).create(title, body);
  }
  await db.query(`UPDATE tickets SET external_id=$2, external_url=$3, external_state=$4, last_synced_at=now() WHERE id=$1`, [tid, result.external_id, result.url, result.state]);
  await db.query(`INSERT INTO finding_events (id, finding_id, kind, to_value, reason, actor, data) VALUES ($1,$2,'ticket',$3,$4,$5,$6)`, [id('fev'), f.id, result.external_id, `Ticket created in ${provider}`, actor || 'system', { url: result.url }]);
  if (f.status === 'new' || f.status === 'triaged') {
    await db.query(`UPDATE findings SET status='assigned', updated_at=now() WHERE id=$1`, [f.id]);
    await db.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor) VALUES ($1,$2,'status',$3,'assigned','Remediation ticket created','system')`, [id('fev'), f.id, f.status]);
  }
  await audit(db, { orgId: f.org_id, actorType: 'system', systemActor: actor || 'tickets' }, 'ticket.created', { targetType: 'ticket', targetId: tid, projectId: f.project_id, data: { provider, external_id: result.external_id } });
  return { ticket: await db.one('SELECT * FROM tickets WHERE id=$1', [tid]), duplicate: false };
}

/** Close linked tickets after verified remediation (outbound sync). */
export async function syncTicketsOnVerified(app, findingId) {
  const tickets = await app.db.query(`SELECT t.*, c.kind, c.config, c.secret_id, c.org_id AS conn_org FROM tickets t LEFT JOIN connections c ON c.id=t.connection_id WHERE t.finding_id=$1 AND COALESCE(t.mapped_state,'open') <> 'done'`, [findingId]);
  for (const t of tickets) {
    if (t.provider !== 'internal') { const ad = await adapterFor(app, { kind: t.kind, config: t.config, secret_id: t.secret_id, org_id: t.conn_org }); await ad.close(t.external_id); }
    await app.db.query(`UPDATE tickets SET mapped_state='done', external_state='closed', last_sync_origin='sentra', last_synced_at=now() WHERE id=$1`, [t.id]);
  }
  return tickets.length;
}

/** Inbound GitHub webhook: issues + pull_request. Signature + delivery-id replay protection. */
export async function handleGithubWebhook(app, { raw, headers }) {
  const secret = app.cfg.githubWebhookSecret;
  if (!secret) throw new AppError(503, 'WEBHOOK_NOT_CONFIGURED', 'GITHUB_WEBHOOK_SECRET not configured.');
  const sig = headers['x-hub-signature-256'] || '';
  if (!safeEqual(sig, 'sha256=' + hmacHex(secret, raw))) throw new AppError(401, 'SIGNATURE_INVALID', 'Webhook signature invalid.');
  const delivery = headers['x-github-delivery'];
  if (!delivery) throw new AppError(400, 'DELIVERY_ID_REQUIRED', 'Missing delivery id.');
  const fresh = await app.db.query(`INSERT INTO webhook_receipts (id, provider, delivery_id) VALUES ($1,'github',$2) ON CONFLICT DO NOTHING RETURNING id`, [id('whr'), delivery]);
  if (!fresh.length) return { duplicate: true };
  const event = headers['x-github-event']; const p = JSON.parse(raw.toString('utf8'));
  if (event === 'issues' && ['closed', 'reopened'].includes(p.action)) {
    const t = await app.db.one(`SELECT t.*, f.status AS finding_status FROM tickets t JOIN findings f ON f.id=t.finding_id WHERE t.provider='github' AND t.external_id=$1 AND t.external_url LIKE $2`, [String(p.issue.number), `%${p.repository.full_name}%`]);
    if (!t) return { ignored: 'unknown_ticket' };
    const mapped = STATE_MAP.github[p.issue.state] || 'open';
    if (t.mapped_state === mapped && t.last_sync_origin === 'sentra') return { ignored: 'own_change' }; // loop prevention
    await app.db.query(`UPDATE tickets SET external_state=$2, mapped_state=$3, last_sync_origin='external', last_synced_at=now() WHERE id=$1`, [t.id, p.issue.state, mapped]);
    await app.db.query(`INSERT INTO finding_events (id, finding_id, kind, to_value, reason, actor) VALUES ($1,$2,'ticket',$3,$4,'github')`, [id('fev'), t.finding_id, mapped,
      mapped === 'done' && !CLOSED_STATUSES.includes(t.finding_status) ? 'External ticket closed. This does not verify remediation; the finding stays open until the deployed fix is verified.' : `External ticket ${p.action}.`]);
    return { ticket: t.id, mapped };
  }
  if (event === 'pull_request' && isRenovate(p.pull_request) && (p.action === 'opened' || (p.action === 'closed' && p.pull_request.merged))) {
    return linkRenovatePr(app, p);
  }
  if (event === 'pull_request' && p.action === 'closed' && p.pull_request?.merged) {
    const ids = [...new Set((p.pull_request.body || '').match(/fnd_[A-Za-z0-9]+/g) || [])];
    for (const fid of ids) await recordPullRequest(app, null, fid, { provider: 'github', url: p.pull_request.html_url, state: 'merged', merged_at: p.pull_request.merged_at, merge_commit_sha: p.pull_request.merge_commit_sha });
    return { linked: ids.length };
  }
  return { ignored: event };
}

export async function recordPullRequest(app, ctx, findingId, pr) {
  const db = app.db;
  const f = await db.one('SELECT * FROM findings WHERE id=$1', [findingId]);
  if (!f) throw notFound('Finding');
  if (!pr.skipInsert) await db.query(`INSERT INTO pull_requests (id, org_id, project_id, finding_id, provider, url, state, merged_at, merge_commit_sha, source) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [id('pr'), f.org_id, f.project_id, f.id, pr.provider || 'github', pr.url || null, pr.state, pr.merged_at || null, pr.merge_commit_sha || null, pr.source || (ctx ? 'manual' : 'github_webhook')]);
  if (pr.state === 'merged' && ['new', 'triaged', 'assigned', 'in_progress'].includes(f.status)) {
    await db.query(`UPDATE findings SET status='fix_available', updated_at=now() WHERE id=$1`, [f.id]);
    await db.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor, data) VALUES ($1,$2,'status',$3,'fix_available',$4,$5,$6)`, [id('fev'), f.id, f.status, 'Fix merged. The finding remains open until the fixed artifact is deployed and verified in this environment.', ctx?.identity?.id || 'github', { url: pr.url, merge_commit_sha: pr.merge_commit_sha }]);
    await emit(db, f.org_id, 'fix.available', { finding_id: f.id, project_id: f.project_id });
  }
  return { recorded: true };
}

// ------------------------------------------------------------------ Renovate pull requests
// Renovate is not embedded (AGPL-3.0); its PRs arrive through the GitHub webhook. A PR is linked to an open finding only
// when the repository belongs to the finding's project, the package matches, and the target version evaluates as
// outside the affected range (deterministic check). Merging moves the finding to fix_available; it stays open until verified.
export const isRenovate = (pr) => !!pr && (/^renovate(\[bot\])?$/i.test(pr.user?.login || '') || /^renovate\//.test(pr.head?.ref || ''));
export function parseRenovateTitle(title) {
  const m = /update (?:dependency )?(\S+?) to v?(\d[\w.\-+]*)/i.exec(String(title || ''));
  return m ? { pkg: m[1], version: m[2] } : null;
}
async function linkRenovatePr(app, p) {
  const parsed = parseRenovateTitle(p.pull_request.title);
  if (!parsed) return { ignored: 'renovate_title_unparsed' };
  const { evaluateRanges } = await import('../domain/versions.mjs');
  const findings = await app.db.query(`SELECT f.id, f.advisory_id, f.status, c.ecosystem, c.name FROM findings f JOIN components c ON c.id=f.component_id JOIN repositories r ON r.project_id=f.project_id
    WHERE lower(r.full_name)=lower($1) AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk') AND (c.name=$2 OR c.name LIKE '%:' || $2 OR c.name LIKE '%/' || $2)`, [p.repository.full_name, parsed.pkg]);
  let linked = 0; const skipped = [];
  for (const f of findings) {
    const ranges = await app.db.query('SELECT * FROM affected_ranges WHERE advisory_id=$1 AND ecosystem=$2 AND package_name=$3', [f.advisory_id, f.ecosystem, f.name]);
    const ev = evaluateRanges(f.ecosystem, parsed.version, ranges);
    if (ev.status !== 'not_affected') { skipped.push({ finding: f.id, reason: `target ${parsed.version} is ${ev.status} for ${f.advisory_id}` }); continue; }
    const merged = p.action === 'closed';
    const exists = await app.db.one('SELECT id FROM pull_requests WHERE finding_id=$1 AND url=$2', [f.id, p.pull_request.html_url]);
    if (exists && merged) await app.db.query(`UPDATE pull_requests SET state='merged', merged_at=$2, merge_commit_sha=$3 WHERE id=$1`, [exists.id, p.pull_request.merged_at, p.pull_request.merge_commit_sha]);
    if (!exists || merged) await recordPullRequest(app, null, f.id, { provider: 'github', url: p.pull_request.html_url, state: merged ? 'merged' : 'open', merged_at: p.pull_request.merged_at, merge_commit_sha: p.pull_request.merge_commit_sha, source: 'renovate', skipInsert: !!exists });
    linked++;
  }
  return { renovate: true, package: parsed.pkg, target: parsed.version, linked, skipped };
}
