// Mandatory end-to-end demonstration (spec §21) and operational acceptance scenarios (§31), over real HTTP.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startApp, as, receiver, drainAll } from './helpers.mjs';
import { cdx, digest, P } from '../src/seed.mjs';
import { executeTool, ToolDenied } from '../src/ai/tools.mjs';
import { loadPrincipal } from '../src/authz.mjs';
import { schedulerTick } from '../src/jobs/runtime.mjs';
import { claim, enqueue, complete, saveCheckpoint, LeaseLostError } from '../src/jobs/queue.mjs';

let app, alice, sam, pat, kim, dana, aud;
const projectFindings = async (c, q = '') => (await c.get('/api/findings?limit=200&status=all' + q)).body.items;

before(async () => {
  app = await startApp();
  [alice, sam, pat, kim, dana, aud] = await Promise.all(['alice', 'sam', 'pat', 'kim', 'dev', 'aud'].map(w => as(app, w)));
});
after(async () => { await app?.close(); });

test('1. two users with different project access cannot read each other\'s data (API, export, assets, agents)', async () => {
  const patF = await projectFindings(pat), kimF = await projectFindings(kim);
  assert.ok(patF.length > 0 && kimF.length > 0);
  assert.ok(patF.every(f => f.project_key === 'tts'), 'pat sees only TTS');
  assert.ok(kimF.every(f => f.project_key === 'kiosk'), 'kim sees only Kiosk');
  assert.equal((await pat.get(`/api/findings/${kimF[0].id}`)).status, 404, 'no existence leak');
  assert.equal((await pat.get('/api/projects/prj_kiosk')).status, 404);
  assert.equal((await pat.get('/api/findings?project_id=prj_kiosk')).body.total, 0, 'client-supplied project id is not proof of access');
  const csv = await pat.get('/api/findings.csv?status=all'); assert.equal(csv.status, 200); assert.ok(!csv.body.includes('kiosk'));
  assert.equal((await pat.get('/api/assets/ast_search_node')).status, 404);
  assert.equal((await pat.post('/api/investigations', { workflow: 'impact', finding_id: kimF[0].id })).status, 404);
  assert.equal((await dana.post(`/api/findings/${kimF[0].id}/transition`, { to: 'false_positive', reason: 'not relevant here' })).status, 403, 'developer lacks findings:triage');
  assert.equal((await aud.post('/api/projects', { key: 'x1', name: 'x' })).status, 403, 'auditor is read-only');
  assert.equal((await aud.get('/api/org/audit')).status, 200);
  assert.equal((await pat.get('/api/org/audit')).status, 403);
});

test('agent tool calls outside project scope are denied; prompt injection in advisory text cannot expand permissions', async () => {
  const ident = await app.db.one(`SELECT id, email, display_name FROM identities WHERE id='idn_pat'`);
  const principal = await loadPrincipal(app.db, ident, 'org_demo');
  const run = { org_id: 'org_demo', workflow: 'copilot', inputs: {} };
  const rt = { app, run, principal, scopeIds: new Set(['prj_tts']), allowed: new Set(['get_project', 'get_advisory', 'search_inventory']) };
  await assert.rejects(() => executeTool(rt, 'get_project', { project_id: 'prj_kiosk' }), ToolDenied);
  await assert.rejects(() => executeTool(rt, 'list_findings', { project_id: 'prj_tts' }), ToolDenied, 'tool not in workflow policy');
  const adv = await executeTool(rt, 'get_advisory', { advisory_id: 'SYNTH-2026-0003' });
  assert.match(adv.details.untrusted_content, /IGNORE ALL PREVIOUS INSTRUCTIONS/);
  assert.match(adv.details.handling, /cannot grant permissions/);
  await assert.rejects(() => executeTool(rt, 'search_inventory', { project_id: 'prj_kiosk', package: 'acme' }), ToolDenied);
  // even an org-wide principal is bounded by the investigation's frozen scope
  const samP = await loadPrincipal(app.db, await app.db.one(`SELECT id FROM identities WHERE id='idn_sam'`), 'org_demo');
  await assert.rejects(() => executeTool({ ...rt, principal: samP }, 'get_project', { project_id: 'prj_kiosk' }), ToolDenied);
});

test('2. onboard a project with services and UAT/Production environments', async () => {
  const r = await alice.post('/api/projects', { key: 'payments', name: 'Payments (synthetic)', criticality: 'critical', exposure: 'internet', services: [{ key: 'gateway' }], environments: [{ key: 'uat' }, { key: 'production', is_production: true }] });
  assert.equal(r.status, 200);
  assert.equal(r.body.environments.length, 2);
  assert.ok(r.body.onboarding_steps.find(s => s.step === 'metadata').done);
  assert.ok(!r.body.onboarding_steps.find(s => s.step === 'first_ingestion').done, 'wizard does not imply protection');
  assert.equal((await alice.post('/api/projects', { key: 'payments', name: 'dup' })).status, 409);
});

let ciToken, fixedDigest, httpFinding;
test('3+4. CI SBOM upload: scoped token, receipt, idempotent duplicate, revoked token; advisory matched to deployments', async () => {
  const t = await pat.post('/api/projects/prj_tts/ci-tokens', { name: 'gha', service_id: 'api', expires_in_days: 30 });
  assert.equal(t.status, 200); ciToken = t.body.token; assert.match(ciToken, /^stk_/);
  const bearer = { Authorization: 'Bearer ' + ciToken };
  fixedDigest = digest('tts/api/2.4.0');
  const meta = { project_id: 'prj_tts', service_id: 'api', commit_sha: 'a'.repeat(40), artifact_digest: fixedDigest, source_timestamp: new Date().toISOString(), branch: 'main', ci_run_url: 'https://ci.example.invalid/1' };
  const doc = cdx('tts-api', '2.4.0', [P.acmeHttp('7.4.2'), P.laravelish('10.2.1'), P.ssl('3.0.8-1.amzn2023.0.9')]);
  const up = await pat.req('POST', '/api/v1/ingestions/sbom', { metadata: meta, document: doc }, { headers: bearer, csrf: false });
  assert.equal(up.status, 202, JSON.stringify(up.body)); assert.ok(up.body.ingestion_id && up.body.status_url);
  const dup = await pat.req('POST', '/api/v1/ingestions/sbom', { metadata: meta, document: doc }, { headers: bearer, csrf: false });
  assert.equal(dup.status, 200); assert.equal(dup.body.ingestion_id, up.body.ingestion_id); assert.equal(dup.body.duplicate, true);
  // scope mismatch / tag instead of digest / other project
  assert.equal((await pat.req('POST', '/api/v1/ingestions/sbom', { metadata: { ...meta, artifact_digest: 'app:latest' }, document: doc }, { headers: bearer, csrf: false })).status, 400);
  assert.equal((await pat.req('POST', '/api/v1/ingestions/sbom', { metadata: { ...meta, project_id: 'prj_kiosk', service_id: 'backend' }, document: doc }, { headers: bearer, csrf: false })).status, 404);
  assert.equal((await pat.req('POST', '/api/v1/ingestions/sbom', { metadata: { ...meta, service_id: 'ingest' }, document: doc }, { headers: bearer, csrf: false })).status, 403, 'service-scoped token');
  assert.equal((await pat.req('POST', '/api/v1/ingestions/sbom', { metadata: meta, document: { bomFormat: 'nope' } }, { headers: bearer, csrf: false })).status, 422);
  await drainAll(app);
  const st = await pat.req('GET', up.body.status_url, undefined, { headers: bearer });
  assert.equal(st.body.status, 'completed');
  const ev = await pat.req('GET', st.body.policy_evaluation_url, undefined, { headers: bearer });
  assert.equal(ev.body.decision, 'pass', 'fixed build has no new violations');
  // a build upload alone creates no finding and no deployment
  const f = (await projectFindings(pat)).find(x => x.advisory_id === 'SYNTH-2026-0001' && x.environment === 'production');
  assert.equal(f.observed_version, '7.3.0'); httpFinding = f.id;
  // revoke → 401
  await pat.post(`/api/ci-tokens/${t.body.id}/revoke`);
  assert.equal((await pat.req('GET', up.body.status_url, undefined, { headers: bearer })).status, 401);
});

test('5. agent impact investigation shows evidence, unknowns and a human-approved proposal', async () => {
  const f = (await projectFindings(kim)).find(x => x.advisory_id === 'SYNTH-2026-0005' && x.environment === 'production');
  const inv = await kim.post('/api/investigations', { workflow: 'impact', finding_id: f.id });
  assert.equal(inv.status, 200);
  await drainAll(app);
  const r = (await kim.get(`/api/investigations/${inv.body.id}`)).body;
  assert.equal(r.state, 'waiting_approval');
  assert.equal(r.result.dimensions.presence, 'confirmed');
  assert.equal(r.result.dimensions.prerequisites, 'not_met', 'asset attribute admin_handler_exposed=false');
  assert.equal(r.result.dimensions.reachability, 'unknown');
  assert.ok(r.result.claims.every(c => c.evidence_refs.length > 0), 'every claim cites tool receipts');
  assert.ok(r.result.limitations.length > 0);
  assert.ok(r.tool_executions.length >= 5 && r.tool_executions.every(t => t.status === 'ok'));
  // finding unchanged until a human approves
  assert.equal((await kim.get(`/api/findings/${f.id}`)).body.applicability, 'under_investigation');
  assert.equal((await dana.post(`/api/investigations/${inv.body.id}/proposals`, { finding_id: f.id, decision: 'approve' })).status, 403);
  const ap = await kim.post(`/api/investigations/${inv.body.id}/proposals`, { finding_id: f.id, decision: 'approve' });
  assert.equal(ap.status, 200); assert.equal(ap.body.state, 'completed');
  assert.equal((await kim.get(`/api/findings/${f.id}`)).body.applicability, 'not_affected');
});

test('6+7. explainable priority, exactly one routed alert, idempotent remediation ticket, webhook retry without duplicates', async () => {
  const rx = await receiver(2);
  const ch = await alice.post('/api/channels', { kind: 'webhook', name: 'soc-hook', url: rx.url + '/hook' });
  assert.equal(ch.status, 200); assert.ok(ch.body.signing_key);
  const rule = await alice.post('/api/alert-rules', { name: 'kiosk webhook', project_id: 'prj_kiosk', triggers: ['finding.created'], conditions: { production_only: true }, actions: [{ type: 'notify', channel_id: ch.body.id }] });
  assert.equal(rule.status, 200);
  // a new advisory affecting kiosk/backend production
  const osv = { id: 'SYNTH-2026-0100', summary: '[SYNTHETIC] DoS in demo-logging', modified: new Date().toISOString(), severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }], affected: [{ package: { ecosystem: 'PyPI', name: 'demo-logging' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.0.0' }, { fixed: '2.1.5' }] }] }] };
  assert.equal((await sam.post('/api/advisories', { osv, synthetic: true })).status, 200);
  await drainAll(app);
  const f = (await projectFindings(kim)).find(x => x.advisory_id === 'SYNTH-2026-0100' && x.environment === 'production');
  assert.ok(f, 'advisory matched to deployed kiosk/backend');
  const detail = (await kim.get(`/api/findings/${f.id}`)).body;
  assert.ok(detail.priority_explanation.length >= 4);
  assert.ok(detail.evidence.some(e => e.kind === 'deployment'));
  const alerts = (await kim.get('/api/alerts')).body.filter(a => a.finding_id === f.id && a.rule_id === rule.body.id);
  assert.equal(alerts.length, 1, 'exactly one alert');
  const d = alerts[0].deliveries[0];
  assert.equal(d.status, 'accepted'); assert.equal(d.attempts, 3, 'two transient failures retried');
  assert.equal(rx.got.filter(g => g.method === 'POST').length, 3);
  assert.match(rx.got[2].headers['x-sentra-signature'], /^v1=[a-f0-9]{64}$/);
  // re-evaluation does not duplicate alerts or deliveries
  await app.db.query(`INSERT INTO outbox (org_id, event_type, payload) VALUES ('org_demo','finding.created',$1)`, [{ finding_id: f.id, project_id: 'prj_kiosk' }]);
  await drainAll(app);
  assert.equal((await kim.get('/api/alerts')).body.filter(a => a.finding_id === f.id && a.rule_id === rule.body.id).length, 1);
  assert.equal(rx.got.length, 3, 'no duplicate delivery');
  // ticket idempotency
  const t1 = await kim.post(`/api/findings/${f.id}/tickets`, { provider: 'internal' });
  const t2 = await kim.post(`/api/findings/${f.id}/tickets`, { provider: 'internal' });
  assert.equal(t1.body.ticket.id, t2.body.ticket.id); assert.equal(t2.body.duplicate, true);
  rx.close();
});

test('8-10. merged fix stays open; deploying the fixed artifact verifies the correct environment; contradiction reopens', async () => {
  const pr = await pat.post(`/api/findings/${httpFinding}/pull-requests`, { state: 'merged', url: 'https://github.example.invalid/acme/tts/pull/7', merge_commit_sha: 'b'.repeat(40) });
  assert.equal(pr.status, 200);
  let f = (await pat.get(`/api/findings/${httpFinding}`)).body;
  assert.equal(f.status, 'fix_available'); assert.notEqual(f.status, 'verified_fixed');
  assert.equal((await pat.post(`/api/findings/${httpFinding}/transition`, { to: 'verified_fixed' })).status, 403, 'humans cannot mark verified');
  // deploy fixed artifact to UAT only → production finding stays open
  const t = await pat.post('/api/projects/prj_tts/ci-tokens', { name: 'deployer', expires_in_days: 7 });
  const bearer = { Authorization: 'Bearer ' + t.body.token };
  const dep = (env) => pat.req('POST', '/api/v1/deployments', { project_id: 'prj_tts', service_id: 'api', environment_id: env, artifact_digest: fixedDigest, deployed_at: new Date().toISOString() }, { headers: bearer, csrf: false });
  assert.equal((await dep('uat')).status, 201);
  await drainAll(app);
  f = (await pat.get(`/api/findings/${httpFinding}`)).body;
  assert.equal(f.status, 'fix_available', 'production still runs the vulnerable artifact');
  const uat = (await projectFindings(pat)).find(x => x.advisory_id === 'SYNTH-2026-0001' && x.environment === 'uat');
  assert.equal(uat.status, 'verified_fixed', 'UAT verified by its own deployment');
  // unknown artifact deployments are rejected
  assert.equal((await pat.req('POST', '/api/v1/deployments', { project_id: 'prj_tts', service_id: 'api', environment_id: 'production', artifact_digest: digest('never-built'), deployed_at: new Date().toISOString() }, { headers: bearer, csrf: false })).status, 422);
  assert.equal((await dep('production')).status, 201);
  await drainAll(app);
  f = (await pat.get(`/api/findings/${httpFinding}`)).body;
  assert.equal(f.status, 'verified_fixed'); assert.equal(f.verification_status, 'verified');
  const v = f.evidence.find(e => e.kind === 'verification' && e.stance === 'supporting');
  assert.equal(v.data.digest, fixedDigest); assert.ok(v.data.deployed_at && v.data.snapshot_id);
  assert.ok(f.tickets.every(t2 => t2.mapped_state === 'done'), 'linked ticket closed after verification');
  // rollback to the vulnerable artifact → contradictory evidence reopens
  const oldDigest = digest('tts/api/2.3.0');
  assert.equal((await pat.req('POST', '/api/v1/deployments', { project_id: 'prj_tts', service_id: 'api', environment_id: 'production', artifact_digest: oldDigest, deployed_at: new Date().toISOString() }, { headers: bearer, csrf: false })).status, 201);
  await drainAll(app);
  f = (await pat.get(`/api/findings/${httpFinding}`)).body;
  assert.equal(f.status, 'new'); assert.equal(f.verification_status, 'contradicted');
});

test('advisory revision re-evaluates deployed inventory without a new build; withdrawn excludes', async () => {
  const base = { id: 'SYNTH-2026-0200', summary: '[SYNTHETIC] revision test', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }] };
  await sam.post('/api/advisories', { osv: { ...base, modified: '2026-11-01T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: '@acme/xml-parser' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.9.0' }] }] }] } });
  await drainAll(app);
  let fs = (await projectFindings(pat)).filter(x => x.advisory_id === 'SYNTH-2026-0200');
  assert.equal(fs.length, 2, 'uat + production ingest');
  const r = await sam.post('/api/advisories', { osv: { ...base, modified: '2026-11-02T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: '@acme/xml-parser' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '2.8.0' }, { fixed: '2.9.0' }] }] }] } });
  assert.equal(r.body.revision, 2); assert.ok(r.body.changes.some(c => c.field === 'affected'));
  await drainAll(app);
  fs = (await projectFindings(pat)).filter(x => x.advisory_id === 'SYNTH-2026-0200');
  assert.ok(fs.every(x => x.status === 'false_positive' && x.applicability === 'not_affected'));
  const ev = (await pat.get(`/api/findings/${fs[0].id}`)).body.events;
  assert.ok(ev.some(e => /advisory_revision/.test(e.reason || '')), 'reason recorded');
  const same = await sam.post('/api/advisories', { osv: { ...base, modified: '2026-11-02T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: '@acme/xml-parser' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '2.8.0' }, { fixed: '2.9.0' }] }] }] } });
  assert.equal(same.body.changed, false, 'identical revision is a no-op');
});

test('11. audit timeline is complete and hash chain verifies; dashboard drills down', async () => {
  const a = (await aud.get('/api/org/audit?limit=500')).body.items.map(e => e.action);
  for (const act of ['auth.login', 'ingestion.accepted', 'deployment.recorded', 'finding.verified_fixed', 'ci_token.revoked', 'investigation.proposal_approved', 'channel.created']) assert.ok(a.includes(act), act);
  assert.equal((await aud.get('/api/org/audit/verify')).body.ok, true);
  const d = (await sam.get('/api/dashboard/portfolio')).body;
  assert.ok(d.projects.length >= 2); assert.ok(d.totals.verified >= 1, "UAT stays verified; production was reopened by the rollback scenario");
  assert.match(d.metrics.remediation_median_hours.population, /n=\d+/);
});

test('12. broken connector produces coverage warning and stale observations, never a safe result', async () => {
  const imp = await kim.post('/api/projects/prj_kiosk/imports/commit', { filename: 'runtime.json', content: JSON.stringify([{ ecosystem: 'pypi', name: 'demo-logging', version: '2.1.0' }]), target: { kind: 'asset', identifier: 'i-0demo-batch', asset_kind: 'server', environment_id: 'production' } });
  assert.equal(imp.status, 200);
  const dupe = await kim.post('/api/projects/prj_kiosk/imports/commit', { filename: 'runtime.json', content: JSON.stringify([{ ecosystem: 'pypi', name: 'demo-logging', version: '2.1.0' }]), target: { kind: 'asset', identifier: 'i-0demo-batch', asset_kind: 'server', environment_id: 'production' } });
  assert.equal(dupe.body.duplicate, true);
  const rx = await receiver(0); rx.respond = () => ({ version: '4.11' });
  const c = await kim.post('/api/connections', { kind: 'dependency_track', name: 'dtrack', project_id: 'prj_kiosk', config: { api_base: rx.url, project_uuid: 'u1' }, secret_value: 'dt-api-key-value' });
  assert.equal(c.status, 200); assert.equal(c.body.test.ok, true);
  const conns = (await kim.get('/api/connections')).body; assert.ok(!JSON.stringify(conns).includes('dt-api-key-value'), 'secret never returned');
  rx.close();
  const failed = await kim.post(`/api/connections/${c.body.id}/test`); assert.equal(failed.body.ok, false);
  await app.db.query(`UPDATE observations SET source=$1 WHERE snapshot_id=$2`, [`connector:${c.body.id}`, imp.body.receipt.snapshot_id]);
  assert.equal((await kim.post(`/api/connections/${c.body.id}/disconnect`)).status, 200);
  assert.equal((await kim.post(`/api/connections/${c.body.id}/sync`)).status, 409, 'disconnected source cannot sync');
  await drainAll(app);
  const cov = (await kim.get('/api/projects/prj_kiosk/coverage')).body;
  assert.ok(cov.gaps.some(g => g.kind === 'stale_observations')); assert.ok(cov.gaps.some(g => g.kind === 'connector_disconnected'));
  const stale = (await sam.get('/api/alerts')).body.find(a => a.trigger === 'inventory.stale');
  assert.ok(stale, 'operational warning raised');
});

test('CSRF, origin checks, security headers and unauthenticated access', async () => {
  assert.equal((await sam.post('/api/projects', { key: 'csrf-x', name: 'x' }, { csrf: false })).status, 403);
  assert.equal((await sam.req('POST', '/api/projects', { key: 'csrf-y', name: 'y' }, { headers: { Origin: 'https://evil.example' } })).status, 403);
  const anon = await fetch(app.base + '/api/findings'); assert.equal(anon.status, 401);
  assert.equal(anon.headers.get('x-content-type-options'), 'nosniff'); assert.match(anon.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  const spoof = await fetch(app.base + '/api/findings', { headers: { 'X-Forwarded-User': 'idn_alice', 'oai-authenticated-user-id': 'idn_alice' } }); assert.equal(spoof.status, 401, 'identity headers are not trusted');
  assert.equal((await pat.put('/api/projects/prj_tts/drafts/sources', { token: 'ghp_' + 'Z'.repeat(30) })).status, 400, 'drafts reject secrets');
});

test('scheduler: missed daily report applies catch-up policy with original occurrence time; Vietnamese incomplete-coverage report', async () => {
  const s = await alice.post('/api/schedules', { name: 'test report', job_type: 'daily_report', timezone: 'Asia/Ho_Chi_Minh', frequency: 'daily', local_time: '08:00', missed_run_policy: 'run_once', params: { language: 'vi' } });
  await app.db.query(`UPDATE schedules SET next_run_at = now() - interval '3 days' + interval '1 minute' WHERE id=$1`, [s.body.id]);
  await schedulerTick(app);
  const jobs = await app.db.query('SELECT * FROM jobs WHERE schedule_id=$1', [s.body.id]);
  assert.equal(jobs.length, 1, 'run_once catches up once');
  assert.equal(new Date(jobs[0].scheduled_for).getUTCHours(), 1, '08:00 Asia/Ho_Chi_Minh = 01:00 UTC preserved');
  await schedulerTick(app); assert.equal((await app.db.query('SELECT * FROM jobs WHERE schedule_id=$1', [s.body.id])).length, 1, 'idempotent occurrence');
  const s2 = await alice.post('/api/schedules', { name: 'all', job_type: 'sla_evaluation', timezone: 'UTC', frequency: 'daily', local_time: '00:00', missed_run_policy: 'run_all', overlap_policy: 'allow' });
  await app.db.query(`UPDATE schedules SET next_run_at = date_trunc('day', now()) - interval '2 days' WHERE id=$1`, [s2.body.id]);
  await schedulerTick(app);
  assert.equal((await app.db.query('SELECT * FROM jobs WHERE schedule_id=$1', [s2.body.id])).length, 3);
  await app.db.query(`UPDATE connections SET config='{"feed_url":"http://127.0.0.1:1/unreachable"}' WHERE kind='thn'`);
  await drainAll(app);
  const reports = (await sam.get('/api/reports')).body;
  const rep = (await sam.get(`/api/reports/${reports[0].id}`)).body;
  assert.equal(rep.language, 'vi'); assert.equal(rep.coverage_status, 'incomplete', 'THN not reachable in tests → incomplete, not zero');
  assert.match(rep.rendered_text, /Báo cáo bảo mật hằng ngày/); assert.match(rep.rendered_text, /chưa đầy đủ/);
  assert.doesNotMatch(rep.rendered_text, /all software is safe/);
  const runNow = await alice.post(`/api/schedules/${s.body.id}/run-now`, {}); assert.ok(runNow.body.job_id);
  const sch = await app.db.one('SELECT next_run_at FROM schedules WHERE id=$1', [s.body.id]); assert.ok(new Date(sch.next_run_at) > new Date(), 'run now does not alter recurrence');
});

test('queue: lease expiry recovery, fencing, cancellation and dead-letter replay', async () => {
  const { job } = await enqueue(app.db, { type: 'noop_test', orgId: 'org_demo', idempotencyKey: 'q-test-1', maxAttempts: 2 });
  const c1 = await claim(app.db, 'w1', 60, ['noop_test']);
  assert.equal(c1.id, job.id);
  await app.db.query(`UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id=$1`, [job.id]);
  const c2 = await claim(app.db, 'w2', 60, ['noop_test']);
  assert.equal(c2.id, job.id); assert.ok(c2.fence > c1.fence, 'new fencing token');
  await assert.rejects(() => saveCheckpoint(app.db, c1, { step: 1 }), LeaseLostError, 'stale worker cannot write');
  assert.equal(await complete(app.db, c1, {}), false); assert.equal(await complete(app.db, c2, {}), true);
  const dup = await enqueue(app.db, { type: 'noop_test', orgId: 'org_demo', idempotencyKey: 'q-test-1' }); assert.equal(dup.created, false);
  const { job: j3 } = await enqueue(app.db, { type: 'no_such_handler', orgId: 'org_demo' });
  await drainAll(app);
  const dead = (await alice.get('/api/jobs?status=dead')).body.items.find(j => j.id === j3.id); assert.ok(dead);
  assert.equal((await alice.post(`/api/jobs/${j3.id}/replay`)).body.status, 'queued');
  const { job: j4 } = await enqueue(app.db, { type: 'noop_test', orgId: 'org_demo', runAfter: new Date(Date.now() + 3600e3).toISOString() });
  assert.equal((await alice.post(`/api/jobs/${j4.id}/cancel`)).body.status, 'cancelled');
});

test('role removal revokes sessions; background investigations re-check access at execution', async () => {
  const f = (await projectFindings(kim)).find(x => x.environment === 'uat');
  const inv = await dana.post('/api/investigations', { workflow: 'impact', finding_id: f.id });
  assert.equal(inv.status, 200);
  await alice.req('DELETE', '/api/projects/prj_kiosk/members/idn_dev');
  await drainAll(app);
  const r = await app.db.one('SELECT state, error FROM investigations WHERE id=$1', [inv.body.id]);
  assert.ok(r.state === 'completed' || r.state === 'partial' || r.state === 'waiting_approval');
  const tools = await app.db.query(`SELECT status FROM tool_executions WHERE investigation_id=$1`, [inv.body.id]);
  assert.ok(tools.some(t => t.status === 'denied'), 'tool calls denied after access removal');
  await alice.patch('/api/org/members/idn_dev', { disabled: true });
  assert.equal((await dana.get('/api/me')).status, 401, 'session revoked');
});
