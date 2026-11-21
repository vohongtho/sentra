// Features added after the core build: XLSX import, VEX export, attack paths, editable priority/SLA policies with
// business-hours calendars, draft remediation PRs, Wazuh / DefectDojo connectors, SIEM channel, Renovate linking,
// retention with audit archival. External systems are local test doubles shaped like their public APIs.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { zipSync, strToU8 } from 'fflate';
import { startApp, as, drainAll } from './helpers.mjs';
import { bumpManifest } from '../src/services/remediation-pr.mjs';
import { addBusinessHours } from '../src/domain/policy.mjs';
import { runRetention } from '../src/services/retention.mjs';
import { hmacHex } from '../src/crypto.mjs';
import { parseRenovateTitle } from '../src/services/tickets.mjs';

let app, alice, pat, kim, double;
const routes = new Map(); const seen = [];
before(async () => {
  double = http.createServer(async (req, res) => {
    let b = ''; for await (const c of req) b += c;
    const u = new URL(req.url, 'http://x'); seen.push({ method: req.method, path: u.pathname, search: u.search, headers: req.headers, body: b });
    const h = routes.get(`${req.method} ${u.pathname}`);
    const out = h ? h({ body: b ? JSON.parse(b) : null, headers: req.headers, url: u }) : { status: 404, json: { message: 'no route' } };
    res.writeHead(out.status || 200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(out.json ?? {}));
  });
  await new Promise(r => double.listen(0, '127.0.0.1', r));
  double.base = `http://127.0.0.1:${double.address().port}`;
  app = await startApp({ GITHUB_WEBHOOK_SECRET: 'whsec-test-value' });
  [alice, pat, kim] = await Promise.all(['alice', 'pat', 'kim'].map(w => as(app, w)));
});
after(async () => { await app?.close(); double?.close(); });
const findings = async (c, q = '') => (await c.get('/api/findings?limit=500&status=all' + q)).body.items;

function xlsx(rows) {
  const strings = [...new Set(rows.flat().map(String))];
  const cell = (v, ci, ri) => `<c r="${String.fromCharCode(65 + ci)}${ri + 1}" t="s"><v>${strings.indexOf(String(v))}</v></c>`;
  const sheet = `<worksheet><sheetData>${rows.map((r, ri) => `<row r="${ri + 1}">${r.map((v, ci) => cell(v, ci, ri)).join('')}</row>`).join('')}</sheetData></worksheet>`;
  const sst = `<sst>${strings.map(s => `<si><t>${s.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</t></si>`).join('')}</sst>`;
  return Buffer.from(zipSync({ 'xl/worksheets/sheet1.xml': strToU8(sheet), 'xl/sharedStrings.xml': strToU8(sst), 'xl/workbook.xml': strToU8('<workbook/>') })).toString('base64');
}

test('XLSX inventory import: preview, row errors, commit; zip bombs rejected', async () => {
  const content = xlsx([['ecosystem', 'name', 'version'], ['npm', 'left-pad', '1.3.0'], ['php', 'acme/x', ''], ['', '', '9']]);
  const pv = await pat.post('/api/projects/prj_tts/imports/preview', { filename: 'inventory.xlsx', encoding: 'base64', content, target: { kind: 'asset', identifier: 'xlsx-host', asset_kind: 'server' } });
  assert.equal(pv.status, 200, JSON.stringify(pv.body)); assert.equal(pv.body.format, 'xlsx'); assert.equal(pv.body.accepted, 2); assert.equal(pv.body.rejected, 1);
  assert.equal((await pat.post('/api/projects/prj_tts/imports/preview', { filename: 'inventory.xlsx', content, target: { kind: 'asset', identifier: 'x', asset_kind: 'server' } })).status, 400, 'base64 encoding required');
  const bomb = Buffer.from(zipSync({ 'xl/worksheets/sheet1.xml': strToU8('<worksheet>' + ' '.repeat(52 * 1024 * 1024) + '</worksheet>') }, { level: 9 })).toString('base64');
  const r = await pat.post('/api/projects/prj_tts/imports/preview', { filename: 'bomb.xlsx', encoding: 'base64', content: bomb, target: { kind: 'asset', identifier: 'x', asset_kind: 'server' } });
  assert.equal(r.status, 422); assert.match(r.body.message, /50 MB/);
  assert.equal((await pat.post('/api/projects/prj_tts/imports/preview', { filename: 'macro.xlsm', encoding: 'base64', content, target: { kind: 'asset', identifier: 'x', asset_kind: 'server' } })).status, 400);
});

test('CycloneDX VEX export maps applicability explicitly and is project-scoped', async () => {
  const r = await kim.req('GET', '/api/projects/prj_kiosk/vex.cdx.json');
  assert.equal(r.status, 200); assert.match(r.headers.get('content-type'), /cyclonedx/);
  const vex = r.body; assert.equal(vex.bomFormat, 'CycloneDX'); assert.equal(vex.specVersion, '1.5');
  const v3 = vex.vulnerabilities.find(v => v.id === 'SYNTH-2026-0003');
  assert.equal(v3.analysis.state, 'in_triage', 'under investigation → in_triage');
  assert.ok(v3.affects.every(a => a.ref.startsWith('pkg:maven/')));
  assert.ok(vex.metadata.properties.some(p => p.name === 'sentra:vex_mapping'));
  assert.equal((await pat.req('GET', '/api/projects/prj_kiosk/vex.cdx.json')).status, 404);
});

test('attack paths label verified and inferred edges, include identity and downstream assets, and show prerequisites', async () => {
  const ap = (await kim.get('/api/projects/prj_kiosk/attack-paths')).body;
  const p = ap.paths.find(x => x.hops.some(h => /search @ production/.test(h.to_label)) && x.hops.some(h => /SYNTH-2026-0005/.test(h.to_label)));
  assert.ok(p, 'path to search production finding');
  assert.equal(p.hops[0].kind, 'inferred'); assert.match(p.hops[0].basis, /Declared exposure/);
  assert.ok(p.hops.some(h => h.kind === 'verified' && /Deployment record/.test(h.basis)));
  assert.equal(p.prerequisites[0].status, 'not_met'); assert.equal(p.blocked_by_prerequisite, true);
  assert.ok(p.blast_radius.some(b => b.type === 'identity' && b.kind === 'verified'));
  assert.ok(p.blast_radius.some(b => b.type === 'downstream' && b.kind === 'inferred'));
  assert.ok(ap.edges.some(e => e.kind === 'verified' && e.to.startsWith('downstream:')));
});

test('editable priority and SLA policies: validation, versioning, re-scoring and business-hours calendars', async () => {
  assert.equal((await alice.post('/api/policies/priority', { definition: { thresholds: { P0: 10, P1: 50 } } })).status, 400, 'thresholds must descend');
  assert.equal((await alice.post('/api/policies/priority', { definition: { severity_points: { unknown: 1 } } })).status, 400, 'unknown may not score below low');
  assert.equal((await pat.post('/api/policies/priority', { definition: {} })).status, 403);
  const saved = await alice.post('/api/policies/priority', { definition: { exposure_points: { partner: 40 } } });
  assert.equal(saved.status, 200); const version = saved.body.version; assert.ok(version >= 2);
  const cal = { type: 'business', timezone: 'Asia/Ho_Chi_Minh', days: [1, 2, 3, 4, 5], start: '09:00', end: '18:00', holidays: [] };
  assert.equal((await alice.post('/api/policies/sla', { definition: { calendar: { ...cal, start: '18:00', end: '09:00' } } })).status, 400);
  assert.equal((await alice.post('/api/policies/sla', { definition: { calendar: cal } })).status, 200);
  await drainAll(app);
  const fs = (await findings(kim)).filter(f => f.status !== 'false_positive');
  const one = (await kim.get(`/api/findings/${fs[0].id}`)).body;
  assert.equal(one.priority_policy_version, version);
  assert.ok(one.priority_explanation.some(x => x.factor === 'exposure' && x.points === 40));
  const prodP1 = fs.find(f => f.is_production && f.priority !== 'P4' && f.sla_due_at);
  const d = (await kim.get(`/api/findings/${prodP1.id}`)).body;
  const hours = { P0: 48, P1: 168, P2: 720, P3: 2160 }[d.priority];
  assert.equal(new Date(d.sla_due_at).toISOString(), addBusinessHours(d.first_seen_at, hours, cal));
});

test('draft remediation PR: manifest bump rules, GitHub draft PR, finding stays open', async () => {
  assert.equal(bumpManifest('npm', '{"dependencies":{"a":"^1.0.0"}}', 'a', '1.2.3').change, 'dependencies.a: ^1.0.0 → ^1.2.3');
  assert.match(bumpManifest('npm', '{"dependencies":{}}', 'deep', '2.0.0').note, /transitive/);
  assert.throws(() => bumpManifest('composer', '{"require":{}}', 'acme/x', '1.0'), /parent/);
  assert.equal(bumpManifest('pypi', 'Django==4.2.1\nrequests>=2\n', 'django', '4.2.9').content, 'Django==4.2.9\nrequests>=2\n');
  assert.throws(() => bumpManifest('maven', '<dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version></dependency>', 'g:a', '2'), /property/);
  let prBody;
  routes.set('GET /repos/acme/tts', () => ({ json: { default_branch: 'main', full_name: 'acme/tts' } }));
  routes.set('GET /repos/acme/tts/git/ref/heads/main', () => ({ json: { object: { sha: 'c0ffee' } } }));
  routes.set('GET /repos/acme/tts/contents/composer.json', () => ({ json: { sha: 'f1', content: Buffer.from(JSON.stringify({ require: { 'acme/http-client': '^7.3' } })).toString('base64') } }));
  routes.set('POST /repos/acme/tts/git/refs', () => ({ status: 201, json: {} }));
  routes.set('PUT /repos/acme/tts/contents/composer.json', ({ body }) => { assert.match(Buffer.from(body.content, 'base64').toString(), /"acme\/http-client": "\^7\.4\.2"/); return { status: 200, json: {} }; });
  routes.set('POST /repos/acme/tts/pulls', ({ body }) => { prBody = body; return { status: 201, json: { html_url: 'https://github.example.invalid/acme/tts/pull/42', number: 42 } }; });
  const conn = await pat.post('/api/connections', { kind: 'github', name: 'tts repo', project_id: 'prj_tts', config: { owner: 'acme', repo: 'tts', api_base: double.base }, secret_value: 'gh-token-test' });
  assert.equal(conn.status, 200, JSON.stringify(conn.body));
  const f = (await findings(pat)).find(x => x.advisory_id === 'SYNTH-2026-0001' && x.environment === 'uat');
  const r = await pat.post(`/api/findings/${f.id}/draft-pr`, { connection_id: conn.body.id });
  assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.number, 42);
  assert.equal(prBody.draft, true); assert.match(prBody.body, new RegExp(`Sentra-Finding: ${f.id}`)); assert.match(prBody.body, /Regenerate the lockfile/);
  const after = (await pat.get(`/api/findings/${f.id}`)).body;
  assert.ok(after.pull_requests.some(p => p.state === 'draft' && p.source === 'sentra_draft'));
  assert.notEqual(after.status, 'verified_fixed');
  assert.ok(seen.find(s => s.path === '/repos/acme/tts/pulls').headers.authorization === 'Bearer gh-token-test');
});

test('Renovate PRs link to findings only when the target version is fixed; merge keeps the finding open', async () => {
  assert.deepEqual(parseRenovateTitle('fix(deps): update dependency acme/http-client to v7.4.2'), { pkg: 'acme/http-client', version: '7.4.2' });
  await pat.post('/api/projects/prj_tts/repositories', { provider: 'github', full_name: 'acme/tts' });
  const hook = async (payload, delivery) => {
    const raw = JSON.stringify(payload);
    return fetch(app.base + '/api/webhooks/github', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-GitHub-Event': 'pull_request', 'X-GitHub-Delivery': delivery, 'X-Hub-Signature-256': 'sha256=' + hmacHex('whsec-test-value', raw) }, body: raw }).then(r => r.json());
  };
  const pr = (title, action, merged = false) => ({ action, repository: { full_name: 'acme/tts' }, pull_request: { title, user: { login: 'renovate[bot]' }, head: { ref: 'renovate/acme-http-client' }, html_url: 'https://github.example.invalid/acme/tts/pull/77', merged, merged_at: merged ? new Date().toISOString() : null, merge_commit_sha: merged ? 'd'.repeat(40) : null, body: '' } });
  const still = await hook(pr('Update dependency acme/http-client to v7.3.5', 'opened'), 'd-1');
  assert.equal(still.linked, 0); assert.match(still.skipped[0].reason, /affected/);
  const ok = await hook(pr('Update dependency acme/http-client to v7.4.2', 'opened'), 'd-2');
  assert.ok(ok.linked >= 1);
  assert.equal((await hook(pr('Update dependency acme/http-client to v7.4.2', 'opened'), 'd-2')).duplicate, true, 'delivery replay ignored');
  await hook(pr('Update dependency acme/http-client to v7.4.2', 'closed', true), 'd-3');
  const prod = (await findings(pat)).find(x => x.advisory_id === 'SYNTH-2026-0001' && x.environment === 'production');
  const d = (await pat.get(`/api/findings/${prod.id}`)).body;
  assert.equal(d.status, 'fix_available'); assert.ok(d.pull_requests.some(p => p.source === 'renovate' && p.state === 'merged'));
});

test('Wazuh runtime packages produce distro- and architecture-aware findings', async () => {
  routes.set('POST /security/user/authenticate', ({ headers }) => (headers.authorization === 'Basic ' + Buffer.from('reader:wz-pass').toString('base64') ? { json: { data: { token: 'wz-jwt' } } } : { status: 401 }));
  routes.set('GET /agents', () => ({ json: { data: { total_affected_items: 2, affected_items: [{ id: '000', name: 'manager' }, { id: '007', name: 'batch-x86', ip: '10.0.0.7', os: { platform: 'amzn', major: '2023', version: '2023', arch: 'x86_64', name: 'Amazon Linux' } }] } } }));
  routes.set('GET /syscollector/007/packages', () => ({ json: { data: { affected_items: [{ name: 'acme-openssl-libs', version: '3.0.8-1.amzn2023.0.9', format: 'rpm', architecture: 'x86_64' }, { name: 'bash', version: '5.2.15-1.amzn2023.0.2', format: 'rpm' }] } } }));
  const c = await kim.post('/api/connections', { kind: 'wazuh', name: 'wazuh', project_id: 'prj_kiosk', config: { api_base: double.base, environment_id: 'production' }, secret_value: JSON.stringify({ user: 'reader', password: 'wz-pass' }) });
  assert.equal(c.body.test.ok, true, JSON.stringify(c.body));
  await kim.post(`/api/connections/${c.body.id}/sync`); await drainAll(app);
  const f = (await findings(kim)).find(x => x.advisory_id === 'SYNTH-2026-0004');
  assert.ok(f, 'x86_64 host is affected by the x86_64-only advisory (the arm64 TTS host was not)');
  assert.equal(f.observed_version, '3.0.8-1.amzn2023.0.9');
  assert.ok(!(await findings(pat)).some(x => x.advisory_id === 'SYNTH-2026-0004'));
});

test('DefectDojo findings are imported as linked references, not merged', async () => {
  routes.set('GET /api/v2/findings/', ({ headers }) => (headers.authorization !== 'Token dd-key' ? { status: 401 } : { json: { count: 2, next: null, results: [{ id: 501, title: 'Interpolation RCE', severity: 'Critical', active: true, verified: true, component_name: 'acme-commons-text', component_version: '1.9', vulnerability_ids: [{ vulnerability_id: 'SYNTH-2026-0003' }] }, { id: 502, title: 'Hardcoded password', severity: 'High', active: true, verified: false }] } }));
  const c = await kim.post('/api/connections', { kind: 'defectdojo', name: 'dojo', project_id: 'prj_kiosk', config: { api_base: double.base, product_id: '9' }, secret_value: 'dd-key' });
  assert.equal(c.body.test.ok, true);
  await kim.post(`/api/connections/${c.body.id}/sync`); await drainAll(app);
  const xf = (await kim.get('/api/projects/prj_kiosk/external-findings')).body;
  assert.equal(xf.length, 2);
  assert.ok(xf.find(x => x.external_id === '501').linked_finding_id);
  assert.equal(xf.find(x => x.external_id === '502').linked_finding_id, null);
});

test('SIEM channel sends to Splunk HEC with the collector token', async () => {
  let got;
  routes.set('POST /services/collector/event', ({ body, headers }) => { got = { body, headers }; return { json: { text: 'Success', code: 0 } }; });
  const ch = await alice.post('/api/channels', { kind: 'siem', name: 'splunk', url: double.base + '/services/collector/event', collector_token: 'hec-token-1', index: 'security' });
  assert.equal(ch.status, 200);
  const t = await alice.post(`/api/channels/${ch.body.id}/test`);
  assert.equal(t.body.outcome, 'accepted');
  assert.equal(got.headers.authorization, 'Splunk hec-token-1'); assert.equal(got.body.sourcetype, 'sentra:alert'); assert.equal(got.body.index, 'security');
  assert.ok(!JSON.stringify((await alice.get('/api/channels')).body).includes('hec-token-1'));
});

test('retention purges expired data and archives audit periods; the chain still verifies', async () => {
  await alice.patch('/api/org/settings', { retention_days: 30 });
  await app.db.query(`UPDATE audit_events SET created_at = now() - interval '60 days' WHERE org_id='org_demo' AND seq IN (SELECT seq FROM audit_events WHERE org_id='org_demo' ORDER BY seq LIMIT 5)`);
  // created_at participates in each event hash, so rewrite the first five as if they had been written 60 days ago
  const { sha256, stableStringify } = await import('../src/util.mjs');
  let prev = null;
  for (const r of await app.db.query(`SELECT * FROM audit_events WHERE org_id='org_demo' ORDER BY seq`)) {
    const row = { id: r.id, org_id: r.org_id, project_id: r.project_id, actor_id: r.actor_id, actor_type: r.actor_type, action: r.action, target_type: r.target_type, target_id: r.target_id, data: r.data, correlation_id: r.correlation_id, created_at: new Date(r.created_at).toISOString() };
    const hash = sha256((prev || 'genesis') + stableStringify(row));
    await app.db.query('UPDATE audit_events SET prev_hash=$2, hash=$3 WHERE seq=$1', [r.seq, prev, hash]); prev = hash;
  }
  await app.db.query(`UPDATE deliveries SET updated_at = now() - interval '60 days' WHERE org_id='org_demo'`);
  assert.equal((await alice.get('/api/org/audit/verify')).body.ok, true);
  const before = (await app.db.one(`SELECT count(*)::int AS n FROM audit_events WHERE org_id='org_demo'`)).n;
  const r = await runRetention(app, 'org_demo');
  assert.equal(r.deleted.audit_archived, 5); assert.ok(r.deleted.deliveries > 0);
  assert.equal((await app.db.one(`SELECT count(*)::int AS n FROM audit_events WHERE org_id='org_demo'`)).n, before - 5);
  const v = (await alice.get('/api/org/audit/verify')).body; assert.equal(v.ok, true); assert.ok(v.anchored_at_seq);
  const arc = await app.db.one(`SELECT * FROM audit_archives WHERE org_id='org_demo'`);
  const archived = JSON.parse((await app.objects.get(arc.object_key)).toString());
  assert.equal(archived.events.length, 5); assert.equal(archived.last_hash, arc.last_hash);
  assert.ok((await findings(alice)).length > 0, 'findings are never purged');
});

test('submitted-evidence analysis (handoff "Live AI analysis"): deterministic matches, redaction, no false safety', async () => {
  const leaked = 'ghp_' + 'Q'.repeat(30);
  const inv = await pat.post('/api/investigations', { workflow: 'evidence_analysis', project_id: 'prj_tts', question: 'Is this inventory affected?', evidence: { text: `ingest lambda inventory; token ${leaked}`, json: [{ ecosystem: 'npm', name: '@acme/xml-parser', version: '2.7.0' }, { ecosystem: 'npm', name: '@acme/xml-parser', version: '2.9.0' }] } });
  assert.equal(inv.status, 200, JSON.stringify(inv.body));
  await drainAll(app);
  const r = (await pat.get(`/api/investigations/${inv.body.id}`)).body;
  assert.equal(r.state, 'completed');
  assert.ok(r.result.claims.some(c => /2\.7\.0.*SYNTH-2026-0002: affected/.test(c.statement)));
  assert.ok(!r.result.claims.some(c => /2\.9\.0.*SYNTH-2026-0002/.test(c.statement)), '2.9.0 is outside the range');
  assert.ok(r.result.limitations.some(l => /not evidence of safety/.test(l)));
  const stored = await app.db.one('SELECT inputs FROM investigations WHERE id=$1', [inv.body.id]);
  assert.ok(!JSON.stringify(stored.inputs).includes(leaked), 'secret-shaped values are redacted before storage');
  assert.equal((await pat.post('/api/investigations', { workflow: 'evidence_analysis', project_id: 'prj_tts', evidence: {} })).status, 400);
});
