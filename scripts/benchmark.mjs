#!/usr/bin/env node
// Representative load benchmark. Creates P projects × S services × 2 environments, each artifact with C components,
// A advisories whose ranges hit a fraction of packages; measures ingestion+matching, finding queries and dashboard.
//   node scripts/benchmark.mjs [projects=10] [components=300] [advisories=200]
//   TEST_DATABASE_URL=postgres://... node scripts/benchmark.mjs   # against PostgreSQL
import { startApp, as, drainAll } from '../tests/helpers.mjs';
import { upsertAdvisory } from '../src/services/advisories.mjs';
import { acceptSbom, recordDeployment } from '../src/services/ingestion.mjs';
import { cdx, digest } from '../src/seed.mjs';

const [P = 10, C = 300, A = 200] = process.argv.slice(2).map(Number);
const S = 4;
const app = await startApp({ SEED_DEMO: 'true' });
const sys = { db: app.db, cfg: app.cfg, orgId: 'org_demo', actorType: 'system', systemActor: 'bench', orgRole: 'org_admin', projectRoles: new Map() };
const t = {}; const time = async (k, fn) => { const s = performance.now(); const r = await fn(); t[k] = Math.round(performance.now() - s); return r; };

await time('setup_projects_ms', async () => {
  for (let p = 0; p < P; p++) {
    const pid = `prj_b${p}`;
    await app.db.query(`INSERT INTO projects (id, org_id, key, name, owner_identity_id) VALUES ($1,'org_demo',$2,$3,'idn_sam')`, [pid, `bench-${p}`, `Bench ${p}`]);
    for (let s = 0; s < S; s++) await app.db.query(`INSERT INTO services (id, org_id, project_id, key, name) VALUES ($1,'org_demo',$2,$3,$3)`, [`svc_b${p}_${s}`, pid, `svc${s}`]);
    for (const [e, prod] of [['uat', false], ['production', true]]) await app.db.query(`INSERT INTO environments (id, org_id, project_id, key, name, is_production) VALUES ($1,'org_demo',$2,$3,$3,$4)`, [`env_b${p}_${e}`, pid, e, prod]);
  }
});
await time('advisories_ms', () => app.db.tx(async (tx) => { for (let a = 0; a < A; a++) await upsertAdvisory(tx, { id: `SYNTH-BENCH-${a}`, summary: '[SYNTHETIC] bench', modified: '2026-11-01T00:00:00Z', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }], affected: [{ package: { ecosystem: 'npm', name: `bench-pkg-${a * 3}` }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] }, { orgId: 'org_demo' }); }));
await drainAll(app);
const comps = (p, s) => Array.from({ length: C }, (_, i) => ({ name: `bench-pkg-${(i + p * 7 + s * 13) % (C * 2)}`, version: `1.${i % 10}.0`, purl: `pkg:npm/bench-pkg-${(i + p * 7 + s * 13) % (C * 2)}@1.${i % 10}.0` }));
await time('ingest_and_deploy_ms', async () => {
  for (let p = 0; p < P; p++) for (let s = 0; s < S; s++) {
    const dg = digest(`bench/${p}/${s}`);
    await acceptSbom(app, sys, { metadata: { project_id: `prj_b${p}`, service_id: `svc${s}`, commit_sha: 'f'.repeat(40), artifact_digest: dg, source_timestamp: new Date().toISOString() }, document: cdx(`b${p}s${s}`, '1.0.0', comps(p, s)) });
  }
  await drainAll(app);
  for (let p = 0; p < P; p++) for (let s = 0; s < S; s++) for (const e of ['uat', 'production']) await recordDeployment(app, sys, { project_id: `prj_b${p}`, service_id: `svc${s}`, environment_id: e, artifact_digest: digest(`bench/${p}/${s}`), deployed_at: new Date().toISOString() });
  await drainAll(app);
});
const counts = await app.db.one(`SELECT (SELECT count(*)::int FROM findings) AS findings, (SELECT count(*)::int FROM observations) AS observations, (SELECT count(*)::int FROM components) AS components`);
const sam = await as(app, 'sam');
await time('findings_list_p95_ms', async () => { const ls = []; for (let i = 0; i < 20; i++) { const s = performance.now(); await sam.get('/api/findings?limit=50&priority=P1,P2&offset=' + i * 50); ls.push(performance.now() - s); } ls.sort((a, b) => a - b); return ls; }).then(ls => { t.findings_list_p95_ms = Math.round(ls[18]); });
await time('dashboard_ms', () => sam.get('/api/dashboard/portfolio'));
await time('advisory_revision_reassess_ms', async () => { await upsertAdvisory(app.db, { id: 'SYNTH-BENCH-0', summary: 'rev', modified: '2026-11-02T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: 'bench-pkg-0' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.5.0' }, { fixed: '2.0.0' }] }] }] }, { orgId: 'org_demo' }); await drainAll(app); });
const result = { database: app.db.kind, projects: P, services_per_project: S, environments: 2, components_per_artifact: C, advisories: A, ...counts, timings: t, node: process.version, at: new Date().toISOString() };
console.log(JSON.stringify(result, null, 2));
await app.close();
