#!/usr/bin/env node
// Live connectivity check for the public intelligence feeds (no credentials needed): OSV.dev, CISA KEV, FIRST EPSS,
// The Hacker News RSS. Imports a small inventory of real, publicly known vulnerable package versions into a scratch
// project on an in-memory database, runs the real connector syncs over the network, and reports what came back.
// Nothing is written outside the in-memory database.
import { startApp, as, drainAll } from '../tests/helpers.mjs';
import { CONNECTORS, syncConnection, testConnection } from '../src/connectors/index.mjs';

const app = await startApp({ EXTERNAL_FEEDS: 'true' });
const alice = await as(app, 'alice');
const inventory = [
  { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },          // prototype pollution / command injection advisories (fixed 4.17.21)
  { ecosystem: 'maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1' }, // Log4Shell (CISA KEV listed)
  { ecosystem: 'pypi', name: 'django', version: '3.2.0' },
  { ecosystem: 'npm', name: 'lodash-not-a-real-package-xyz', version: '1.0.0' },
];
const imp = await alice.post('/api/projects/prj_tts/imports/commit', { filename: 'live.json', content: JSON.stringify(inventory), target: { kind: 'asset', identifier: 'live-feed-check-host', asset_kind: 'server', environment_id: 'production' } });
if (imp.status !== 200) throw new Error('import failed: ' + JSON.stringify(imp.body));
await drainAll(app);

const results = {};
for (const kind of ['osv', 'kev', 'epss', 'thn']) {
  const conn = await app.db.one('SELECT * FROM connections WHERE kind=$1', [kind]);
  const t0 = Date.now();
  const test = await testConnection(app, conn);
  let sync = null, error = null;
  try { sync = await syncConnection(app, await app.db.one('SELECT * FROM connections WHERE id=$1', [conn.id])); } catch (e) { error = e.message; }
  results[kind] = { test, sync, error, ms: Date.now() - t0 };
  await drainAll(app);
}
const advisories = await app.db.query(`SELECT a.id, a.severity, a.source, (SELECT json_agg(alias) FROM advisory_aliases al WHERE al.advisory_id=a.id) AS aliases FROM advisories a WHERE NOT a.is_synthetic ORDER BY a.id`);
const signals = await app.db.query(`SELECT advisory_id, kind, source, value FROM exploit_signals WHERE source IN ('cisa-kev','first-epss') ORDER BY kind, advisory_id`);
const findings = await app.db.query(`SELECT f.advisory_id, c.name, f.observed_version, f.fixed_version, f.priority, f.exploitation, f.applicability FROM findings f JOIN components c ON c.id=f.component_id JOIN advisories a ON a.id=f.advisory_id WHERE NOT a.is_synthetic ORDER BY f.priority, f.advisory_id`);
console.log(JSON.stringify({ at: new Date().toISOString(), connectors: Object.fromEntries(Object.entries(results).map(([k, v]) => [k, { test_ok: v.test.ok, test_detail: v.test.detail || v.test.error, sync: v.sync, error: v.error, ms: v.ms }])), real_advisories: advisories.length, sample_advisories: advisories.slice(0, 8), kev_signals: signals.filter(s => s.kind === 'kev').map(s => s.advisory_id), epss_scored: signals.filter(s => s.kind === 'epss').length, real_findings: findings.length, findings_sample: findings.slice(0, 12) }, null, 2));
await app.close();
