#!/usr/bin/env node
// Post-restore verification: boot against a restored database (no seeding), check migrations, audit hash chains,
// queue state and that the scheduler/worker can resume.  Usage: node scripts/verify-restore.mjs <database-url>
import { setQuiet } from '../src/log.mjs';
import { createApp } from '../src/app.mjs';
import { verifyAuditChain } from '../src/audit.mjs';
import { schedulerTick, drain } from '../src/jobs/runtime.mjs';
setQuiet(true);
const url = process.argv[2];
if (!url) { console.error('usage: verify-restore.mjs <database-url>'); process.exit(2); }
const app = await createApp({ DATABASE_URL: url, SEED_DEMO: 'false', RUN_WORKERS: 'false', RUN_SCHEDULER: 'false', EXTERNAL_FEEDS: 'false', SENTRA_ENV: 'test' });
const orgs = await app.db.query('SELECT id FROM organizations');
const chains = {}; for (const o of orgs) chains[o.id] = await verifyAuditChain(app.db, o.id);
const counts = await app.db.one(`SELECT (SELECT count(*)::int FROM findings) AS findings, (SELECT count(*)::int FROM inventory_snapshots) AS snapshots, (SELECT count(*)::int FROM jobs WHERE status IN ('queued','running')) AS active_jobs, (SELECT count(*)::int FROM outbox WHERE processed_at IS NULL) AS pending_outbox`);
const tick = await schedulerTick(app); const ran = await drain(app);
console.log(JSON.stringify({ migrations: (await app.db.query('SELECT name FROM schema_migrations ORDER BY name')).map(r => r.name), audit_chains: chains, counts, scheduler_tick: tick, jobs_run_after_restore: ran }, null, 2));
await app.db.close();
process.exit(Object.values(chains).every(c => c.ok) ? 0 : 1);
