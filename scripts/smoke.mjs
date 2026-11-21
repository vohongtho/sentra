// Developer smoke check: boot with an in-memory database, seed the synthetic demo, print pipeline results.
import { setQuiet } from '../src/log.mjs';
import { createApp } from '../src/app.mjs';
setQuiet(true);
const t = Date.now();
const app = await createApp({ SENTRA_ENV: 'test', AUTH_MODE: 'dev', SEED_DEMO: 'true', EXTERNAL_FEEDS: 'false', PGLITE_DIR: '' , DATABASE_URL: '' });
console.log('boot+seed ms', Date.now() - t);
const db = app.db;
console.table(await db.query(`SELECT f.advisory_id, c.name, f.observed_version, f.priority, f.applicability, f.exploitation, f.status, e.key AS env, s.key AS svc FROM findings f JOIN components c ON c.id=f.component_id LEFT JOIN environments e ON e.id=f.environment_id LEFT JOIN services s ON s.id=f.service_id ORDER BY f.priority, f.advisory_id`));
console.table(await db.query('SELECT trigger, left(title, 90) AS title, state, occurrences FROM alerts'));
console.table(await db.query('SELECT type, status, count(*)::int AS n, max(last_error) AS err FROM jobs GROUP BY type, status ORDER BY type'));
console.table(await db.query('SELECT provider, external_id, mapped_state FROM tickets'));
console.table(await db.query('SELECT d.status, c.kind, d.attempts, d.last_error FROM deliveries d JOIN channels c ON c.id=d.channel_id'));
await db.close();
