import http from 'node:http';
import { setQuiet } from '../src/log.mjs';
import { createApp } from '../src/app.mjs';
import { drain } from '../src/jobs/runtime.mjs';
setQuiet(true);

let portSeq = 19000 + Math.floor(Math.random() * 2000);
// Set TEST_DATABASE_URL (e.g. postgres://postgres@127.0.0.1:55432/postgres) to run against real PostgreSQL;
// each app instance gets its own fresh database. Otherwise embedded PGlite (in-memory) is used.
async function freshDatabase() {
  const admin = globalThis.process.env.TEST_DATABASE_URL;
  if (!admin) return '';
  const pg = (await import('pg')).default;
  const name = 'sentra_test_' + Math.random().toString(36).slice(2, 10);
  // The application connects as a non-superuser that owns the database, as in production: superusers bypass RLS.
  const c = new pg.Client({ connectionString: admin }); await c.connect();
  await c.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sentra_app') THEN CREATE ROLE sentra_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$`);
  await c.query(`CREATE DATABASE ${name} OWNER sentra_app`); await c.end();
  const u = new URL(admin); u.pathname = '/' + name; u.username = 'sentra_app'; u.password = ''; return u.toString();
}
export async function startApp(overrides = {}) {
  const port = portSeq++;
  const dbUrl = await freshDatabase();
  const app = await createApp({ SENTRA_ENV: 'test', AUTH_MODE: 'dev', SEED_DEMO: 'true', EXTERNAL_FEEDS: 'false', RUN_WORKERS: 'false', RUN_SCHEDULER: 'false', ALLOW_PRIVATE_WEBHOOK_TARGETS: 'true', PORT: String(port), APP_ORIGIN: `http://127.0.0.1:${port}`, DATABASE_URL: dbUrl, PGLITE_DIR: '', OBJECT_STORE_DIR: '', ...overrides });
  await new Promise(r => app.server.listen(port, '127.0.0.1', r));
  app.base = `http://127.0.0.1:${port}`;
  app.drain = () => drain(app);
  app.close = async () => { await new Promise(r => app.server.close(r)); await app.db.close(); };
  return app;
}

export class Client {
  constructor(app) { this.app = app; this.cookie = ''; this.csrf = ''; }
  async login(identityId) {
    const r = await fetch(this.app.base + '/api/auth/dev/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ identity_id: identityId }) });
    if (!r.ok) throw new Error('login failed ' + r.status);
    this.cookie = r.headers.get('set-cookie').split(';')[0]; this.csrf = (await r.json()).csrf_token; return this;
  }
  async req(method, path, body, { headers = {}, csrf = true } = {}) {
    const h = { ...headers }; if (this.cookie) h.Cookie = this.cookie; if (body !== undefined) h['Content-Type'] = 'application/json'; if (csrf && method !== 'GET' && this.csrf) h['X-CSRF-Token'] = this.csrf;
    const r = await fetch(this.app.base + path, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined, redirect: 'manual' });
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { json = text; }
    return { status: r.status, body: json, headers: r.headers };
  }
  get(p) { return this.req('GET', p); } post(p, b = {}, o) { return this.req('POST', p, b, o); } put(p, b = {}) { return this.req('PUT', p, b); } patch(p, b = {}) { return this.req('PATCH', p, b); }
}
export const as = async (app, who) => new Client(app).login('idn_' + who);

/** Local HTTP receiver whose first `failFirst` requests return 500. */
export async function receiver(failFirst = 0) {
  const got = [];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', c => (b += c)); req.on('end', () => { got.push({ headers: req.headers, body: b, url: req.url, method: req.method }); if (got.length <= failFirst) { res.writeHead(500); res.end('boom'); } else { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(srv.respond ? JSON.stringify(srv.respond(req, b)) : '{"ok":true}'); } }); });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  srv.url = `http://127.0.0.1:${srv.address().port}`; srv.got = got;
  return srv;
}
/** Run due jobs; jobs scheduled in the future (backoff) are pulled forward to simulate time passing. */
export async function drainAll(app, rounds = 6) {
  for (let i = 0; i < rounds; i++) { await app.drain(); await app.db.query(`UPDATE jobs SET run_after=now() WHERE status='queued'`); }
  await app.drain();
}
