// Application assembly: config → crypto → database (+migrations) → object store → handlers → router.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.mjs';
import { initCrypto } from './crypto.mjs';
import { createDb, migrate } from './db.mjs';
import { createObjectStore } from './storage.mjs';
import { Router, createServer } from './http/server.mjs';
import { registerAuthRoutes, makeAuthenticator } from './auth/auth.mjs';
import { registerCore } from './api/core.mjs';
import { registerSecurity } from './api/security.mjs';
import { registerOps } from './api/ops.mjs';
import { registerAll } from './jobs/handlers.mjs';
import { startBackground } from './jobs/runtime.mjs';
import { seedDemo } from './seed.mjs';
import { log } from './log.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
let handlersRegistered = false;

export async function createApp(overrides = {}) {
  const cfg = loadConfig(overrides);
  initCrypto(cfg);
  const db = await createDb(cfg);
  await migrate(db);
  const objects = await createObjectStore(cfg);
  if (!handlersRegistered) { registerAll(); handlersRegistered = true; }
  const app = { cfg, db, objects };
  const router = new Router();
  registerAuthRoutes(router, app);
  registerCore(router);
  registerSecurity(router);
  registerOps(router);
  router.get('/api/openapi.json', async () => openapi(router), { public: true });
  app.router = router;
  app.server = createServer(app, router, { publicDir: path.join(here, '..', 'public'), authenticate: makeAuthenticator(app) });
  if (cfg.seedDemo && !(await db.one('SELECT 1 FROM organizations LIMIT 1'))) { log.info('seeding_demo', {}); await seedDemo(app); }
  app.start = () => { app.stopBackground = startBackground(app); return new Promise(res => app.server.listen(cfg.port, () => { log.info('listening', { port: cfg.port, origin: cfg.appOrigin, db: db.kind, auth: cfg.authMode, ai: cfg.ai.provider }); res(); })); };
  app.stop = async () => { app.stopBackground?.(); await new Promise(r => app.server.close(() => r())); await db.close(); };
  return app;
}

function openapi(router) {
  const paths = {};
  for (const r of router.routes) {
    const p = r.re.source.replace(/^\^/, '').replace(/\/\?\$$/, '').replace(/\\\//g, '/');
    let i = 0; const path2 = p.replace(/\(\[\^\/\]\+\)/g, () => `{${r.keys[i++]}}`);
    paths[path2] = paths[path2] || {};
    paths[path2][r.method.toLowerCase()] = { security: r.opts.public ? [] : r.opts.ci ? [{ ciToken: [] }, { session: [] }] : [{ session: [] }], ...(r.opts.ci ? { tags: ['ci-v1'] } : {}) };
  }
  return { openapi: '3.1.0', info: { title: 'Sentra API', version: '1.0.0', description: 'Detailed request/response contracts for /api/v1 are in docs/openapi-v1.yaml.' }, components: { securitySchemes: { session: { type: 'apiKey', in: 'cookie', name: 'sentra_sid', description: 'Keycloak BFF session; mutations require X-CSRF-Token.' }, ciToken: { type: 'http', scheme: 'bearer', description: 'Scoped, expiring CI token (stk_...).' } } }, paths };
}
