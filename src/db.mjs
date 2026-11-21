// Database access: PostgreSQL via `pg` when DATABASE_URL is set; embedded PGlite (PostgreSQL compiled to WASM)
// otherwise. Both use $1-style parameters and identical SQL, so migrations and queries are shared.
import { readdir, readFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { log } from './log.mjs';
const here = path.dirname(fileURLToPath(import.meta.url));

export async function createDb(cfg) {
  if (cfg.databaseUrl) {
    const pg = (await import('pg')).default;
    pg.types.setTypeParser(1700, v => (v == null ? null : Number(v)));
    pg.types.setTypeParser(20, v => (v == null ? null : Number(v)));
    const pool = new pg.Pool({ ...(cfg.databaseUrl === 'pg-env' ? {} : { connectionString: cfg.databaseUrl }), max: Number(process.env.DB_POOL_MAX || 20) });
    // node-postgres encodes JS arrays as Postgres array literals. Arrays containing objects are always JSONB payloads
    // here, so they are sent as JSON; arrays of primitives stay native for `= ANY($1)` filters.
    const norm = (p) => p.map(v => (Array.isArray(v) && v.some(x => x !== null && typeof x === 'object') ? JSON.stringify(v) : v));
    const wrap = (q) => ({ kind: 'postgres', query: async (s, p = []) => (await q.query(s, norm(p))).rows, one: async (s, p = []) => (await q.query(s, norm(p))).rows[0] || null });
    const db = {
      ...wrap(pool),
      async tx(fn) {
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          const t = wrap(client); t.tx = (f) => f(t);
          const res = await fn(t);
          await client.query('COMMIT');
          return res;
        } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; } finally { client.release(); }
      },
      exec: async (sql) => { await pool.query(sql); },
      close: () => pool.end(),
      /**
       * Request-scoped handle: one pooled connection with app.org_id set, so row-level security hides other tenants'
       * rows from every query made with it. Call release() when the request ends (the HTTP layer does this).
       */
      scoped(orgId) {
        let clientP = null;
        const get = () => (clientP ??= pool.connect().then(async (c) => { await c.query(`SELECT set_config('app.org_id', $1, false)`, [orgId]); return c; }));
        const s = {
          kind: 'postgres', orgId,
          query: async (sql, p = []) => (await (await get()).query(sql, norm(p))).rows,
          one: async (sql, p = []) => (await (await get()).query(sql, norm(p))).rows[0] || null,
          async tx(fn) {
            const c = await get();
            await c.query('BEGIN');
            try { const t = wrap(c); t.tx = (f) => f(t); const r = await fn(t); await c.query('COMMIT'); return r; }
            catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
          },
          async release() {
            if (!clientP) return;
            const c = await clientP; clientP = null;
            try { await c.query(`RESET app.org_id`); c.release(); } catch (e) { c.release(e); }
          },
        };
        return s;
      },
    };
    return db;
  }
  const { PGlite } = await import('@electric-sql/pglite');
  if (cfg.pgliteDir) await mkdir(cfg.pgliteDir, { recursive: true });
  const pgl = cfg.pgliteDir ? new PGlite(cfg.pgliteDir) : new PGlite();
  await pgl.waitReady;
  // PGlite has one connection. A promise-chain mutex serializes statements/transactions so concurrent
  // requests cannot interleave inside a transaction. Nested tx() calls on the tx handle reuse it.
  let chain = Promise.resolve();
  const lock = (fn) => { const run = chain.then(fn, fn); chain = run.catch(() => {}); return run; };
  const norm = (rows) => rows.map(r => { for (const k in r) if (typeof r[k] === 'bigint') r[k] = Number(r[k]); return r; });
  const db = {
    kind: 'pglite',
    query: (s, p = []) => lock(async () => norm((await pgl.query(s, p)).rows)),
    async one(s, p) { return (await db.query(s, p))[0] || null; },
    tx: (fn) => lock(() => pgl.transaction(async (t) => {
      const tq = { kind: 'pglite', query: async (s, p = []) => norm((await t.query(s, p)).rows) };
      tq.one = async (s, p) => (await tq.query(s, p))[0] || null;
      tq.tx = (f) => f(tq);
      return fn(tq);
    })),
    exec: (sql) => lock(() => pgl.exec(sql)),
    close: () => pgl.close(),
    // PGlite runs as a superuser, which always bypasses row-level security; application authorization still applies.
    scoped: () => Object.assign(Object.create(db), { release: async () => {} }),
  };
  return db;
}

export async function migrate(db) {
  const dir = path.join(here, '..', 'migrations');
  const files = (await readdir(dir)).filter(f => f.endsWith('.sql')).sort();
  if (db.kind === 'postgres') {
    // Several processes (API, workers) may start at once: one transaction holding an advisory lock applies migrations;
    // the others wait, then see them as applied.
    await db.tx(async (t) => {
      await t.query(`SELECT pg_advisory_xact_lock(hashtext('sentra:migrations'))`);
      await t.query(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
      const done = new Set((await t.query('SELECT name FROM schema_migrations')).map(r => r.name));
      for (const f of files) {
        if (done.has(f)) continue;
        await t.query(await readFile(path.join(dir, f), 'utf8'));
        await t.query('INSERT INTO schema_migrations(name) VALUES ($1)', [f]);
        log.info('migration_applied', { name: f });
      }
    });
    return;
  }
  await db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  const done = new Set((await db.query('SELECT name FROM schema_migrations')).map(r => r.name));
  for (const f of files) {
    if (done.has(f)) continue;
    const sql = await readFile(path.join(dir, f), 'utf8');
    await db.exec(`BEGIN;\n${sql}\nINSERT INTO schema_migrations(name) VALUES ('${f.replace(/'/g, "''")}');\nCOMMIT;`);
    log.info('migration_applied', { name: f });
  }
}
