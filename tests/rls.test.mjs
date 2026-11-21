// Row-level security (defense in depth). Runs only against real PostgreSQL (TEST_DATABASE_URL), as a non-superuser.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startApp, as } from './helpers.mjs';

const pgMode = !!globalThis.process.env.TEST_DATABASE_URL;
let app;
before(async () => {
  if (!pgMode) return;
  app = await startApp();
  await app.db.query(`INSERT INTO organizations (id, slug, name) VALUES ('org_other','other','Other org')`);
  await app.db.query(`INSERT INTO projects (id, org_id, key, name) VALUES ('prj_other','org_other','secret-proj','Other org project')`);
  await app.db.query(`INSERT INTO findings (id, org_id, project_id, advisory_id, component_id, dedupe_key, root_cause_key, severity, priority)
    SELECT 'fnd_other', 'org_other', 'prj_other', advisory_id, component_id, 'other-key', root_cause_key, severity, priority FROM findings LIMIT 1`);
});
after(async () => { await app?.close(); });

test('scoped connections cannot read or write another organization\'s rows, even with raw SQL', { skip: !pgMode && 'requires TEST_DATABASE_URL' }, async () => {
  const s = app.db.scoped('org_demo');
  try {
    const projects = (await s.query('SELECT org_id FROM projects')).map(r => r.org_id);
    assert.ok(projects.length >= 2 && projects.every(o => o === 'org_demo'));
    assert.equal((await s.query(`SELECT * FROM findings WHERE id='fnd_other'`)).length, 0);
    await assert.rejects(() => s.query(`INSERT INTO projects (id, org_id, key, name) VALUES ('prj_x','org_other','x','x')`), /row-level security/);
    assert.equal((await s.query(`UPDATE projects SET name='pwned' WHERE id='prj_other' RETURNING id`)).length, 0);
  } finally { await s.release(); }
  // unscoped (worker) connections still see everything; the setting does not leak back into the pool
  const all = (await app.db.query('SELECT DISTINCT org_id FROM projects')).map(r => r.org_id).sort();
  assert.deepEqual(all, ['org_demo', 'org_other']);
});

test('API requests run on scoped connections', { skip: !pgMode && 'requires TEST_DATABASE_URL' }, async () => {
  const alice = await as(app, 'alice');
  const r = await alice.get('/api/findings?status=all&limit=500');
  assert.ok(r.body.items.every(f => f.project_id !== 'prj_other'));
  assert.equal((await alice.get('/api/projects/prj_other')).status, 404);
});
