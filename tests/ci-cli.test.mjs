// GitHub Actions path: drive scripts/sentra-ci.mjs as a subprocess (as the workflow does) against a running server.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFile, mkdtemp } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { startApp, as } from './helpers.mjs';
import { cdx, digest, P } from '../src/seed.mjs';
import { startBackground } from '../src/jobs/runtime.mjs';

let app, stop, token, dir;
before(async () => {
  app = await startApp({ WORKER_POLL_MS: '100' });
  app.cfg.runWorkers = true; stop = startBackground(app);
  const pat = await as(app, 'pat');
  token = (await pat.post('/api/projects/prj_tts/ci-tokens', { name: 'gha', expires_in_days: 1 })).body.token;
  await pat.post('/api/policies/gate', { project_id: 'prj_tts', mode: 'block_new', fail_mode: 'closed', block_on: { min_severity: 'high', only_new: true } });
  dir = await mkdtemp(path.join(os.tmpdir(), 'sentra-ci-'));
});
after(async () => { stop?.(); await app?.close(); });

function run(args, env = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, ['scripts/sentra-ci.mjs', ...args], { env: { PATH: '', SENTRA_URL: app.base, SENTRA_TOKEN: token, SENTRA_PROJECT: 'prj_tts', GITHUB_STEP_SUMMARY: path.join(dir, 'summary.md'), ...env } });
    let out = '', err = ''; p.stdout.on('data', d => (out += d)); p.stderr.on('data', d => (err += d));
    p.on('close', code => resolve({ code, out, err }));
  });
}

test('passing build exits 0 and writes a job summary', async () => {
  const f = path.join(dir, 'ok.json'); await writeFile(f, JSON.stringify(cdx('tts-api', '2.5.0', [P.acmeHttp('7.4.2')])));
  const r = await run(['upload', '--sbom', f, '--service', 'api', '--digest', digest('ci/2.5.0'), '--commit', 'c'.repeat(40), '--wait', '--timeout', '30']);
  assert.equal(r.code, 0, r.err); assert.match(r.out, /PASS/);
});
test('new high-severity violation fails the build with exit code 1 (block_new)', async () => {
  const f = path.join(dir, 'bad.json'); await writeFile(f, JSON.stringify(cdx('tts-api', '2.6.0', [P.acmeHttp('7.3.0'), P.xml('2.7.0')])));
  const r = await run(['upload', '--sbom', f, '--service', 'api', '--digest', digest('ci/2.6.0'), '--commit', 'd'.repeat(40), '--wait', '--timeout', '30']);
  assert.equal(r.code, 1, r.err + r.out); assert.match(r.out, /FAIL/); assert.match(r.out, /SYNTH-2026-0002/); assert.doesNotMatch(r.out, /SYNTH-2026-0001/, 'already in production baseline, not new');
});
test('unavailable Sentra honours explicit fail mode', async () => {
  const f = path.join(dir, 'ok.json');
  const open = await run(['upload', '--sbom', f, '--service', 'api', '--digest', digest('x'), '--commit', 'e'.repeat(40), '--wait', '--fail-mode', 'open'], { SENTRA_URL: 'http://127.0.0.1:1' });
  assert.equal(open.code, 0); assert.match(open.err, /unavailable/);
  const closed = await run(['upload', '--sbom', f, '--service', 'api', '--digest', digest('x'), '--commit', 'e'.repeat(40), '--wait', '--fail-mode', 'closed'], { SENTRA_URL: 'http://127.0.0.1:1' });
  assert.equal(closed.code, 2);
});
test('invalid token is a hard error, deployment recording works', async () => {
  assert.equal((await run(['deploy', '--service', 'api', '--environment', 'uat', '--digest', digest('ci/2.5.0')], { SENTRA_TOKEN: 'stk_invalid' })).code, 3);
  const r = await run(['deploy', '--service', 'api', '--environment', 'uat', '--digest', digest('ci/2.5.0')]);
  assert.equal(r.code, 0, r.err); assert.match(r.err, /deployment dep_/);
});
