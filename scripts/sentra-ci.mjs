#!/usr/bin/env node
// Sentra CI client (zero dependencies, Node ≥18). Copy into your repository and pin by commit.
//   upload  --sbom <file> --service <key> --digest <sha256:..> --commit <sha> [--branch b] [--run-url u] [--project <id>] [--wait] [--fail-mode open|closed] [--timeout 120]
//   deploy  --service <key> --environment <key> --digest <sha256:..> [--project <id>] [--deployed-at ISO]
// Environment: SENTRA_URL, SENTRA_TOKEN (scoped CI token from the CI secret manager), SENTRA_PROJECT (default project id).
// Exit codes: 0 pass/warn · 1 policy fail · 2 Sentra unavailable/timeout (mapped to 0 when --fail-mode open) · 3 usage/input error.
import { readFile } from 'node:fs/promises';

const args = process.argv.slice(2); const cmd = args[0];
const opt = (k, d) => { const i = args.indexOf('--' + k); return i >= 0 ? (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true) : d; };
const vars = globalThis.process.env;
const base = (vars.SENTRA_URL || '').replace(/\/$/, ''); const token = vars.SENTRA_TOKEN;
const project = opt('project', vars.SENTRA_PROJECT);
const failMode = opt('fail-mode', 'open'); const timeoutS = Number(opt('timeout', 120));
const log = (...m) => console.error('[sentra]', ...m);
const usage = (m) => { log(m); process.exit(3); };
const unavailable = (m) => { log(`Sentra unavailable: ${m}. fail-mode=${failMode}`); if (vars.GITHUB_STEP_SUMMARY) appendSummary(`⚠️ Sentra unavailable (${m}); fail-mode ${failMode}.`); process.exit(failMode === 'closed' ? 2 : 0); };
async function appendSummary(md) { try { const { appendFile } = await import('node:fs/promises'); await appendFile(vars.GITHUB_STEP_SUMMARY, md + '\n'); } catch { /* not in GitHub Actions */ } }
async function call(method, path, body, extraHeaders = {}) {
  let res;
  try { res = await fetch(base + path, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...extraHeaders }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000) }); }
  catch (e) { unavailable(e.message); }
  const text = await res.text(); let j; try { j = JSON.parse(text); } catch { j = { message: text }; }
  if (res.status >= 500 || res.status === 429) unavailable(`HTTP ${res.status}`);
  if (res.status === 401 || res.status === 403) { log(`Rejected (${res.status}): ${j.message}`); process.exit(3); }
  if (!res.ok) { log(`Rejected (${res.status}): ${j.message}`); process.exit(3); }
  return { status: res.status, body: j };
}
if (!base || !token) usage('SENTRA_URL and SENTRA_TOKEN are required.');
if (!project) usage('--project or SENTRA_PROJECT is required.');

if (cmd === 'upload') {
  const file = opt('sbom'); if (!file) usage('--sbom required');
  const document = JSON.parse(await readFile(file, 'utf8'));
  const metadata = { project_id: project, service_id: opt('service'), environment_id: opt('environment') || undefined, commit_sha: opt('commit'), branch: opt('branch') || undefined, ci_run_url: opt('run-url') || undefined, application_version: opt('version') || undefined, artifact_digest: opt('digest'), source_timestamp: new Date().toISOString() };
  for (const k of ['service_id', 'commit_sha', 'artifact_digest']) if (!metadata[k]) usage(`missing --${k.replace('_id', '').replace('_sha', '').replace('artifact_', '')}`);
  const r = await call('POST', '/api/v1/ingestions/sbom', { metadata, document }, { 'Idempotency-Key': `${metadata.artifact_digest}:${metadata.commit_sha}` });
  log(`receipt ${r.body.ingestion_id} (${r.body.duplicate ? 'duplicate of earlier upload' : 'accepted'}), ${r.body.component_count} components`);
  if (!opt('wait')) process.exit(0);
  const deadline = Date.now() + timeoutS * 1000; let ing;
  while (Date.now() < deadline) { ing = (await call('GET', `/api/v1/ingestions/${r.body.ingestion_id}`)).body; if (['completed', 'failed', 'rejected'].includes(ing.status)) break; await new Promise(res => setTimeout(res, 2000)); }
  if (!ing || ing.status !== 'completed') unavailable(`ingestion not completed within ${timeoutS}s (status ${ing?.status})`);
  const ev = (await call('GET', ing.policy_evaluation_url)).body;
  const lines = [`### Sentra gate: ${ev.decision.toUpperCase()} (mode ${ev.mode})`, '', `${ev.summary.total_matches} advisory matches, ${ev.summary.new_matches} new vs. production baseline, ${ev.summary.blocking} blocking.`, ''];
  for (const v of ev.violations.slice(0, 20)) lines.push(`- ${v.excepted ? '~~' : ''}**${v.advisory_id}** ${v.package}@${v.version} (${v.severity}, ${v.exploitation})${v.fixed ? ' → fix ' + v.fixed : ''}${v.excepted ? '~~ (approved exception)' : ''}`);
  console.log(lines.join('\n')); await appendSummary(lines.join('\n'));
  process.exit(ev.exit_code);
} else if (cmd === 'deploy') {
  const body = { project_id: project, service_id: opt('service'), environment_id: opt('environment'), artifact_digest: opt('digest'), deployed_at: opt('deployed-at') || new Date().toISOString() };
  for (const k of ['service_id', 'environment_id', 'artifact_digest']) if (!body[k]) usage(`missing ${k}`);
  const r = await call('POST', '/api/v1/deployments', body);
  log(`deployment ${r.body.deployment_id} recorded${r.body.duplicate ? ' (already current)' : ''}`);
  process.exit(0);
} else usage('usage: sentra-ci.mjs upload|deploy …');
