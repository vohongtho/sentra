#!/usr/bin/env node
// Agent evaluation: runs labeled impact cases (fixtures/agent-eval.json) through the configured provider on a fresh
// in-memory synthetic portfolio, and reports accuracy, unsupported claims, missed prerequisites, cost and latency.
//   node scripts/eval-agents.mjs                         # offline deterministic planner (free)
//   AI_PROVIDER=anthropic ANTHROPIC_API_KEY=... node scripts/eval-agents.mjs   # Claude (billed; run deliberately)
// Re-run whenever models, prompts, tools or policies change. An agent reviewing another agent is not independent proof.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { startApp, as, drainAll } from '../tests/helpers.mjs';

const ds = JSON.parse(await readFile(new URL('../fixtures/agent-eval.json', import.meta.url), 'utf8'));
const overrides = {}; const v = globalThis.process.env;
if (v.AI_PROVIDER) overrides.AI_PROVIDER = v.AI_PROVIDER;
if (v.ANTHROPIC_API_KEY) overrides.ANTHROPIC_API_KEY = v.ANTHROPIC_API_KEY;
const app = await startApp(overrides);
const sam = await as(app, 'sam');
const all = (await sam.get('/api/findings?limit=500&status=all')).body.items;
const rows = [];
for (const c of ds.cases) {
  const f = all.find(x => x.advisory_id === c.advisory && x.project_key === c.project && x.service === c.service && x.environment === c.environment);
  if (!f) { rows.push({ id: c.id, error: 'finding not found' }); continue; }
  const t0 = Date.now();
  const inv = await sam.post('/api/investigations', { workflow: 'impact', finding_id: f.id });
  await drainAll(app);
  const r = (await sam.get(`/api/investigations/${inv.body.id}`)).body;
  const res = r.result || {};
  const text = JSON.stringify([res.missing_evidence, res.claims, res.limitations]);
  const checks = {
    applicability: c.expect.applicability.includes(res.applicability),
    presence: !c.expect.presence || res.dimensions?.presence === c.expect.presence,
    prerequisites: !c.expect.prerequisites || res.dimensions?.prerequisites === c.expect.prerequisites,
    missing_prereq_reported: !c.expect.must_mention_missing || text.includes(c.expect.must_mention_missing),
    never: !c.expect.never || res.applicability !== c.expect.never,
  };
  rows.push({ id: c.id, label: c.label, got: res.applicability, state: r.state, pass: Object.values(checks).every(Boolean), checks, unsupported_claims: (res.unsupported_claims || []).length, claims: (res.claims || []).length, tool_calls: r.tool_executions.length, denied: r.tool_executions.filter(t => t.status === 'denied').length, cost_usd: Number(r.cost_usd || 0), latency_ms: Date.now() - t0, model: r.model });
}
await app.close();
const summary = { dataset: ds.version, provider: rows[0]?.model, cases: rows.length, passed: rows.filter(r => r.pass).length, applicability_accuracy: rows.filter(r => r.checks?.applicability).length / rows.length, unsupported_claims: rows.reduce((s, r) => s + (r.unsupported_claims || 0), 0), missed_prerequisites: rows.filter(r => r.checks && (!r.checks.missing_prereq_reported || !r.checks.prerequisites)).length, total_cost_usd: rows.reduce((s, r) => s + (r.cost_usd || 0), 0), median_latency_ms: rows.map(r => r.latency_ms).sort((a, b) => a - b)[Math.floor(rows.length / 2)], at: new Date().toISOString() };
console.table(rows.map(({ checks, ...r }) => r));
console.log(JSON.stringify(summary, null, 2));
await mkdir(new URL('../docs/eval/', import.meta.url), { recursive: true });
await writeFile(new URL(`../docs/eval/latest-${(summary.provider || 'unknown').replace(/[^\w.-]/g, '_')}.json`, import.meta.url), JSON.stringify({ summary, rows }, null, 2));
process.exit(summary.passed === summary.cases ? 0 : 1);
