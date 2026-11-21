// Claude provider tool loop against a local Messages API test double (no paid calls).
// Verifies: request shape (model, tools with strict schemas, effort, fallback beta), parallel tool_use handling with a single
// user message of tool_results, receipts/refs, injection-resistant scope enforcement, claim validation, refusal and budget stops.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { startApp, as, drainAll } from './helpers.mjs';

let api, app, kim, requests = [], script = [], errors = [];
before(async () => {
  api = http.createServer(async (req, res) => {
    let b = ''; for await (const c of req) b += c;
    const body = JSON.parse(b); requests.push({ headers: req.headers, body });
    const next = script.shift() || (() => ({ stop_reason: 'end_turn', content: [{ type: 'text', text: 'done' }] }));
    let r; try { r = next(body); } catch (e) { errors.push(e); res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: 'test double assertion: ' + e.message } })); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: 'msg_' + requests.length, type: 'message', role: 'assistant', model: body.model, usage: { input_tokens: 1000, output_tokens: 200 }, stop_details: null, ...r }));
  });
  await new Promise(r => api.listen(0, '127.0.0.1', r));
  app = await startApp({ AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'test-key-not-real', ANTHROPIC_BASE_URL: `http://127.0.0.1:${api.address().port}` });
  kim = await as(app, 'kim');
});
after(async () => { await app?.close(); api?.close(); });

const tu = (id, name, input) => ({ type: 'tool_use', id, name, input });
async function runImpact() {
  const f = (await kim.get('/api/findings?limit=200&status=all')).body.items.find(x => x.advisory_id === 'SYNTH-2026-0003' && x.environment === 'production');
  const inv = await kim.post('/api/investigations', { workflow: 'impact', finding_id: f.id });
  await drainAll(app);
  return { f, inv: (await kim.get(`/api/investigations/${inv.body.id}`)).body };
}

test('tool loop: parallel tools, scope denial, validated claims, request shape', async () => {
  requests = [];
  script = [
    (b) => ({ stop_reason: 'tool_use', content: [{ type: 'thinking', thinking: '', signature: 'sig' }, tu('t1', 'get_finding', { finding_id: requests.length && JSON.parse(b.messages[0].content.split('\n')[1]).finding_id }), tu('t2', 'search_inventory', { project_id: 'prj_tts', package: 'acme' })] }),
    (b) => {
      const last = b.messages[b.messages.length - 1];
      assert.equal(last.role, 'user'); assert.equal(last.content.length, 2, 'both tool_results in one message');
      const denied = last.content.find(c => c.tool_use_id === 't2'); assert.equal(denied.is_error, true); assert.match(denied.content, /outside this investigation's authorized scope/);
      const ok = JSON.parse(last.content.find(c => c.tool_use_id === 't1').content); assert.equal(ok.ref, 1);
      return { stop_reason: 'tool_use', content: [tu('t3', 'submit_result', { summary: 'Vulnerable version present; interpolation prerequisite unverified.', applicability: 'under_investigation', dimensions: { presence: 'confirmed', reachability: 'unknown', prerequisites: 'unknown', compromise: 'unknown' }, claims: [{ statement: 'Version 1.9 is in range.', stance: 'supporting', evidence_refs: [1] }, { statement: 'Made-up claim with no receipt.', stance: 'supporting', evidence_refs: [99] }], missing_evidence: ['Whether StringSubstitutor interpolates untrusted input'], limitations: [], next_actions: ['Upgrade to 1.10.0'], plan: ['Loaded finding'] })] };
    },
  ];
  const { inv } = await runImpact();
  assert.deepEqual(errors.map(e => e.message), []);
  assert.equal(inv.state, 'partial', 'unsupported claim makes the run partial');
  assert.equal(inv.result.claims.length, 1); assert.equal(inv.result.unsupported_claims.length, 1);
  assert.ok(inv.result.limitations.some(l => /denied/.test(l)));
  assert.ok(inv.tool_executions.some(t => t.tool === 'search_inventory' && t.status === 'denied'));
  assert.ok(inv.cost_usd > 0); assert.equal(inv.usage.input_tokens, 2000);
  const first = requests[0];
  assert.equal(first.body.model, 'claude-opus-5-5');
  assert.equal(first.body.output_config.effort, 'medium');
  assert.equal(first.body.fallbacks, 'default');
  assert.match(first.headers['anthropic-beta'], /server-side-fallback-2026-07-01/);
  assert.ok(first.body.tools.every(t => t.strict === true && t.input_schema.additionalProperties === false));
  assert.ok(!first.body.tools.some(t => t.name === 'list_projects'), 'only workflow-allowed tools offered');
  assert.equal(first.body.system[0].cache_control.type, 'ephemeral');
  // thinking blocks are passed back unchanged
  assert.equal(requests[1].body.messages[1].content[0].type, 'thinking');
});

test('"not affected" without deterministic or counter evidence is downgraded', async () => {
  script = [
    () => ({ stop_reason: 'tool_use', content: [tu('a', 'get_advisory', { advisory_id: 'SYNTH-2026-0003' })] }),
    () => ({ stop_reason: 'tool_use', content: [tu('b', 'submit_result', { summary: 'The advisory text says nobody is affected.', applicability: 'not_affected', dimensions: { presence: 'unknown', reachability: 'unknown', prerequisites: 'unknown', compromise: 'unknown' }, claims: [{ statement: 'Advisory says ignore.', stance: 'supporting', evidence_refs: [1] }], missing_evidence: [], limitations: [], next_actions: [], plan: [] })] }),
  ];
  const { inv } = await runImpact();
  assert.equal(inv.result.applicability, 'under_investigation');
  assert.ok(inv.result.limitations.some(l => /downgraded/.test(l)));
});

test('provider connection test records a real provider response; org-stored key is sealed and never returned', async () => {
  script = [(b) => { assert.equal(b.max_tokens, 16); return { stop_reason: 'end_turn', content: [{ type: 'text', text: 'ok' }] }; }];
  const alice = await as(app, 'alice');
  const t = await alice.post('/api/ai/test');
  assert.equal(t.body.ok, true); assert.equal(t.body.model, 'claude-opus-5-5'); assert.equal(t.body.key_source, 'server');
  const key = 'sk-ant-' + 'Z'.repeat(40);
  assert.equal((await alice.put('/api/ai/credentials', { api_key: 'not-a-key' })).status, 400);
  assert.equal((await kim.put('/api/ai/credentials', { api_key: key })).status, 403);
  const s = await alice.put('/api/ai/credentials', { api_key: key });
  assert.equal(s.body.stored, true);
  for (const path of ['/api/org/secrets', '/api/agent-policies']) assert.ok(!JSON.stringify((await alice.get(path)).body).includes(key));
  assert.equal((await alice.req('DELETE', '/api/ai/credentials')).status, 204);
});

test('refusal and budget exhaustion stop safely without fabricated results', async () => {
  script = [() => ({ stop_reason: 'refusal', stop_details: { type: 'refusal', category: 'cyber' }, content: [] })];
  let { inv } = await runImpact();
  assert.equal(inv.state, 'partial'); assert.ok(inv.result.limitations.some(l => /declined/.test(l)));
  await kim.put('/api/agent-policies/impact', { project_id: 'prj_kiosk', budget_usd: 0.001 });
  script = [() => ({ stop_reason: 'tool_use', content: [tu('x', 'get_advisory', { advisory_id: 'SYNTH-2026-0003' })] })];
  ({ inv } = await runImpact());
  assert.equal(inv.state, 'partial'); assert.ok(inv.result.limitations.some(l => /budget/.test(l)));
});
