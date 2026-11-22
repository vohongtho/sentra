// ANTHROPIC_AUTH_TOKEN (OAuth bearer for a Claude Console org) as an alternative to an API key, against a local test double.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { startApp, as } from './helpers.mjs';

const seen = [];
const api = http.createServer(async (req, res) => {
  let b = ''; for await (const c of req) b += c;
  const body = JSON.parse(b); seen.push(req.headers);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ id: 'msg_1', type: 'message', role: 'assistant', model: body.model, content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn', usage: { input_tokens: 1, output_tokens: 1 } }));
});
await new Promise(r => api.listen(0, '127.0.0.1', r));
const app = await startApp({ AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: '', ANTHROPIC_AUTH_TOKEN: 'test-bearer-not-real', ANTHROPIC_BASE_URL: `http://127.0.0.1:${api.address().port}` });
after(async () => { await app.close(); api.close(); });

test('connection test authenticates with the bearer token and sends no x-api-key', async () => {
  const alice = await as(app, 'alice');
  const r = await alice.post('/api/ai/test', {});
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true, JSON.stringify(r.body));
  assert.equal(r.body.key_source, 'server_oauth');
  assert.equal(seen.at(-1).authorization, 'Bearer test-bearer-not-real');
  assert.equal(seen.at(-1)['x-api-key'], undefined);
});
