// Keycloak BFF flow against a mock OIDC provider that signs real RS256 tokens (JWKS, discovery, token endpoint).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { startApp } from './helpers.mjs';

let idp, app, keys, issuer;
const codes = new Map(); let refreshAllowed = true;
const b64 = (b) => Buffer.from(b).toString('base64url');

async function sign(claims, { kid = 'k1', aud = 'sentra' } = {}) {
  return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid }).setIssuer(issuer).setAudience(aud).setIssuedAt().setExpirationTime('5m').sign(keys.privateKey);
}
before(async () => {
  keys = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(keys.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  idp = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    const json = (o, s = 200) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u.pathname === '/realms/sentra/.well-known/openid-configuration') return json({ issuer, authorization_endpoint: issuer + '/auth', token_endpoint: issuer + '/token', jwks_uri: issuer + '/certs', end_session_endpoint: issuer + '/logout' });
    if (u.pathname === '/realms/sentra/certs') return json({ keys: [jwk] });
    if (u.pathname === '/realms/sentra/token') {
      let body = ''; for await (const c of req) body += c; const f = new URLSearchParams(body);
      if (f.get('grant_type') === 'authorization_code') {
        const c = codes.get(f.get('code'));
        if (!c || createHash('sha256').update(f.get('code_verifier')).digest('base64url') !== c.challenge) return json({ error: 'invalid_grant' }, 400);
        return json({ id_token: await sign({ sub: c.sub, nonce: c.nonce, sid: 'sid-' + c.sub, email: c.email, email_verified: true, name: c.name, groups: c.groups }), refresh_token: 'rt-' + c.sub, expires_in: 1 });
      }
      if (f.get('grant_type') === 'refresh_token') return refreshAllowed ? json({ id_token: await sign({ sub: 'u' }), access_token: 'a', expires_in: 300 }) : json({ error: 'invalid_grant' }, 400);
    }
    res.writeHead(404); res.end();
  });
  await new Promise(r => idp.listen(0, '127.0.0.1', r));
  issuer = `http://127.0.0.1:${idp.address().port}/realms/sentra`;
  app = await startApp({ AUTH_MODE: 'keycloak', KEYCLOAK_ISSUER: issuer, KEYCLOAK_CLIENT_ID: 'sentra', KEYCLOAK_ALLOW_HTTP: 'true' });
  await app.db.query(`INSERT INTO invitations (id, org_id, email, org_role, project_roles, expires_at) VALUES ('inv_t','org_demo','new.user@demo.sentra.local','member',$1, now() + interval '1 day')`, [JSON.stringify([{ project_id: 'prj_tts', role: 'viewer' }])]);
});
after(async () => { await app?.close(); idp?.close(); });

async function login({ sub, email, name, groups = [], tamperNonce = false, tamperState = false }) {
  const r = await fetch(app.base + '/api/auth/login?return_to=/findings', { redirect: 'manual' });
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.searchParams.get('code_challenge_method'), 'S256');
  const flowCookie = r.headers.get('set-cookie').split(';')[0];
  const code = randomUUID();
  codes.set(code, { sub, email, name, groups, challenge: loc.searchParams.get('code_challenge'), nonce: tamperNonce ? 'wrong' : loc.searchParams.get('nonce') });
  const cb = await fetch(app.base + `/api/auth/callback?code=${code}&state=${tamperState ? 'bad' : loc.searchParams.get('state')}`, { headers: { Cookie: flowCookie }, redirect: 'manual' });
  return cb;
}
const cookieOf = (res) => (res.headers.getSetCookie?.() || [res.headers.get('set-cookie')]).find(c => c.startsWith('sentra_sid=')).split(';')[0];

test('Authorization Code + PKCE login; tokens never reach the browser; SSO alone grants no access', async () => {
  const cb = await login({ sub: 'kc-stranger', email: 'stranger@example.com', name: 'Stranger' });
  assert.equal(cb.status, 302); const c = cookieOf(cb);
  assert.match(cb.headers.get('set-cookie'), /HttpOnly/); assert.doesNotMatch(cb.headers.get('set-cookie'), /eyJ/, 'no JWT in cookies');
  const me = await (await fetch(app.base + '/api/me', { headers: { Cookie: c } })).json();
  assert.equal(me.organization, null, 'authenticated but no membership');
  assert.equal((await fetch(app.base + '/api/findings', { headers: { Cookie: c } })).status, 403);
});
test('invitation by verified email grants exactly the invited project role', async () => {
  const cb = await login({ sub: 'kc-new', email: 'new.user@demo.sentra.local', name: 'New User' });
  const c = cookieOf(cb);
  const me = await (await fetch(app.base + '/api/me', { headers: { Cookie: c } })).json();
  assert.equal(me.organization.role, 'member'); assert.deepEqual(me.project_roles, { prj_tts: 'viewer' });
  const ps = await (await fetch(app.base + '/api/projects', { headers: { Cookie: c } })).json();
  assert.deepEqual(ps.map(p => p.key), ['tts']);
});
test('group mapping maps Keycloak groups to organization roles', async () => {
  const c = cookieOf(await login({ sub: 'kc-sec', email: 'sec@example.com', name: 'Sec', groups: ['/sentra-security'] }));
  const me = await (await fetch(app.base + '/api/me', { headers: { Cookie: c } })).json();
  assert.equal(me.organization.role, 'security_analyst');
});
test('state and nonce mismatches are rejected', async () => {
  assert.equal((await login({ sub: 'x', email: 'x@x.io', tamperState: true })).status, 401);
  assert.equal((await login({ sub: 'x', email: 'x@x.io', tamperNonce: true })).status, 401);
});
test('refresh failure (revoked Keycloak session) ends the application session', async () => {
  const c = cookieOf(await login({ sub: 'kc-new', email: 'new.user@demo.sentra.local', name: 'New User' }));
  await new Promise(r => setTimeout(r, 1200)); // access token (1s) expired
  refreshAllowed = false;
  assert.equal((await fetch(app.base + '/api/me', { headers: { Cookie: c } })).status, 401);
  refreshAllowed = true;
});
test('back-channel logout revokes sessions by sid; invalid tokens rejected', async () => {
  const c = cookieOf(await login({ sub: 'kc-new', email: 'new.user@demo.sentra.local', name: 'New User' }));
  assert.equal((await fetch(app.base + '/api/me', { headers: { Cookie: c } })).status, 200);
  const bad = await fetch(app.base + '/api/auth/backchannel-logout', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'logout_token=' + (await sign({ sub: 'kc-new', nonce: 'n', events: { 'http://schemas.openid.net/event/backchannel-logout': {} } })) });
  assert.equal(bad.status, 400, 'logout token must not carry a nonce');
  const lt = await sign({ sub: 'kc-new', sid: 'sid-kc-new', jti: randomUUID(), events: { 'http://schemas.openid.net/event/backchannel-logout': {} } });
  const r = await fetch(app.base + '/api/auth/backchannel-logout', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'logout_token=' + lt });
  assert.equal(r.status, 200); assert.ok((await r.json()).revoked >= 1);
  assert.equal((await fetch(app.base + '/api/me', { headers: { Cookie: c } })).status, 401);
});
test('logout requires CSRF token and returns RP-initiated end-session URL', async () => {
  const cb = await login({ sub: 'kc-new', email: 'new.user@demo.sentra.local', name: 'New User' });
  const c = cookieOf(cb);
  const me = await (await fetch(app.base + '/api/me', { headers: { Cookie: c } })).json();
  assert.equal((await fetch(app.base + '/api/auth/logout', { method: 'POST', headers: { Cookie: c } })).status, 403);
  const out = await fetch(app.base + '/api/auth/logout', { method: 'POST', headers: { Cookie: c, 'X-CSRF-Token': me.csrf_token } });
  const j = await out.json(); assert.match(j.end_session_url, /\/logout\?id_token_hint=/);
  assert.equal((await fetch(app.base + '/api/me', { headers: { Cookie: c } })).status, 401);
});
test('dev identity routes are unavailable in keycloak mode', async () => {
  assert.equal((await fetch(app.base + '/api/auth/dev/identities')).status, 404);
});
