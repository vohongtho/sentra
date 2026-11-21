// Identity: Keycloak OIDC (Authorization Code + PKCE) in a Backend-for-Frontend. Tokens never reach the browser;
// the browser holds only an opaque HttpOnly session cookie. Server-side sessions support idle/absolute expiry,
// refresh against Keycloak, RP-initiated logout and OIDC back-channel logout.
//
// Development identity mode (AUTH_MODE=dev) lets a developer pick a seeded identity without Keycloak. It is refused
// in production and labeled in the UI. It is not a password system.
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { createHash } from 'node:crypto';
import { AppError, id } from '../util.mjs';
import { seal, unseal, hashToken, randomToken, safeEqual } from '../crypto.mjs';
import { loadPrincipal } from '../authz.mjs';
import { audit } from '../audit.mjs';
import { log } from '../log.mjs';
import { Reply } from '../http/server.mjs';

const ALGS = ['RS256', 'PS256', 'ES256'];
const b64url = (b) => Buffer.from(b).toString('base64url');

export function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) { const i = part.indexOf('='); if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); }
  return out;
}
export const sessionCookieName = (cfg) => (cfg.appOrigin.startsWith('https://') ? '__Host-sentra_sid' : 'sentra_sid');
function cookie(cfg, name, value, maxAge, p = '/') {
  const secure = cfg.appOrigin.startsWith('https://');
  return `${name}=${encodeURIComponent(value)}; Path=${p}; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}

// ------------------------------------------------------------------ OIDC discovery / JWKS
const discovery = new Map(); const jwksSets = new Map();
export async function oidcMetadata(cfg) {
  const issuer = cfg.keycloak.issuer;
  if (!issuer || !cfg.keycloak.clientId) throw new AppError(503, 'AUTH_CONFIG_REQUIRED', 'Keycloak is not configured (KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID).');
  const u = new URL(issuer);
  if (u.protocol !== 'https:' && !cfg.keycloak.allowHttpIssuer) throw new AppError(503, 'AUTH_CONFIG_REQUIRED', 'Keycloak issuer must use HTTPS.');
  const c = discovery.get(issuer); if (c && c.exp > Date.now()) return c.value;
  const res = await fetch(issuer + '/.well-known/openid-configuration', { redirect: 'error', signal: AbortSignal.timeout(10000) }).catch(() => null);
  if (!res?.ok) throw new AppError(503, 'OIDC_UNAVAILABLE', 'Unable to reach the Keycloak realm discovery endpoint.');
  const d = await res.json();
  const publicIssuer = cfg.keycloak.publicIssuer || issuer;
  if (d.issuer !== issuer && d.issuer !== publicIssuer) throw new AppError(503, 'OIDC_INVALID', 'Issuer discovery mismatch.');
  discovery.set(issuer, { value: d, exp: Date.now() + 300_000 });
  return d;
}
function jwks(cfg, d) {
  // When the server reaches Keycloak through an internal hostname, rewrite JWKS/token endpoints to that host.
  const internal = (url) => cfg.keycloak.publicIssuer && cfg.keycloak.publicIssuer !== cfg.keycloak.issuer ? url.replace(cfg.keycloak.publicIssuer, cfg.keycloak.issuer) : url;
  const uri = internal(d.jwks_uri);
  if (!jwksSets.has(uri)) jwksSets.set(uri, createRemoteJWKSet(new URL(uri), { cooldownDuration: 30_000, cacheMaxAge: 600_000 })); // handles key rotation
  return { set: jwksSets.get(uri), internal };
}
async function tokenRequest(cfg, d, form) {
  const { internal } = jwks(cfg, d);
  form.set('client_id', cfg.keycloak.clientId);
  if (cfg.keycloak.clientSecret) form.set('client_secret', cfg.keycloak.clientSecret);
  const res = await fetch(internal(d.token_endpoint), { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form, redirect: 'error', signal: AbortSignal.timeout(10000) });
  if (!res.ok) return null;
  return res.json();
}
async function verifyIdToken(cfg, d, token, nonce) {
  const { set } = jwks(cfg, d);
  const { payload } = await jwtVerify(token, set, { issuer: [d.issuer], audience: cfg.keycloak.clientId, algorithms: ALGS, clockTolerance: 5 });
  if (nonce !== undefined && payload.nonce !== nonce) throw new AppError(401, 'NONCE_INVALID', 'OIDC nonce mismatch.');
  if (!payload.sub) throw new AppError(401, 'TOKEN_INVALID', 'Token without subject.');
  return payload;
}

// ------------------------------------------------------------------ sessions
export async function createSession(app, identityId, { method, sid = null, tokens = null, accessExpiresAt = null }) {
  const raw = randomToken(32);
  const csrf = randomToken(24);
  const absolute = new Date(Date.now() + app.cfg.sessionTtlSeconds * 1000);
  await app.db.query(`INSERT INTO sessions (id, identity_id, csrf_token, idp_session_id, tokens_sealed, access_expires_at, expires_at, auth_method) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [hashToken(raw), identityId, csrf, sid, tokens ? seal(JSON.stringify(tokens), 'oidc-tokens') : null, accessExpiresAt, absolute.toISOString(), method]);
  return { raw, csrf, expires: absolute };
}
async function loadSession(app, raw) {
  if (!raw) return null;
  const s = await app.db.one(`SELECT s.*, i.issuer, i.subject, i.email, i.display_name, i.disabled FROM sessions s JOIN identities i ON i.id=s.identity_id WHERE s.id=$1`, [hashToken(raw)]);
  if (!s || s.revoked_at || new Date(s.expires_at) < new Date() || s.disabled) return null;
  if (Date.now() - new Date(s.last_seen_at).getTime() > app.cfg.sessionIdleSeconds * 1000) { await revokeSession(app, s.id, 'idle_timeout'); return null; }
  // Refresh against Keycloak once the access token lifetime passes; failure (revoked realm session) ends the app session.
  if (s.auth_method === 'keycloak' && s.access_expires_at && new Date(s.access_expires_at) < new Date()) {
    const ok = await refreshSession(app, s).catch(() => false);
    if (!ok) { await revokeSession(app, s.id, 'refresh_failed'); return null; }
  }
  if (Date.now() - new Date(s.last_seen_at).getTime() > 60_000) await app.db.query('UPDATE sessions SET last_seen_at=now() WHERE id=$1', [s.id]);
  return s;
}
async function refreshSession(app, s) {
  const tokens = JSON.parse(unseal(s.tokens_sealed, 'oidc-tokens'));
  if (!tokens.refresh_token) return false;
  const d = await oidcMetadata(app.cfg);
  const t = await tokenRequest(app.cfg, d, new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token }));
  if (!t?.id_token && !t?.access_token) return false;
  const next = { refresh_token: t.refresh_token || tokens.refresh_token, id_token: t.id_token || tokens.id_token };
  await app.db.query('UPDATE sessions SET tokens_sealed=$2, access_expires_at=$3 WHERE id=$1', [s.id, seal(JSON.stringify(next), 'oidc-tokens'), new Date(Date.now() + (t.expires_in || 300) * 1000).toISOString()]);
  return true;
}
export async function revokeSession(app, sessionId, reason) {
  await app.db.query('UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL', [sessionId]);
  log.info('session_revoked', { reason });
}

// ------------------------------------------------------------------ identity provisioning (no automatic project access)
export async function provisionIdentity(app, { issuer, subject, email, name, groups = [], clientRoles = [] }) {
  const db = app.db;
  let ident = await db.one('SELECT * FROM identities WHERE issuer=$1 AND subject=$2', [issuer, subject]);
  if (!ident) {
    ident = (await db.query('INSERT INTO identities (id, issuer, subject, email, display_name, groups, last_login_at) VALUES ($1,$2,$3,$4,$5,$6,now()) RETURNING *', [id('idn'), issuer, subject, email || null, name || email || subject, JSON.stringify(groups)]))[0];
  } else {
    ident = (await db.query('UPDATE identities SET email=$2, display_name=$3, groups=$4, last_login_at=now() WHERE id=$1 RETURNING *', [ident.id, email || ident.email, name || ident.display_name, JSON.stringify(groups)]))[0];
  }
  // 1) group / client-role mappings
  const maps = await db.query('SELECT * FROM role_mappings');
  for (const m of maps) {
    const values = m.claim === 'client_roles' ? clientRoles : groups;
    if (!values.includes(m.value)) continue;
    if (m.org_role) await db.query(`INSERT INTO memberships (id, org_id, identity_id, org_role, source) VALUES ($1,$2,$3,$4,'group_mapping') ON CONFLICT (org_id, identity_id) DO UPDATE SET org_role=EXCLUDED.org_role WHERE memberships.source='group_mapping'`, [id('mem'), m.org_id, ident.id, m.org_role]);
    if (m.project_id && m.project_role) {
      await db.query(`INSERT INTO memberships (id, org_id, identity_id, org_role, source) VALUES ($1,$2,$3,'member','group_mapping') ON CONFLICT DO NOTHING`, [id('mem'), m.org_id, ident.id]);
      await db.query(`INSERT INTO project_access (id, project_id, identity_id, role, granted_by) VALUES ($1,$2,$3,$4,'group_mapping') ON CONFLICT (project_id, identity_id) DO NOTHING`, [id('pa'), m.project_id, ident.id, m.project_role]);
    }
  }
  // 2) pending invitations by verified email
  if (email) {
    const invs = await db.query('SELECT * FROM invitations WHERE lower(email)=lower($1) AND accepted_at IS NULL AND expires_at > now()', [email]);
    for (const inv of invs) {
      await db.query(`INSERT INTO memberships (id, org_id, identity_id, org_role, source) VALUES ($1,$2,$3,$4,'invitation') ON CONFLICT (org_id, identity_id) DO NOTHING`, [id('mem'), inv.org_id, ident.id, inv.org_role]);
      for (const pr of inv.project_roles || []) await db.query(`INSERT INTO project_access (id, project_id, identity_id, role, granted_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (project_id, identity_id) DO NOTHING`, [id('pa'), pr.project_id, ident.id, pr.role, inv.invited_by]);
      await db.query('UPDATE invitations SET accepted_at=now() WHERE id=$1', [inv.id]);
    }
  }
  return ident;
}

// ------------------------------------------------------------------ routes
export function registerAuthRoutes(router, app) {
  const cfg = app.cfg;
  router.get('/api/auth/status', async ({ ctx }) => ({
    mode: cfg.authMode, keycloak_configured: !!(cfg.keycloak.issuer && cfg.keycloak.clientId),
    authenticated: !!ctx.identity, has_access: !!ctx.orgId,
    dev_mode_warning: cfg.authMode === 'dev' ? 'Development identity mode: identities are selected without Keycloak. Never use in production.' : null,
  }), { public: true, optionalAuth: true });

  router.get('/api/auth/login', async ({ url }) => {
    const d = await oidcMetadata(cfg);
    const verifier = randomToken(32), state = randomToken(24), nonce = randomToken(24);
    const returnTo = (url.searchParams.get('return_to') || '/').startsWith('/') && !url.searchParams.get('return_to')?.startsWith('//') ? url.searchParams.get('return_to') || '/' : '/';
    const flow = seal(JSON.stringify({ verifier, state, nonce, returnTo, exp: Date.now() + 600_000 }), 'oidc-flow');
    const target = new URL(d.authorization_endpoint);
    for (const [k, v] of Object.entries({ client_id: cfg.keycloak.clientId, response_type: 'code', scope: 'openid profile email', redirect_uri: cfg.appOrigin + '/api/auth/callback', state, nonce, code_challenge: b64url(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256' })) target.searchParams.set(k, v);
    return redirect(target.toString(), [cookie(cfg, 'sentra_oidc_flow', flow, 600, '/api/auth')]);
  }, { public: true });

  router.get('/api/auth/callback', async ({ url, req }) => {
    const flowRaw = parseCookies(req.headers.cookie).sentra_oidc_flow;
    if (!flowRaw) throw new AppError(401, 'FLOW_EXPIRED', 'Sign-in flow expired. Start again.');
    let flow; try { flow = JSON.parse(unseal(flowRaw, 'oidc-flow')); } catch { throw new AppError(401, 'FLOW_INVALID', 'Sign-in flow invalid. Start again.'); }
    if (flow.exp < Date.now()) throw new AppError(401, 'FLOW_EXPIRED', 'Sign-in flow expired.');
    if (url.searchParams.get('error')) throw new AppError(401, 'IDP_ERROR', 'Keycloak returned an error: ' + url.searchParams.get('error'));
    const code = url.searchParams.get('code');
    if (!code || !safeEqual(url.searchParams.get('state') || '', flow.state)) throw new AppError(401, 'STATE_INVALID', 'OIDC state mismatch.');
    const d = await oidcMetadata(cfg);
    const t = await tokenRequest(cfg, d, new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: cfg.appOrigin + '/api/auth/callback', code_verifier: flow.verifier }));
    if (!t?.id_token) throw new AppError(401, 'TOKEN_EXCHANGE_FAILED', 'Keycloak did not accept this sign-in.');
    const claims = await verifyIdToken(cfg, d, t.id_token, flow.nonce);
    const groups = (claims.groups || []).map(g => String(g).replace(/^\//, ''));
    const clientRoles = claims.resource_access?.[cfg.keycloak.clientId]?.roles || [];
    const ident = await provisionIdentity(app, { issuer: claims.iss, subject: claims.sub, email: claims.email_verified === false ? null : claims.email, name: claims.name || claims.preferred_username, groups, clientRoles });
    const sess = await createSession(app, ident.id, { method: 'keycloak', sid: claims.sid || null, tokens: { refresh_token: t.refresh_token, id_token: t.id_token }, accessExpiresAt: new Date(Date.now() + (t.expires_in || 300) * 1000).toISOString() });
    const principal = await loadPrincipal(app.db, ident);
    await audit(app.db, principal || { actorType: 'user', identity: ident }, 'auth.login', { targetType: 'identity', targetId: ident.id, data: { method: 'keycloak', has_access: !!principal } });
    return redirect(cfg.appOrigin + (flow.returnTo || '/'), [cookie(cfg, sessionCookieName(cfg), sess.raw, cfg.sessionTtlSeconds), cookie(cfg, 'sentra_oidc_flow', '', 0, '/api/auth')]);
  }, { public: true });

  router.post('/api/auth/logout', async ({ ctx }) => {
    let endSession = null;
    if (ctx.session) {
      await revokeSession(app, ctx.session.id, 'logout');
      await audit(app.db, ctx, 'auth.logout', { targetType: 'identity', targetId: ctx.identity.id });
      if (ctx.session.auth_method === 'keycloak') {
        try {
          const d = await oidcMetadata(cfg);
          const tokens = JSON.parse(unseal(ctx.session.tokens_sealed, 'oidc-tokens'));
          if (d.end_session_endpoint) { const u = new URL(d.end_session_endpoint); u.searchParams.set('id_token_hint', tokens.id_token); u.searchParams.set('post_logout_redirect_uri', cfg.appOrigin + '/'); endSession = u.toString(); }
        } catch { /* local session is still revoked */ }
      }
    }
    return new Reply(200, { logged_out: true, end_session_url: endSession }, { 'Set-Cookie': cookie(cfg, sessionCookieName(cfg), '', 0) });
  });

  // OIDC Back-Channel Logout 1.0: Keycloak posts a signed logout_token.
  router.post('/api/auth/backchannel-logout', async ({ raw }) => {
    const form = new URLSearchParams(raw.toString('utf8'));
    const token = form.get('logout_token');
    if (!token) throw new AppError(400, 'INVALID_REQUEST', 'logout_token required.');
    const d = await oidcMetadata(cfg);
    const { set } = jwks(cfg, d);
    const { payload } = await jwtVerify(token, set, { issuer: [d.issuer], audience: cfg.keycloak.clientId, algorithms: ALGS, clockTolerance: 5 }).catch(() => { throw new AppError(400, 'INVALID_TOKEN', 'logout_token verification failed.'); });
    if (!payload.events?.['http://schemas.openid.net/event/backchannel-logout'] || payload.nonce) throw new AppError(400, 'INVALID_TOKEN', 'Not a logout token.');
    let n = 0;
    if (payload.sid) n += (await app.db.query('UPDATE sessions SET revoked_at=now() WHERE idp_session_id=$1 AND revoked_at IS NULL RETURNING id', [payload.sid])).length;
    if (payload.sub) n += (await app.db.query(`UPDATE sessions SET revoked_at=now() WHERE revoked_at IS NULL AND identity_id IN (SELECT id FROM identities WHERE issuer=$1 AND subject=$2) RETURNING id`, [payload.iss, payload.sub])).length;
    await audit(app.db, { actorType: 'system', systemActor: 'keycloak' }, 'auth.backchannel_logout', { data: { sid: payload.sid, sessions_revoked: n } });
    return { revoked: n };
  }, { public: true, csrfExempt: true, rawBody: true });

  // ---------------- development identity mode
  router.get('/api/auth/dev/identities', async () => {
    devOnly(cfg);
    return { warning: 'Development identity mode — not Keycloak.', identities: await app.db.query(`SELECT i.id, i.display_name, i.email, m.org_role, (SELECT json_agg(json_build_object('project', p.key, 'role', pa.role)) FROM project_access pa JOIN projects p ON p.id=pa.project_id WHERE pa.identity_id=i.id) AS projects FROM identities i LEFT JOIN memberships m ON m.identity_id=i.id WHERE i.issuer='dev' ORDER BY i.display_name`) };
  }, { public: true });
  router.post('/api/auth/dev/login', async ({ body, req }) => {
    devOnly(cfg);
    // Same-origin check (no session yet, so no CSRF token).
    const origin = req.headers.origin; if (origin && origin !== cfg.appOrigin) throw new AppError(403, 'ORIGIN_REJECTED', 'Cross-origin login rejected.');
    const ident = await app.db.one(`SELECT * FROM identities WHERE id=$1 AND issuer='dev'`, [body.identity_id]);
    if (!ident) throw new AppError(404, 'NOT_FOUND', 'Unknown development identity.');
    const sess = await createSession(app, ident.id, { method: 'dev' });
    const principal = await loadPrincipal(app.db, ident);
    await audit(app.db, principal || { actorType: 'user', identity: ident }, 'auth.login', { targetType: 'identity', targetId: ident.id, data: { method: 'dev' } });
    return new Reply(200, { ok: true, csrf_token: sess.csrf }, { 'Set-Cookie': cookie(cfg, sessionCookieName(cfg), sess.raw, cfg.sessionTtlSeconds) });
  }, { public: true, csrfExempt: true });
}
function devOnly(cfg) { if (cfg.authMode !== 'dev' || cfg.isProduction) throw new AppError(404, 'NOT_FOUND', 'Unknown API route.'); }
function redirect(location, cookies = []) {
  return new Reply(302, '', { Location: location, 'Set-Cookie': cookies });
}

// ------------------------------------------------------------------ request authentication
export function makeAuthenticator(app) {
  const cfg = app.cfg;
  return async function authenticate(req, url, opts, { correlationId }) {
    const base = { db: app.db, cfg, app, correlationId, actorType: 'anonymous' };
    // CI / service identity: Bearer stk_... tokens; never cookies.
    const authz = req.headers.authorization || '';
    if (opts.ci && authz.startsWith('Bearer ')) {
      const token = authz.slice(7).trim();
      const t = await app.db.one('SELECT * FROM ci_tokens WHERE token_hash=$1', [hashToken(token)]);
      if (!t || t.revoked_at || new Date(t.expires_at) < new Date()) throw new AppError(401, 'TOKEN_INVALID', 'CI token is invalid, expired or revoked.');
      await app.db.query('UPDATE ci_tokens SET last_used_at=now() WHERE id=$1', [t.id]);
      return { ...base, db: app.db.scoped(t.org_id), actorType: 'ci', ciToken: t, orgId: t.org_id };
    }
    if (opts.ci && !opts.allowSession) throw new AppError(401, 'TOKEN_REQUIRED', 'Use a scoped CI token (Authorization: Bearer stk_...).');
    if (opts.public && !opts.optionalAuth) return base;
    const raw = parseCookies(req.headers.cookie)[sessionCookieName(cfg)];
    const s = await loadSession(app, raw);
    if (!s) { if (opts.optionalAuth) return base; throw new AppError(401, 'LOGIN_REQUIRED', 'Sign in required.'); }
    // CSRF: same-origin + synchronizer token for cookie-authenticated mutations.
    if (!['GET', 'HEAD'].includes(req.method) && !opts.csrfExempt) {
      const origin = req.headers.origin;
      if (origin && origin !== cfg.appOrigin) throw new AppError(403, 'CSRF_REJECTED', 'Cross-origin request rejected.');
      if (req.headers['sec-fetch-site'] === 'cross-site') throw new AppError(403, 'CSRF_REJECTED', 'Cross-site request rejected.');
      if (!safeEqual(req.headers['x-csrf-token'] || '', s.csrf_token)) throw new AppError(403, 'CSRF_REJECTED', 'Missing or invalid CSRF token.');
    }
    const identity = { id: s.identity_id, email: s.email, display_name: s.display_name, issuer: s.issuer, subject: s.subject };
    const orgHeader = req.headers['x-sentra-org'];
    const principal = await loadPrincipal(app.db, identity, typeof orgHeader === 'string' && orgHeader ? orgHeader : undefined);
    const ctx = { ...base, session: s, identity, csrfToken: s.csrf_token, authMethod: s.auth_method };
    if (!principal) { if (opts.noOrgOk || opts.optionalAuth) return ctx; throw new AppError(403, 'NO_ACCESS', 'Your identity is authenticated but has no organization membership. Ask an administrator for an invitation.'); }
    return { ...ctx, ...principal, identity, db: app.db.scoped(principal.orgId) };
  };
}
