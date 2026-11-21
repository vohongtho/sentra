// Core API: identity, organization administration, projects, inventory, imports, drafts.
import { id, badRequest, notFound, need, oneOf, clampInt, conflict, AppError } from '../util.mjs';
import { requireOrg, requireProject, accessibleProjectIds, hasOrgPerm, ORG_ROLES, PROJECT_ROLES, permissionMatrix, projectPermissions, orgWide } from '../authz.mjs';
import { audit, verifyAuditChain } from '../audit.mjs';
import { putSecret, listSecrets } from '../services/secrets.mjs';
import { parseDocument, ParseError } from '../domain/parsers.mjs';
import { recordSnapshot, snapshotDiff, contentHash, deployedInventory } from '../services/inventory.mjs';
import { projectCoverage } from '../services/coverage.mjs';
import { sha256 } from '../util.mjs';
import { isValidTimeZone } from '../domain/timezone.mjs';

const KEY_RE = /^[a-z0-9][a-z0-9-]{1,40}$/;
const CRIT = ['low', 'medium', 'high', 'critical'], CLASS = ['public', 'internal', 'confidential', 'restricted'], EXPO = ['internet', 'partner', 'internal', 'isolated'];

export function registerCore(r) {
  // ---------------- me
  r.get('/api/me', async ({ ctx }) => ({
    identity: ctx.identity, auth_method: ctx.authMethod, csrf_token: ctx.csrfToken,
    organization: ctx.orgId ? { id: ctx.orgId, slug: ctx.orgSlug, name: ctx.orgName, role: ctx.orgRole } : null,
    project_roles: Object.fromEntries(ctx.projectRoles || []),
    org_permissions: ctx.orgId ? permissionMatrix().org[ctx.orgRole] : [],
    unread_notifications: ctx.identity ? (await ctx.db.one('SELECT count(*)::int AS n FROM notifications WHERE identity_id=$1 AND read_at IS NULL', [ctx.identity.id])).n : 0,
  }), { noOrgOk: true });
  r.get('/api/me/notifications', async ({ ctx }) => ctx.db.query('SELECT * FROM notifications WHERE identity_id=$1 AND org_id=$2 ORDER BY created_at DESC LIMIT 50', [ctx.identity.id, ctx.orgId]));
  r.post('/api/me/notifications/read', async ({ ctx }) => { await ctx.db.query('UPDATE notifications SET read_at=now() WHERE identity_id=$1 AND read_at IS NULL', [ctx.identity.id]); return { ok: true }; });
  r.get('/api/me/views', async ({ ctx, query }) => ctx.db.query('SELECT * FROM saved_views WHERE identity_id=$1 AND ($2::text IS NULL OR page=$2) ORDER BY name', [ctx.identity.id, query.page || null]));
  r.post('/api/me/views', async ({ ctx, body }) => { need(body, ['page', 'name', 'query']); const vid = id('view'); await ctx.db.query('INSERT INTO saved_views (id, org_id, identity_id, page, name, query) VALUES ($1,$2,$3,$4,$5,$6)', [vid, ctx.orgId, ctx.identity.id, String(body.page).slice(0, 40), String(body.name).slice(0, 80), body.query]); return { id: vid }; });
  r.delete('/api/me/views/:id', async ({ ctx, params }) => { await ctx.db.query('DELETE FROM saved_views WHERE id=$1 AND identity_id=$2', [params.id, ctx.identity.id]); });

  // ---------------- organization administration
  r.get('/api/org', async ({ ctx }) => { requireOrg(ctx, 'org:read'); return ctx.db.one('SELECT id, slug, name, settings, created_at FROM organizations WHERE id=$1', [ctx.orgId]); });
  r.patch('/api/org/settings', async ({ ctx, body }) => {
    requireOrg(ctx, 'org:admin');
    const s = {};
    if (body.onboarding_policy) s.onboarding_policy = oneOf(body.onboarding_policy, ['invite_only', 'group_mapping_only'], 'onboarding_policy');
    if (body.default_timezone) { if (!isValidTimeZone(body.default_timezone)) throw badRequest('Invalid timezone.'); s.default_timezone = body.default_timezone; }
    if (body.report_language) s.report_language = oneOf(body.report_language, ['vi', 'en'], 'report_language');
    if (body.retention_days) s.retention_days = clampInt(body.retention_days, 365, 30, 3650);
    await ctx.db.query(`UPDATE organizations SET settings = settings || $2 WHERE id=$1`, [ctx.orgId, s]);
    await audit(ctx.db, ctx, 'org.settings_updated', { data: s });
    return ctx.db.one('SELECT settings FROM organizations WHERE id=$1', [ctx.orgId]);
  });
  r.get('/api/org/members', async ({ ctx }) => {
    requireOrg(ctx, 'org:read');
    return ctx.db.query(`SELECT i.id, i.display_name, i.email, i.issuer, i.disabled, i.last_login_at, m.org_role, m.source,
      (SELECT json_agg(json_build_object('project_id', pa.project_id, 'project', p.key, 'role', pa.role)) FROM project_access pa JOIN projects p ON p.id=pa.project_id WHERE pa.identity_id=i.id AND p.org_id=$1) AS projects
      FROM memberships m JOIN identities i ON i.id=m.identity_id WHERE m.org_id=$1 ORDER BY i.display_name`, [ctx.orgId]);
  });
  r.patch('/api/org/members/:id', async ({ ctx, params, body }) => {
    requireOrg(ctx, 'org:admin');
    if (body.org_role) { oneOf(body.org_role, ORG_ROLES, 'org_role'); await ctx.db.query('UPDATE memberships SET org_role=$3, source=$4 WHERE identity_id=$1 AND org_id=$2', [params.id, ctx.orgId, body.org_role, 'manual']); }
    if (body.disabled != null) {
      await ctx.db.query('UPDATE identities SET disabled=$2 WHERE id=$1 AND id IN (SELECT identity_id FROM memberships WHERE org_id=$3)', [params.id, !!body.disabled, ctx.orgId]);
      if (body.disabled) await ctx.db.query('UPDATE sessions SET revoked_at=now() WHERE identity_id=$1 AND revoked_at IS NULL', [params.id]); // existing sessions end immediately
    }
    await audit(ctx.db, ctx, 'org.member_updated', { targetType: 'identity', targetId: params.id, data: body });
    return { ok: true, note: 'Role changes apply on the next request; background tasks re-check access at execution.' };
  });
  r.delete('/api/org/members/:id', async ({ ctx, params }) => {
    requireOrg(ctx, 'org:admin');
    if (params.id === ctx.identity.id) throw badRequest('You cannot remove yourself.');
    await ctx.db.tx(async (t) => {
      await t.query('DELETE FROM project_access WHERE identity_id=$1 AND project_id IN (SELECT id FROM projects WHERE org_id=$2)', [params.id, ctx.orgId]);
      await t.query('DELETE FROM memberships WHERE identity_id=$1 AND org_id=$2', [params.id, ctx.orgId]);
      await t.query('UPDATE sessions SET revoked_at=now() WHERE identity_id=$1 AND revoked_at IS NULL', [params.id]);
      await audit(t, ctx, 'org.member_removed', { targetType: 'identity', targetId: params.id });
    });
  });
  r.get('/api/org/invitations', async ({ ctx }) => { requireOrg(ctx, 'org:admin'); return ctx.db.query('SELECT * FROM invitations WHERE org_id=$1 ORDER BY created_at DESC', [ctx.orgId]); });
  r.post('/api/org/invitations', async ({ ctx, body }) => {
    requireOrg(ctx, 'org:admin'); need(body, ['email', 'org_role']); oneOf(body.org_role, ORG_ROLES, 'org_role');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email)) throw badRequest('Invalid email.');
    const prs = (body.project_roles || []).map(p => ({ project_id: p.project_id, role: oneOf(p.role, PROJECT_ROLES, 'role') }));
    for (const p of prs) await requireProject(ctx, p.project_id, 'project:read');
    const iid = id('inv');
    await ctx.db.query('INSERT INTO invitations (id, org_id, email, org_role, project_roles, invited_by, expires_at) VALUES ($1,$2,$3,$4,$5,$6, now() + interval \'14 days\')', [iid, ctx.orgId, body.email.toLowerCase(), body.org_role, JSON.stringify(prs), ctx.identity.id]);
    await audit(ctx.db, ctx, 'org.invitation_created', { targetType: 'invitation', targetId: iid, data: { email: body.email, org_role: body.org_role, project_roles: prs } });
    return { id: iid, note: 'The invitation is accepted automatically when this email signs in through Keycloak with a verified email.' };
  });
  r.get('/api/org/role-mappings', async ({ ctx }) => { requireOrg(ctx, 'org:admin'); return ctx.db.query('SELECT * FROM role_mappings WHERE org_id=$1', [ctx.orgId]); });
  r.post('/api/org/role-mappings', async ({ ctx, body }) => {
    requireOrg(ctx, 'org:admin'); need(body, ['claim', 'value']); oneOf(body.claim, ['groups', 'client_roles'], 'claim');
    if (body.org_role) oneOf(body.org_role, ORG_ROLES, 'org_role');
    if (body.project_id) { await requireProject(ctx, body.project_id); oneOf(body.project_role, PROJECT_ROLES, 'project_role'); }
    const mid = id('rmap');
    await ctx.db.query('INSERT INTO role_mappings (id, org_id, claim, value, org_role, project_id, project_role) VALUES ($1,$2,$3,$4,$5,$6,$7)', [mid, ctx.orgId, body.claim, body.value, body.org_role || null, body.project_id || null, body.project_role || null]);
    await audit(ctx.db, ctx, 'org.role_mapping_created', { targetType: 'role_mapping', targetId: mid, data: body });
    return { id: mid };
  });
  r.delete('/api/org/role-mappings/:id', async ({ ctx, params }) => { requireOrg(ctx, 'org:admin'); await ctx.db.query('DELETE FROM role_mappings WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); await audit(ctx.db, ctx, 'org.role_mapping_deleted', { targetId: params.id }); });
  r.get('/api/org/teams', async ({ ctx }) => ctx.db.query('SELECT * FROM teams WHERE org_id=$1 ORDER BY name', [ctx.orgId]));
  r.post('/api/org/teams', async ({ ctx, body }) => { requireOrg(ctx, 'org:admin'); need(body, ['name']); const tid = id('team'); await ctx.db.query('INSERT INTO teams (id, org_id, name, email) VALUES ($1,$2,$3,$4)', [tid, ctx.orgId, body.name, body.email || null]); return { id: tid }; });
  r.get('/api/org/secrets', async ({ ctx }) => { requireOrg(ctx, 'connections:manage'); return listSecrets(ctx.db, ctx.orgId); });
  r.post('/api/org/secrets', async ({ ctx, body }) => {
    requireOrg(ctx, 'connections:manage'); need(body, ['name', 'value']);
    const s = await putSecret(ctx.db, ctx.orgId, body.name, body.value, ctx.identity.id);
    await audit(ctx.db, ctx, s.rotated ? 'secret.rotated' : 'secret.created', { targetType: 'secret', targetId: s.id, data: { name: s.name, fingerprint: s.fingerprint } });
    return s; // value is never returned
  });
  r.get('/api/org/audit', async ({ ctx, query }) => {
    requireOrg(ctx, 'audit:read');
    const limit = clampInt(query.limit, 100, 1, 500), before = query.before ? Number(query.before) : null;
    const rows = await ctx.db.query(`SELECT a.*, i.display_name AS actor_name FROM audit_events a LEFT JOIN identities i ON i.id=a.actor_id WHERE a.org_id=$1 AND ($2::bigint IS NULL OR a.seq < $2) AND ($3::text IS NULL OR a.target_id=$3 OR a.project_id=$3) AND ($4::text IS NULL OR a.action LIKE $4 || '%') ORDER BY a.seq DESC LIMIT ${limit}`, [ctx.orgId, before, query.target || null, query.action || null]);
    return { items: rows, next_before: rows.length === limit ? rows[rows.length - 1].seq : null };
  });
  r.get('/api/org/audit/verify', async ({ ctx }) => { requireOrg(ctx, 'audit:read'); return verifyAuditChain(ctx.db, ctx.orgId); });
  r.get('/api/org/permissions', async ({ ctx }) => permissionMatrix());

  // ---------------- projects
  r.get('/api/projects', async ({ ctx, query }) => {
    const ids = await accessibleProjectIds(ctx);
    const rows = await ctx.db.query(`SELECT p.*, i.display_name AS owner_name, t.name AS team_name,
        (SELECT count(*)::int FROM services s WHERE s.project_id=p.id) AS service_count,
        (SELECT json_agg(json_build_object('id', e.id, 'key', e.key, 'is_production', e.is_production) ORDER BY e.is_production DESC, e.key) FROM environments e WHERE e.project_id=p.id) AS environments,
        (SELECT count(*)::int FROM findings f WHERE f.project_id=p.id AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk')) AS open_findings,
        (SELECT count(*)::int FROM findings f WHERE f.project_id=p.id AND f.priority IN ('P0','P1') AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk')) AS urgent_findings,
        (SELECT max(created_at) FROM inventory_snapshots s WHERE s.project_id=p.id) AS last_inventory_at,
        (SELECT array_agg(DISTINCT c.ecosystem) FROM observations o JOIN components c ON c.id=o.component_id WHERE o.project_id=p.id) AS ecosystems
      FROM projects p LEFT JOIN identities i ON i.id=p.owner_identity_id LEFT JOIN teams t ON t.id=p.team_id WHERE p.id = ANY($1) AND ($2::boolean OR p.archived_at IS NULL) ORDER BY p.name`, [ids, query.include_archived === 'true']);
    return rows.map(p => ({ ...p, my_role: ctx.projectRoles?.get(p.id) || ctx.orgRole }));
  });
  r.post('/api/projects', async ({ ctx, body }) => {
    requireOrg(ctx, 'projects:create'); need(body, ['key', 'name']);
    if (!KEY_RE.test(body.key)) throw badRequest('key must be lowercase letters, digits and dashes (2-41 chars).');
    const pid = id('prj');
    await ctx.db.tx(async (t) => {
      if (await t.one('SELECT 1 FROM projects WHERE org_id=$1 AND key=$2', [ctx.orgId, body.key])) throw conflict('Project key already exists.');
      await t.query(`INSERT INTO projects (id, org_id, key, name, description, owner_identity_id, team_id, criticality, data_classification, exposure, tags, metadata, onboarding) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [pid, ctx.orgId, body.key, body.name, body.description || null, body.owner_identity_id || ctx.identity.id, body.team_id || null, body.criticality ? oneOf(body.criticality, CRIT, 'criticality') : 'medium', body.data_classification ? oneOf(body.data_classification, CLASS, 'data_classification') : 'internal', body.exposure ? oneOf(body.exposure, EXPO, 'exposure') : 'internal', JSON.stringify(body.tags || []), body.metadata || {}, { metadata: { done: true, at: new Date().toISOString() } }]);
      await t.query(`INSERT INTO project_access (id, project_id, identity_id, role, granted_by) VALUES ($1,$2,$3,'project_owner',$3)`, [id('pa'), pid, body.owner_identity_id || ctx.identity.id]);
      for (const e of body.environments || []) await t.query(`INSERT INTO environments (id, org_id, project_id, key, name, is_production, exposure, timezone) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [id('env'), ctx.orgId, pid, e.key, e.name || e.key, !!e.is_production, e.exposure || 'internal', e.timezone || 'Asia/Ho_Chi_Minh']);
      for (const s of body.services || []) await t.query(`INSERT INTO services (id, org_id, project_id, key, name, kind) VALUES ($1,$2,$3,$4,$5,$6)`, [id('svc'), ctx.orgId, pid, s.key, s.name || s.key, s.kind || 'application']);
      await audit(t, ctx, 'project.created', { targetType: 'project', targetId: pid, projectId: pid, data: { key: body.key } });
    });
    return getProject(ctx, pid);
  });
  r.get('/api/projects/:id', async ({ ctx, params }) => getProject(ctx, params.id));
  r.patch('/api/projects/:id', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'project:manage');
    const fields = { name: body.name, description: body.description, criticality: body.criticality && oneOf(body.criticality, CRIT, 'criticality'), data_classification: body.data_classification && oneOf(body.data_classification, CLASS, 'data_classification'), exposure: body.exposure && oneOf(body.exposure, EXPO, 'exposure'), owner_identity_id: body.owner_identity_id, team_id: body.team_id, tags: body.tags && JSON.stringify(body.tags), metadata: body.metadata };
    const set = Object.entries(fields).filter(([, v]) => v !== undefined);
    if (body.owner_identity_id && !(await ctx.db.one('SELECT 1 FROM memberships WHERE identity_id=$1 AND org_id=$2', [body.owner_identity_id, ctx.orgId]))) throw badRequest('Owner must be an organization member.');
    if (set.length) await ctx.db.query(`UPDATE projects SET ${set.map(([k], i) => `${k}=$${i + 2}`).join(', ')}, updated_at=now() WHERE id=$1`, [p.id, ...set.map(([, v]) => v)]);
    if (body.owner_identity_id && body.owner_identity_id !== p.owner_identity_id) await ctx.db.query(`INSERT INTO project_access (id, project_id, identity_id, role, granted_by) VALUES ($1,$2,$3,'project_owner',$4) ON CONFLICT (project_id, identity_id) DO UPDATE SET role='project_owner'`, [id('pa'), p.id, body.owner_identity_id, ctx.identity.id]);
    await audit(ctx.db, ctx, body.owner_identity_id && body.owner_identity_id !== p.owner_identity_id ? 'project.ownership_transferred' : 'project.updated', { targetType: 'project', targetId: p.id, projectId: p.id, data: Object.fromEntries(set) });
    return getProject(ctx, p.id);
  });
  r.post('/api/projects/:id/archive', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'project:manage');
    await ctx.db.query('UPDATE projects SET archived_at=CASE WHEN $2 THEN now() ELSE NULL END WHERE id=$1', [p.id, body.archive !== false]);
    await audit(ctx.db, ctx, body.archive !== false ? 'project.archived' : 'project.restored', { targetType: 'project', targetId: p.id, projectId: p.id });
    return { ok: true };
  });
  r.post('/api/projects/:id/services', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'project:manage'); need(body, ['key']);
    if (!KEY_RE.test(body.key)) throw badRequest('Invalid service key.');
    const sid = id('svc');
    await ctx.db.query(`INSERT INTO services (id, org_id, project_id, key, name, kind, owner_team_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [sid, p.org_id, p.id, body.key, body.name || body.key, body.kind || 'application', body.owner_team_id || null]).catch(e => { throw /unique|duplicate/i.test(e.message) ? conflict('Service key exists.') : e; });
    await markOnboarding(ctx.db, p.id, 'services');
    await audit(ctx.db, ctx, 'service.created', { targetType: 'service', targetId: sid, projectId: p.id, data: { key: body.key } });
    return { id: sid };
  });
  r.post('/api/projects/:id/environments', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'project:manage'); need(body, ['key']);
    if (body.timezone && !isValidTimeZone(body.timezone)) throw badRequest('Invalid IANA timezone.');
    const eid = id('env');
    await ctx.db.query(`INSERT INTO environments (id, org_id, project_id, key, name, is_production, exposure, timezone) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [eid, p.org_id, p.id, body.key, body.name || body.key, !!body.is_production, body.exposure ? oneOf(body.exposure, EXPO, 'exposure') : 'internal', body.timezone || 'Asia/Ho_Chi_Minh']).catch(e => { throw /unique|duplicate/i.test(e.message) ? conflict('Environment key exists.') : e; });
    await markOnboarding(ctx.db, p.id, 'environments');
    await audit(ctx.db, ctx, 'environment.created', { targetType: 'environment', targetId: eid, projectId: p.id, data: { key: body.key } });
    return { id: eid };
  });
  r.post('/api/projects/:id/repositories', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'project:manage'); need(body, ['provider', 'full_name']);
    const rid = id('repo');
    await ctx.db.query(`INSERT INTO repositories (id, org_id, project_id, provider, full_name, default_branch, connection_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [rid, p.org_id, p.id, body.provider, body.full_name, body.default_branch || 'main', body.connection_id || null]);
    return { id: rid };
  });
  r.get('/api/projects/:id/members', async ({ ctx, params }) => { await requireProject(ctx, params.id); return ctx.db.query('SELECT pa.*, i.display_name, i.email FROM project_access pa JOIN identities i ON i.id=pa.identity_id WHERE pa.project_id=$1', [params.id]); });
  r.put('/api/projects/:id/members/:identity', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'project:members'); oneOf(body.role, PROJECT_ROLES, 'role');
    if (!(await ctx.db.one('SELECT 1 FROM memberships WHERE identity_id=$1 AND org_id=$2', [params.identity, ctx.orgId]))) throw badRequest('Identity is not an organization member.');
    await ctx.db.query(`INSERT INTO project_access (id, project_id, identity_id, role, granted_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (project_id, identity_id) DO UPDATE SET role=EXCLUDED.role`, [id('pa'), p.id, params.identity, body.role, ctx.identity.id]);
    await audit(ctx.db, ctx, 'project.member_set', { targetType: 'identity', targetId: params.identity, projectId: p.id, data: { role: body.role } });
    return { ok: true };
  });
  r.delete('/api/projects/:id/members/:identity', async ({ ctx, params }) => {
    const p = await requireProject(ctx, params.id, 'project:members');
    await ctx.db.query('DELETE FROM project_access WHERE project_id=$1 AND identity_id=$2', [p.id, params.identity]);
    await audit(ctx.db, ctx, 'project.member_removed', { targetType: 'identity', targetId: params.identity, projectId: p.id });
  });
  r.get('/api/projects/:id/activity', async ({ ctx, params, query }) => { await requireProject(ctx, params.id); return ctx.db.query(`SELECT a.*, i.display_name AS actor_name FROM audit_events a LEFT JOIN identities i ON i.id=a.actor_id WHERE a.project_id=$1 ORDER BY a.seq DESC LIMIT $2`, [params.id, clampInt(query.limit, 50, 1, 200)]); });
  r.get('/api/projects/:id/coverage', async ({ ctx, params }) => { await requireProject(ctx, params.id); return projectCoverage(ctx.db, params.id); });
  r.get('/api/projects/:id/knowledge', async ({ ctx, params }) => { await requireProject(ctx, params.id); return ctx.db.query('SELECT * FROM knowledge_items WHERE project_id=$1 ORDER BY created_at DESC', [params.id]); });
  r.post('/api/projects/:id/knowledge', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'knowledge:write'); need(body, ['title', 'body']);
    const kid = id('kn');
    await ctx.db.query(`INSERT INTO knowledge_items (id, org_id, project_id, title, body, kind, evidence_ref, reviewed_by, expires_at, revalidate_on) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [kid, p.org_id, p.id, body.title, body.body, body.kind || 'assumption', body.evidence_ref || null, ctx.identity.id, body.expires_at || null, JSON.stringify(body.revalidate_on || [])]);
    await audit(ctx.db, ctx, 'knowledge.created', { targetType: 'knowledge', targetId: kid, projectId: p.id });
    return { id: kid };
  });
  r.get('/api/projects/:id/drafts/:section', async ({ ctx, params }) => { await requireProject(ctx, params.id); return (await ctx.db.one('SELECT data, updated_at, updated_by FROM draft_configs WHERE project_id=$1 AND section=$2', [params.id, params.section])) || { data: null }; });
  r.put('/api/projects/:id/drafts/:section', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'project:manage');
    if (JSON.stringify(body).length > 50000) throw badRequest('Draft too large.');
    if (/(sk-|ghp_|github_pat_|AKIA|xox[bp]-|-----BEGIN)/.test(JSON.stringify(body))) throw badRequest('Drafts must not contain secret values. Store credentials in the encrypted secret store and reference them.');
    await ctx.db.query(`INSERT INTO draft_configs (id, org_id, project_id, section, data, updated_by) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (project_id, section) DO UPDATE SET data=EXCLUDED.data, updated_by=EXCLUDED.updated_by, updated_at=now()`, [id('drf'), p.org_id, p.id, String(params.section).slice(0, 40), body, ctx.identity.id]);
    return { saved: true, note: 'Draft saved server-side. Drafts do not activate integrations.' };
  });

  // ---------------- inventory
  r.get('/api/projects/:id/inventory', async ({ ctx, params, query }) => {
    await requireProject(ctx, params.id);
    const rows = await deployedInventory(ctx.db, params.id, { environmentId: query.environment_id || null, componentName: query.q || null });
    return { total: rows.length, items: rows.slice(0, clampInt(query.limit, 300, 1, 2000)) };
  });
  r.get('/api/projects/:id/snapshots', async ({ ctx, params }) => { await requireProject(ctx, params.id); return ctx.db.query(`SELECT s.*, a.digest, ast.name AS asset_name FROM inventory_snapshots s LEFT JOIN artifacts a ON a.id=s.artifact_id LEFT JOIN assets ast ON ast.id=s.asset_id WHERE s.project_id=$1 ORDER BY s.created_at DESC LIMIT 100`, [params.id]); });
  r.get('/api/snapshots/:id/diff', async ({ ctx, params, query }) => {
    const s = await ctx.db.one('SELECT * FROM inventory_snapshots WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!s) throw notFound('Snapshot');
    await requireProject(ctx, s.project_id);
    const prev = query.against || (await ctx.db.one(`SELECT id FROM inventory_snapshots WHERE project_id=$1 AND created_at < $2 AND ((artifact_id IS NOT NULL AND artifact_id IN (SELECT id FROM artifacts WHERE service_id=(SELECT service_id FROM artifacts WHERE id=$3))) OR (asset_id IS NOT NULL AND asset_id=$4) OR (source=$5)) ORDER BY created_at DESC LIMIT 1`, [s.project_id, s.created_at, s.artifact_id, s.asset_id, s.source]))?.id;
    return snapshotDiff(ctx.db, prev || null, s.id);
  });
  r.get('/api/projects/:id/artifacts', async ({ ctx, params }) => { await requireProject(ctx, params.id); return ctx.db.query(`SELECT a.*, s.key AS service FROM artifacts a LEFT JOIN services s ON s.id=a.service_id WHERE a.project_id=$1 ORDER BY a.created_at DESC LIMIT 100`, [params.id]); });
  r.get('/api/projects/:id/deployments', async ({ ctx, params }) => { await requireProject(ctx, params.id); return ctx.db.query(`SELECT d.*, s.key AS service, e.key AS environment, e.is_production, a.digest, a.version, a.commit_sha FROM deployments d JOIN services s ON s.id=d.service_id JOIN environments e ON e.id=d.environment_id JOIN artifacts a ON a.id=d.artifact_id WHERE d.project_id=$1 ORDER BY d.deployed_at DESC LIMIT 200`, [params.id]); });
  r.get('/api/assets', async ({ ctx, query }) => {
    const ids = await accessibleProjectIds(ctx);
    return ctx.db.query(`SELECT a.*, json_agg(json_build_object('project_id', p.id, 'project', p.key, 'environment', e.key)) AS projects FROM assets a JOIN asset_projects ap ON ap.asset_id=a.id JOIN projects p ON p.id=ap.project_id LEFT JOIN environments e ON e.id=ap.environment_id WHERE a.org_id=$1 AND ap.project_id = ANY($2) AND ($3::text IS NULL OR a.name ILIKE '%'||$3||'%') GROUP BY a.id ORDER BY a.name LIMIT 300`, [ctx.orgId, ids, query.q || null]);
  });
  r.get('/api/assets/:id', async ({ ctx, params }) => {
    const ids = await accessibleProjectIds(ctx);
    const a = await ctx.db.one('SELECT * FROM assets WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!a) throw notFound('Asset');
    const links = await ctx.db.query('SELECT ap.*, p.key AS project, e.key AS environment FROM asset_projects ap JOIN projects p ON p.id=ap.project_id LEFT JOIN environments e ON e.id=ap.environment_id WHERE ap.asset_id=$1', [a.id]);
    const visible = links.filter(l => ids.includes(l.project_id)); if (!visible.length) throw notFound('Asset');
    const snaps = await ctx.db.query('SELECT id, source, collection_method, format, component_count, collected_at, created_at FROM inventory_snapshots WHERE asset_id=$1 ORDER BY created_at DESC LIMIT 20', [a.id]);
    const comps = snaps[0] ? await ctx.db.query('SELECT c.*, o.version_kind, o.architecture, o.confidence, o.observed_at, o.stale, o.source FROM observations o JOIN components c ON c.id=o.component_id WHERE o.snapshot_id=$1', [snaps[0].id]) : [];
    const findings = await ctx.db.query(`SELECT f.id, f.advisory_id, f.priority, f.status, p.key AS project FROM findings f JOIN projects p ON p.id=f.project_id WHERE f.asset_id=$1 AND f.project_id = ANY($2)`, [a.id, ids]);
    return { ...a, projects: visible, hidden_project_links: links.length - visible.length, snapshots: snaps, components: comps, findings };
  });
  r.get('/api/components/:id', async ({ ctx, params }) => {
    const ids = await accessibleProjectIds(ctx);
    const c = await ctx.db.one('SELECT * FROM components WHERE id=$1', [params.id]); if (!c) throw notFound('Component');
    const obs = await ctx.db.query(`SELECT o.*, p.key AS project, e.key AS environment, s.key AS service, a.digest, ast.name AS asset FROM observations o JOIN projects p ON p.id=o.project_id LEFT JOIN environments e ON e.id=o.environment_id LEFT JOIN services s ON s.id=o.service_id LEFT JOIN artifacts a ON a.id=o.artifact_id LEFT JOIN assets ast ON ast.id=o.asset_id WHERE o.component_id=$1 AND o.project_id = ANY($2) ORDER BY o.observed_at DESC LIMIT 100`, [c.id, ids]);
    if (!obs.length) throw notFound('Component');
    const findings = await ctx.db.query(`SELECT f.id, f.advisory_id, f.priority, f.status, p.key AS project, e.key AS environment FROM findings f JOIN projects p ON p.id=f.project_id LEFT JOIN environments e ON e.id=f.environment_id WHERE f.component_id=$1 AND f.project_id = ANY($2)`, [c.id, ids]);
    return { ...c, observations: obs, findings };
  });

  // ---------------- import workbench (preview = dry run; commit = immutable snapshot + receipt)
  const parseImport = (app, body) => {
    need(body, ['content']);
    if (Buffer.byteLength(body.content) > app.cfg.maxUploadBytes) throw new AppError(413, 'PAYLOAD_TOO_LARGE', 'File too large.');
    if (body.filename && /\.(zip|tar|gz|tgz|7z|rar|xls|xlsm)$/i.test(body.filename)) throw badRequest('Archives, legacy .xls and macro-enabled workbooks are not accepted; upload XLSX, CycloneDX/SPDX JSON, Trivy JSON, SARIF, CSV, JSON or YAML.');
    if (/\.xlsx$/i.test(body.filename || '') && body.encoding !== 'base64') throw badRequest('XLSX content must be sent base64-encoded with encoding="base64".');
    try { return parseDocument(body.content, { filename: body.filename || '', format: body.format }); } catch (e) { throw new AppError(422, 'IMPORT_INVALID', e instanceof ParseError ? e.message : 'Could not parse: ' + e.message, e.errors); }
  };
  r.post('/api/projects/:id/imports/preview', async ({ ctx, params, body, app }) => {
    const p = await requireProject(ctx, params.id, 'inventory:write');
    const parsed = parseImport(app, body);
    const prev = await findTargetSnapshot(ctx.db, p.id, body.target || {});
    let diff = null;
    if (prev) { const prevRows = await ctx.db.query('SELECT c.ecosystem, c.name, c.version FROM observations o JOIN components c ON c.id=o.component_id WHERE o.snapshot_id=$1', [prev.id]); const key = r => `${r.ecosystem}:${r.name}`; const A = new Map(prevRows.map(r => [key(r), r])); const B = new Map(parsed.components.map(r => [key(r), r])); diff = { added: [...B.keys()].filter(k => !A.has(k)).length, removed: [...A.keys()].filter(k => !B.has(k)).length, changed: [...B.entries()].filter(([k, v]) => A.has(k) && A.get(k).version !== v.version).length }; }
    const dup = await ctx.db.one('SELECT id, created_at FROM ingestions WHERE project_id=$1 AND idempotency_key=$2', [p.id, 'import:' + sha256(body.content) + ':' + JSON.stringify(body.target || {})]);
    return { dry_run: true, format: parsed.format, accepted: parsed.components.length, rejected: parsed.errors.filter(e => e.severity !== 'warning').length, warnings: parsed.errors.filter(e => e.severity === 'warning').length, errors: parsed.errors.slice(0, 200), sample: parsed.components.slice(0, 50).map(c => ({ ecosystem: c.ecosystem, name: c.name, version: c.version, kind: c.kind, direct: c.direct, purl: c.purl })), scanner_findings: parsed.findings.length, diff_vs_previous: diff, duplicate_of: dup?.id || null, metadata: parsed.metadata };
  });
  r.post('/api/projects/:id/imports/commit', async ({ ctx, params, body, app }) => {
    const p = await requireProject(ctx, params.id, 'inventory:write');
    const parsed = parseImport(app, body);
    const t = body.target || {}; oneOf(t.kind, ['asset', 'artifact', 'repository'], 'target.kind');
    const key = 'import:' + sha256(body.content) + ':' + JSON.stringify(t);
    return ctx.db.tx(async (tx) => {
      const dup = await tx.one('SELECT * FROM ingestions WHERE project_id=$1 AND idempotency_key=$2', [p.id, key]);
      if (dup) return { duplicate: true, receipt: dup.receipt };
      let assetId = null, artifactId = null, envId = null;
      if (t.environment_id) { const e = await tx.one('SELECT id FROM environments WHERE project_id=$1 AND (id=$2 OR key=$2)', [p.id, t.environment_id]); if (!e) throw badRequest('Unknown environment.'); envId = e.id; }
      if (t.kind === 'asset') {
        need(t, ['identifier', 'asset_kind']);
        const a = (await tx.query(`INSERT INTO assets (id, org_id, kind, identifier, name, architecture, os, attributes, last_observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now()) ON CONFLICT (org_id, kind, identifier) DO UPDATE SET last_observed_at=now(), architecture=COALESCE(EXCLUDED.architecture, assets.architecture), attributes=assets.attributes || EXCLUDED.attributes RETURNING id`, [id('ast'), p.org_id, t.asset_kind, t.identifier, t.name || t.identifier, t.architecture || null, t.os || null, t.attributes || {}]))[0];
        assetId = a.id;
        await tx.query(`INSERT INTO asset_projects (asset_id, project_id, environment_id) VALUES ($1,$2,$3) ON CONFLICT (asset_id, project_id) DO UPDATE SET environment_id=COALESCE(EXCLUDED.environment_id, asset_projects.environment_id)`, [assetId, p.id, envId]);
      } else if (t.kind === 'artifact') {
        need(t, ['digest', 'service_id']);
        if (!/^sha(256|384|512):[a-f0-9]{64,128}$/.test(t.digest)) throw badRequest('Artifact digest must be immutable (sha256:...).');
        const svc = await tx.one('SELECT id FROM services WHERE project_id=$1 AND (id=$2 OR key=$2)', [p.id, t.service_id]); if (!svc) throw badRequest('Unknown service.');
        artifactId = (await tx.one('SELECT id FROM artifacts WHERE project_id=$1 AND digest=$2', [p.id, t.digest]))?.id || (await tx.query(`INSERT INTO artifacts (id, org_id, project_id, service_id, digest, version) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, [id('art'), p.org_id, p.id, svc.id, t.digest, t.version || null]))[0].id;
      }
      const objectKey = await app.objects.put(`${p.org_id}/${p.id}/imports/${sha256(body.content)}`, Buffer.from(body.content));
      const snap = await recordSnapshot(tx, { orgId: p.org_id, projectId: p.id, assetId, artifactId, environmentId: envId, source: t.kind === 'repository' ? 'upload:repository' : 'upload', method: t.kind === 'repository' ? 'discovery_upload' : 'manual_import', parsed, contentSha256: contentHash(body.content), objectKey, versionKind: t.kind === 'repository' ? 'declared' : t.version_kind || (t.kind === 'asset' ? 'runtime' : 'artifact'), confidence: 'reported' });
      const iid = id('ing');
      const receipt = { ingestion_id: iid, snapshot_id: snap.snapshotId, content_sha256: contentHash(body.content), accepted: parsed.components.length, rejected: parsed.errors.filter(e => e.severity !== 'warning').length, received_at: new Date().toISOString(), immutable: true };
      await tx.query(`INSERT INTO ingestions (id, org_id, project_id, idempotency_key, kind, status, receipt, request_meta, object_key, snapshot_id, stats, created_by, completed_at) VALUES ($1,$2,$3,$4,'import','completed',$5,$6,$7,$8,$9,$10,now())`, [iid, p.org_id, p.id, key, receipt, { filename: body.filename, target: t }, objectKey, snap.snapshotId, { errors: parsed.errors.slice(0, 200) }, ctx.identity.id]);
      await markOnboarding(tx, p.id, 'first_ingestion', { snapshot_id: snap.snapshotId });
      await audit(tx, ctx, 'inventory.imported', { targetType: 'snapshot', targetId: snap.snapshotId, projectId: p.id, data: { format: parsed.format, accepted: parsed.components.length, target: t.kind } });
      return { duplicate: false, receipt };
    });
  }, { maxBody: 12 * 1024 * 1024 });
  r.get('/api/projects/:id/ingestions', async ({ ctx, params }) => { await requireProject(ctx, params.id); return ctx.db.query('SELECT id, kind, status, receipt, stats, error, created_at, completed_at FROM ingestions WHERE project_id=$1 ORDER BY created_at DESC LIMIT 100', [params.id]); });
  r.post('/api/projects/:id/overrides', async ({ ctx, params, body }) => {
    const p = await requireProject(ctx, params.id, 'inventory:write'); need(body, ['target', 'field', 'value', 'reason', 'expires_at']);
    if (body.reason.length < 10) throw badRequest('Reason must be at least 10 characters.');
    const oid = id('ovr');
    await ctx.db.query(`INSERT INTO inventory_overrides (id, org_id, project_id, target, field, value, reason, requested_by, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [oid, p.org_id, p.id, body.target, body.field, JSON.stringify(body.value), body.reason, ctx.identity.id, body.expires_at]);
    await audit(ctx.db, ctx, 'inventory.override_requested', { targetType: 'override', targetId: oid, projectId: p.id, data: body });
    return { id: oid, status: 'pending_approval' };
  });
  r.post('/api/overrides/:id/approve', async ({ ctx, params }) => {
    const o = await ctx.db.one('SELECT * FROM inventory_overrides WHERE id=$1 AND org_id=$2', [params.id, ctx.orgId]); if (!o) throw notFound('Override');
    await requireProject(ctx, o.project_id, 'exceptions:approve');
    if (o.requested_by === ctx.identity.id) throw new AppError(403, 'FORBIDDEN', 'Requester cannot approve their own override.');
    await ctx.db.query('UPDATE inventory_overrides SET approved_by=$2 WHERE id=$1', [o.id, ctx.identity.id]);
    await audit(ctx.db, ctx, 'inventory.override_approved', { targetType: 'override', targetId: o.id, projectId: o.project_id });
    return { ok: true };
  });
  r.get('/api/projects/:id/overrides', async ({ ctx, params }) => { await requireProject(ctx, params.id); return ctx.db.query('SELECT * FROM inventory_overrides WHERE project_id=$1 ORDER BY created_at DESC', [params.id]); });
}

async function findTargetSnapshot(db, projectId, t) {
  if (t.kind === 'asset' && t.identifier) return db.one(`SELECT s.id FROM inventory_snapshots s JOIN assets a ON a.id=s.asset_id WHERE s.project_id=$1 AND a.identifier=$2 ORDER BY s.created_at DESC LIMIT 1`, [projectId, t.identifier]);
  if (t.kind === 'artifact' && t.service_id) return db.one(`SELECT s.id FROM inventory_snapshots s JOIN artifacts a ON a.id=s.artifact_id JOIN services sv ON sv.id=a.service_id WHERE s.project_id=$1 AND (sv.id=$2 OR sv.key=$2) ORDER BY s.created_at DESC LIMIT 1`, [projectId, t.service_id]);
  if (t.kind === 'repository') return db.one(`SELECT id FROM inventory_snapshots WHERE project_id=$1 AND collection_method IN ('repository_scan','discovery_upload') ORDER BY created_at DESC LIMIT 1`, [projectId]);
  return null;
}
export async function markOnboarding(db, projectId, step, data = {}) {
  await db.query(`UPDATE projects SET onboarding = onboarding || jsonb_build_object($2::text, $3::jsonb) WHERE id=$1`, [projectId, step, { done: true, at: new Date().toISOString(), ...data }]);
}

async function getProject(ctx, projectId) {
  const p = await requireProject(ctx, projectId);
  const db = ctx.db;
  const [services, environments, repositories, deployments, connections, members] = await Promise.all([
    db.query('SELECT s.*, t.name AS team FROM services s LEFT JOIN teams t ON t.id=s.owner_team_id WHERE s.project_id=$1 ORDER BY s.key', [p.id]),
    db.query('SELECT * FROM environments WHERE project_id=$1 ORDER BY is_production DESC, key', [p.id]),
    db.query('SELECT * FROM repositories WHERE project_id=$1', [p.id]),
    db.query(`SELECT d.id, s.key AS service, e.key AS environment, e.is_production, a.digest, a.version, a.commit_sha, d.deployed_at FROM deployments d JOIN services s ON s.id=d.service_id JOIN environments e ON e.id=d.environment_id JOIN artifacts a ON a.id=d.artifact_id WHERE d.project_id=$1 AND d.is_current ORDER BY s.key, e.key`, [p.id]),
    db.query(`SELECT id, kind, name, status, last_success_at, last_error FROM connections WHERE project_id=$1`, [p.id]),
    db.query('SELECT pa.identity_id, pa.role, i.display_name, i.email FROM project_access pa JOIN identities i ON i.id=pa.identity_id WHERE pa.project_id=$1', [p.id]),
  ]);
  const owner = p.owner_identity_id ? await db.one('SELECT id, display_name, email FROM identities WHERE id=$1', [p.owner_identity_id]) : null;
  const counts = await db.one(`SELECT count(*) FILTER (WHERE status NOT IN ('verified_fixed','false_positive','accepted_risk'))::int AS open, count(*) FILTER (WHERE priority IN ('P0','P1') AND status NOT IN ('verified_fixed','false_positive','accepted_risk'))::int AS urgent, count(*) FILTER (WHERE status='verified_fixed')::int AS verified FROM findings WHERE project_id=$1`, [p.id]);
  const onboarding = p.onboarding || {};
  const steps = ['metadata', 'services', 'environments', 'connection', 'discovery', 'conflicts', 'inventory', 'policy', 'first_ingestion'].map(k => ({ step: k, done: !!onboarding[k]?.done, at: onboarding[k]?.at || null }));
  return { ...p, owner, services, environments, repositories, deployments, connections, members, finding_counts: counts, onboarding_steps: steps, protected_note: 'Completing onboarding does not mean the project is protected; coverage and verified ingestion determine trust.', my_permissions: [...projectPermissions(ctx, p.id)] };
}
export { getProject };
