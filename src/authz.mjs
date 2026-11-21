// Deterministic authorization. Every project-scoped read/write goes through requireProject/accessibleProjectIds.
// Client-supplied org/project IDs are never trusted as proof of access.
import { AppError, notFound, forbidden } from './util.mjs';

export const ORG_ROLES = ['org_admin', 'security_analyst', 'member', 'management_viewer', 'auditor'];
export const PROJECT_ROLES = ['project_owner', 'tech_lead', 'developer', 'devops', 'viewer'];

const READ = ['project:read', 'export'];
const PROJECT_PERMS = {
  project_owner: [...READ, 'project:manage', 'project:members', 'inventory:write', 'findings:write', 'findings:triage', 'exceptions:request', 'exceptions:approve', 'investigations:run', 'tickets:write', 'deployments:write', 'ci_tokens:manage', 'connections:manage', 'alerts:manage', 'schedules:manage', 'agent_policies:manage', 'knowledge:write'],
  tech_lead: [...READ, 'inventory:write', 'findings:write', 'findings:triage', 'exceptions:request', 'investigations:run', 'tickets:write', 'deployments:write', 'connections:manage', 'knowledge:write'],
  developer: [...READ, 'findings:write', 'investigations:run', 'tickets:write'],
  devops: [...READ, 'inventory:write', 'deployments:write', 'ci_tokens:manage', 'connections:manage', 'investigations:run'],
  viewer: [...READ],
};
// Org-wide roles implicitly grant per-project permissions across the organization.
const ORG_PROJECT_PERMS = {
  org_admin: new Set(Object.values(PROJECT_PERMS).flat()),
  security_analyst: new Set([...READ, 'inventory:write', 'findings:write', 'findings:triage', 'exceptions:request', 'exceptions:approve', 'investigations:run', 'tickets:write', 'alerts:manage', 'schedules:manage', 'knowledge:write']),
  management_viewer: new Set(READ),
  auditor: new Set(READ),
  member: new Set(),
};
const ORG_PERMS = {
  org_admin: ['org:admin', 'org:read', 'audit:read', 'advisories:write', 'alerts:manage', 'schedules:manage', 'agent_policies:manage', 'projects:create', 'connections:manage', 'campaigns:manage'],
  security_analyst: ['org:read', 'advisories:write', 'alerts:manage', 'schedules:manage', 'projects:create', 'campaigns:manage', 'connections:manage'],
  management_viewer: ['org:read'],
  auditor: ['org:read', 'audit:read'],
  member: [],
};

export function projectPermissions(ctx, projectId) {
  const set = new Set(ORG_PROJECT_PERMS[ctx.orgRole] || []);
  const role = ctx.projectRoles?.get(projectId);
  if (role) for (const p of PROJECT_PERMS[role] || []) set.add(p);
  return set;
}
export const hasOrgPerm = (ctx, perm) => (ORG_PERMS[ctx.orgRole] || []).includes(perm);
export function requireOrg(ctx, perm) {
  if (!ctx.identity && ctx.actorType !== 'system') throw new AppError(401, 'LOGIN_REQUIRED', 'Sign in required.');
  if (ctx.actorType === 'system') return;
  if (!hasOrgPerm(ctx, perm)) throw forbidden();
}
export const orgWide = (ctx) => ['org_admin', 'security_analyst', 'management_viewer', 'auditor'].includes(ctx.orgRole) || ctx.actorType === 'system';

/** Project ids this principal may read. CI tokens are pinned to exactly one project. */
export async function accessibleProjectIds(ctx, db = ctx.db) {
  if (ctx.actorType === 'ci') return [ctx.ciToken.project_id];
  if (ctx.actorType === 'system') return (await db.query('SELECT id FROM projects WHERE org_id=$1', [ctx.orgId])).map(r => r.id);
  if (orgWide(ctx)) return (await db.query('SELECT id FROM projects WHERE org_id=$1 AND archived_at IS NULL', [ctx.orgId])).map(r => r.id);
  return [...(ctx.projectRoles?.keys() || [])];
}

/** Load a project the principal can access; 404 when unreadable (no existence leak), 403 when readable but perm missing. */
export async function requireProject(ctx, projectId, perm = 'project:read', db = ctx.db) {
  if (!projectId || typeof projectId !== 'string') throw notFound('Project');
  const p = await db.one('SELECT * FROM projects WHERE id=$1 AND org_id=$2', [projectId, ctx.orgId]);
  if (!p) throw notFound('Project');
  if (ctx.actorType === 'system') return p;
  if (ctx.actorType === 'ci') {
    if (ctx.ciToken.project_id !== projectId) throw notFound('Project');
    const scopeFor = { 'inventory:write': 'ingest:sbom', 'deployments:write': 'deployments:write', 'project:read': 'policy:read' };
    if (!ctx.ciToken.scopes.includes(scopeFor[perm] || '__none__')) throw forbidden('CI token scope does not permit this action.');
    return p;
  }
  const perms = projectPermissions(ctx, projectId);
  if (!perms.has('project:read')) throw notFound('Project');
  if (!perms.has(perm)) throw forbidden(`Missing permission ${perm} on project ${p.key}.`);
  return p;
}

/** Build the principal for a human identity: org membership + project roles, loaded fresh per request so role changes apply immediately. */
export async function loadPrincipal(db, identity, orgId) {
  const m = orgId
    ? await db.one('SELECT m.*, o.slug, o.name AS org_name FROM memberships m JOIN organizations o ON o.id=m.org_id WHERE m.identity_id=$1 AND m.org_id=$2', [identity.id, orgId])
    : await db.one('SELECT m.*, o.slug, o.name AS org_name FROM memberships m JOIN organizations o ON o.id=m.org_id WHERE m.identity_id=$1 ORDER BY m.created_at LIMIT 1', [identity.id]);
  if (!m || identity.disabled) return null;
  const rows = await db.query('SELECT pa.project_id, pa.role FROM project_access pa JOIN projects p ON p.id=pa.project_id WHERE pa.identity_id=$1 AND p.org_id=$2', [identity.id, m.org_id]);
  return { identity, orgId: m.org_id, orgSlug: m.slug, orgName: m.org_name, orgRole: m.org_role, projectRoles: new Map(rows.map(r => [r.project_id, r.role])), actorType: 'user' };
}

export function permissionMatrix() { return { org: ORG_PERMS, project: PROJECT_PERMS, org_project_implicit: Object.fromEntries(Object.entries(ORG_PROJECT_PERMS).map(([k, v]) => [k, [...v]])) }; }
