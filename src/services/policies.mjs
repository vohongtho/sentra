// Versioned priority and SLA policies per organization, optionally overridden per project.
// Saving a policy creates a new version and queues reassessment so every finding records the version it was scored with.
import { id, badRequest } from '../util.mjs';
import { DEFAULT_PRIORITY_POLICY, DEFAULT_SLA_POLICY, validatePriorityPolicy, validateSlaPolicy } from '../domain/policy.mjs';
import { enqueue } from '../jobs/queue.mjs';

export async function loadPolicies(db, orgId, projectId) {
  const rows = await db.query(`SELECT * FROM policies WHERE org_id=$1 AND kind IN ('priority','sla') AND active AND (project_id=$2 OR project_id IS NULL) ORDER BY project_id NULLS FIRST, version`, [orgId, projectId]);
  let priority = { ...DEFAULT_PRIORITY_POLICY }, sla = { ...DEFAULT_SLA_POLICY };
  for (const r of rows) {
    if (r.kind === 'priority') priority = { ...validatePriorityPolicy(r.definition), version: r.version, policy_id: r.id, scope: r.project_id ? 'project' : 'org' };
    if (r.kind === 'sla') sla = { ...validateSlaPolicy(r.definition), version: r.version, policy_id: r.id, scope: r.project_id ? 'project' : 'org' };
  }
  return { priority, sla };
}

export async function savePolicy(db, ctx, kind, { project_id = null, definition }) {
  let def;
  try { def = kind === 'priority' ? validatePriorityPolicy(definition || {}) : validateSlaPolicy(definition || {}); } catch (e) { throw badRequest(e.message); }
  delete def.version; delete def.policy_id; delete def.scope;
  return db.tx(async (t) => {
    const prev = await t.one(`SELECT max(version)::int AS v FROM policies WHERE org_id=$1 AND kind=$2 AND project_id IS NOT DISTINCT FROM $3`, [ctx.orgId, kind, project_id]);
    // Versions start above the built-in v1 so stored policies are distinguishable from the default.
    const version = Math.max(prev?.v || 0, 1) + 1;
    await t.query(`UPDATE policies SET active=false WHERE org_id=$1 AND kind=$2 AND project_id IS NOT DISTINCT FROM $3`, [ctx.orgId, kind, project_id]);
    const pid = id('pol');
    await t.query(`INSERT INTO policies (id, org_id, project_id, kind, version, definition, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [pid, ctx.orgId, project_id, kind, version, def, ctx.identity?.id]);
    await enqueue(t, { type: 'inventory_reassessment', orgId: ctx.orgId, projectId: project_id, payload: { reason: `${kind}_policy_v${version}` }, idempotencyKey: `policy:${pid}` });
    return { id: pid, version, definition: def };
  });
}
