// Coverage and blind spots: where assessments cannot be trusted. Missing or stale inventory is a coverage problem,
// never evidence that no vulnerability exists.
const STALE_DAYS = 7;

export async function projectCoverage(db, projectId) {
  const services = await db.query('SELECT id, key FROM services WHERE project_id=$1', [projectId]);
  const envs = await db.query('SELECT id, key, is_production FROM environments WHERE project_id=$1', [projectId]);
  const deps = await db.query(`SELECT d.service_id, d.environment_id, d.deployed_at, a.digest, (SELECT format FROM inventory_snapshots s WHERE s.artifact_id=d.artifact_id ORDER BY created_at DESC LIMIT 1) AS sbom_format,
      (SELECT created_at FROM inventory_snapshots s WHERE s.artifact_id=d.artifact_id ORDER BY created_at DESC LIMIT 1) AS sbom_at FROM deployments d JOIN artifacts a ON a.id=d.artifact_id WHERE d.project_id=$1 AND d.is_current`, [projectId]);
  const gaps = [];
  for (const s of services) for (const e of envs) {
    const d = deps.find(x => x.service_id === s.id && x.environment_id === e.id);
    if (!d) gaps.push({ kind: 'no_deployment_record', severity: e.is_production ? 'high' : 'medium', service: s.key, environment: e.key, detail: 'No deployment recorded; what runs here is unknown.' });
    else if (!d.sbom_format) gaps.push({ kind: 'missing_sbom', severity: e.is_production ? 'high' : 'medium', service: s.key, environment: e.key, detail: `Deployed artifact ${d.digest} has no SBOM.` });
    else if (Date.now() - new Date(d.sbom_at) > STALE_DAYS * 86400000) gaps.push({ kind: 'stale_inventory', severity: 'medium', service: s.key, environment: e.key, detail: `SBOM older than ${STALE_DAYS} days.` });
  }
  const stale = await db.one('SELECT count(*)::int AS n FROM observations WHERE project_id=$1 AND stale', [projectId]);
  if (stale.n) gaps.push({ kind: 'stale_observations', severity: 'high', detail: `${stale.n} observations are stale (source disconnected or expired).` });
  const unknownVersions = await db.one(`SELECT count(DISTINCT c.id)::int AS n FROM observations o JOIN components c ON c.id=o.component_id WHERE o.project_id=$1 AND c.version IS NULL`, [projectId]);
  if (unknownVersions.n) gaps.push({ kind: 'unknown_versions', severity: 'medium', detail: `${unknownVersions.n} components have no version; matching is Unknown.` });
  const unsupported = await db.one(`SELECT count(DISTINCT c.id)::int AS n FROM observations o JOIN components c ON c.id=o.component_id WHERE o.project_id=$1 AND c.ecosystem='generic'`, [projectId]);
  if (unsupported.n) gaps.push({ kind: 'unsupported_analysis', severity: 'low', detail: `${unsupported.n} components use a generic identity; advisory range matching is limited.` });
  const failed = await db.query(`SELECT name, kind, status, last_error, last_success_at FROM connections WHERE project_id=$1 AND status IN ('failed','degraded','disconnected')`, [projectId]);
  for (const c of failed) gaps.push({ kind: 'connector_' + c.status, severity: 'high', detail: `${c.name} (${c.kind}) is ${c.status}${c.last_error ? ': ' + c.last_error : ''}.` });
  const unowned = await db.one(`SELECT count(*)::int AS n FROM asset_projects ap JOIN assets a ON a.id=ap.asset_id WHERE ap.project_id=$1 AND a.owner_team_id IS NULL`, [projectId]);
  if (unowned.n) gaps.push({ kind: 'unowned_assets', severity: 'low', detail: `${unowned.n} assets have no owning team.` });
  const p = await db.one('SELECT owner_identity_id FROM projects WHERE id=$1', [projectId]);
  if (!p?.owner_identity_id) gaps.push({ kind: 'no_project_owner', severity: 'medium', detail: 'Project has no owner; alerts cannot be routed to a person.' });
  const expected = services.length * envs.length;
  const covered = deps.filter(d => d.sbom_format && Date.now() - new Date(d.sbom_at) <= STALE_DAYS * 86400000).length;
  return { project_id: projectId, expected_scopes: expected, covered_scopes: covered, coverage_ratio: expected ? covered / expected : 0, gaps, assessed_at: new Date().toISOString(), note: 'Coverage = service×environment scopes with a current deployment record and fresh SBOM.' };
}

export async function orgCoverage(db, projectIds) {
  const out = [];
  for (const pid of projectIds) { const p = await db.one('SELECT key, name FROM projects WHERE id=$1', [pid]); out.push({ project_id: pid, project: p.key, name: p.name, ...(await projectCoverage(db, pid)) }); }
  return out;
}
