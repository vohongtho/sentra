// Attack-path exploration (spec §10.10). Builds paths from an exposure point through the deployed service and asset to
// open findings. Every edge is labeled:
//   verified — backed by a recorded fact (deployment record, asset link, SBOM observation, asset attribute)
//   inferred — derived from declared metadata (environment/project exposure) without observed network evidence
// Unverified advisory prerequisites are listed per path. Paths are ordered by finding priority; nothing is called safe.
const EXPOSED = ['internet', 'partner'];

export async function projectAttackPaths(db, projectId) {
  const p = await db.one('SELECT id, key, name, exposure FROM projects WHERE id=$1', [projectId]);
  const rows = await db.query(`SELECT f.id, f.advisory_id, f.priority, f.applicability, f.exploitation, f.status, f.observed_version, c.name AS package,
      s.id AS service_id, s.key AS service, e.id AS env_id, e.key AS environment, e.exposure AS env_exposure, e.is_production,
      d.id AS deployment_id, art.digest, ast.id AS asset_id, ast.name AS asset_name, ast.kind AS asset_kind, ast.attributes AS asset_attributes, a.prerequisites
    FROM findings f JOIN components c ON c.id=f.component_id JOIN advisories a ON a.id=f.advisory_id
    LEFT JOIN services s ON s.id=f.service_id LEFT JOIN environments e ON e.id=f.environment_id LEFT JOIN deployments d ON d.id=f.deployment_id
    LEFT JOIN artifacts art ON art.id=f.artifact_id LEFT JOIN assets ast ON ast.id=COALESCE(f.asset_id, d.asset_id)
    WHERE f.project_id=$1 AND f.status NOT IN ('verified_fixed','false_positive') AND f.applicability <> 'not_affected'
    ORDER BY f.priority, f.advisory_id`, [projectId]);
  const nodes = new Map(); const edges = new Map(); const paths = [];
  const node = (id, type, label, extra = {}) => { if (!nodes.has(id)) nodes.set(id, { id, type, label, ...extra }); return id; };
  const edge = (from, to, kind, basis) => { const k = `${from}>${to}`; if (!edges.has(k)) edges.set(k, { from, to, kind, basis }); return edges.get(k); };
  for (const r of rows) {
    const exposure = r.env_exposure || p.exposure;
    const entry = EXPOSED.includes(exposure) ? node(`exposure:${exposure}`, 'exposure', exposure === 'internet' ? 'Internet' : 'Partner network') : node(`exposure:${exposure}`, 'exposure', `${exposure} network`);
    const hops = [];
    const envNode = node(`env:${r.env_id}`, 'environment', `${r.environment}${r.is_production ? ' (production)' : ''}`);
    hops.push(edge(entry, envNode, 'inferred', `Declared exposure "${exposure}" on ${r.env_exposure ? 'environment' : 'project'}; no observed network path.`));
    let last = envNode;
    if (r.service_id) {
      const svc = node(`svc:${r.service_id}:${r.env_id}`, 'service', `${r.service} @ ${r.environment}`, { digest: r.digest });
      hops.push(edge(last, svc, r.deployment_id ? 'verified' : 'inferred', r.deployment_id ? `Deployment record ${r.deployment_id} (artifact ${String(r.digest).slice(0, 19)}…).` : 'No deployment record.'));
      last = svc;
    }
    if (r.asset_id) {
      const ast = node(`asset:${r.asset_id}`, 'asset', `${r.asset_name} (${r.asset_kind})`, { attributes: r.asset_attributes });
      hops.push(edge(last, ast, 'verified', r.service_id ? 'Deployment linked to asset.' : 'Asset observation.'));
      last = ast;
      // Identity and downstream assets come from recorded asset attributes (AWS connector, imports, manual entry).
      const attrs = r.asset_attributes || {};
      if (attrs.identity) { const idn = node(`identity:${attrs.identity}`, 'identity', String(attrs.identity)); edge(ast, idn, 'verified', 'Asset attribute "identity" (e.g. execution role / instance profile).'); }
      for (const d of [].concat(attrs.downstream || [])) {
        const target = typeof d === 'string' ? d : d.target; if (!target) continue;
        const dn = node(`downstream:${target}`, 'downstream', String(target), { via: d.via || null });
        edge(ast, dn, d.observed ? 'verified' : 'inferred', d.observed ? `Observed connection${d.via ? ' via ' + d.via : ''}.` : `Declared dependency${d.via ? ' via ' + d.via : ''}; not observed.`);
      }
    }
    const fn = node(`finding:${r.id}`, 'finding', `${r.advisory_id} in ${r.package}@${r.observed_version || '?'}`, { priority: r.priority, applicability: r.applicability, exploitation: r.exploitation });
    hops.push(edge(last, fn, r.applicability === 'affected' ? 'verified' : 'inferred', r.applicability === 'affected' ? 'Vulnerable version observed in deployed inventory.' : `Applicability ${r.applicability}: presence observed, exploitability not established.`));
    const prereqs = (r.prerequisites || []).map(pr => {
      const attr = pr.attribute ? r.asset_attributes?.[pr.attribute] : undefined;
      return { prerequisite: `${pr.kind}: ${pr.value}`, status: attr === undefined ? 'unknown' : String(attr) === String(pr.required_value) ? 'met' : 'not_met', evidence: attr === undefined ? null : `${pr.attribute}=${attr}` };
    });
    const attrs = r.asset_attributes || {};
    const blast = [attrs.identity ? { type: 'identity', target: attrs.identity, kind: 'verified' } : null, ...[].concat(attrs.downstream || []).map(d => ({ type: 'downstream', target: typeof d === 'string' ? d : d.target, kind: d.observed ? 'verified' : 'inferred' }))].filter(Boolean);
    paths.push({ blast_radius: blast, finding_id: r.id, priority: r.priority, exploitation: r.exploitation, entry: nodes.get(entry).label, hops: hops.map(h => ({ ...h, from_label: nodes.get(h.from).label, to_label: nodes.get(h.to).label })), verified_hops: hops.filter(h => h.kind === 'verified').length, inferred_hops: hops.filter(h => h.kind === 'inferred').length, prerequisites: prereqs, blocked_by_prerequisite: prereqs.some(x => x.status === 'not_met') });
  }
  return { project: p.key, nodes: [...nodes.values()], edges: [...edges.values()], paths, legend: { verified: 'Backed by a recorded deployment, asset link, SBOM observation or asset attribute.', inferred: 'Derived from declared exposure or unestablished applicability; confirm before relying on it.' }, limits: 'Identity and downstream edges exist only where recorded as asset attributes (identity, downstream). Network reachability from the exposure point to the service is declared, never observed.' };
}
