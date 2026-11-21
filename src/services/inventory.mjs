// Inventory: components, immutable snapshots, observations, dependency edges, snapshot diffs.
import { id, sha256 } from '../util.mjs';
import { emit } from '../jobs/runtime.mjs';

export async function upsertComponent(db, c) {
  const row = await db.one('SELECT id FROM components WHERE purl=$1', [c.purl]);
  if (row) return row.id;
  const cid = id('cmp');
  await db.query(`INSERT INTO components (id, purl, ecosystem, namespace, name, version, kind, cpe, distro) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (purl) DO NOTHING`,
    [cid, c.purl, c.ecosystem, c.namespace || null, c.name, c.version || null, c.kind || 'library', c.cpe || null, c.distro || null]);
  return (await db.one('SELECT id FROM components WHERE purl=$1', [c.purl])).id;
}

/**
 * Persist an immutable snapshot of a parsed document. Must be called inside a transaction (db = tx handle).
 * @returns {{snapshotId, componentCount, observationIds}}
 */
export async function recordSnapshot(db, { orgId, projectId, artifactId = null, assetId = null, environmentId = null, serviceId = null, source, method, parsed, contentSha256, objectKey = null, collectedAt = new Date().toISOString(), versionKind = 'resolved', confidence = 'reported' }) {
  const snapshotId = id('snp');
  await db.query(`INSERT INTO inventory_snapshots (id, org_id, project_id, artifact_id, asset_id, source, collection_method, format, content_sha256, object_key, component_count, collected_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [snapshotId, orgId, projectId, artifactId, assetId, source, method, parsed.format, contentSha256, objectKey, parsed.components.length, collectedAt]);
  const refToComp = new Map(); const seen = new Set();
  for (const c of parsed.components) {
    const cid = await upsertComponent(db, c);
    refToComp.set(c.ref || c.purl, cid);
    if (seen.has(cid)) continue; seen.add(cid);
    await db.query(`INSERT INTO observations (id, org_id, project_id, snapshot_id, component_id, artifact_id, asset_id, environment_id, service_id, version_kind, direct, dependency_path, architecture, confidence, source, observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [id('obs'), orgId, projectId, snapshotId, cid, artifactId, assetId, environmentId, serviceId, c.version_kind || versionKind, c.direct ?? null, JSON.stringify(c.dependency_path || []), c.architecture || null, confidence, source, collectedAt]);
  }
  for (const [p, ch] of parsed.edges || []) {
    const a = refToComp.get(p), b = refToComp.get(ch);
    if (a && b && a !== b) await db.query('INSERT INTO dependency_edges (snapshot_id, parent_component_id, child_component_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [snapshotId, a, b]);
  }
  await emit(db, orgId, 'inventory.updated', { project_id: projectId, snapshot_id: snapshotId, artifact_id: artifactId, asset_id: assetId, environment_id: environmentId });
  return { snapshotId, componentCount: seen.size };
}

export async function snapshotDiff(db, fromId, toId) {
  const q = 'SELECT c.purl, c.ecosystem, c.name, c.version FROM observations o JOIN components c ON c.id=o.component_id WHERE o.snapshot_id=$1';
  const a = fromId ? await db.query(q, [fromId]) : []; const b = await db.query(q, [toId]);
  const key = (r) => `${r.ecosystem}:${r.name}`;
  const A = new Map(a.map(r => [key(r), r])), B = new Map(b.map(r => [key(r), r]));
  const added = [], removed = [], changed = [];
  for (const [k, r] of B) { if (!A.has(k)) added.push(r); else if (A.get(k).version !== r.version) changed.push({ name: r.name, ecosystem: r.ecosystem, from: A.get(k).version, to: r.version }); }
  for (const [k, r] of A) if (!B.has(k)) removed.push(r);
  return { from: fromId, to: toId, added, removed, changed, unchanged: b.length - added.length - changed.length };
}

/** Current deployed + observed inventory for a project, optionally filtered. Used by matching, agents and UI. */
export async function deployedInventory(db, projectId, { environmentId = null, componentName = null } = {}) {
  // Artifact inventory for current deployments
  const artifactRows = await db.query(`
    SELECT d.id AS deployment_id, d.service_id, d.environment_id, d.artifact_id, d.asset_id, d.deployed_at, a.digest,
           e.key AS env_key, e.is_production, s.key AS service_key, o.id AS observation_id, o.direct, o.dependency_path, o.architecture, o.version_kind, o.observed_at, o.stale,
           c.id AS component_id, c.purl, c.ecosystem, c.name, c.version, c.kind, c.distro, snap.id AS snapshot_id
    FROM deployments d
    JOIN artifacts a ON a.id=d.artifact_id
    JOIN environments e ON e.id=d.environment_id
    JOIN services s ON s.id=d.service_id
    JOIN LATERAL (SELECT id FROM inventory_snapshots WHERE artifact_id=d.artifact_id ORDER BY created_at DESC LIMIT 1) snap ON true
    JOIN observations o ON o.snapshot_id=snap.id
    JOIN components c ON c.id=o.component_id
    WHERE d.project_id=$1 AND d.is_current AND ($2::text IS NULL OR d.environment_id=$2) AND ($3::text IS NULL OR c.name ILIKE '%' || $3 || '%')`, [projectId, environmentId, componentName]);
  // Runtime/asset observations (latest snapshot per asset)
  const assetRows = await db.query(`
    SELECT NULL AS deployment_id, o.service_id, ap.environment_id, NULL AS artifact_id, ast.id AS asset_id, NULL AS deployed_at, NULL AS digest,
           e.key AS env_key, e.is_production, NULL AS service_key, o.id AS observation_id, o.direct, o.dependency_path, COALESCE(o.architecture, ast.architecture) AS architecture, o.version_kind, o.observed_at, o.stale,
           c.id AS component_id, c.purl, c.ecosystem, c.name, c.version, c.kind, c.distro, snap.id AS snapshot_id
    FROM asset_projects ap
    JOIN assets ast ON ast.id=ap.asset_id
    LEFT JOIN environments e ON e.id=ap.environment_id
    JOIN LATERAL (SELECT id FROM inventory_snapshots WHERE asset_id=ast.id ORDER BY created_at DESC LIMIT 1) snap ON true
    JOIN observations o ON o.snapshot_id=snap.id
    JOIN components c ON c.id=o.component_id
    WHERE ap.project_id=$1 AND ($2::text IS NULL OR ap.environment_id=$2) AND ($3::text IS NULL OR c.name ILIKE '%' || $3 || '%')`, [projectId, environmentId, componentName]);
  return [...artifactRows, ...assetRows];
}

export const contentHash = (buf) => 'sha256:' + sha256(buf);
