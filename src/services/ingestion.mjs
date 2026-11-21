// CI/CD ingestion: SBOM upload receipts, asynchronous processing, deterministic policy gates and deployment records.
// Contracts: POST /api/v1/ingestions/sbom, GET /api/v1/ingestions/{id}, POST /api/v1/deployments, GET /api/v1/policy-evaluations/{id}
import { id, sha256, badRequest, AppError, conflict, notFound } from '../util.mjs';
import { parseDocument, ParseError } from '../domain/parsers.mjs';
import { recordSnapshot, contentHash } from './inventory.mjs';
import { evaluateSnapshotMatches } from './matching.mjs';
import { enqueue } from '../jobs/queue.mjs';
import { emit } from '../jobs/runtime.mjs';
import { audit } from '../audit.mjs';
import { requireProject } from '../authz.mjs';

const DIGEST_RE = /^sha(256|384|512):[a-f0-9]{64,128}$/;
export const DEFAULT_GATE = { version: 1, mode: 'observe', fail_mode: 'open', block_on: { min_severity: 'critical', exploitation: ['kev_listed', 'actively_exploited'], only_new: true, require_fix_available: false }, timeout_s: 120 };
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0, unknown: 3 };

async function resolveScope(db, ctx, m, perm = 'inventory:write') {
  const project = await requireProject(ctx, m.project_id, perm, db);
  if (m.organization_id && m.organization_id !== project.org_id) throw new AppError(403, 'SCOPE_MISMATCH', 'organization_id does not match the project.');
  const service = await db.one('SELECT * FROM services WHERE project_id=$1 AND (id=$2 OR key=$2)', [project.id, m.service_id]);
  if (!service) throw new AppError(422, 'SCOPE_MISMATCH', 'service_id does not belong to this project.');
  if (ctx.actorType === 'ci' && ctx.ciToken.service_id && ctx.ciToken.service_id !== service.id) throw new AppError(403, 'SCOPE_MISMATCH', 'CI token is scoped to a different service.');
  let env = null;
  if (m.environment_id) { env = await db.one('SELECT * FROM environments WHERE project_id=$1 AND (id=$2 OR key=$2)', [project.id, m.environment_id]); if (!env) throw new AppError(422, 'SCOPE_MISMATCH', 'environment_id does not belong to this project.'); }
  return { project, service, env };
}

export async function acceptSbom(app, ctx, { metadata, document, idempotencyKey }) {
  const m = metadata || {};
  for (const f of ['project_id', 'service_id', 'commit_sha', 'artifact_digest', 'source_timestamp']) if (!m[f]) throw badRequest(`metadata.${f} is required.`);
  if (!DIGEST_RE.test(m.artifact_digest)) throw badRequest('artifact_digest must be an immutable digest like sha256:<64 hex>. A tag is not an artifact identity.');
  if (!/^[a-f0-9]{7,64}$/i.test(m.commit_sha)) throw badRequest('commit_sha must be a hex commit id.');
  if (m.ci_run_url && !/^https:\/\//.test(m.ci_run_url)) throw badRequest('ci_run_url must be https.');
  if (isNaN(Date.parse(m.source_timestamp))) throw badRequest('source_timestamp must be ISO-8601.');
  const raw = typeof document === 'string' ? document : JSON.stringify(document);
  if (!raw || raw.length < 2) throw badRequest('document is required.');
  if (Buffer.byteLength(raw) > app.cfg.maxUploadBytes) throw new AppError(413, 'PAYLOAD_TOO_LARGE', `SBOM exceeds ${app.cfg.maxUploadBytes} bytes.`);
  let parsed;
  try { parsed = parseDocument(raw); } catch (e) { throw new AppError(422, 'SBOM_INVALID', e instanceof ParseError ? e.message : 'Malformed SBOM: ' + e.message); }
  if (!['cyclonedx', 'spdx'].includes(parsed.format)) throw new AppError(422, 'SBOM_UNSUPPORTED', `Expected CycloneDX or SPDX JSON; received ${parsed.format}.`);
  const key = idempotencyKey || sha256(`${m.project_id}|${m.service_id}|${m.artifact_digest}|${sha256(raw)}`);
  return app.db.tx(async (db) => {
    const { project, service, env } = await resolveScope(db, ctx, m);
    const dup = await db.one('SELECT * FROM ingestions WHERE project_id=$1 AND idempotency_key=$2', [project.id, key]);
    if (dup) return { duplicate: true, ingestion: dup };
    const iid = id('ing');
    const objectKey = await app.objects.put(`${project.org_id}/${project.id}/sbom/${sha256(raw)}.json`, Buffer.from(raw), 'application/json');
    const receipt = { ingestion_id: iid, status: 'accepted', status_url: `/api/v1/ingestions/${iid}`, received_at: new Date().toISOString(), content_sha256: contentHash(raw), artifact_digest: m.artifact_digest, commit_sha: m.commit_sha, project: project.key, service: service.key, format: parsed.format, component_count: parsed.components.length, idempotency_key: key };
    await db.query(`INSERT INTO ingestions (id, org_id, project_id, idempotency_key, kind, status, receipt, request_meta, object_key, created_by) VALUES ($1,$2,$3,$4,'sbom','accepted',$5,$6,$7,$8)`,
      [iid, project.org_id, project.id, key, receipt, { ...m, service_id: service.id, environment_id: env?.id || null }, objectKey, ctx.ciToken?.id || ctx.identity?.id]);
    await enqueue(db, { type: 'process_ingestion', orgId: project.org_id, projectId: project.id, payload: { ingestion_id: iid }, idempotencyKey: `ingest:${iid}`, priority: 10 });
    await audit(db, ctx, 'ingestion.accepted', { targetType: 'ingestion', targetId: iid, projectId: project.id, data: { digest: m.artifact_digest, commit: m.commit_sha, components: parsed.components.length } });
    return { duplicate: false, ingestion: { id: iid, receipt, status: 'accepted' } };
  });
}

export async function processIngestion(app, ingestionId) {
  const ing = await app.db.one('SELECT * FROM ingestions WHERE id=$1', [ingestionId]);
  if (!ing || ['completed', 'rejected'].includes(ing.status)) return { skipped: true };
  const raw = (await app.objects.get(ing.object_key)).toString('utf8');
  const parsed = parseDocument(raw);
  const m = ing.request_meta;
  return app.db.tx(async (db) => {
    await db.query(`UPDATE ingestions SET status='processing' WHERE id=$1`, [ingestionId]);
    let art = await db.one('SELECT * FROM artifacts WHERE project_id=$1 AND digest=$2', [ing.project_id, m.artifact_digest]);
    if (!art) {
      art = (await db.query(`INSERT INTO artifacts (id, org_id, project_id, service_id, digest, name, tag, version, commit_sha, branch, ci_run_url, built_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
        [id('art'), ing.org_id, ing.project_id, m.service_id, m.artifact_digest, m.artifact_name || null, m.image_tag || null, m.application_version || null, m.commit_sha, m.branch || null, m.ci_run_url || null, m.source_timestamp]))[0];
    }
    const prev = await db.one('SELECT id FROM inventory_snapshots WHERE artifact_id=$1 ORDER BY created_at DESC LIMIT 1', [art.id]);
    const snap = await recordSnapshot(db, { orgId: ing.org_id, projectId: ing.project_id, artifactId: art.id, serviceId: m.service_id, source: 'ci_sbom', method: 'ci_upload', parsed, contentSha256: ing.receipt.content_sha256, objectKey: ing.object_key, collectedAt: m.source_timestamp, versionKind: 'artifact', confidence: 'reported' });
    const evaluation = await evaluateGate(db, { orgId: ing.org_id, projectId: ing.project_id, ingestionId, snapshotId: snap.snapshotId, baselineSnapshotId: prev?.id || (await baselineFor(db, m.service_id)) });
    const stats = { components: snap.componentCount, parse_warnings: parsed.errors.length };
    await db.query(`UPDATE ingestions SET status='completed', snapshot_id=$2, evaluation_id=$3, stats=$4, completed_at=now(), receipt=receipt || $5 WHERE id=$1`, [ingestionId, snap.snapshotId, evaluation.id, stats, { status: 'completed', artifact_id: art.id, snapshot_id: snap.snapshotId, policy_evaluation_url: `/api/v1/policy-evaluations/${evaluation.id}` }]);
    await emit(db, ing.org_id, 'artifact.scanned', { project_id: ing.project_id, artifact_id: art.id, snapshot_id: snap.snapshotId, evaluation_id: evaluation.id });
    return { snapshot_id: snap.snapshotId, evaluation_id: evaluation.id };
  });
}

async function baselineFor(db, serviceId) {
  // Baseline = inventory of the current production deployment of this service (what is already accepted in prod).
  const r = await db.one(`SELECT s.id FROM deployments d JOIN environments e ON e.id=d.environment_id JOIN inventory_snapshots s ON s.artifact_id=d.artifact_id WHERE d.service_id=$1 AND d.is_current AND e.is_production ORDER BY s.created_at DESC LIMIT 1`, [serviceId]);
  return r?.id || null;
}

export async function gatePolicy(db, orgId, projectId) {
  const p = await db.one(`SELECT * FROM policies WHERE org_id=$1 AND kind='gate' AND active AND (project_id=$2 OR project_id IS NULL) ORDER BY project_id NULLS LAST, version DESC LIMIT 1`, [orgId, projectId]);
  return p ? { id: p.id, ...p.definition, version: p.version } : { id: null, ...DEFAULT_GATE };
}

export async function evaluateGate(db, { orgId, projectId, ingestionId, snapshotId, baselineSnapshotId }) {
  const policy = await gatePolicy(db, orgId, projectId);
  const matches = await evaluateSnapshotMatches(db, snapshotId);
  const baseline = baselineSnapshotId ? new Set((await evaluateSnapshotMatches(db, baselineSnapshotId)).map(x => `${x.advisory_id}|${x.package}`)) : new Set();
  const exceptions = await db.query(`SELECT * FROM risk_exceptions WHERE project_id=$1 AND kind IN ('gate_exception','accepted_risk') AND revoked_at IS NULL AND expires_at > now() AND approved_by IS NOT NULL`, [projectId]);
  const excepted = new Set(exceptions.map(e => e.advisory_id).filter(Boolean));
  const b = policy.block_on || {};
  const violations = [];
  for (const x of matches) {
    const isNew = !baseline.has(`${x.advisory_id}|${x.package}`);
    const sevHit = SEV_RANK[x.severity] >= SEV_RANK[b.min_severity || 'critical'];
    const expHit = (b.exploitation || []).includes(x.exploitation);
    if (!(sevHit || expHit)) continue;
    if (b.only_new && !isNew) continue;
    if (b.require_fix_available && !x.fixed) continue;
    violations.push({ ...x, new: isNew, excepted: excepted.has(x.advisory_id), rule: sevHit ? `severity>=${b.min_severity}` : `exploitation in ${b.exploitation.join('|')}` });
  }
  const blocking = violations.filter(v => !v.excepted);
  const decision = blocking.length ? (policy.mode === 'block_new' ? 'fail' : 'warn') : 'pass';
  const evId = id('pev');
  const summary = { total_matches: matches.length, new_matches: matches.filter(x => !baseline.has(`${x.advisory_id}|${x.package}`)).length, violations: violations.length, blocking: blocking.length, baseline_snapshot_id: baselineSnapshotId, note: 'Deterministic evaluation. AI output never changes a gate decision.' };
  await db.query(`INSERT INTO policy_evaluations (id, org_id, project_id, ingestion_id, policy_id, policy_version, status, decision, mode, fail_mode, exit_code, summary, violations, completed_at) VALUES ($1,$2,$3,$4,$5,$6,'completed',$7,$8,$9,$10,$11,$12,now())`,
    [evId, orgId, projectId, ingestionId, policy.id, policy.version, decision, policy.mode, policy.fail_mode, decision === 'fail' ? 1 : 0, summary, JSON.stringify(violations)]);
  return { id: evId, decision };
}

export async function recordDeployment(app, ctx, body) {
  for (const f of ['project_id', 'service_id', 'environment_id', 'artifact_digest', 'deployed_at']) if (!body[f]) throw badRequest(`${f} is required.`);
  if (!DIGEST_RE.test(body.artifact_digest)) throw badRequest('artifact_digest must be an immutable digest.');
  if (isNaN(Date.parse(body.deployed_at))) throw badRequest('deployed_at must be ISO-8601.');
  return app.db.tx(async (db) => {
    const project = await requireProject(ctx, body.project_id, 'deployments:write', db);
    const { service, env } = await resolveScope(db, ctx, { ...body, project_id: project.id }, 'deployments:write');
    if (!env) throw badRequest('environment_id is required.');
    const art = await db.one('SELECT * FROM artifacts WHERE project_id=$1 AND digest=$2', [project.id, body.artifact_digest]);
    if (!art) throw new AppError(422, 'ARTIFACT_UNKNOWN', 'No ingested artifact with this digest. Upload the SBOM for this artifact first; a deployment must reference a known immutable artifact.');
    const cur = await db.one('SELECT * FROM deployments WHERE service_id=$1 AND environment_id=$2 AND is_current', [service.id, env.id]);
    if (cur && cur.artifact_id === art.id) return { deployment: cur, duplicate: true };
    if (cur) await db.query('UPDATE deployments SET is_current=false WHERE id=$1', [cur.id]);
    const dep = (await db.query(`INSERT INTO deployments (id, org_id, project_id, service_id, environment_id, artifact_id, asset_id, deployed_at, recorded_by, source) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [id('dep'), project.org_id, project.id, service.id, env.id, art.id, body.asset_id || null, body.deployed_at, ctx.ciToken?.id || ctx.identity?.id, ctx.actorType === 'ci' ? 'ci' : 'manual']))[0];
    await emit(db, project.org_id, 'deployment.recorded', { project_id: project.id, deployment_id: dep.id, service_id: service.id, environment_id: env.id, artifact_id: art.id, previous_artifact_id: cur?.artifact_id || null });
    await audit(db, ctx, 'deployment.recorded', { targetType: 'deployment', targetId: dep.id, projectId: project.id, data: { digest: art.digest, environment: env.key, service: service.key } });
    return { deployment: dep, duplicate: false };
  });
}

export async function getIngestion(db, ctx, ingestionId) {
  const ing = await db.one('SELECT * FROM ingestions WHERE id=$1 AND org_id=$2', [ingestionId, ctx.orgId]);
  if (!ing) throw notFound('Ingestion');
  await requireProject(ctx, ing.project_id, 'project:read', db);
  return { id: ing.id, status: ing.status, receipt: ing.receipt, stats: ing.stats, error: ing.error, policy_evaluation_url: ing.evaluation_id ? `/api/v1/policy-evaluations/${ing.evaluation_id}` : null, created_at: ing.created_at, completed_at: ing.completed_at };
}
export async function getEvaluation(db, ctx, evalId) {
  const ev = await db.one('SELECT * FROM policy_evaluations WHERE id=$1 AND org_id=$2', [evalId, ctx.orgId]);
  if (!ev) throw notFound('Policy evaluation');
  await requireProject(ctx, ev.project_id, 'project:read', db);
  return ev;
}
export { conflict };
