// Deterministic matching of advisories against *deployed* and *observed* inventory, finding upsert/deduplication,
// reassessment on advisory revisions, and verification of fixes on the intended environment.
// A build upload alone never creates a finding; it is evaluated by the CI policy gate instead.
import { id, sha256 } from '../util.mjs';
import { evaluateRanges, compareVersions } from '../domain/versions.mjs';
import { computePriority, slaDueWithPolicy, CLOSED_STATUSES } from '../domain/policy.mjs';
import { loadPolicies } from './policies.mjs';
import { deployedInventory } from './inventory.mjs';
import { exploitationFor } from './advisories.mjs';
import { emit } from '../jobs/runtime.mjs';
import { enqueue } from '../jobs/queue.mjs';
import { audit } from '../audit.mjs';

export const normName = (eco, name) => (eco === 'pypi' ? String(name).toLowerCase().replace(/[-_.]+/g, '-') : name);
export function normDistro(d) {
  if (!d) return null;
  const s = String(d).toLowerCase().replace(/\s+/g, '');
  const m = /^(amzn|amazonlinux|amazon|debian|ubuntu|alpine|rhel|redhat|rocky|rockylinux|almalinux|alma)[-:_]?(\d+(?:\.\d+)?)?/.exec(s);
  if (!m) return s;
  const fam = { amzn: 'amazonlinux', amazon: 'amazonlinux', redhat: 'rhel', rockylinux: 'rocky', alma: 'almalinux' }[m[1]] || m[1];
  const ver = m[2] ? (fam === 'ubuntu' || fam === 'alpine' ? m[2] : m[2].split('.')[0]) : '';
  return ver ? `${fam}:${ver}` : fam;
}

/** Match one component against stored advisories. Returns [{advisory, evaluation, range, caveats[]}]. */
export async function matchComponent(db, comp, { architecture = null, advisoryId = null } = {}) {
  const rows = await db.query(`SELECT r.*, a.status AS adv_status FROM affected_ranges r JOIN advisories a ON a.id=r.advisory_id
    WHERE r.ecosystem=$1 AND r.package_name=$2 AND a.status NOT IN ('withdrawn','rejected') AND ($3::text IS NULL OR r.advisory_id=$3)`, [comp.ecosystem, normName(comp.ecosystem, comp.name), advisoryId]);
  const byAdv = new Map();
  for (const r of rows) { if (!byAdv.has(r.advisory_id)) byAdv.set(r.advisory_id, []); byAdv.get(r.advisory_id).push(r); }
  const out = [];
  const compDistro = normDistro(comp.distro);
  for (const [advId, ranges] of byAdv) {
    const caveats = [];
    let use = ranges;
    if (['deb', 'rpm', 'apk'].includes(comp.ecosystem)) {
      const distroRanges = ranges.filter(r => r.distro);
      const mine = distroRanges.filter(r => compDistro && normDistro(r.distro) === compDistro);
      if (mine.length) use = mine;
      else if (distroRanges.length && !ranges.some(r => !r.distro)) continue; // advisory tracks other distributions only
      else { use = ranges.filter(r => !r.distro); caveats.push({ kind: 'backport', note: `Only upstream ranges are available for ${compDistro || 'this distribution'}; vendor backports may fix the flaw without changing the upstream version.` }); }
    }
    const evaluation = evaluateRanges(comp.ecosystem, comp.version, use);
    if (evaluation.status === 'not_affected') continue;
    const range = evaluation.range || use[0];
    if (range?.architectures && architecture) {
      const list = range.architectures.map(normArch);
      if (!list.includes(normArch(architecture))) { out.push({ advisoryId: advId, evaluation: { ...evaluation, status: 'not_affected', reason: `Advisory limits impact to ${list.join(', ')}; observed architecture is ${architecture}.` }, range, caveats, excludedByArch: true }); continue; }
    } else if (range?.architectures && !architecture) caveats.push({ kind: 'architecture', note: `Advisory limits impact to ${range.architectures.join(', ')}; observed architecture is unknown.` });
    out.push({ advisoryId: advId, evaluation, range, caveats });
  }
  return out;
}

export const normArch = (a) => { const s = String(a || '').toLowerCase(); return { aarch64: 'arm64', amd64: 'x86_64', x64: 'x86_64', x86_64: 'x86_64', arm64: 'arm64' }[s] || s; };
const scopeKey = (row) => (row.deployment_id ? `svc:${row.service_id}:${row.environment_id}` : `asset:${row.asset_id}:${row.environment_id || '-'}`);

/**
 * Reassess a project. reason is recorded on every evaluation. Returns stats.
 * Runs in a single transaction for consistency.
 */
export async function assessProject(app, projectId, { reason, advisoryId = null } = {}) {
  const stats = { created: 0, updated: 0, reopened: 0, closed_not_affected: 0, verification_pending: 0, unchanged: 0 };
  await app.db.tx(async (db) => {
    const project = await db.one('SELECT * FROM projects WHERE id=$1', [projectId]);
    if (!project) return;
    const inv = await deployedInventory(db, projectId);
    const pol = await loadPolicies(db, project.org_id, projectId);
    const slaDue = (p, prod, start) => slaDueWithPolicy(p, prod, start, pol.sla);
    const envs = new Map((await db.query('SELECT * FROM environments WHERE project_id=$1', [projectId])).map(e => [e.id, e]));
    const services = new Map((await db.query('SELECT * FROM services WHERE project_id=$1', [projectId])).map(s => [s.id, s]));
    const seenKeys = new Set();
    const advisoryCache = new Map();
    const getAdv = async (aid) => { if (!advisoryCache.has(aid)) advisoryCache.set(aid, { adv: await db.one('SELECT * FROM advisories WHERE id=$1', [aid]), exp: await exploitationFor(db, aid) }); return advisoryCache.get(aid); };
    // Only packages that appear in any affected range can match; skip the rest without per-component queries.
    const candidates = new Set((await db.query(`SELECT DISTINCT r.ecosystem, r.package_name FROM affected_ranges r JOIN advisories a ON a.id=r.advisory_id WHERE a.status NOT IN ('withdrawn','rejected') AND ($1::text IS NULL OR r.advisory_id=$1)`, [advisoryId])).map(r => `${r.ecosystem}|${r.package_name}`));
    const existingByKey = new Map((await db.query('SELECT * FROM findings WHERE project_id=$1', [projectId])).map(f => [f.dedupe_key, f]));
    const matchCache = new Map(); const unchangedIds = [];

    for (const row of inv) {
      if (!candidates.has(`${row.ecosystem}|${normName(row.ecosystem, row.name)}`)) continue;
      const mk = `${row.component_id}|${normArch(row.architecture)}`;
      if (!matchCache.has(mk)) matchCache.set(mk, await matchComponent(db, row, { architecture: row.architecture, advisoryId }));
      const matches = matchCache.get(mk);
      for (const m of matches) {
        if (m.excludedByArch) continue;
        const { adv, exp } = await getAdv(m.advisoryId);
        const env = envs.get(row.environment_id) || {};
        const svc = services.get(row.service_id) || {};
        const dedupeKey = sha256(`${m.advisoryId}|${row.ecosystem}:${normName(row.ecosystem, row.name)}|${projectId}|${scopeKey(row)}`); // per project: shared assets stay linked to every project
        seenKeys.add(dedupeKey);
        const unverifiedPrereq = (adv.prerequisites || []).length > 0;
        const applicability = m.evaluation.status === 'unknown' ? 'unknown' : (unverifiedPrereq || m.caveats.length) ? 'under_investigation' : 'affected';
        const pr = computePriority({ severity: adv.severity, applicability, exploitation: exp.status, epss: exp.epss, production: !!env.is_production, exposure: env.exposure || project.exposure, criticality: project.criticality, version_unknown: m.evaluation.status === 'unknown' }, pol.priority);
        const existing = existingByKey.get(dedupeKey) || null;
        const rootCause = `${m.advisoryId}|${row.ecosystem}:${normName(row.ecosystem, row.name)}`;
        if (!existing) {
          const fid = id('fnd');
          const firstSeen = new Date().toISOString();
          await db.query(`INSERT INTO findings (id, org_id, project_id, advisory_id, component_id, service_id, environment_id, deployment_id, artifact_id, asset_id, dedupe_key, root_cause_key,
              severity, applicability, applicability_justification, exploitation, priority, priority_explanation, priority_policy_version, observed_version, fixed_version, owner_identity_id, owner_team_id, sla_due_at, first_seen_at, last_evaluation_reason)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`,
          [fid, project.org_id, projectId, m.advisoryId, row.component_id, row.service_id, row.environment_id, row.deployment_id, row.artifact_id, row.asset_id, dedupeKey, rootCause,
            adv.severity, applicability, m.evaluation.reason, exp.status, pr.priority, JSON.stringify(pr.factors), pr.policy_version, row.version, m.evaluation.fixed || null, project.owner_identity_id, svc.owner_team_id || project.team_id, slaDue(pr.priority, !!env.is_production, firstSeen), firstSeen, reason]);
          await writeEvidence(db, project, fid, row, m, adv, env, svc);
          await db.query(`INSERT INTO finding_events (id, finding_id, kind, to_value, reason, actor, data) VALUES ($1,$2,'created',$3,$4,'system',$5)`, [id('fev'), fid, 'new', reason, { priority: pr.priority, applicability }]);
          await emit(db, project.org_id, 'finding.created', { finding_id: fid, project_id: projectId, priority: pr.priority, applicability, production: !!env.is_production, reason });
          stats.created++;
          existingByKey.set(dedupeKey, await db.one('SELECT * FROM findings WHERE id=$1', [fid]));
          continue;
        }
        // existing finding: update evaluation, detect changes
        const changes = {};
        if (existing.priority !== pr.priority) changes.priority = [existing.priority, pr.priority];
        if (existing.priority_policy_version !== pr.policy_version) changes.policy_version = [existing.priority_policy_version, pr.policy_version];
        if (existing.exploitation !== exp.status) changes.exploitation = [existing.exploitation, exp.status];
        if (existing.observed_version !== row.version) changes.observed_version = [existing.observed_version, row.version];
        if (existing.deployment_id !== row.deployment_id) changes.deployment = [existing.deployment_id, row.deployment_id];
        let status = existing.status, verification = existing.verification_status;
        if (existing.status === 'verified_fixed' || (['verification_pending', 'deployed'].includes(existing.status) && existing.observed_version === row.version && changes.deployment)) {
          // Vulnerable version observed again in the same scope after a fix: contradictory evidence reopens review.
          status = 'new'; verification = 'contradicted'; changes.reopened = [existing.status, 'new'];
        }
        const manualApplicability = ['not_affected'].includes(existing.applicability) && existing.status === 'false_positive' && !changes.observed_version;
        const newApplicability = manualApplicability ? existing.applicability : (existing.applicability === 'affected' && applicability !== 'unknown' ? 'affected' : applicability);
        // SLA due date follows the current SLA policy; time spent paused is added back.
        const baseDue = slaDue(pr.priority, !!env.is_production, existing.first_seen_at);
        const dueWithPause = baseDue ? new Date(new Date(baseDue).getTime() + (existing.sla_paused_seconds || 0) * 1000).toISOString() : null;
        const slaChanged = !existing.sla_paused_at && (existing.sla_due_at ? new Date(existing.sla_due_at).toISOString() : null) !== dueWithPause;
        const fieldsChanged = slaChanged || Object.keys(changes).length || existing.severity !== adv.severity || existing.status !== status || existing.applicability !== newApplicability || (m.evaluation.fixed && existing.fixed_version !== m.evaluation.fixed) || existing.artifact_id !== row.artifact_id;
        if (!fieldsChanged) { unchangedIds.push(existing.id); stats.unchanged++; continue; }
        await db.query(`UPDATE findings SET severity=$2, exploitation=$3, priority=$4, priority_explanation=$5, observed_version=$6, fixed_version=COALESCE($7, fixed_version), deployment_id=$8, artifact_id=$9,
            sla_due_at=CASE WHEN sla_paused_at IS NULL THEN $10 ELSE sla_due_at END, status=$11, verification_status=$12, applicability=$13, last_evaluated_at=now(), last_evaluation_reason=$14, updated_at=now(), priority_policy_version=$15,
            closed_at=CASE WHEN $11 IN ('verified_fixed','false_positive','accepted_risk') THEN closed_at ELSE NULL END WHERE id=$1`,
        [existing.id, adv.severity, exp.status, pr.priority, JSON.stringify(pr.factors), row.version, m.evaluation.fixed || null, row.deployment_id, row.artifact_id,
          dueWithPause, status, verification, newApplicability, reason, pr.policy_version]);
        existingByKey.set(dedupeKey, await db.one('SELECT * FROM findings WHERE id=$1', [existing.id]));
        if (Object.keys(changes).length) {
          await db.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor, data) VALUES ($1,$2,'reassessed',$3,$4,$5,'system',$6)`,
            [id('fev'), existing.id, existing.priority, pr.priority, reason, changes]);
          if (changes.priority) await emit(db, project.org_id, 'finding.priority_changed', { finding_id: existing.id, project_id: projectId, from: existing.priority, to: pr.priority, reason, increased: pr.priority < existing.priority });
          if (changes.exploitation) await emit(db, project.org_id, 'finding.exploitation_changed', { finding_id: existing.id, project_id: projectId, from: existing.exploitation, to: exp.status, reason });
          if (changes.reopened) { await emit(db, project.org_id, 'verification.contradicted', { finding_id: existing.id, project_id: projectId, reason }); stats.reopened++; }
          if (changes.deployment && !changes.reopened) await emit(db, project.org_id, 'deployment.newly_affected', { finding_id: existing.id, project_id: projectId, deployment_id: row.deployment_id });
          stats.updated++;
        } else stats.unchanged++;
      }
    }
    if (unchangedIds.length) await db.query('UPDATE findings SET last_evaluated_at=now(), last_evaluation_reason=$2 WHERE id = ANY($1)', [unchangedIds, reason]);
    // Open findings no longer matched: decide why, never silently close.
    const open = await db.query(`SELECT f.*, c.ecosystem, c.name AS comp_name FROM findings f JOIN components c ON c.id=f.component_id WHERE f.project_id=$1 AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk') AND ($2::text IS NULL OR f.advisory_id=$2)`, [projectId, advisoryId]);
    for (const f of open) {
      if (seenKeys.has(f.dedupe_key)) continue;
      const same = inv.filter(r => (f.deployment_id || f.service_id ? r.service_id === f.service_id && r.environment_id === f.environment_id && r.deployment_id : r.asset_id === f.asset_id) && r.ecosystem === f.ecosystem && normName(r.ecosystem, r.name) === normName(f.ecosystem, f.comp_name));
      if (same.some(r => r.stale)) continue; // stale data cannot prove anything
      const sameVersion = same.find(r => r.version === f.observed_version);
      if (sameVersion) {
        // Same version no longer matches => advisory revision (or architecture exclusion) changed applicability.
        await db.query(`UPDATE findings SET applicability='not_affected', applicability_justification=$2, status='false_positive', status_reason=$2, priority='P4', closed_at=now(), updated_at=now(), last_evaluation_reason=$3 WHERE id=$1`,
          [f.id, `Deterministic re-evaluation (${reason}) no longer matches observed version ${f.observed_version}.`, reason]);
        await db.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor) VALUES ($1,$2,'status',$3,'false_positive',$4,'system')`, [id('fev'), f.id, f.status, `Re-evaluation: ${reason}`]);
        await emit(db, project.org_id, 'finding.not_affected', { finding_id: f.id, project_id: projectId, reason });
        stats.closed_not_affected++;
      } else if (f.status !== 'verification_pending') {
        // Component upgraded or removed in this scope: fix has reached the environment; verify before closing.
        await db.query(`UPDATE findings SET status='verification_pending', verification_status='pending', updated_at=now(), last_evaluation_reason=$2 WHERE id=$1`, [f.id, reason]);
        await db.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor) VALUES ($1,$2,'status',$3,'verification_pending',$4,'system')`, [id('fev'), f.id, f.status, 'Inventory in this environment no longer shows the affected version; verification queued.']);
        await enqueue(db, { type: 'verify_finding', orgId: project.org_id, projectId, payload: { finding_id: f.id }, idempotencyKey: `verify:${f.id}:${sha256(JSON.stringify(same.map(s => s.snapshot_id)))}` });
        stats.verification_pending++;
      }
    }
  });
  return stats;
}

async function writeEvidence(db, project, findingId, row, m, adv, env, svc) {
  // Rows are collected and written in one multi-row INSERT (one round trip per finding).
  const rows = [];
  const ev = async (kind, stance, summary, data, ref) => { rows.push([id('evd'), project.org_id, project.id, findingId, kind, stance, summary, JSON.stringify(data ?? {}), ref || null]); };
  try { await collect(); } finally {
    if (rows.length) await db.query(`INSERT INTO evidence (id, org_id, project_id, finding_id, kind, stance, summary, data, source_ref) VALUES ${rows.map((_, i) => `(${Array.from({ length: 9 }, (__, j) => `$${i * 9 + j + 1}${j === 7 ? '::jsonb' : ''}`).join(',')})`).join(',')}`, rows.flat());
  }
  async function collect() {
  const where = row.deployment_id ? `artifact ${row.digest} (service ${svc.key || row.service_id})` : `asset ${row.asset_id}`;
  await ev('package_presence', row.version ? 'supporting' : 'missing', `${row.name}${row.version ? '@' + row.version : ' (version unknown)'} observed in ${where}; ${row.version_kind} version, snapshot ${row.snapshot_id}.`, { purl: row.purl, snapshot_id: row.snapshot_id, observed_at: row.observed_at, version_kind: row.version_kind }, row.snapshot_id);
  await ev('version_match', m.evaluation.status === 'affected' ? 'supporting' : 'missing', m.evaluation.reason, { comparator: m.evaluation.comparator, fixed: m.evaluation.fixed || null, advisory_revision: adv.current_revision }, adv.id);
  if (row.deployment_id) await ev('deployment', 'supporting', `Artifact ${row.digest} is the current deployment of ${svc.key || 'service'} in ${env.key || 'environment'} since ${new Date(row.deployed_at).toISOString()}.`, { deployment_id: row.deployment_id, digest: row.digest }, row.deployment_id);
  else await ev('runtime', 'supporting', `Observed on asset ${row.asset_id} in ${env.key || 'unassigned environment'}.`, { asset_id: row.asset_id }, row.asset_id);
  await ev('dependency_path', 'neutral', row.direct === true ? 'Direct dependency.' : row.direct === false ? `Transitive dependency via ${(row.dependency_path || []).join(' → ') || 'unknown path'}.` : 'Direct/transitive status unknown.', { direct: row.direct, path: row.dependency_path }, null);
  for (const p of adv.prerequisites || []) await ev('prerequisite', 'missing', `Prerequisite not yet verified: ${p.kind}: ${p.value}${p.note ? ' — ' + p.note : ''}`, p, adv.id);
  for (const c of m.caveats) await ev(c.kind, 'missing', c.note, {}, adv.id);
  }
}

/** Verify a fix on the intended environment. Never driven by ticket state or merged PRs. */
export async function verifyFinding(app, findingId) {
  return app.db.tx(async (db) => {
    const f = await db.one(`SELECT f.*, c.ecosystem, c.name AS comp_name, e.key AS env_key FROM findings f JOIN components c ON c.id=f.component_id LEFT JOIN environments e ON e.id=f.environment_id WHERE f.id=$1`, [findingId]);
    if (!f || !['verification_pending', 'deployed'].includes(f.status)) return { skipped: true };
    const inv = (await deployedInventory(db, f.project_id, { environmentId: f.environment_id }))
      .filter(r => (f.service_id ? r.service_id === f.service_id && r.deployment_id : r.asset_id === f.asset_id));
    const ranges = await db.query('SELECT * FROM affected_ranges WHERE advisory_id=$1 AND ecosystem=$2 AND package_name=$3', [f.advisory_id, f.ecosystem, normName(f.ecosystem, f.comp_name)]);
    const ev = (stance, summary, data) => db.query(`INSERT INTO evidence (id, org_id, project_id, finding_id, kind, stance, summary, data) VALUES ($1,$2,$3,$4,'verification',$5,$6,$7)`, [id('evd'), f.org_id, f.project_id, f.id, stance, summary, data]);
    const event = (to, reason, data = {}) => db.query(`INSERT INTO finding_events (id, finding_id, kind, from_value, to_value, reason, actor, data) VALUES ($1,$2,'verification',$3,$4,$5,'system:verification',$6)`, [id('fev'), f.id, f.status, to, reason, data]);
    const dep = f.service_id ? await db.one('SELECT d.*, a.digest FROM deployments d JOIN artifacts a ON a.id=d.artifact_id WHERE d.service_id=$1 AND d.environment_id=$2 AND d.is_current', [f.service_id, f.environment_id]) : null;
    if (f.service_id && !dep) { await ev('missing', 'No current deployment recorded for this service/environment; cannot verify.', {}); await event('verification_pending', 'insufficient_evidence'); return { verified: false, reason: 'no_deployment' }; }
    const snapshot = dep ? await db.one('SELECT * FROM inventory_snapshots WHERE artifact_id=$1 ORDER BY created_at DESC LIMIT 1', [dep.artifact_id]) : null;
    if (dep && (!snapshot || !['cyclonedx', 'spdx', 'trivy'].includes(snapshot.format))) {
      await ev('missing', `Deployed artifact ${dep.digest} has no SBOM-level inventory; verification requires component evidence for the deployed digest.`, { digest: dep.digest });
      await event('verification_pending', 'insufficient_evidence'); return { verified: false, reason: 'no_sbom' };
    }
    const present = inv.filter(r => r.ecosystem === f.ecosystem && normName(r.ecosystem, r.name) === normName(f.ecosystem, f.comp_name));
    if (present.some(r => r.stale)) { await ev('missing', 'Observations for this scope are stale; verification deferred.', {}); await event('verification_pending', 'stale_inventory'); return { verified: false, reason: 'stale' }; }
    const stillAffected = present.filter(r => evaluateRanges(f.ecosystem, r.version, ranges).status !== 'not_affected');
    // runtime contradiction: asset observations in the same environment still showing the vulnerable version
    const runtime = f.environment_id ? (await deployedInventory(db, f.project_id, { environmentId: f.environment_id })).filter(r => !r.deployment_id && r.ecosystem === f.ecosystem && normName(r.ecosystem, r.name) === normName(f.ecosystem, f.comp_name) && evaluateRanges(f.ecosystem, r.version, ranges).status === 'affected') : [];
    if (stillAffected.length || runtime.length) {
      const why = stillAffected.length ? `Deployed artifact ${dep?.digest || ''} still contains ${f.comp_name}@${stillAffected[0].version}.` : `Runtime observation on asset ${runtime[0].asset_id} still shows ${f.comp_name}@${runtime[0].version}.`;
      await ev('counter', why, { digest: dep?.digest });
      await db.query(`UPDATE findings SET status='in_progress', verification_status='failed', updated_at=now() WHERE id=$1`, [f.id]);
      await event('in_progress', 'verification_failed', { why });
      await emit(db, f.org_id, 'verification.failed', { finding_id: f.id, project_id: f.project_id, reason: why });
      return { verified: false, reason: 'still_affected' };
    }
    const summary = present.length ? `Environment ${f.env_key}: deployed artifact ${dep?.digest} contains ${f.comp_name}@${present.map(p => p.version).join(', ')}, outside affected ranges.` : `Environment ${f.env_key}: ${f.comp_name} is no longer present in deployed artifact ${dep?.digest || ''}.`;
    await ev('supporting', summary, { digest: dep?.digest, deployment_id: dep?.id, deployed_at: dep?.deployed_at, snapshot_id: snapshot?.id, snapshot_format: snapshot?.format, verified_at: new Date().toISOString() });
    await db.query(`UPDATE findings SET status='verified_fixed', verification_status='verified', closed_at=now(), updated_at=now() WHERE id=$1`, [f.id]);
    await event('verified_fixed', summary, { digest: dep?.digest });
    await emit(db, f.org_id, 'remediation.verified', { finding_id: f.id, project_id: f.project_id, digest: dep?.digest });
    await audit(db, { orgId: f.org_id, actorType: 'system', systemActor: 'verification' }, 'finding.verified_fixed', { targetType: 'finding', targetId: f.id, projectId: f.project_id, data: { digest: dep?.digest, environment: f.env_key } });
    return { verified: true };
  });
}

/** CI gate: deterministic evaluation of an artifact snapshot (not deployed => no findings created). */
export async function evaluateSnapshotMatches(db, snapshotId) {
  const comps = await db.query(`SELECT c.*, o.architecture FROM observations o JOIN components c ON c.id=o.component_id WHERE o.snapshot_id=$1`, [snapshotId]);
  const out = [];
  for (const c of comps) for (const m of await matchComponent(db, c, { architecture: c.architecture })) {
    if (m.excludedByArch) continue;
    const adv = await db.one('SELECT id, severity, title FROM advisories WHERE id=$1', [m.advisoryId]);
    const exp = await exploitationFor(db, m.advisoryId);
    out.push({ advisory_id: m.advisoryId, title: adv.title, severity: adv.severity, exploitation: exp.status, package: c.name, ecosystem: c.ecosystem, version: c.version, fixed: m.evaluation.fixed || null, status: m.evaluation.status, purl: c.purl });
  }
  return out;
}
export { compareVersions };
