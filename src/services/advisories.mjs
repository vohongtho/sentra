// Advisory ingestion in OSV schema (https://ossf.github.io/osv-schema/): aliases, revisions with change summaries,
// withdrawn/rejected handling, affected ranges and separate exploitation signals.
import { id, sha256, stableStringify, badRequest } from '../util.mjs';
import { ecosystemFromOsv } from '../domain/versions.mjs';
import { emit } from '../jobs/runtime.mjs';

// ---------------- CVSS v3.x base score (FIRST spec)
const W = { AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 }, C: { H: 0.56, L: 0.22, N: 0 } };
const roundUp = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
export function cvss3Score(vector) {
  const m = Object.fromEntries(String(vector).split('/').slice(1).map(p => p.split(':')));
  if (!/^CVSS:3\.[01]/.test(vector) || !m.AV || !m.S) return null;
  const changed = m.S === 'C';
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const iss = 1 - (1 - W.C[m.C]) * (1 - W.C[m.I]) * (1 - W.C[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * PR * W.UI[m.UI];
  if (impact <= 0) return 0;
  return changed ? roundUp(Math.min(1.08 * (impact + expl), 10)) : roundUp(Math.min(impact + expl, 10));
}
export const severityFromScore = (s) => (s == null ? 'unknown' : s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : s > 0 ? 'low' : 'none');

function canonicalId(osv) {
  const cve = [osv.id, ...(osv.aliases || [])].find(a => /^CVE-\d{4}-\d+$/.test(a));
  return cve || osv.id;
}
function deriveSeverity(osv) {
  let vector = null, version = null, score = null;
  for (const s of osv.severity || []) {
    if (s.type === 'CVSS_V3' || /^CVSS:3/.test(s.score)) { vector = s.score; version = '3.x'; score = cvss3Score(s.score); break; }
    if (s.type === 'CVSS_V4') { vector = s.score; version = '4.0'; }
  }
  const named = (osv.database_specific?.severity || osv.affected?.[0]?.database_specific?.severity || osv.affected?.[0]?.ecosystem_specific?.severity || '').toString().toLowerCase();
  const map = { critical: 'critical', high: 'high', important: 'high', moderate: 'medium', medium: 'medium', low: 'low' };
  const severity = score != null ? severityFromScore(score) : map[named] || 'unknown';
  return { vector, version, score, severity };
}
export function validateOsv(osv) {
  if (!osv || typeof osv !== 'object') throw badRequest('Advisory must be an OSV JSON object.');
  if (!osv.id || typeof osv.id !== 'string' || osv.id.length > 128) throw badRequest('OSV id is required.');
  if (!Array.isArray(osv.affected) && !osv.withdrawn) throw badRequest('OSV "affected" array is required.');
  for (const a of osv.affected || []) {
    if (!a.package?.name || !a.package?.ecosystem) throw badRequest(`affected[].package.{ecosystem,name} required in ${osv.id}.`);
    for (const r of a.ranges || []) if (!['ECOSYSTEM', 'SEMVER', 'GIT'].includes(r.type)) throw badRequest(`Unsupported range type ${r.type}.`);
  }
}

function summarizeChanges(prev, next) {
  if (!prev) return [{ field: 'advisory', change: 'created' }];
  const out = [];
  const p = prev.raw || {};
  if (stableStringify(p.affected) !== stableStringify(next.affected)) out.push({ field: 'affected', change: 'ranges_or_packages_changed' });
  if (deriveSeverity(p).severity !== deriveSeverity(next).severity) out.push({ field: 'severity', from: deriveSeverity(p).severity, to: deriveSeverity(next).severity });
  if (!!p.withdrawn !== !!next.withdrawn) out.push({ field: 'withdrawn', to: next.withdrawn || null });
  if (stableStringify(p.aliases || []) !== stableStringify(next.aliases || [])) out.push({ field: 'aliases', change: 'changed' });
  if ((p.summary || '') !== (next.summary || '')) out.push({ field: 'summary', change: 'changed' });
  if (stableStringify(p.database_specific?.prerequisites || null) !== stableStringify(next.database_specific?.prerequisites || null)) out.push({ field: 'prerequisites', change: 'changed' });
  return out;
}

/** Upsert an OSV advisory. Call with a transaction handle. Returns {advisoryId, revision, changed, changes}. */
export async function upsertAdvisory(db, osv, { source = 'osv', synthetic = false, orgId = null } = {}) {
  validateOsv(osv);
  const advisoryId = canonicalId(osv);
  const contentSha = sha256(stableStringify(osv));
  const existing = await db.one('SELECT * FROM advisories WHERE id=$1', [advisoryId]);
  if (existing) {
    const last = await db.one('SELECT content_sha256 FROM advisory_revisions WHERE advisory_id=$1 ORDER BY revision DESC LIMIT 1', [advisoryId]);
    if (last?.content_sha256 === contentSha) return { advisoryId, revision: existing.current_revision, changed: false, changes: [] };
  }
  const changes = summarizeChanges(existing, osv);
  const sev = deriveSeverity(osv);
  const status = osv.withdrawn ? 'withdrawn' : /REJECT/i.test(osv.summary || '') ? 'rejected' : osv.database_specific?.disputed ? 'disputed' : 'published';
  const revision = existing ? existing.current_revision + 1 : 1;
  const prerequisites = osv.database_specific?.prerequisites || [];
  const isSynthetic = synthetic || /^SYNTH-/.test(osv.id) || !!osv.database_specific?.synthetic;
  const params = [advisoryId, source, osv.summary || null, osv.summary || null, osv.details || null, sev.severity, sev.vector, sev.version, sev.score, status, osv.published || null, osv.modified || null, revision, isSynthetic, JSON.stringify(osv.references || []), JSON.stringify(prerequisites), JSON.stringify(osv.database_specific?.mitigations || []), osv];
  if (existing) {
    await db.query(`UPDATE advisories SET source=$2, title=$3, summary=$4, details=$5, severity=$6, cvss_vector=$7, cvss_version=$8, cvss_score=$9, status=$10, published_at=$11, modified_at=$12, current_revision=$13, is_synthetic=$14, references_json=$15, prerequisites=$16, mitigations=$17, raw=$18, updated_at=now() WHERE id=$1`, params);
    await db.query('DELETE FROM affected_ranges WHERE advisory_id=$1', [advisoryId]);
  } else {
    await db.query(`INSERT INTO advisories (id, source, title, summary, details, severity, cvss_vector, cvss_version, cvss_score, status, published_at, modified_at, current_revision, is_synthetic, references_json, prerequisites, mitigations, raw) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, params);
  }
  await db.query('INSERT INTO advisory_revisions (advisory_id, revision, modified_at, content_sha256, change_summary, raw) VALUES ($1,$2,$3,$4,$5,$6)', [advisoryId, revision, osv.modified || null, contentSha, JSON.stringify(changes), osv]);
  for (const alias of new Set([osv.id, ...(osv.aliases || [])])) await db.query('INSERT INTO advisory_aliases (alias, advisory_id) VALUES ($1,$2) ON CONFLICT (alias) DO UPDATE SET advisory_id=EXCLUDED.advisory_id', [alias, advisoryId]);
  for (const a of osv.affected || []) {
    const eco = ecosystemFromOsv(a.package.ecosystem);
    const distro = String(a.package.ecosystem).includes(':') ? String(a.package.ecosystem).toLowerCase().replace(/\s+/g, '') : null;
    const name = eco === 'pypi' ? a.package.name.toLowerCase().replace(/[-_.]+/g, '-') : a.package.name;
    const ranges = a.ranges?.length ? a.ranges : [{ type: 'ECOSYSTEM', events: [] }];
    for (const r of ranges) {
      await db.query(`INSERT INTO affected_ranges (id, advisory_id, ecosystem, package_name, range_type, events, versions, distro, architectures, database_specific) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [id('rng'), advisoryId, eco, name, r.type, JSON.stringify(r.events || []), JSON.stringify(a.versions || []), distro, a.ecosystem_specific?.architectures ? JSON.stringify(a.ecosystem_specific.architectures) : null, a.database_specific || null]);
    }
  }
  await emit(db, orgId, 'advisory.updated', { advisory_id: advisoryId, revision, changes, reason: existing ? 'advisory_revision' : 'advisory_new' });
  return { advisoryId, revision, changed: true, changes };
}

export async function upsertSignal(db, advisoryOrAlias, kind, value, source, observedAt = new Date().toISOString()) {
  const target = (await db.one('SELECT advisory_id FROM advisory_aliases WHERE alias=$1', [advisoryOrAlias]))?.advisory_id || advisoryOrAlias;
  const prev = await db.one('SELECT value FROM exploit_signals WHERE advisory_id=$1 AND kind=$2 AND source=$3', [target, kind, source]);
  await db.query(`INSERT INTO exploit_signals (id, advisory_id, kind, value, source, observed_at) VALUES ($1,$2,$3,$4,$5,$6)
    ON CONFLICT (advisory_id, kind, source) DO UPDATE SET value=EXCLUDED.value, observed_at=EXCLUDED.observed_at`, [id('sig'), target, kind, value, source, observedAt]);
  const changed = stableStringify(prev?.value ?? null) !== stableStringify(value);
  if (changed && kind !== 'epss') await emit(db, null, 'advisory.updated', { advisory_id: target, reason: `exploitation_signal:${kind}`, changes: [{ field: 'exploitation', kind }] });
  return changed;
}

/** Exploitation status (one field) plus separate signals; never merged into a single score. */
export async function exploitationFor(db, advisoryId) {
  const sigs = await db.query(`SELECT kind, value, source, observed_at FROM exploit_signals WHERE advisory_id=$1 OR advisory_id IN (SELECT alias FROM advisory_aliases WHERE advisory_id=$1)`, [advisoryId]);
  const has = (k) => sigs.some(s => s.kind === k && (s.value?.present ?? true));
  const status = has('observed_in_env') ? 'observed_in_env' : has('vendor_exploited') ? 'actively_exploited' : has('kev') ? 'kev_listed' : has('public_poc') ? 'poc_public' : 'none_known';
  const epss = sigs.find(s => s.kind === 'epss')?.value?.score ?? null;
  return { status, epss, signals: sigs };
}
