// CycloneDX 1.5 VEX export for a project's deployed inventory.
// Applicability → VEX analysis.state mapping (explicit, documented in the document metadata):
//   verified_fixed (status)          → resolved
//   false_positive (status)          → false_positive
//   not_affected                     → not_affected (detail = recorded justification; `justification` code only if recorded)
//   affected                         → exploitable
//   under_investigation / unknown    → in_triage
// accepted_risk keeps the applicability mapping and adds the risk-acceptance note to detail.
import { randomUUID } from 'node:crypto';

const STATE = (f) => (f.status === 'verified_fixed' ? 'resolved' : f.status === 'false_positive' ? 'false_positive' : f.applicability === 'not_affected' ? 'not_affected' : f.applicability === 'affected' ? 'exploitable' : 'in_triage');
const VEX_JUSTIFICATIONS = ['code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency', 'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control'];

export async function projectVex(db, projectId, { environment = null } = {}) {
  const p = await db.one('SELECT id, key, name FROM projects WHERE id=$1', [projectId]);
  const rows = await db.query(`SELECT f.*, c.purl, c.name AS package, c.version AS comp_version, a.severity AS adv_severity, a.cvss_vector, a.cvss_score, a.source AS adv_source, a.references_json, a.is_synthetic, e.key AS env_key, s.key AS service_key
    FROM findings f JOIN components c ON c.id=f.component_id JOIN advisories a ON a.id=f.advisory_id LEFT JOIN environments e ON e.id=f.environment_id LEFT JOIN services s ON s.id=f.service_id
    WHERE f.project_id=$1 AND ($2::text IS NULL OR e.key=$2) ORDER BY f.advisory_id`, [projectId, environment]);
  const components = new Map(); const vulns = new Map();
  for (const f of rows) {
    components.set(f.purl, { type: 'library', 'bom-ref': f.purl, name: f.package, version: f.comp_version || undefined, purl: f.purl });
    const v = vulns.get(f.advisory_id) || { id: f.advisory_id, source: { name: f.is_synthetic ? 'SYNTHETIC (Sentra demo)' : f.adv_source }, ratings: [{ severity: f.adv_severity, ...(f.cvss_vector ? { method: f.cvss_vector.startsWith('CVSS:3') ? 'CVSSv31' : 'other', vector: f.cvss_vector, score: f.cvss_score ?? undefined } : {}) }], affects: [], analysis: null, _states: [] };
    v.affects.push({ ref: f.purl, versions: [{ version: f.observed_version || 'unknown', status: STATE(f) === 'exploitable' || STATE(f) === 'in_triage' ? (STATE(f) === 'in_triage' ? 'unknown' : 'affected') : 'unaffected' }] });
    v._states.push({ state: STATE(f), scope: `${f.service_key || 'asset'}/${f.env_key || '-'}`, detail: f.applicability_justification || f.status_reason || null, justification: VEX_JUSTIFICATIONS.includes(f.applicability_justification) ? f.applicability_justification : null, status: f.status });
    vulns.set(f.advisory_id, v);
  }
  // One analysis per vulnerability: the least favourable state across scopes, with per-scope detail retained.
  const rank = ['exploitable', 'in_triage', 'false_positive', 'not_affected', 'resolved'];
  const out = [...vulns.values()].map(({ _states, ...v }) => {
    const worst = _states.map(s => s.state).sort((a, b) => rank.indexOf(a) - rank.indexOf(b))[0];
    const just = _states.every(s => s.justification) && new Set(_states.map(s => s.justification)).size === 1 ? _states[0].justification : undefined;
    return { ...v, analysis: { state: worst, ...(just ? { justification: just } : {}), detail: _states.map(s => `${s.scope}: ${s.state}${s.detail ? ' — ' + s.detail : ''}${s.status === 'accepted_risk' ? ' (risk accepted)' : ''}`).join('\n').slice(0, 8000) } };
  });
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:' + randomUUID(), version: 1,
    metadata: { timestamp: new Date().toISOString(), tools: { components: [{ type: 'application', name: 'Sentra', version: '1.0.0' }] }, component: { type: 'application', name: p.name, 'bom-ref': `sentra:${p.key}` },
      properties: [{ name: 'sentra:vex_mapping', value: 'verified_fixed→resolved; false_positive→false_positive; not_affected→not_affected; affected→exploitable; under_investigation|unknown→in_triage' }, { name: 'sentra:scope', value: environment || 'all environments' }] },
    components: [...components.values()], vulnerabilities: out,
  };
}
