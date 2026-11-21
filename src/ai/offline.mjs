// Offline deterministic planner: runs the same scoped tools as the model-backed agent with a fixed plan and composes a
// structured result strictly from tool outputs. It is labeled "offline-deterministic-planner" in every result; it makes
// no inferences beyond the evidence and never claims reachability or compromise.
import { WaitingEvidence, CancelledError } from './agents.mjs';

const LIMIT_NO_REACH = 'No static/runtime reachability analysis tool is configured; reachability is not assessed.';
const LIMIT_OFFLINE = 'Produced by the offline deterministic planner (no language model). It reports tool evidence only.';
const base = () => ({ summary: '', applicability: 'unknown', dimensions: { presence: 'unknown', reachability: 'unknown', prerequisites: 'unknown', compromise: 'unknown' }, claims: [], missing_evidence: [], limitations: [LIMIT_OFFLINE], next_actions: [], plan: [] });

export async function offlinePlan(run, ctrl) {
  const step = async (label, tool, input) => { if (await ctrl.isCancelled()) throw new CancelledError(); const r = await ctrl.callTool(tool, input); r.label = label; return r; };
  const W = { evidence_analysis: evidenceAnalysis, impact, advisory_research: research, remediation, verification, portfolio, discovery, copilot };
  return { result: await W[run.workflow](run, step), stopReason: null };
}

async function impact(run, step) {
  const R = base();
  const f = await step('Load finding', 'get_finding', { finding_id: run.inputs.finding_id }); R.plan.push('Loaded finding and existing evidence');
  if (f.status !== 'ok') { R.summary = 'Finding not accessible.'; return R; }
  const fo = f.output;
  const a = await step('Load advisory', 'get_advisory', { advisory_id: fo.advisory_id }); R.plan.push('Read advisory ranges, prerequisites and exploitation signals');
  const ev = await step('Evaluate version', 'evaluate_version', { advisory_id: fo.advisory_id, ecosystem: fo.component.ecosystem, package: fo.component.name, version: fo.observed_version || '' }); R.plan.push('Deterministic version evaluation');
  const dp = await step('Dependency path', 'get_dependency_path', { finding_id: fo.id });
  const deps = await step('Deployments', 'get_deployments', { project_id: fo.project_id }); R.plan.push('Checked current deployments');
  const kn = await step('Project knowledge', 'get_knowledge', { project_id: fo.project_id });
  let asset = null; if (fo.asset_id) asset = await step('Asset', 'get_asset', { asset_id: fo.asset_id });
  const evo = ev.output;
  if (evo.status === 'affected') { R.dimensions.presence = 'confirmed'; R.claims.push({ statement: `${fo.component.name}@${fo.observed_version} is inside an affected range (${evo.reason}).`, stance: 'supporting', evidence_refs: [ev.ref, f.ref] }); }
  else if (evo.status === 'not_affected' || evo.status === 'not_listed') { R.dimensions.presence = 'not_present'; R.claims.push({ statement: `Deterministic evaluation: ${evo.reason}`, stance: 'counter', evidence_refs: [ev.ref] }); }
  else { R.missing_evidence.push(`Version evidence: ${evo.reason}`); }
  const env = (deps.output || []).find(d => d && fo.environment_id && d.environment) ;
  if (Array.isArray(deps.output) && deps.output.length) R.claims.push({ statement: `Current deployments recorded: ${deps.output.map(d => `${d.service}/${d.environment}@${String(d.digest).slice(0, 19)}`).join(', ')}.`, stance: 'neutral', evidence_refs: [deps.ref] });
  if (dp.output?.direct === false) R.claims.push({ statement: `Transitive dependency via ${(dp.output.dependency_path || []).join(' → ') || 'unknown path'}; transitivity does not reduce severity.`, stance: 'neutral', evidence_refs: [dp.ref] });
  const prereqs = a.output?.prerequisites || [];
  const assetAttrs = asset?.output?.attributes || {};
  if (!prereqs.length) R.dimensions.prerequisites = 'none';
  for (const p of prereqs) {
    const attrVal = p.attribute ? assetAttrs[p.attribute] : undefined;
    if (attrVal !== undefined && p.required_value !== undefined) {
      const met = String(attrVal) === String(p.required_value);
      R.claims.push({ statement: `Prerequisite ${p.kind} "${p.value}": asset attribute ${p.attribute}=${attrVal} (${met ? 'met' : 'not met'}).`, stance: met ? 'supporting' : 'counter', evidence_refs: [asset.ref, a.ref] });
      R.dimensions.prerequisites = met ? 'met' : (R.dimensions.prerequisites === 'met' ? 'met' : 'not_met');
    } else R.missing_evidence.push(`Prerequisite not verified: ${p.kind}: ${p.value}${p.note ? ' (' + p.note + ')' : ''}`);
  }
  const exp = a.output?.exploitation?.status;
  if (exp && exp !== 'none_known') R.claims.push({ statement: `Exploitation signal: ${exp} (separate from observed compromise in this environment).`, stance: 'supporting', evidence_refs: [a.ref] });
  for (const k of (kn.output || []).filter(k => !k.expired)) R.claims.push({ statement: `Reviewed project knowledge present: "${k.title}" (${k.kind}). Validate relevance manually.`, stance: 'neutral', evidence_refs: [kn.ref] });
  R.limitations.push(LIMIT_NO_REACH, 'No runtime compromise telemetry is connected; compromise is not assessed.');
  if (R.dimensions.presence === 'confirmed') R.applicability = R.dimensions.prerequisites === 'not_met' ? 'not_affected' : (R.dimensions.prerequisites === 'none' || R.dimensions.prerequisites === 'met') ? 'affected' : 'under_investigation';
  else if (R.dimensions.presence === 'not_present') R.applicability = 'not_affected';
  if (R.applicability === 'not_affected' && R.dimensions.prerequisites === 'not_met') R.claims.push({ statement: 'Vulnerable version is present but a required prerequisite is not met on the observed asset; a human should confirm before changing applicability.', stance: 'counter', evidence_refs: [asset?.ref, a.ref].filter(Boolean) });
  if (R.applicability !== fo.applicability && ['affected', 'not_affected'].includes(R.applicability)) {
    const p = await step('Propose update', 'propose_finding_update', { finding_id: fo.id, applicability: R.applicability, justification: R.claims.filter(c => c.stance !== 'neutral').map(c => c.statement).join(' ') });
    R.plan.push('Proposed applicability change for human approval');
    R.claims.push({ statement: `Proposed applicability ${R.applicability} for approval.`, stance: 'neutral', evidence_refs: [p.ref] });
  }
  R.next_actions.push(fo.fixed_version ? `Upgrade ${fo.component.name} to ${fo.fixed_version}+ and redeploy; Sentra verifies the deployed digest.` : 'Identify a vendor-fixed release or mitigation.');
  if (R.missing_evidence.length) R.next_actions.push('Collect the missing prerequisite evidence (configuration/runtime) and rerun.');
  R.summary = `Presence ${R.dimensions.presence}; prerequisites ${R.dimensions.prerequisites}; reachability not assessed; compromise not assessed. Applicability: ${R.applicability}.`;
  return R;
}

async function research(run, step) {
  const R = base(); R.applicability = 'not_applicable'; R.dimensions = { presence: 'not_applicable', reachability: 'not_applicable', prerequisites: 'unknown', compromise: 'not_applicable' };
  const a = await step('Advisory', 'get_advisory', { advisory_id: run.inputs.advisory_id });
  if (!a.output || a.output.found === false) { R.summary = 'Advisory not found in the intelligence store. Ingest it (OSV JSON) first.'; R.missing_evidence.push('Advisory record'); return R; }
  const o = a.output; R.plan.push('Read stored advisory record and revisions');
  for (const r of o.ranges) R.claims.push({ statement: `${r.ecosystem}/${r.package_name}${r.distro ? ' (' + r.distro + ')' : ''}: ${r.events.map(e => Object.entries(e).map(([k, v]) => `${k} ${v}`).join('')).join(', ') || 'explicit versions ' + (r.versions || []).join(', ')}.`, stance: 'neutral', evidence_refs: [a.ref] });
  R.claims.push({ statement: `Severity ${o.severity}${o.cvss_vector ? ' (' + o.cvss_vector + ')' : ''}; exploitation status ${o.exploitation.status}${o.exploitation.epss != null ? '; EPSS ' + o.exploitation.epss : ''}.`, stance: 'neutral', evidence_refs: [a.ref] });
  R.dimensions.prerequisites = o.prerequisites.length ? 'unknown' : 'none';
  for (const p of o.prerequisites) R.claims.push({ statement: `Prerequisite: ${p.kind} — ${p.value}`, stance: 'neutral', evidence_refs: [a.ref] });
  if (!o.references.length) R.missing_evidence.push('No primary references recorded.');
  R.limitations.push('Only the stored advisory record was read; external pages were not fetched by the offline planner.');
  if (o.synthetic) R.limitations.push('This is a SYNTHETIC demonstration advisory.');
  R.summary = `${o.id}: ${o.ranges.length} affected range(s), ${o.prerequisites.length} prerequisite(s), revision ${o.revision}.`;
  return R;
}

async function remediation(run, step) {
  const R = await impact({ ...run, inputs: run.inputs }, step);
  const f = await step('Finding', 'get_finding', { finding_id: run.inputs.finding_id });
  const fo = f.output;
  const others = await step('Other occurrences', 'search_inventory', { project_id: fo.project_id, package: fo.component.name });
  const envs = [...new Set((others.output || []).map(o => `${o.service || 'asset'}/${o.environment}@${o.version}`))];
  R.claims.push({ statement: `Same package in this project: ${envs.join(', ') || 'none'}.`, stance: 'neutral', evidence_refs: [others.ref] });
  if (fo.fixed_version) {
    const check = await step('Check fixed version', 'evaluate_version', { advisory_id: fo.advisory_id, ecosystem: fo.component.ecosystem, package: fo.component.name, version: fo.fixed_version });
    R.claims.push({ statement: `Candidate fixed version ${fo.fixed_version} evaluates as ${check.output.status}.`, stance: check.output.status === 'not_affected' ? 'supporting' : 'counter', evidence_refs: [check.ref] });
  } else R.missing_evidence.push('No fixed version in advisory ranges; mitigation required.');
  R.next_actions = [
    fo.fixed_version ? `Bump ${fo.component.name} to ${fo.fixed_version} (${fo.component.ecosystem}); if transitive, upgrade the parent dependency or add an override/resolution and regenerate the lockfile.` : 'Apply vendor mitigation; track exception with expiry.',
    'Run the full test suite and the SBOM/CI gate on the rebuilt artifact.',
    'Roll out UAT first, then production; record each deployment so Sentra can verify the deployed digest.',
    'Rollback: redeploy the previous digest; the finding re-opens automatically if the vulnerable version returns.',
  ];
  R.limitations.push('Compatibility assessment is limited to version evidence; breaking changes require changelog review.');
  R.summary = `Remediation plan for ${fo.advisory_id} in ${fo.component.name}: ${fo.fixed_version ? 'upgrade to ' + fo.fixed_version : 'no fixed release known'}.`;
  return R;
}

async function verification(run, step) {
  const R = base();
  const f = await step('Finding', 'get_finding', { finding_id: run.inputs.finding_id }); const fo = f.output;
  const deps = await step('Deployments', 'get_deployments', { project_id: fo.project_id });
  const inv = await step('Inventory', 'search_inventory', { project_id: fo.project_id, package: fo.component.name });
  const rows = (inv.output || []).filter(r => r.package === fo.component.name);
  for (const r of rows) {
    const e = await step('Evaluate', 'evaluate_version', { advisory_id: fo.advisory_id, ecosystem: r.ecosystem, package: r.package, version: r.version || '' });
    R.claims.push({ statement: `${r.service || r.asset_id}/${r.environment}: ${r.package}@${r.version} → ${e.output.status}${r.stale ? ' (stale observation)' : ''}.`, stance: e.output.status === 'not_affected' ? 'counter' : 'supporting', evidence_refs: [e.ref, inv.ref] });
  }
  R.claims.push({ statement: `${(deps.output || []).length} current deployment(s) recorded.`, stance: 'neutral', evidence_refs: [deps.ref] });
  R.dimensions.presence = rows.length ? (R.claims.some(c => c.stance === 'supporting') ? 'confirmed' : 'not_present') : 'not_present';
  R.applicability = R.dimensions.presence === 'confirmed' ? 'affected' : 'not_affected';
  R.limitations.push('Verification closure is performed by the deterministic verification service; this run is advisory.');
  R.summary = `Fix verification view: vulnerable version ${R.dimensions.presence === 'confirmed' ? 'still observed' : 'not observed'} in current inventory.`;
  return R;
}

async function portfolio(run, step) {
  const R = base(); R.applicability = 'not_applicable'; R.dimensions = { presence: 'not_applicable', reachability: 'not_applicable', prerequisites: 'not_applicable', compromise: 'not_applicable' };
  const s = await step('Shared components', 'shared_components', {});
  for (const g of (s.output || []).slice(0, 10)) {
    const projects = [...new Set(g.occurrences.map(o => o.project))];
    R.claims.push({ statement: `${g.package} (${g.advisory_id}) open in ${g.occurrences.length} scope(s) across ${projects.join(', ')}; fixed ${g.fixed_version || 'unknown'}; owners ${[...new Set(g.occurrences.map(o => o.owner || 'unassigned'))].join(', ')}.`, stance: 'neutral', evidence_refs: [s.ref] });
    R.next_actions.push(`Campaign: ${g.package} → ${g.fixed_version || 'mitigation'}; order: ${g.occurrences.sort((a, b) => a.priority.localeCompare(b.priority)).map(o => `${o.project}/${o.service || '-'}/${o.environment} (${o.priority})`).join(' → ')}.`);
  }
  R.limitations.push('Expected benefit is described qualitatively; no precise risk-reduction figures are produced.');
  R.summary = `${(s.output || []).length} shared root cause(s) found in scope.`;
  return R;
}

async function discovery(run, step) {
  const R = base(); R.applicability = 'not_applicable'; R.dimensions = { presence: 'not_applicable', reachability: 'not_applicable', prerequisites: 'not_applicable', compromise: 'not_applicable' };
  const p = await step('Project', 'get_project', { project_id: run.project_id });
  const repo = await step('Repository inventory', 'get_repository_inventory', { project_id: run.project_id });
  const files = (run.inputs.files || []).length ? await step('Attached manifests', 'parse_submitted_manifests', {}) : null;
  if (!repo.output?.available && !files) throw new WaitingEvidence('No repository scan or attached manifests. Connect a repository or attach manifests, then rerun.');
  const comps = [...(repo.output?.components || []), ...((files?.output || []).flatMap(f => f.components || []))];
  const byEco = {}; for (const c of comps) byEco[c.ecosystem] = (byEco[c.ecosystem] || 0) + 1;
  const runtimes = comps.filter(c => ['runtime', 'framework'].includes(c.kind));
  R.claims.push({ statement: `Proposed stack: ${Object.entries(byEco).map(([k, v]) => `${k} (${v})`).join(', ')}.`, stance: 'neutral', evidence_refs: [repo.ref, files?.ref].filter(Boolean) });
  if (runtimes.length) R.claims.push({ statement: `Runtimes/frameworks/base images: ${runtimes.map(c => `${c.name}${c.version ? '@' + c.version : ''}`).slice(0, 20).join(', ')}.`, stance: 'neutral', evidence_refs: [repo.ref, files?.ref].filter(Boolean) });
  const unpinned = comps.filter(c => !c.version || c.version_kind === 'declared');
  if (unpinned.length) R.missing_evidence.push(`${unpinned.length} component(s) have declared/unpinned versions; build or runtime versions are needed.`);
  const existing = (p.output?.services || []).map(s => s.key);
  R.next_actions.push(`Review proposed inventory; existing services: ${existing.join(', ') || 'none'}. Confirm service boundaries before importing.`, 'Add CI SBOM upload per service to obtain artifact-level versions.');
  R.limitations.push('Discovery proposes inventory for review; it does not modify confirmed inventory.');
  R.summary = `Discovered ${comps.length} component(s) across ${Object.keys(byEco).length} ecosystem(s).`;
  return R;
}

async function copilot(run, step) {
  const R = base(); R.applicability = 'not_applicable'; R.dimensions = { presence: 'not_applicable', reachability: 'not_applicable', prerequisites: 'not_applicable', compromise: 'not_applicable' };
  const q = String(run.question || '').toLowerCase();
  const projects = await step('Projects in scope', 'list_projects', {});
  const plist = projects.output || [];
  R.plan.push(`Scope: ${plist.map(p => p.key).join(', ')}`);
  const target = plist.filter(p => q.includes(p.key.toLowerCase()) || q.includes(p.name.toLowerCase()));
  const scope = target.length ? target : plist;
  const advMatch = /(cve-\d{4}-\d+|ghsa-[\w-]+|synth-[\w-]+)/i.exec(run.question || '');
  if (advMatch) {
    const a = await step('Advisory', 'get_advisory', { advisory_id: advMatch[1].toUpperCase().replace(/^GHSA/, 'GHSA') });
    if (a.output?.found === false) { R.missing_evidence.push(`Advisory ${advMatch[1]} is not in the intelligence store.`); }
    else for (const p of scope) for (const r of a.output.ranges) {
      const inv = await step('Inventory', 'search_inventory', { project_id: p.id, package: r.package_name.split(/[:/]/).pop() });
      for (const row of (inv.output || []).filter(x => x.package === r.package_name || x.package.endsWith(r.package_name))) {
        const e = await step('Evaluate', 'evaluate_version', { advisory_id: a.output.id, ecosystem: row.ecosystem, package: row.package, version: row.version || '' });
        R.claims.push({ statement: `${p.key}/${row.service || row.asset_id || '-'}/${row.environment}: ${row.package}@${row.version || 'unknown'} → ${e.output.status}.`, stance: e.output.status === 'affected' ? 'supporting' : e.output.status === 'not_affected' ? 'counter' : 'neutral', evidence_refs: [e.ref, inv.ref] });
      }
    }
    if (!R.claims.length) R.claims.push({ statement: `No inventory in scope contains packages named by ${advMatch[1]}. Coverage gaps may hide affected deployments.`, stance: 'neutral', evidence_refs: [projects.ref] });
    R.summary = `Impact of ${advMatch[1]} across ${scope.length} project(s).`;
  } else if (/changed|since yesterday|what's new|what is new/.test(q)) {
    const since = new Date(Date.now() - 86400000).toISOString();
    for (const p of scope) { const c = await step('Changes', 'get_changes_since', { project_id: p.id, since }); const o = c.output; R.claims.push({ statement: `${p.key}: ${o.finding_events.length} finding event(s), ${o.deployments.length} deployment(s), ${o.snapshots.length} inventory snapshot(s) since ${since}.`, stance: 'neutral', evidence_refs: [c.ref] }); }
    R.summary = 'Changes in the last 24 hours.';
  } else if (/insufficient|coverage|blind|stale|evidence for assessment/.test(q)) {
    for (const p of scope) { const c = await step('Coverage', 'coverage_report', { project_id: p.id }); R.claims.push({ statement: `${p.key}: coverage ${Math.round((c.output.coverage_ratio || 0) * 100)}%; gaps: ${c.output.gaps.map(g => g.kind).join(', ') || 'none'}.`, stance: 'neutral', evidence_refs: [c.ref] }); }
    R.summary = 'Projects with insufficient evidence for assessment.';
  } else if (/old image|after the fix|merged|still run/.test(q)) {
    for (const p of scope) { const fl = await step('Findings', 'list_findings', { project_id: p.id, status_group: 'open', environment: '', ecosystem: '' }); for (const f of (fl.output || []).filter(f => ['fix_available', 'deployed', 'verification_pending'].includes(f.status))) R.claims.push({ statement: `${p.key}/${f.service}/${f.environment}: ${f.package}@${f.observed_version} — fix merged/available but not verified in this environment (${f.status}).`, stance: 'supporting', evidence_refs: [fl.ref] }); }
    if (!R.claims.length) R.claims.push({ statement: 'No findings with a merged-but-unverified fix in scope.', stance: 'neutral', evidence_refs: [projects.ref] });
    R.summary = 'Deployments still running a vulnerable artifact after a fix was merged.';
  } else if (/why .*priority|priority .*(increase|change)/.test(q)) {
    for (const p of scope) { const c = await step('Changes', 'get_changes_since', { project_id: p.id, since: new Date(Date.now() - 7 * 86400000).toISOString() }); for (const e of c.output.finding_events.filter(e => e.kind === 'reassessed' && e.from_value !== e.to_value)) R.claims.push({ statement: `${p.key}: finding ${e.finding_id} priority ${e.from_value} → ${e.to_value} (${e.reason}).`, stance: 'neutral', evidence_refs: [c.ref] }); }
    if (!R.claims.length) R.claims.push({ statement: 'No priority changes in the last 7 days in scope.', stance: 'neutral', evidence_refs: [projects.ref] });
    R.summary = 'Priority changes and their recorded triggers.';
  } else {
    const eco = /java|maven|spring|solr/.test(q) ? 'maven' : /php|composer|laravel/.test(q) ? 'composer' : /node|npm|javascript|typescript/.test(q) ? 'npm' : /python|pip/.test(q) ? 'pypi' : '';
    const env = /prod/.test(q) ? 'production' : /uat/.test(q) ? 'uat' : '';
    for (const p of scope) { const fl = await step('Findings', 'list_findings', { project_id: p.id, status_group: 'open', environment: env, ecosystem: eco }); for (const f of (fl.output || []).slice(0, 8)) R.claims.push({ statement: `${f.priority} ${p.key}/${f.service || '-'}/${f.environment}: ${f.advisory_id} in ${f.package}@${f.observed_version} (${f.applicability}, ${f.exploitation}); due ${f.sla_due_at ? new Date(f.sla_due_at).toISOString().slice(0, 10) : 'n/a'}.`, stance: 'neutral', evidence_refs: [fl.ref] }); }
    R.summary = `Open findings ordered by priority${eco ? ' for ' + eco : ''}${env ? ' in ' + env : ''}.`;
  }
  R.limitations.push(`Scope: ${scope.map(p => p.key).join(', ')} (authorized projects only).`);
  return R;
}

async function evidenceAnalysis(run, step) {
  const R = base(); R.applicability = 'not_applicable'; R.dimensions = { presence: 'not_applicable', reachability: 'not_applicable', prerequisites: 'unknown', compromise: 'not_applicable' };
  const ev = await step('Submitted evidence', 'get_submitted_evidence', {});
  R.plan.push('Read submitted evidence (untrusted) and parsed components');
  for (const p of ev.output?.parsed || []) if (p.error) R.missing_evidence.push(`${p.source}: could not be parsed (${p.error}).`);
  const m = await step('Match components', 'match_submitted_components', {});
  R.plan.push('Deterministic match against stored advisories');
  const matches = m.output?.matches || [];
  for (const x of matches) R.claims.push({ statement: `${x.package}@${x.version || 'unknown'} (${x.ecosystem}) → ${x.advisory_id}: ${x.status}${x.fixed ? '; fixed in ' + x.fixed : ''}${x.synthetic ? ' [synthetic advisory]' : ''}.`, stance: x.status === 'affected' ? 'supporting' : x.status === 'not_affected' ? 'counter' : 'neutral', evidence_refs: [m.ref] });
  if (!m.output?.components_checked) R.missing_evidence.push('No machine-readable components found. Submit an SBOM, lockfile or inventory JSON; free text is read but not matched.');
  if (ev.output?.evidence_text?.untrusted_content) R.claims.push({ statement: 'Free-text evidence was submitted; the offline planner records it but does not interpret prose.', stance: 'neutral', evidence_refs: [ev.ref] });
  R.limitations.push('Only advisories stored in Sentra are matched; an empty result is not evidence of safety.', 'Submitted evidence is not verified against deployed artifacts; record a deployment for verified findings.');
  R.next_actions.push(matches.some(x => x.status === 'affected') ? 'Import this inventory against the right artifact or asset so Sentra creates tracked findings.' : 'Sync OSV advisories for these packages, or import the inventory into a project for continuous matching.');
  R.summary = `${m.output?.components_checked || 0} component(s) checked; ${matches.filter(x => x.status === 'affected').length} affected match(es), ${matches.filter(x => x.status === 'unknown').length} unknown.`;
  return R;
}
