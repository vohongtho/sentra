import { Link, useNavigate, useParams } from 'react-router-dom';
import { get, post, qs, type Project } from '../api';
import { Badge, Empty, Icon, Load, PageHead, PRIORITY, SavedViews, Synth, Table, fmtDate, fmtDay, label, onSubmit, pct, rel, safeHref, shortDigest, useLoad, useQuery, useUi } from '../ui';

// ---------------------------------------------------------------- overview
export function Overview() {
  const s = useLoad(() => get('/api/dashboard/portfolio'), []);
  return <Load s={s}>{d => {
    const t = d.totals; const maxBar = Math.max(1, ...d.trend.map((x: any) => x.opened + x.closed));
    return <>
      <PageHead title="Portfolio overview" sub="Risk shown next to coverage and uncertainty. Every number links to its records.">
        <Link className="btn" to="/advisories/new"><Icon n="shield" s={15} /> Investigate a CVE</Link><Link className="btn primary" to="/projects/new"><Icon n="folder" s={15} /> Onboard project</Link>
      </PageHead>
      <div className="grid g4" style={{ marginBottom: 16 }}>
        <Link className="card stat" to="/findings?priority=P0,P1"><span className="l">P0 / P1 open</span><span className="v">{t.p0 || 0} / {t.p1 || 0}</span><span className="l">priority policy — explainable factors</span></Link>
        <Link className="card stat" to="/findings?exploitation=kev_listed,actively_exploited,observed_in_env"><span className="l">Exploitation evidence</span><span className="v">{t.exploited || 0}</span><span className="l">KEV / vendor-reported / observed (separate signals)</span></Link>
        <Link className="card stat" to="/findings?overdue=true"><span className="l">Overdue (SLA breached)</span><span className="v">{t.overdue || 0}</span><span className="l">clock paused time excluded</span></Link>
        <Link className="card stat" to="/findings?applicability=unknown,under_investigation"><span className="l">Uncertain applicability</span><span className="v">{t.uncertain || 0}</span><span className="l">Unknown is not low risk</span></Link>
      </div>
      <div className="grid g21">
        <div className="card"><div className="head"><h2 className="grow">Projects</h2><Link className="btn sm" to="/coverage">Coverage details</Link></div>
          <Table rows={d.projects} onRow={(p: any) => `/projects/${p.id}`} empty="No projects in your scope yet." cols={[
            { label: 'Project', render: (p: any) => <><b>{p.name}</b><br /><small>{p.key} · {p.criticality} · {p.exposure}</small></> },
            { label: 'Open', render: (p: any) => <Link to={`/findings?project_id=${p.id}`}>{p.open}</Link> },
            { label: 'P0/P1', render: (p: any) => <Link to={`/findings?project_id=${p.id}&priority=P0,P1`}>{p.p0 + p.p1}</Link> },
            { label: 'Exploited', render: (p: any) => p.exploited ? <Link to={`/findings?project_id=${p.id}&exploitation=kev_listed,actively_exploited,observed_in_env`}><Badge v={String(p.exploited)} cls="red" /></Link> : '0' },
            { label: 'Overdue', render: (p: any) => <Link to={`/findings?project_id=${p.id}&overdue=true`}>{p.overdue}</Link> },
            { label: 'Coverage', render: (p: any) => <><Link to="/coverage"><Badge v={pct(p.coverage_ratio)} cls={p.coverage_ratio >= 0.8 ? 'green' : p.coverage_ratio >= 0.5 ? 'orange' : 'red'} /></Link> <small>{p.coverage_gaps} gaps</small></> },
          ]} /></div>
        <div className="col">
          <div className="card"><h3>Opened vs closed (14 days)</h3>
            <div className="bars" aria-label="Opened and closed findings per day">{d.trend.map((x: any) => <div key={x.day} title={`${fmtDay(x.day)}: ${x.opened} opened, ${x.closed} closed`}><span style={{ height: (x.opened / maxBar) * 85, background: 'var(--orange)' }} /><span style={{ height: (x.closed / maxBar) * 85, background: 'var(--green)' }} /></div>)}</div>
            <small><span style={{ color: 'var(--orange)' }}>■</span> opened <span style={{ color: 'var(--green)' }}>■</span> verified/closed</small></div>
          <div className="card"><h3>Response metrics</h3><dl className="kv">
            <dt>Remediation (median)</dt><dd>{d.metrics.remediation_median_hours.value != null ? Math.round(d.metrics.remediation_median_hours.value) + ' h' : '—'}<br /><small>{d.metrics.remediation_median_hours.population}</small></dd>
            <dt>Acknowledgement (median)</dt><dd>{d.metrics.ack_median_minutes.value != null ? Math.round(d.metrics.ack_median_minutes.value) + ' min' : '—'}<br /><small>{d.metrics.ack_median_minutes.population}</small></dd>
            <dt>Verified closures</dt><dd><Link to="/findings?status=verified_fixed">{t.verified || 0}</Link></dd></dl></div>
          <div className="card"><div className="head"><h3 className="grow">Intelligence & connectors</h3><Link className="btn sm" to="/integrations">Manage</Link></div>
            {d.connectors.length ? d.connectors.map((c: any) => <div key={c.name} className="row" style={{ justifyContent: 'space-between', padding: '4px 0' }}><span>{c.name}</span><span><Badge v={c.status} /> <small>{c.last_success_at ? rel(c.last_success_at) : 'never synced'}</small></span></div>) : <Empty title="No connectors configured" />}</div>
        </div>
      </div>
    </>;
  }}</Load>;
}

export function Notifications() {
  const { act } = useUi();
  const s = useLoad(() => get('/api/me/notifications'), []);
  return <><PageHead title="Notifications"><button className="btn" onClick={() => act(() => post('/api/me/notifications/read'), 'Marked read').then(s.reload)}>Mark all read</button></PageHead>
    <Load s={s}>{items => <Table rows={items} empty="No notifications." cols={[{ label: 'When', render: (n: any) => rel(n.created_at) }, { label: 'Title', render: (n: any) => <>{!n.read_at && <span className="dot" style={{ color: 'var(--lime)' }} />} {n.link ? <a href={'#' + String(n.link).split('#')[1]}>{n.title}</a> : n.title}</> }]} />}</Load></>;
}

// ---------------------------------------------------------------- advisories
export function Advisories() {
  const q = useQuery(); const nav = useNavigate();
  const s = useLoad(() => get('/api/advisories' + qs({ q: q.q, affecting: q.affecting, offset: q.offset, limit: 50 })), [q.q, q.affecting, q.offset]);
  return <><PageHead title="Advisories" sub="OSV-schema records with aliases, revisions and separate exploitation signals."><Link className="btn primary" to="/advisories/new">Investigate a CVE</Link></PageHead>
    <SavedViews page="advisories" query={q} base="/advisories" />
    <form className="row" style={{ marginBottom: 12 }} onSubmit={onSubmit(d => nav('/advisories' + qs({ q: d.q, affecting: d.affecting ? 'true' : '' })))}><input className="i" name="q" placeholder="CVE, GHSA, title…" defaultValue={q.q} style={{ maxWidth: 300 }} /><label className="row"><input type="checkbox" name="affecting" defaultChecked={!!q.affecting} /> affecting my projects</label><button className="btn">Search</button></form>
    <Load s={s}>{r => <Table rows={r.items} onRow={(a: any) => `/advisories/${encodeURIComponent(a.id)}`} empty="No advisories stored yet. Sync OSV or paste an advisory." cols={[
      { label: 'Advisory', render: (a: any) => <><b>{a.id}</b> <Synth on={a.is_synthetic} /><br /><small>{(a.aliases || []).join(', ')}</small></> },
      { label: 'Title', render: (a: any) => (a.title || '').slice(0, 90) },
      { label: 'Severity', render: (a: any) => <><Badge v={a.severity} /> {a.cvss_score ?? ''}</> },
      { label: 'Status', render: (a: any) => <Badge v={a.status} /> },
      { label: 'Revision', render: (a: any) => `r${a.current_revision}` },
      { label: 'Open findings', render: (a: any) => a.open_findings },
      { label: 'Modified', render: (a: any) => rel(a.modified_at) },
    ]} />}</Load></>;
}

export function NewAdvisory() {
  const { act, toast } = useUi(); const nav = useNavigate();
  return <><PageHead title="Investigate a CVE" sub="Paste an advisory in OSV JSON (from osv.dev, the GitHub Advisory Database, or a vendor feed converted to OSV). Sentra stores it as a revision and re-evaluates all deployed inventory in scope deterministically." />
    <div className="grid g21"><form className="card form" onSubmit={onSubmit(async d => {
      let osv; try { osv = JSON.parse(d.osv); } catch { toast('Not valid JSON', true); return; }
      const r = await act(() => post('/api/advisories', { osv, synthetic: d.synthetic }));
      toast(r.note); setTimeout(() => nav(`/advisories/${encodeURIComponent(r.advisoryId)}`), 1200);
    })}><label className="f">OSV JSON<textarea className="i" name="osv" required style={{ minHeight: 320 }} placeholder='{"id":"GHSA-xxxx","aliases":["CVE-…"],"affected":[{"package":{"ecosystem":"npm","name":"…"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}' /></label>
      <label className="row"><input type="checkbox" name="synthetic" /> This is synthetic/demo data</label><div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Store & assess portfolio</button></div></form>
      <div className="card md"><h3>What happens</h3><ul><li>Schema validation; identical content is a no-op.</li><li>Aliases (CVE/GHSA/vendor) are linked; a changed record becomes a new revision with a change summary.</li><li>Every project whose deployed or observed inventory contains the package is re-evaluated using ecosystem-specific version comparison.</li><li>New affected deployments create findings with evidence; revisions that exclude a version close findings as not affected, with the reason recorded.</li><li>Model output never decides version applicability.</li></ul></div></div></>;
}

export function Advisory() {
  const { id = '' } = useParams(); const { act, modal } = useUi(); const nav = useNavigate();
  const s = useLoad(() => get(`/api/advisories/${encodeURIComponent(id)}`), [id]);
  return <Load s={s}>{a => <>
    <PageHead title={a.id} sub={<>{a.title}<br /><small>{a.aliases.join(' · ')}</small></>}>
      <button className="btn" onClick={async () => { const inv = await act(() => post('/api/investigations', { workflow: 'advisory_research', advisory_id: a.id }), 'Research queued'); nav(`/investigations/${inv.id}`); }}><Icon n="spark" s={15} /> Research advisory</button></PageHead>
    <div className="pill-row" style={{ marginBottom: 12 }}><Badge v={a.severity} /><Badge v={a.status} /><Synth on={a.is_synthetic} /><span className="b">r{a.current_revision}</span></div>
    <div className="grid g21"><div className="col">
      <div className="card"><h2>Portfolio impact (your scope)</h2><Table rows={a.findings} onRow={(f: any) => `/findings/${f.id}`} empty="No deployed or observed inventory in your scope matches this advisory. Check coverage: missing inventory is not evidence of safety." cols={[
        { label: 'Scope', render: (f: any) => <>{f.project}/{f.service || 'asset'}/<Badge v={f.environment} cls={f.is_production ? 'orange' : ''} /></> },
        { label: 'Package', render: (f: any) => `${f.package}@${f.observed_version || '?'}` }, { label: 'Priority', render: (f: any) => <PRIORITY p={f.priority} /> },
        { label: 'Applicability', render: (f: any) => <Badge v={f.applicability} /> }, { label: 'Status', render: (f: any) => <Badge v={f.status} /> }]} /></div>
      <div className="card"><h2>Affected ranges</h2><Table rows={a.ranges} cols={[
        { label: 'Ecosystem', render: (r: any) => <>{r.ecosystem}{r.distro && <small> {r.distro}</small>}</> }, { label: 'Package', render: (r: any) => r.package_name },
        { label: 'Events', render: (r: any) => <code>{(r.events || []).map((e: any) => Object.entries(e).map(([k, v]) => `${k} ${v}`).join('')).join(', ') || (r.versions || []).join(', ')}</code> },
        { label: 'Architectures', render: (r: any) => r.architectures ? r.architectures.join(', ') : 'all' }]} /></div>
      <div className="card"><h2>Details</h2><p style={{ whiteSpace: 'pre-wrap' }}>{a.details || a.summary}</p>{a.cvss_vector && <p style={{ marginTop: 8 }}><code>{a.cvss_vector}</code> ({a.cvss_score ?? 'score n/a'})</p>}
        {(a.prerequisites || []).length > 0 && <><h3 style={{ marginTop: 12 }}>Prerequisites</h3>{a.prerequisites.map((p: any, i: number) => <div key={i} className="ev missing">{p.kind}: {p.value}{p.note && <small> {p.note}</small>}</div>)}</>}</div>
    </div><div className="col">
      <div className="card"><h2>Exploitation</h2><p><Badge v={a.exploitation.status} /> {a.exploitation.epss != null && <span className="b">EPSS {a.exploitation.epss}</span>}</p>
        {a.exploitation.signals.map((sg: any, i: number) => <div key={i} className="ev neutral"><Badge v={sg.kind} /> <small>{sg.source} · {rel(sg.observed_at)}</small></div>)}
        <button className="btn sm" style={{ marginTop: 8 }} onClick={() => modal(close => <form className="form" onSubmit={onSubmit(async d => { await act(() => post(`/api/advisories/${encodeURIComponent(a.id)}/signals`, d), 'Signal recorded; findings will be re-prioritized'); close(); s.reload(); })}>
          <h2>Record exploitation signal</h2><label className="f">Kind<select className="i" name="kind"><option value="public_poc">Public proof-of-concept</option><option value="vendor_exploited">Vendor-reported exploitation</option><option value="observed_in_env">Observed in our environment</option></select></label>
          <label className="f">Source URL (required except observed)<input className="i" name="source_url" /></label><label className="f">Note<input className="i" name="note" /></label>
          <div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn" onClick={close}>Cancel</button><button className="btn primary">Record</button></div></form>)}>Record signal</button></div>
      <div className="card"><h2>Revisions</h2><ul className="timeline">{a.revisions.map((r: any) => <li key={r.revision}><b>r{r.revision}</b> <small>{fmtDate(r.created_at)}</small><br /><small>{(r.change_summary || []).map((c: any) => `${c.field}${c.change ? ': ' + label(c.change) : c.to ? ': ' + c.from + '→' + c.to : ''}`).join('; ')}</small></li>)}</ul></div>
      <div className="card"><h2>References</h2>{(a.references_json || []).map((r: any, i: number) => <div key={i}><a href={safeHref(r.url)} target="_blank" rel="noopener noreferrer">{r.type || 'link'}</a> <small>{r.url}</small></div>)}</div>
    </div></div></>}</Load>;
}

// ---------------------------------------------------------------- assets & components
export function Assets() {
  const q = useQuery(); const nav = useNavigate();
  const s = useLoad(() => get('/api/assets' + qs({ q: q.q })), [q.q]);
  return <><PageHead title="Assets" sub="Servers, workloads, functions and managed services. Shared assets show only the project links you can see." />
    <SavedViews page="assets" query={q} base="/assets" />
    <form className="row" style={{ marginBottom: 12 }} onSubmit={onSubmit(d => nav('/assets' + qs(d)))}><input className="i" name="q" defaultValue={q.q} placeholder="Filter by name" style={{ maxWidth: 300 }} /><button className="btn">Filter</button></form>
    <Load s={s}>{as => <Table rows={as} onRow={(a: any) => `/assets/${a.id}`} empty="No assets. Import runtime inventory or connect AWS, Wazuh or Dependency-Track." cols={[
      { label: 'Asset', render: (a: any) => <><b>{a.name}</b><br /><small>{a.identifier}</small></> }, { label: 'Kind', render: (a: any) => a.kind }, { label: 'Arch', render: (a: any) => a.architecture || '—' }, { label: 'OS', render: (a: any) => a.os || '—' },
      { label: 'Projects', render: (a: any) => <div className="pill-row">{(a.projects || []).map((p: any, i: number) => <span key={i} className="b">{p.project}/{p.environment || '-'}</span>)}</div> }, { label: 'Observed', render: (a: any) => rel(a.last_observed_at) }]} />}</Load></>;
}
export function Asset() {
  const { id = '' } = useParams(); const s = useLoad(() => get(`/api/assets/${id}`), [id]);
  return <Load s={s}>{a => <>
    <PageHead title={a.name} sub={`${a.kind} · ${a.identifier}`} />
    {a.hidden_project_links > 0 && <div className="notice info" style={{ marginBottom: 12 }}>This asset is shared with {a.hidden_project_links} project(s) outside your access.</div>}
    <div className="grid g2"><div className="card"><h2>Identity & configuration</h2><dl className="kv"><dt>Architecture</dt><dd>{a.architecture || 'unknown'}</dd><dt>OS</dt><dd>{a.os || '—'}</dd><dt>Criticality</dt><dd><Badge v={a.criticality} /></dd><dt>Last observed</dt><dd>{fmtDate(a.last_observed_at)}</dd>
      {Object.entries(a.attributes || {}).map(([k, v]) => <div key={k} style={{ display: 'contents' }}><dt>{label(k)}</dt><dd><code>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</code></dd></div>)}</dl></div>
      <div className="card"><h2>Projects</h2>{a.projects.map((p: any) => <div key={p.project_id}><Link to={`/projects/${p.project_id}`}>{p.project}</Link> / {p.environment || '-'}</div>)}
        <h2 style={{ marginTop: 14 }}>Findings</h2>{a.findings.length ? a.findings.map((f: any) => <div key={f.id}><Link to={`/findings/${f.id}`}>{f.advisory_id}</Link> <PRIORITY p={f.priority} /> <Badge v={f.status} /> <small>{f.project}</small></div>) : <p className="muted">None in your scope.</p>}</div>
      <div className="card" style={{ gridColumn: '1/-1' }}><h2>Observed components (latest snapshot)</h2><Table rows={a.components} empty="No component observations for this asset." cols={[
        { label: 'Package', render: (c: any) => <Link to={`/components/${c.id}`}>{c.name}</Link> }, { label: 'Version', render: (c: any) => c.version || <Badge v="unknown" /> }, { label: 'Kind', render: (c: any) => c.kind },
        { label: 'Version kind', render: (c: any) => c.version_kind }, { label: 'Confidence', render: (c: any) => c.confidence }, { label: 'Source', render: (c: any) => c.source }, { label: 'Observed', render: (c: any) => <>{rel(c.observed_at)} {c.stale && <Badge v="stale" />}</> }]} /></div>
      <div className="card" style={{ gridColumn: '1/-1' }}><h2>Snapshot history</h2><Table rows={a.snapshots} cols={[{ label: 'When', render: (x: any) => fmtDate(x.created_at) }, { label: 'Source', render: (x: any) => x.source }, { label: 'Method', render: (x: any) => x.collection_method }, { label: 'Components', render: (x: any) => x.component_count }]} /></div>
    </div></>}</Load>;
}
export function Component() {
  const { id = '' } = useParams(); const s = useLoad(() => get(`/api/components/${id}`), [id]);
  return <Load s={s}>{c => <><PageHead title={`${c.name}${c.version ? '@' + c.version : ''}`} sub={<><code>{c.purl}</code> · {c.ecosystem} · {c.kind}{c.distro ? ' · ' + c.distro : ''}</>} />
    <div className="card"><h2>Where it is observed</h2><Table rows={c.observations} cols={[{ label: 'Project', render: (o: any) => o.project }, { label: 'Scope', render: (o: any) => `${o.service || o.asset || '—'} / ${o.environment || '—'}` }, { label: 'Artifact', render: (o: any) => o.digest ? <code>{shortDigest(o.digest)}</code> : '—' }, { label: 'Version kind', render: (o: any) => o.version_kind }, { label: 'Direct', render: (o: any) => o.direct == null ? '?' : o.direct ? 'direct' : 'transitive' }, { label: 'Arch', render: (o: any) => o.architecture || '—' }, { label: 'Observed', render: (o: any) => <>{rel(o.observed_at)} {o.stale && <Badge v="stale" />}</> }]} /></div>
    <div className="card" style={{ marginTop: 16 }}><h2>Findings</h2><Table rows={c.findings} onRow={(f: any) => `/findings/${f.id}`} empty="No findings for this component." cols={[{ label: 'Advisory', render: (f: any) => f.advisory_id }, { label: 'Project', render: (f: any) => f.project }, { label: 'Env', render: (f: any) => f.environment }, { label: 'Priority', render: (f: any) => <PRIORITY p={f.priority} /> }, { label: 'Status', render: (f: any) => <Badge v={f.status} /> }]} /></div></>}</Load>;
}

// ---------------------------------------------------------------- drift, campaigns, coverage
export function Drift() {
  const q = useQuery(); const nav = useNavigate();
  const ps = useLoad(() => get<Project[]>('/api/projects'), []);
  const pid = q.project_id || ps.data?.[0]?.id;
  const s = useLoad(() => (pid ? get('/api/drift' + qs({ project_id: pid })) : Promise.resolve(null)), [pid]);
  return <Load s={ps}>{projects => !pid ? <Empty title="No projects in scope" /> : <>
    <PageHead title="Stack & deployment drift" sub={s.data?.legend}><select className="i" style={{ maxWidth: 240 }} value={pid} onChange={e => nav('/drift?project_id=' + e.target.value)}>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></PageHead>
    <Load s={s}>{d => <>{d.services.map((sv: any) => <div key={sv.service} className="card" style={{ marginBottom: 14 }}>
      <div className="head"><h2 className="grow">{sv.service}</h2>{sv.latest_build ? <small>latest build <code>{shortDigest(sv.latest_build.digest)}</code> · {rel(sv.latest_build.at)}</small> : <span className="b warn">no build SBOM</span>}</div>
      <div className="pill-row" style={{ marginBottom: 10 }}>{sv.environments.map((e: any) => <span key={e.environment} className={`b ${e.behind_latest_build ? 'orange' : e.deployed_digest ? 'green' : 'red'}`}>{e.environment}: {e.deployed_digest ? shortDigest(e.deployed_digest) : 'not deployed'}{e.behind_latest_build ? ' (behind latest build)' : ''}</span>)}</div>
      {sv.drift.length ? <div className="tablewrap"><table><thead><tr><th>Component</th><th>Declared</th><th>Build</th>{sv.environments.map((e: any) => <th key={e.environment}>{e.environment} deployed / observed</th>)}</tr></thead>
        <tbody>{sv.drift.map((r: any) => <tr key={r.component}><td>{r.component}</td><td>{r.declared || '—'}</td><td>{r.build || '—'}</td>{sv.environments.map((e: any) => <td key={e.environment}>{r.environments[e.environment]?.deployed || '—'} / {r.environments[e.environment]?.observed || '—'}</td>)}</tr>)}</tbody></table></div>
        : <p className="muted">No version differences between available sources. Missing sources are listed as coverage gaps.</p>}</div>)}</>}</Load></>}</Load>;
}

export function Campaigns() {
  const { act } = useUi(); const nav = useNavigate();
  const s = useLoad(() => Promise.all([get('/api/campaigns'), get('/api/campaigns/suggestions')]), []);
  return <><PageHead title="Remediation campaigns" sub="Coordinate one root-cause fix across services and projects. Closure counts only verified deployments.">
    <button className="btn" onClick={async () => { const inv = await act(() => post('/api/investigations', { workflow: 'portfolio' }), 'Portfolio analysis queued'); nav(`/investigations/${inv.id}`); }}><Icon n="spark" s={15} /> Portfolio agent</button></PageHead>
    <Load s={s}>{([cs, sug]) => <div className="grid g21"><div className="col">{cs.length ? cs.map((c: any) => <div key={c.id} className="card"><div className="head"><h2 className="grow">{c.name}</h2><Badge v={c.status} /></div><p className="muted">{c.description || c.root_cause_key}</p>
      <div className="row" style={{ margin: '10px 0' }}><span className="b green">{c.progress.verified}/{c.progress.total} verified</span><span className="b blue">{c.progress.in_flight} in flight</span>{c.progress.blocked > 0 && <span className="b orange">{c.progress.blocked} blocked</span>}</div>
      <Table rows={[...(c.findings || [])].sort((a: any, b: any) => a.priority.localeCompare(b.priority))} onRow={(f: any) => `/findings/${f.id}`} cols={[{ label: 'Scope', render: (f: any) => `${f.project}/${f.service || '-'}/${f.environment || '-'}` }, { label: 'Priority', render: (f: any) => <PRIORITY p={f.priority} /> }, { label: 'Status', render: (f: any) => <Badge v={f.status} /> }, { label: 'Verification', render: (f: any) => <Badge v={f.verification} /> }, { label: 'Owner', render: (f: any) => f.owner || '—' }]} /></div>) : <Empty title="No campaigns yet">Create one from a shared root cause.</Empty>}</div>
      <div className="card"><h2>Shared root causes</h2>{sug.length ? sug.map((x: any) => <div key={x.root_cause_key} className="ev neutral"><b>{x.package}</b> — {x.advisory_id} <PRIORITY p={x.top_priority} /><br /><small>{x.occurrences} occurrences in {x.projects} project(s): {(x.project_keys || []).join(', ')} · fix {x.fixed_version || 'unknown'}</small><br />
        <button className="btn sm" style={{ marginTop: 6 }} onClick={() => act(() => post('/api/campaigns', { name: `${x.package} → ${x.fixed_version || 'mitigation'}`, root_cause_key: x.root_cause_key }), 'Campaign created').then(s.reload)}>Create campaign</button></div>) : <p className="muted">No shared root causes in scope.</p>}</div></div>}</Load></>;
}

export function Coverage() {
  const s = useLoad(() => get('/api/coverage'), []);
  return <><PageHead title="Coverage & blind spots" sub="Where assessments cannot be trusted: missing SBOMs, stale observations, failed connectors, unsupported analysis and unowned assets. Missing data is never treated as 'no vulnerabilities'." />
    <Load s={s}>{cov => cov.length ? cov.map((p: any) => <div key={p.project_id} className="card" style={{ marginBottom: 14 }}><div className="head"><h2 className="grow"><Link to={`/projects/${p.project_id}`}>{p.name}</Link></h2><Badge v={pct(p.coverage_ratio)} cls={p.coverage_ratio >= 0.8 ? 'green' : p.coverage_ratio >= 0.5 ? 'orange' : 'red'} /><small>{p.covered_scopes}/{p.expected_scopes} scopes</small></div>
      {p.gaps.length ? <Table rows={p.gaps} cols={[{ label: 'Gap', render: (g: any) => <><Badge v={g.severity} /> {label(g.kind)}</> }, { label: 'Scope', render: (g: any) => g.service ? `${g.service}/${g.environment}` : '—' }, { label: 'Detail', render: (g: any) => g.detail }]} /> : <div className="notice ok">No gaps detected for this project.</div>}</div>) : <Empty title="No projects in scope" />}</Load></>;
}
