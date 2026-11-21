import { useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, get, post, put, qs, type Project, type ProjectDetail } from '../api';
import { useMe } from '../Shell';
import { Badge, Empty, Load, PageHead, Synth, Table, Tabs, fmtDate, fmtDay, label, onSubmit, pct, rel, safeHref, shortDigest, useConfirm, useLoad, useQuery, useUi, PRIORITY } from '../ui';

export function ProjectList() {
  const q = useQuery();
  const s = useLoad(() => get<Project[]>('/api/projects' + qs({ include_archived: q.archived })), [q.archived]);
  return <><PageHead title="Projects" sub="Ownership, stack, environments, criticality and inventory freshness.">
    <Link className="btn" to={q.archived ? '/projects' : '/projects?archived=true'}>{q.archived ? 'Hide' : 'Show'} archived</Link><Link className="btn primary" to="/projects/new">Onboard project</Link></PageHead>
    <Load s={s}>{ps => <Table rows={ps} onRow={p => `/projects/${p.id}`} empty="No projects you can access. Successful sign-in does not grant project access; ask a project owner." cols={[
      { label: 'Project', render: p => <><b>{p.name}</b> {p.archived_at && <Badge v="archived" />}<br /><small>{p.key} · {label(p.my_role)}</small></> },
      { label: 'Owner', render: p => p.owner_name || <span className="b warn">no owner</span> },
      { label: 'Stack', render: p => <div className="pill-row">{(p.ecosystems || []).map(e => <span key={e} className="b">{e}</span>)}</div> },
      { label: 'Environments', render: p => <div className="pill-row">{(p.environments || []).map(e => <span key={e.id} className={`b ${e.is_production ? 'orange' : ''}`}>{e.key}</span>)}</div> },
      { label: 'Criticality', render: p => <Badge v={p.criticality} /> },
      { label: 'Open / urgent', render: p => <>{p.open_findings} / <b>{p.urgent_findings}</b></> },
      { label: 'Inventory', render: p => p.last_inventory_at ? <span title={fmtDate(p.last_inventory_at)}>{rel(p.last_inventory_at)}{Date.now() - new Date(p.last_inventory_at).getTime() > 7 * 864e5 && <> <Badge v="stale" /></>}</span> : <span className="b warn">none</span> },
    ]} />}</Load></>;
}

export function NewProject() {
  const { me, refresh } = useMe(); const { act } = useUi(); const nav = useNavigate();
  const s = useLoad(() => get('/api/org/members').catch(() => []), []);
  return <><PageHead title="Project onboarding" sub="Metadata → services/environments → connection → discovery preview → conflict review → inventory → policy/routing → first verified ingestion. Completing the wizard does not mark a project protected." />
    <div className="steps">{['Metadata', 'Services & environments', 'Connection', 'Discovery', 'Conflicts', 'Inventory', 'Policy & routing', 'First ingestion'].map((x, i) => <span key={x} className={i < 2 ? 'cur' : ''}>{i + 1}. {x}</span>)}</div>
    <Load s={s}>{members => <form className="card form two" onSubmit={onSubmit(async d => {
      const body = { ...d, services: String(d.services).split(',').map(x => x.trim()).filter(Boolean).map(key => ({ key })), environments: String(d.envs).split(',').map(x => x.trim()).filter(Boolean).map(key => ({ key, is_production: /prod/.test(key) })) };
      delete (body as any).envs;
      const p = await act(() => post('/api/projects', body), 'Project created'); await refresh(); nav(`/projects/${p.id}/onboarding`);
    })}>
      <label className="f">Key<input className="i" name="key" required pattern="[a-z0-9][a-z0-9-]{1,40}" placeholder="e.g. payments" /></label>
      <label className="f">Name<input className="i" name="name" required /></label>
      <label className="f full">Description<input className="i" name="description" /></label>
      <label className="f">Owner<select className="i" name="owner_identity_id" defaultValue={me.identity?.id}>{members.map((m: any) => <option key={m.id} value={m.id}>{m.display_name}</option>)}</select></label>
      <label className="f">Criticality<select className="i" name="criticality" defaultValue="medium">{['low', 'medium', 'high', 'critical'].map(c => <option key={c}>{c}</option>)}</select></label>
      <label className="f">Data classification<select className="i" name="data_classification" defaultValue="internal">{['public', 'internal', 'confidential', 'restricted'].map(c => <option key={c}>{c}</option>)}</select></label>
      <label className="f">Exposure<select className="i" name="exposure" defaultValue="internal">{['internet', 'partner', 'internal', 'isolated'].map(c => <option key={c}>{c}</option>)}</select></label>
      <label className="f">Services (comma-separated keys)<input className="i" name="services" placeholder="api, worker" /></label>
      <label className="f">Environments<input className="i" name="envs" defaultValue="uat, production" /><small>"production" is marked as a production environment.</small></label>
      <div className="full row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Create project</button></div>
    </form>}</Load></>;
}

/** Shared project frame: header + tabs + child content once the project has loaded. */
function ProjectFrame({ children }: { children: (p: ProjectDetail, reload: () => void) => ReactNode }) {
  const { id = '' } = useParams();
  const s = useLoad(() => get<ProjectDetail>(`/api/projects/${id}`), [id]);
  const tabs: [string, string][] = [[`/projects/${id}`, 'Overview'], [`/projects/${id}/onboarding`, 'Onboarding'], [`/projects/${id}/inventory`, 'Inventory'], [`/projects/${id}/deployments`, 'Deployments'], [`/projects/${id}/import`, 'Import'], [`/projects/${id}/access`, 'Access'], [`/projects/${id}/knowledge`, 'Knowledge'], [`/projects/${id}/attack-paths`, 'Attack paths'], [`/projects/${id}/external`, 'External findings'], [`/projects/${id}/activity`, 'Activity']];
  return <Load s={s}>{p => <>
    <PageHead title={p.name} sub={<>{p.key} · {p.description}<span className="pill-row" style={{ marginTop: 8, display: 'flex' }}><Badge v={p.criticality} /><Badge v={p.exposure} cls="blue" /><Badge v={p.data_classification} />{(p.tags || []).map(t => t === 'synthetic' ? <Synth key={t} on /> : <span key={t} className="b">{t}</span>)}</span></>}>
      <Link className="btn" to={`/findings?project_id=${p.id}`}>Findings ({p.finding_counts.open})</Link><Link className="btn" to={`/drift?project_id=${p.id}`}>Drift</Link>
      <a className="btn" href={`/api/projects/${p.id}/vex.cdx.json`} title="CycloneDX 1.5 VEX of this project's findings">Export VEX</a><Link className="btn primary" to={`/projects/${p.id}/import`}>Import inventory</Link></PageHead>
    <Tabs items={tabs} />{children(p, s.reload)}</>}</Load>;
}

export function ProjectOverview() {
  const { modal, act } = useUi();
  return <ProjectFrame>{(p, reload) => <ProjectOverviewBody p={p} reload={reload} modal={modal} act={act} />}</ProjectFrame>;
}
function ProjectOverviewBody({ p, reload, modal, act }: { p: ProjectDetail; reload: () => void; modal: ReturnType<typeof useUi>['modal']; act: ReturnType<typeof useUi>['act'] }) {
  const cov = useLoad(() => get(`/api/projects/${p.id}/coverage`), [p.id]);
  const canManage = p.my_permissions.includes('project:manage');
  const add = (kind: 'service' | 'environment') => modal(close => <form className="form" onSubmit={onSubmit(async d => { await act(() => post(`/api/projects/${p.id}/${kind === 'service' ? 'services' : 'environments'}`, d), 'Saved'); close(); reload(); })}>
    <h2>Add {kind}</h2><label className="f">Key<input className="i" name="key" required /></label><label className="f">Name<input className="i" name="name" /></label>
    {kind === 'environment' && <><label className="row"><input type="checkbox" name="is_production" /> Production</label><label className="f">Timezone<input className="i" name="timezone" defaultValue="Asia/Ho_Chi_Minh" /></label></>}
    <div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn" onClick={close}>Cancel</button><button className="btn primary">Add</button></div></form>);
  return <Load s={cov}>{c => <>
    <div className="grid g3" style={{ marginBottom: 16 }}>
      <Link className="card stat" to={`/findings?project_id=${p.id}`}><span className="l">Open findings</span><span className="v">{p.finding_counts.open}</span></Link>
      <Link className="card stat" to={`/findings?project_id=${p.id}&priority=P0,P1`}><span className="l">P0/P1</span><span className="v">{p.finding_counts.urgent}</span></Link>
      <Link className="card stat" to="/coverage"><span className="l">Coverage</span><span className="v">{pct(c.coverage_ratio)}</span><span className="l">{c.covered_scopes}/{c.expected_scopes} service×env scopes</span></Link></div>
    <div className="grid g2">
      <div className="card"><div className="head"><h2 className="grow">Services</h2>{canManage && <button className="btn sm" onClick={() => add('service')}>Add</button>}</div><Table rows={p.services} empty="No services defined." cols={[{ label: 'Key', render: x => x.key }, { label: 'Name', render: x => x.name }, { label: 'Team', render: x => x.team || '—' }]} /></div>
      <div className="card"><div className="head"><h2 className="grow">Environments</h2>{canManage && <button className="btn sm" onClick={() => add('environment')}>Add</button>}</div><Table rows={p.environments} empty="No environments." cols={[{ label: 'Key', render: e => <>{e.key} {e.is_production && <Badge v="production" cls="orange" />}</> }, { label: 'Exposure', render: e => e.exposure }, { label: 'Timezone', render: e => e.timezone }]} /></div>
      <div className="card"><h2>Current deployments</h2><Table rows={p.deployments} empty="No deployments recorded. Findings are created only for deployed or observed inventory." cols={[{ label: 'Service', render: d => d.service }, { label: 'Env', render: d => d.environment }, { label: 'Artifact', render: d => <><code title={d.digest}>{shortDigest(d.digest)}</code> {d.version}</> }, { label: 'Deployed', render: d => rel(d.deployed_at) }]} /></div>
      <div className="card"><h2>Coverage gaps</h2>{c.gaps.length ? c.gaps.map((g: any, i: number) => <div key={i} className={`notice ${g.severity === 'high' ? 'warn' : ''}`} style={{ marginBottom: 6 }}><b>{label(g.kind)}</b> {g.service ? `· ${g.service}/${g.environment}` : ''} — {g.detail}</div>) : <div className="notice ok">No coverage gaps detected. This does not mean the project is free of vulnerabilities.</div>}</div>
      <div className="card"><h2>Ownership</h2><dl className="kv"><dt>Owner</dt><dd>{p.owner?.display_name || <span className="b warn">none</span>}</dd><dt>Members</dt><dd>{p.members.map(m => <div key={m.identity_id}>{m.display_name} <small>{label(m.role)}</small></div>)}</dd><dt>Connections</dt><dd>{p.connections.length ? p.connections.map(x => <div key={x.id}>{x.name} <Badge v={x.status} /></div>) : '—'}</dd></dl></div>
    </div></>}</Load>;
}

export function Onboarding() {
  const desc: Record<string, string> = { metadata: 'Project metadata, owner, criticality', services: 'Services defined', environments: 'Environments defined', connection: 'Repository/CI/cloud connection or upload method configured', discovery: 'Stack discovery reviewed (AI proposes; owner confirms)', conflicts: 'Manual vs automated conflicts reviewed', inventory: 'Inventory confirmed', policy: 'Gate policy and alert routing configured', first_ingestion: 'First verified ingestion (CI SBOM or import receipt)' };
  return <ProjectFrame>{p => {
    const links: Record<string, string> = { connection: `/integrations?project_id=${p.id}`, discovery: `/investigations/new?workflow=discovery&project_id=${p.id}`, inventory: `/projects/${p.id}/import`, policy: `/ci?project_id=${p.id}`, first_ingestion: `/ci?project_id=${p.id}`, conflicts: `/projects/${p.id}/inventory` };
    return <><div className="notice info" style={{ marginBottom: 14 }}>{p.protected_note}</div>
      <div className="card">{p.onboarding_steps.map((x, i) => <div key={x.step} className="row" style={{ padding: '10px 0', borderBottom: '1px solid var(--line)' }}><span className={`b ${x.done ? 'green' : ''}`}>{x.done ? '✓' : i + 1}</span><div style={{ flex: 1 }}><b>{label(x.step)}</b><br /><small>{desc[x.step]}{x.at ? ' · ' + fmtDate(x.at) : ''}</small></div>{links[x.step] && <Link className="btn sm" to={links[x.step]}>{x.done ? 'Review' : 'Start'}</Link>}</div>)}</div></>;
  }}</ProjectFrame>;
}

export function Inventory() {
  const q = useQuery(); const nav = useNavigate(); const { modal, act } = useUi();
  return <ProjectFrame>{p => <InventoryBody p={p} q={q} nav={nav} modal={modal} act={act} />}</ProjectFrame>;
}
function InventoryBody({ p, q, nav, modal, act }: { p: ProjectDetail; q: Record<string, string>; nav: (to: string) => void; modal: ReturnType<typeof useUi>['modal']; act: ReturnType<typeof useUi>['act'] }) {
  const s = useLoad(() => Promise.all([get(`/api/projects/${p.id}/inventory` + qs({ q: q.q, environment_id: q.environment_id })), get(`/api/projects/${p.id}/snapshots`), get(`/api/projects/${p.id}/overrides`)]), [p.id, q.q, q.environment_id]);
  const diff = async (sid: string) => { const d = await get(`/api/snapshots/${sid}/diff`); modal(close => <><h2>Snapshot diff</h2><p className="muted">{d.from ? 'Against previous snapshot ' + d.from : 'No previous snapshot for this target'}</p>
    <div className="grid g3" style={{ margin: '12px 0' }}><div className="stat"><span className="v">{d.added.length}</span><span className="l">added</span></div><div className="stat"><span className="v">{d.removed.length}</span><span className="l">removed</span></div><div className="stat"><span className="v">{d.changed.length}</span><span className="l">changed</span></div></div>
    {d.changed.length > 0 && <Table rows={d.changed} cols={[{ label: 'Package', render: (x: any) => x.name }, { label: 'From', render: (x: any) => x.from }, { label: 'To', render: (x: any) => x.to }]} />}
    {d.added.length > 0 && <><h3 style={{ marginTop: 12 }}>Added</h3><small>{d.added.map((a: any) => `${a.name}@${a.version || '?'}`).join(', ')}</small></>}
    {d.removed.length > 0 && <><h3 style={{ marginTop: 12 }}>Removed</h3><small>{d.removed.map((a: any) => `${a.name}@${a.version || '?'}`).join(', ')}</small></>}
    <div className="row" style={{ justifyContent: 'flex-end', marginTop: 14 }}><button className="btn" onClick={close}>Close</button></div></>); };
  return <Load s={s}>{([inv, snaps, ov]) => <>
    <form className="row" style={{ marginBottom: 12 }} onSubmit={onSubmit(d => nav(`/projects/${p.id}/inventory` + qs(d)))}><input className="i" style={{ maxWidth: 280 }} name="q" placeholder="Filter package" defaultValue={q.q} />
      <select className="i" style={{ maxWidth: 200 }} name="environment_id" defaultValue={q.environment_id || ''}><option value="">All environments</option>{p.environments.map(e => <option key={e.id} value={e.id}>{e.key}</option>)}</select><button className="btn">Filter</button>
      <button type="button" className="btn" onClick={() => modal(close => <form className="form" onSubmit={onSubmit(async d => { await act(() => post(`/api/projects/${p.id}/overrides`, d), 'Override requested'); close(); s.reload(); })}><h2>Request inventory override</h2>
        <label className="f">Target (purl or asset id)<input className="i" name="target" required /></label><label className="f">Field<input className="i" name="field" defaultValue="version" required /></label><label className="f">Value<input className="i" name="value" required /></label>
        <label className="f">Reason<textarea className="i" name="reason" required minLength={10} /></label><label className="f">Expires<input className="i" type="date" name="expires_at" required /></label>
        <div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn" onClick={close}>Cancel</button><button className="btn primary">Request</button></div></form>)}>Request override</button></form>
    <Table rows={inv.items} empty="No deployed or observed inventory. Upload an SBOM from CI or import inventory." cols={[
      { label: 'Package', render: (r: any) => <><Link to={`/components/${r.component_id}`}>{r.name}</Link><br /><small>{r.ecosystem} · {r.kind}</small></> },
      { label: 'Version', render: (r: any) => r.version ? <><code>{r.version}</code> <small>{r.version_kind}</small></> : <Badge v="unknown" /> },
      { label: 'Scope', render: (r: any) => `${r.service_key || (r.asset_id ? 'asset' : '—')} / ${r.env_key || '—'}` },
      { label: 'Identity', render: (r: any) => r.digest ? <code title={r.digest}>{shortDigest(r.digest)}</code> : <Link to={`/assets/${r.asset_id}`}>asset</Link> },
      { label: 'Dependency', render: (r: any) => r.direct === true ? 'direct' : r.direct === false ? <>transitive<br /><small>{(r.dependency_path || []).join(' → ')}</small></> : 'unknown' },
      { label: 'Arch', render: (r: any) => r.architecture || '—' },
      { label: 'Observed', render: (r: any) => <>{rel(r.observed_at)} {r.stale && <Badge v="stale" />}</> }]} />
    {inv.total > inv.items.length && <small>Showing {inv.items.length} of {inv.total}.</small>}
    <div className="card" style={{ marginTop: 16 }}><h2>Immutable snapshots</h2><Table rows={snaps} cols={[{ label: 'Created', render: (x: any) => fmtDate(x.created_at) }, { label: 'Source', render: (x: any) => <>{x.source}<br /><small>{x.collection_method}</small></> }, { label: 'Format', render: (x: any) => x.format }, { label: 'Target', render: (x: any) => x.digest ? <code>{shortDigest(x.digest)}</code> : x.asset_name || 'repository' }, { label: 'Components', render: (x: any) => x.component_count }, { label: 'Content hash', render: (x: any) => <code title={x.content_sha256}>{String(x.content_sha256).slice(7, 19)}</code> }, { label: '', render: (x: any) => <button className="btn sm" onClick={() => diff(x.id)}>Diff</button> }]} /></div>
    <div className="card" style={{ marginTop: 16 }}><h2>Overrides</h2><p className="muted" style={{ marginBottom: 8 }}>Manual overrides require reason, approver (not the requester) and expiry.</p>
      <Table rows={ov} empty="No overrides." cols={[{ label: 'Target', render: (o: any) => o.target }, { label: 'Field', render: (o: any) => o.field }, { label: 'Value', render: (o: any) => JSON.stringify(o.value) }, { label: 'Reason', render: (o: any) => o.reason }, { label: 'Expires', render: (o: any) => fmtDay(o.expires_at) }, { label: 'Status', render: (o: any) => o.approved_by ? <Badge v="approved" cls="green" /> : <button className="btn sm" onClick={() => act(() => post(`/api/overrides/${o.id}/approve`), 'Approved').then(s.reload)}>Approve</button> }]} /></div>
  </>}</Load>;
}

export function Deployments() {
  return <ProjectFrame>{p => <DeploymentsBody id={p.id} />}</ProjectFrame>;
}
function DeploymentsBody({ id }: { id: string }) {
  const s = useLoad(() => Promise.all([get(`/api/projects/${id}/deployments`), get(`/api/projects/${id}/artifacts`), get(`/api/projects/${id}/ingestions`)]), [id]);
  return <Load s={s}>{([deps, arts, ings]) => <div className="grid g2">
    <div className="card"><h2>Deployment history</h2><Table rows={deps} empty="No deployments recorded. A build upload alone is not proof of deployment." cols={[{ label: 'When', render: (d: any) => fmtDate(d.deployed_at) }, { label: 'Service/env', render: (d: any) => <>{d.service} / {d.environment} {d.is_current && <Badge v="current" cls="green" />}</> }, { label: 'Artifact', render: (d: any) => <><code title={d.digest}>{shortDigest(d.digest)}</code> {d.version}</> }, { label: 'Source', render: (d: any) => d.source }]} /></div>
    <div className="card"><h2>Artifacts (immutable digests)</h2><Table rows={arts} cols={[{ label: 'Service', render: (a: any) => a.service }, { label: 'Digest', render: (a: any) => <code title={a.digest}>{shortDigest(a.digest)}</code> }, { label: 'Version', render: (a: any) => a.version }, { label: 'Commit', render: (a: any) => <code>{String(a.commit_sha || '').slice(0, 8)}</code> }, { label: 'Built', render: (a: any) => rel(a.built_at || a.created_at) }]} /></div>
    <div className="card" style={{ gridColumn: '1/-1' }}><h2>Ingestion receipts</h2><Table rows={ings} cols={[{ label: 'Received', render: (i: any) => fmtDate(i.created_at) }, { label: 'Kind', render: (i: any) => i.kind }, { label: 'Status', render: (i: any) => <Badge v={i.status} /> }, { label: 'Receipt', render: (i: any) => <><code>{i.receipt?.content_sha256?.slice(7, 19)}</code> {i.receipt?.component_count ?? i.receipt?.accepted} components</> }, { label: 'Gate', render: (i: any) => i.receipt?.policy_evaluation_url ? <Link to={`/ci/evaluation/${i.receipt.policy_evaluation_url.split('/').pop()}`}>evaluation</Link> : '—' }]} /></div>
  </div>}</Load>;
}

export function Import() {
  return <ProjectFrame>{p => <ImportBody p={p} />}</ProjectFrame>;
}
function ImportBody({ p }: { p: ProjectDetail }) {
  const { act, toast } = useUi();
  const [kind, setKind] = useState('asset'); const [file, setFile] = useState<{ name: string; content: string; encoding?: string } | null>(null);
  const [preview, setPreview] = useState<any>(null); const [receipt, setReceipt] = useState<any>(null);
  const body = (form: HTMLFormElement) => {
    const f = new FormData(form); const g = (k: string) => String(f.get(k) || '');
    const target: Record<string, unknown> = { kind, environment_id: g('environment_id') || undefined };
    if (kind === 'asset') Object.assign(target, { identifier: g('identifier'), asset_kind: g('asset_kind'), architecture: g('architecture') || undefined });
    if (kind === 'artifact') Object.assign(target, { service_id: g('service_id'), digest: g('digest') });
    const pasted = g('content');
    return file && !pasted ? { content: file.content, filename: file.name, encoding: file.encoding, target } : { content: pasted, filename: file?.name || '', target };
  };
  const onFile = async (fl: File | undefined) => {
    if (!fl) return; if (fl.size > 10 * 1024 * 1024) { toast('File exceeds 10 MB', true); return; }
    if (/\.xlsx$/i.test(fl.name)) { const b = new Uint8Array(await fl.arrayBuffer()); let bin = ''; for (let i = 0; i < b.length; i += 0x8000) bin += String.fromCharCode(...b.subarray(i, i + 0x8000)); setFile({ name: fl.name, content: btoa(bin), encoding: 'base64' }); }
    else setFile({ name: fl.name, content: await fl.text() });
  };
  return <div className="grid g21"><form className="card form" id="imf" onSubmit={async e => { e.preventDefault(); const r = await act(() => post(`/api/projects/${p.id}/imports/commit`, body(e.currentTarget))); toast(r.duplicate ? 'Duplicate — original receipt returned' : 'Imported'); setReceipt(r.receipt); }}>
    <h2>Import workbench</h2><p className="muted">CycloneDX/SPDX JSON, Trivy JSON, SARIF, XLSX (first sheet, header row), CSV, JSON or YAML (max 10 MB). Preview is a dry run; commit creates an immutable snapshot and receipt. Duplicate content returns the original receipt.</p>
    <div className="form two"><label className="f">Target<select className="i" value={kind} onChange={e => setKind(e.target.value)}><option value="asset">Asset / runtime observation</option><option value="artifact">Build artifact (digest)</option><option value="repository">Repository manifests (declared)</option></select></label>
      <label className="f">Environment<select className="i" name="environment_id"><option value="">—</option>{p.environments.map(e => <option key={e.id} value={e.id}>{e.key}</option>)}</select></label>
      {kind === 'asset' && <><label className="f">Asset identifier<input className="i" name="identifier" placeholder="hostname, ARN, cluster/ns/workload" /></label>
        <label className="f">Asset kind<select className="i" name="asset_kind">{['server', 'container_workload', 'database', 'managed_service', 'load_balancer', 'function', 'application'].map(k => <option key={k}>{k}</option>)}</select></label>
        <label className="f">Architecture<select className="i" name="architecture"><option value="">unknown</option><option>x86_64</option><option>arm64</option></select></label></>}
      {kind === 'artifact' && <><label className="f">Service<select className="i" name="service_id">{p.services.map(x => <option key={x.id} value={x.id}>{x.key}</option>)}</select></label><label className="f">Artifact digest<input className="i" name="digest" placeholder="sha256:…" /></label></>}</div>
    <label className="f">File<input type="file" className="i" accept=".json,.csv,.yaml,.yml,.txt,.lock,.mod,.xml,.xlsx" onChange={e => onFile(e.target.files?.[0])} /></label>
    <label className="f">…or paste content<textarea className="i" name="content" style={{ minHeight: 160 }} placeholder='[{"ecosystem":"npm","name":"express","version":"4.18.2"}]' /></label>
    <div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn" onClick={async () => { const form = document.getElementById('imf') as HTMLFormElement; setPreview(await act(() => post(`/api/projects/${p.id}/imports/preview`, body(form)))); setReceipt(null); }}>Preview (dry run)</button><button className="btn primary" disabled={!preview}>Commit import</button></div></form>
    <div className="card">{receipt ? <><h2>Receipt</h2><pre className="code">{JSON.stringify(receipt, null, 2)}</pre><Link className="btn" to={`/projects/${p.id}/inventory`}>View inventory</Link></>
      : preview ? <><h2>Preview — {preview.format}</h2>{preview.duplicate_of && <div className="notice warn">Identical content was already imported ({preview.duplicate_of}); committing returns the original receipt.</div>}
        <div className="grid g3" style={{ margin: '10px 0' }}><div className="stat"><span className="v">{preview.accepted}</span><span className="l">accepted</span></div><div className="stat"><span className="v">{preview.rejected}</span><span className="l">rejected</span></div><div className="stat"><span className="v">{preview.warnings}</span><span className="l">warnings</span></div></div>
        {preview.diff_vs_previous ? <p>Diff vs previous: +{preview.diff_vs_previous.added} / −{preview.diff_vs_previous.removed} / ~{preview.diff_vs_previous.changed}</p> : <p className="muted">No previous snapshot for this target.</p>}
        {preview.errors.length > 0 && <><h3 style={{ marginTop: 10 }}>Row-level issues</h3><Table rows={preview.errors} cols={[{ label: 'Row', render: (x: any) => x.row ?? x.file ?? '' }, { label: 'Field', render: (x: any) => x.field || '' }, { label: 'Issue', render: (x: any) => <>{x.severity === 'warning' ? <Badge v="warning" cls="orange" /> : <Badge v="error" cls="red" />} {x.message}</> }]} /></>}
        <h3 style={{ marginTop: 10 }}>Sample</h3><Table rows={preview.sample} cols={[{ label: 'Ecosystem', render: (c: any) => c.ecosystem }, { label: 'Name', render: (c: any) => c.name }, { label: 'Version', render: (c: any) => c.version || <Badge v="unknown" /> }, { label: 'Direct', render: (c: any) => c.direct == null ? '?' : c.direct ? 'yes' : 'no' }]} /></>
      : <Empty title="No preview yet">Run a dry-run preview to see accepted/rejected rows, row-level errors and the diff against the previous snapshot.</Empty>}</div></div>;
}

export function Access() {
  return <ProjectFrame>{(p, reload) => <AccessBody p={p} reload={reload} />}</ProjectFrame>;
}
function AccessBody({ p, reload }: { p: ProjectDetail; reload: () => void }) {
  const { act } = useUi(); const confirm = useConfirm();
  const members = useLoad(() => get('/api/org/members').catch(() => []), []);
  const canEdit = p.my_permissions.includes('project:members'); const roles = ['project_owner', 'tech_lead', 'developer', 'devops', 'viewer'];
  return <><div className="notice info" style={{ marginBottom: 12 }}>Project access is application-managed. Organization-wide roles (admin, analyst, viewer, auditor) see all projects; members see only projects listed here.</div>
    <Table rows={p.members.map(m => ({ ...m, id: m.identity_id }))} cols={[{ label: 'Member', render: m => <>{m.display_name}<br /><small>{m.email}</small></> },
      { label: 'Role', render: m => canEdit ? <select className="i" defaultValue={m.role} onChange={e => act(() => put(`/api/projects/${p.id}/members/${m.identity_id}`, { role: e.target.value }), 'Role updated')}>{roles.map(r => <option key={r}>{r}</option>)}</select> : label(m.role) },
      { label: '', render: m => canEdit ? <button className="btn sm danger" onClick={() => confirm('Remove this member from the project?', () => act(() => api('DELETE', `/api/projects/${p.id}/members/${m.identity_id}`), 'Removed').then(reload), true)}>Remove</button> : null }]} />
    {canEdit && <Load s={members}>{ms => <form className="row card" style={{ marginTop: 12 }} onSubmit={onSubmit(async d => { await act(() => put(`/api/projects/${p.id}/members/${d.identity}`, { role: d.role }), 'Access granted'); reload(); })}>
      <select className="i" name="identity" style={{ maxWidth: 280 }}>{ms.filter((m: any) => !p.members.some(x => x.identity_id === m.id)).map((m: any) => <option key={m.id} value={m.id}>{m.display_name}</option>)}</select>
      <select className="i" name="role" style={{ maxWidth: 200 }}>{roles.map(r => <option key={r}>{r}</option>)}</select><button className="btn primary">Grant access</button></form>}</Load>}</>;
}

export function Knowledge() {
  return <ProjectFrame>{p => <KnowledgeBody id={p.id} />}</ProjectFrame>;
}
function KnowledgeBody({ id }: { id: string }) {
  const { act, modal } = useUi(); const s = useLoad(() => get(`/api/projects/${id}/knowledge`), [id]);
  return <><div className="pagehead"><div className="grow"><p>Reviewed architecture assumptions and custom controls with evidence, expiry and revalidation triggers. Agents read these as untrusted notes.</p></div>
    <button className="btn primary" onClick={() => modal(close => <form className="form" onSubmit={onSubmit(async d => { await act(() => post(`/api/projects/${id}/knowledge`, d), 'Saved'); close(); s.reload(); })}><h2>Add knowledge item</h2>
      <label className="f">Title<input className="i" name="title" required /></label><label className="f">Kind<select className="i" name="kind"><option>assumption</option><option>control</option><option>architecture</option></select></label>
      <label className="f">Body<textarea className="i" name="body" required /></label><label className="f">Evidence reference<input className="i" name="evidence_ref" /></label><label className="f">Expires<input className="i" type="date" name="expires_at" /></label>
      <div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn" onClick={close}>Cancel</button><button className="btn primary">Save</button></div></form>)}>Add item</button></div>
    <Load s={s}>{items => items.length ? items.map((k: any) => <div key={k.id} className="card" style={{ marginBottom: 10 }}><div className="head"><h3 className="grow">{k.title}</h3><Badge v={k.kind} cls="blue" />{k.expires_at && new Date(k.expires_at) < new Date() ? <Badge v="expired" cls="red" /> : <small>expires {fmtDay(k.expires_at)}</small>}</div><p>{k.body}</p>{k.evidence_ref && <small>Evidence: {k.evidence_ref}</small>}</div>) : <Empty title="No knowledge items" />}</Load></>;
}

export function AttackPaths() {
  return <ProjectFrame>{p => <AttackBody id={p.id} />}</ProjectFrame>;
}
function AttackBody({ id }: { id: string }) {
  const s = useLoad(() => get(`/api/projects/${id}/attack-paths`), [id]);
  return <Load s={s}>{ap => <><div className="notice info" style={{ marginBottom: 12 }}><b>verified</b>: {ap.legend.verified} <b>inferred</b>: {ap.legend.inferred}<br /><small>{ap.limits}</small></div>
    {ap.paths.length ? ap.paths.map((x: any) => <div key={x.finding_id} className="card" style={{ marginBottom: 10 }}>
      <div className="head"><div className="grow"><PRIORITY p={x.priority} /> <Badge v={x.exploitation} /> <b>{x.entry}</b> → … <small>{x.verified_hops} verified / {x.inferred_hops} inferred hops</small></div>{x.blocked_by_prerequisite && <Badge v="prerequisite not met" cls="green" />}<Link className="btn sm" to={`/findings/${x.finding_id}`}>Finding</Link></div>
      <ol className="timeline" style={{ paddingLeft: 0 }}>{x.hops.map((h: any, i: number) => <li key={i}><span className={`b ${h.kind === 'verified' ? 'green' : 'orange'}`}>{h.kind}</span> {h.from_label} → <b>{h.to_label}</b><br /><small>{h.basis}</small></li>)}</ol>
      {x.blast_radius.length > 0 && <div><small className="muted">Beyond the asset:</small> {x.blast_radius.map((b: any, i: number) => <span key={i} className={`b ${b.kind === 'verified' ? 'green' : 'orange'}`}>{b.type}: {b.target} ({b.kind})</span>)}</div>}
      {x.prerequisites.length > 0 && <div style={{ marginTop: 6 }}>{x.prerequisites.map((pr: any, i: number) => <div key={i} className={`ev ${pr.status === 'not_met' ? 'counter' : pr.status === 'met' ? 'supporting' : 'missing'}`}>{pr.prerequisite}: <b>{pr.status}</b>{pr.evidence && <small> ({pr.evidence})</small>}</div>)}</div>}</div>)
      : <Empty title="No open paths">No open, applicable findings in deployed or observed inventory. Check coverage before reading this as safe.</Empty>}</>}</Load>;
}

export function External() {
  return <ProjectFrame>{p => <ExternalBody id={p.id} />}</ProjectFrame>;
}
function ExternalBody({ id }: { id: string }) {
  const s = useLoad(() => get(`/api/projects/${id}/external-findings`), [id]);
  return <><div className="notice info" style={{ marginBottom: 12 }}>Findings reported by other platforms (e.g. DefectDojo) are kept as references and linked to Sentra findings by advisory alias and component. Sentra remains the source of truth for lifecycle state.</div>
    <Load s={s}>{xs => <Table rows={xs} empty="No external findings. Connect DefectDojo under Integrations." cols={[{ label: 'Source', render: (x: any) => x.connection }, { label: 'External', render: (x: any) => <a href={safeHref(x.url)} target="_blank" rel="noopener noreferrer">{x.external_id}</a> }, { label: 'Title', render: (x: any) => x.title }, { label: 'Severity', render: (x: any) => <Badge v={x.severity} /> }, { label: 'IDs', render: (x: any) => (x.vulnerability_ids || []).join(', ') }, { label: 'Component', render: (x: any) => `${x.component || '—'} ${x.component_version || ''}` }, { label: 'State', render: (x: any) => x.state }, { label: 'Sentra finding', render: (x: any) => x.linked_finding_id ? <Link to={`/findings/${x.linked_finding_id}`}>linked</Link> : <span className="b">unlinked</span> }]} />}</Load></>;
}

export function Activity() {
  return <ProjectFrame>{p => <ActivityBody id={p.id} />}</ProjectFrame>;
}
function ActivityBody({ id }: { id: string }) {
  const s = useLoad(() => get(`/api/projects/${id}/activity`), [id]);
  return <Load s={s}>{a => <Table rows={a} empty="No activity yet." cols={[{ label: 'When', render: (e: any) => fmtDate(e.created_at) }, { label: 'Actor', render: (e: any) => <>{e.actor_name || e.actor_id || 'system'} <small>{e.actor_type}</small></> }, { label: 'Action', render: (e: any) => <code>{e.action}</code> }, { label: 'Target', render: (e: any) => <>{e.target_type} <small>{e.target_id}</small></> }]} />}</Load>;
}
