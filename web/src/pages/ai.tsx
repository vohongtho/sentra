import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { del, get, post, put, qs, type Investigation, type Project } from '../api';
import { Badge, Empty, ErrorState, Icon, Load, Loading, PageHead, SavedViews, Table, fmtDate, label, onSubmit, rel, useLoad, useQuery, useUi } from '../ui';

const TERMINAL = ['completed', 'partial', 'failed', 'cancelled', 'waiting_approval', 'waiting_evidence'];
const WF: [string, string][] = [['evidence_analysis', 'Submitted evidence analysis'], ['discovery', 'Project discovery (stack, services, missing data)'], ['advisory_research', 'Advisory research'], ['impact', 'Impact investigation (finding)'], ['remediation', 'Remediation planning (finding)'], ['verification', 'Verification review (finding)'], ['portfolio', 'Portfolio & campaigns'], ['copilot', 'Security Copilot question']];

export function InvestigationList() {
  const q = useQuery();
  const s = useLoad(() => get('/api/investigations' + qs({ workflow: q.workflow })), [q.workflow]);
  return <><PageHead title="AI investigations" sub="Tool-using agents with scoped permissions, evidence receipts and structured conclusions. Deterministic code owns authorization, version matching, SLA, gates and dedupe."><Link className="btn primary" to="/investigations/new">New investigation</Link></PageHead>
    <SavedViews page="investigations" query={q} base="/investigations" />
    <div className="row" style={{ marginBottom: 10 }}>{['', ...WF.map(w => w[0])].map(w => <Link key={w} className={`b ${(q.workflow || '') === w ? 'blue' : ''}`} to={'/investigations' + qs({ workflow: w })}>{w ? label(w) : 'all'}</Link>)}</div>
    <Load s={s}>{items => <Table rows={items} onRow={(i: any) => `/investigations/${i.id}`} empty="No investigations yet." cols={[
      { label: 'Workflow', render: (i: any) => <><b>{label(i.workflow)}</b><br /><small>{i.question || i.advisory_id || i.finding_id}</small></> },
      { label: 'Project', render: (i: any) => i.project || 'portfolio' }, { label: 'State', render: (i: any) => <Badge v={i.state} /> },
      { label: 'Conclusion', render: (i: any) => <>{i.applicability && <Badge v={i.applicability} />} <small>{(i.summary || '').slice(0, 110)}</small></> },
      { label: 'Model', render: (i: any) => <small>{i.model}</small> }, { label: 'Cost', render: (i: any) => `$${Number(i.cost_usd || 0).toFixed(3)}` }, { label: 'Created', render: (i: any) => rel(i.created_at) }]} />}</Load></>;
}

async function readFiles(input: HTMLInputElement | null) {
  return Promise.all(Array.from(input?.files || []).slice(0, 20).map(async f => ({ name: f.name, content: await f.text() })));
}

export function NewInvestigation() {
  const q = useQuery(); const nav = useNavigate(); const { act } = useUi();
  const s = useLoad(() => get<Project[]>('/api/projects'), []);
  return <><PageHead title="New investigation" sub="Choose a workflow. The agent can use only the tools its workflow policy allows, inside projects you can access." />
    <Load s={s}>{projects => <form className="card form two" onSubmit={onSubmit(async (d, form) => {
      const files = await readFiles(form.querySelector('input[type=file]'));
      const inv = await act(() => post('/api/investigations', { workflow: d.workflow, project_id: d.project_id || undefined, finding_id: d.finding_id || undefined, advisory_id: d.advisory_id || undefined, question: d.question || undefined, files }), 'Investigation queued');
      nav(`/investigations/${inv.id}`);
    })}>
      <label className="f">Workflow<select className="i" name="workflow" defaultValue={q.workflow || 'discovery'}>{WF.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
      <label className="f">Project<select className="i" name="project_id" defaultValue={q.project_id || ''}><option value="">— portfolio / all in scope —</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
      <label className="f">Finding id (impact/remediation/verification)<input className="i" name="finding_id" defaultValue={q.finding_id} /></label>
      <label className="f">Advisory id (research)<input className="i" name="advisory_id" defaultValue={q.advisory_id} /></label>
      <label className="f full">Question (copilot)<input className="i" name="question" placeholder="Which production Java services require action first?" /></label>
      <label className="f full">Attach manifests (package-lock.json, composer.lock, pom.xml, go.mod, requirements.txt, Dockerfile…)<input type="file" className="i" multiple /></label>
      <div className="full notice">Attached content is untrusted data. Secret-shaped values are redacted before storage, and it is sent to the model provider only if the project's data classification allows it.</div>
      <div className="full row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Start</button></div></form>}</Load></>;
}

/** Handoff "Live AI analysis": submit evidence text/JSON with a question; deterministic matching + agent conclusion. */
export function Analysis() {
  const nav = useNavigate(); const { act } = useUi();
  const s = useLoad(() => Promise.all([get<Project[]>('/api/projects'), get('/api/investigations?workflow=evidence_analysis&limit=10'), get('/api/agent-policies')]), []);
  return <><PageHead title="Live AI analysis" sub="Analyze the evidence you provide. Components in it are matched deterministically against stored advisories; no scripted result or silent demo fallback." />
    <Load s={s}>{([projects, recent, pol]) => <>
      {!pol.provider.anthropic_key_configured && <div className="notice warn" style={{ marginBottom: 12 }}><b>Model provider not configured.</b> Runs use the offline deterministic planner (matching and structure, no language model). Configure a key under <Link to="/agents">AI agents</Link>.</div>}
      <div className="grid g21"><form className="card form" onSubmit={onSubmit(async (d, form) => {
        const files = await readFiles(form.querySelector('input[type=file]'));
        let json: unknown = undefined; if (d.json) { try { json = JSON.parse(d.json); } catch { json = d.json; } }
        const inv = await act(() => post('/api/investigations', { workflow: 'evidence_analysis', project_id: d.project_id || undefined, question: d.question || undefined, evidence: { text: d.text || undefined, json }, files }), 'Analysis queued');
        nav(`/investigations/${inv.id}`);
      })}>
        <h2>Investigation input</h2><p className="muted">Only the evidence you submit is analyzed. Secret-shaped values are redacted before storage.</p>
        <label className="f">Project context (optional)<select className="i" name="project_id"><option value="">— none —</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
        <label className="f">Question<textarea className="i" name="question" placeholder="What can be established from this inventory and advisory?" /></label>
        <label className="f">Evidence text<textarea className="i" name="text" style={{ minHeight: 140 }} placeholder="Paste a sanitized manifest excerpt, runtime inventory or vendor advisory excerpt. Remove credentials and sensitive data." /></label>
        <label className="f">Optional JSON evidence / SBOM (CycloneDX, SPDX, inventory rows)<textarea className="i" name="json" style={{ minHeight: 120 }} placeholder='[{"ecosystem":"npm","name":"@acme/xml-parser","version":"2.7.0"}]' /></label>
        <label className="f">…or files<input type="file" className="i" multiple /></label>
        <div className="row" style={{ justifyContent: 'flex-end' }}><span className="b orange">Human review required</span><button className="btn primary">Analyze</button></div></form>
        <div className="col"><div className="card"><h3>What this run actually does</h3><ul className="md"><li>Reads only the evidence from this form.</li><li>Parses machine-readable components and matches them against stored advisories with ecosystem-specific version rules.</li><li>Calls the configured model server-side (or the offline planner) with scoped tools.</li><li>Rejects claims without tool receipts and stores the result with usage.</li></ul><p className="muted" style={{ marginTop: 8 }}>No repository, AWS or advisory feed is consulted by this workflow. An empty match list is not evidence of safety.</p></div>
          <div className="card"><h3>Recent analyses</h3>{recent.length ? recent.map((i: any) => <div key={i.id}><Link to={`/investigations/${i.id}`}>{(i.question || 'analysis').slice(0, 50)}</Link> <Badge v={i.state} /> <small>{rel(i.created_at)}</small></div>) : <p className="muted">None yet.</p>}</div></div></div>
    </>}</Load></>;
}

function ResultView({ r, onRef }: { r: any; onRef: (n: number) => void }) {
  const dims = r.dimensions || {};
  const tone: Record<string, string> = { confirmed: 'red', met: 'red', observed: 'red', potential: 'orange', not_present: 'green', not_reachable: 'green', not_met: 'green', none: 'green', not_observed: 'green' };
  return <>
    <div className="card"><div className="head"><h2 className="grow">Conclusion</h2>{r.applicability && r.applicability !== 'not_applicable' && <Badge v={r.applicability} />}{r.partial && <Badge v="partial" />}</div><p>{r.summary}</p>
      {r.applicability !== 'not_applicable' && <><div className="grid g4" style={{ marginTop: 12 }}>{['presence', 'reachability', 'prerequisites', 'compromise'].map(k => <div key={k} className="stat"><span className="l">{k}</span><span><Badge v={dims[k] || 'unknown'} cls={tone[dims[k]] || 'blue'} /></span></div>)}</div><small className="muted">Kept separate by design: presence ≠ reachability ≠ prerequisites ≠ compromise.</small></>}
      {r.change_explanation && <div className="notice info" style={{ marginTop: 10 }}>Change vs previous run: {r.change_explanation}</div>}</div>
    <div className="card"><h2>Claims with evidence</h2>{(r.claims || []).length ? r.claims.map((c: any, i: number) => <div key={i} className={`ev ${c.stance}`}><span>{c.statement}</span><div className="pill-row" style={{ marginTop: 4 }}>{(c.evidence || []).map((e: any) => <button key={e.ref} className="b" onClick={() => onRef(e.ref)}>#{e.ref} {e.tool}</button>)}</div></div>) : <p className="muted">No supported claims.</p>}
      {(r.unsupported_claims || []).length > 0 && <><h3 style={{ marginTop: 10 }}>Rejected (no valid evidence reference)</h3>{r.unsupported_claims.map((c: any, i: number) => <div key={i} className="ev missing"><s>{c.statement}</s></div>)}</>}</div>
    <div className="grid g2"><div className="card"><h3>Missing evidence</h3>{(r.missing_evidence || []).length ? <ul>{r.missing_evidence.map((m: string, i: number) => <li key={i}>{m}</li>)}</ul> : <p className="muted">None listed.</p>}</div>
      <div className="card"><h3>Limitations</h3><ul>{(r.limitations || []).map((m: string, i: number) => <li key={i}>{m}</li>)}</ul></div></div>
    <div className="card"><h3>Next actions</h3><ul>{(r.next_actions || []).map((m: string, i: number) => <li key={i}>{m}</li>)}</ul></div></>;
}

export function InvestigationView() {
  const { id = '' } = useParams(); const nav = useNavigate(); const { act, modal } = useUi();
  const s = useLoad(() => get<Investigation>(`/api/investigations/${id}`), [id]);
  const running = s.data && !TERMINAL.includes(s.data.state);
  useEffect(() => { if (!running) return; const t = setTimeout(s.reload, 1500); return () => clearTimeout(t); }, [running, s.data, s.reload]);
  const showRef = async (seq: number) => { const t = await get(`/api/investigations/${id}/tool/${seq}`); modal(close => <><h2>#{t.seq} {t.tool} <Badge v={t.status} /></h2><h3 style={{ marginTop: 10 }}>Input</h3><pre className="code">{JSON.stringify(t.input, null, 2)}</pre><h3>Output (redacted)</h3><pre className="code">{JSON.stringify(t.output, null, 2)}</pre><div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn" onClick={close}>Close</button></div></>); };
  return <Load s={s}>{i => {
    const r = i.result;
    return <>
      <div className="pill-row" style={{ marginBottom: 6 }}><Badge v={i.state} /><span className="b">{label(i.workflow)}</span><span className="b blue">{i.provider}: {i.model}</span></div>
      <PageHead title={i.question || label(i.workflow) + ' investigation'} sub={<>{i.inputs?.finding_id && <>Finding <Link to={`/findings/${i.inputs.finding_id}`}>{i.inputs.finding_id}</Link> · </>}{i.inputs?.advisory_id && <>Advisory <Link to={`/advisories/${encodeURIComponent(i.inputs.advisory_id)}`}>{i.inputs.advisory_id}</Link> · </>}scope {(i.scope?.project_ids || []).length} project(s) · prompt {i.prompt_version} · policy {i.policy_version} · tools {i.tool_version}</>}>
        {!TERMINAL.includes(i.state) ? <button className="btn danger" onClick={() => act(() => post(`/api/investigations/${i.id}/cancel`), 'Cancellation requested').then(s.reload)}>Cancel</button>
          : <button className="btn" onClick={async () => { const n = await act(() => post(`/api/investigations/${i.id}/rerun`, { reason: 'manual rerun from workspace' }), 'Rerun queued'); nav(`/investigations/${n.id}`); }}>Rerun</button>}</PageHead>
      {i.state === 'waiting_evidence' && <div className="notice warn" style={{ marginBottom: 12 }}>Waiting for evidence: {i.error}</div>}
      {i.state === 'failed' && <div className="notice err" style={{ marginBottom: 12 }}>Failed: {i.error}. No fallback result was generated.</div>}
      {i.provider === 'offline' && <div className="notice info" style={{ marginBottom: 12 }}>Offline deterministic planner (no language model). Configure an Anthropic key and the agent policy to use Claude.</div>}
      <div className="grid g21"><div className="col">
        {(r?.proposals || []).filter((p: any) => p.status === 'pending_approval').map((p: any) => <div key={p.finding_id} className="notice warn">Proposal requires approval: set applicability of <Link to={`/findings/${p.finding_id}`}>{p.finding_id}</Link> to <b>{label(p.applicability)}</b>.<br /><small>{p.justification}</small>
          <div className="row" style={{ marginTop: 8 }}>{(['approve', 'reject'] as const).map(dcs => <button key={dcs} className={`btn sm ${dcs === 'approve' ? 'primary' : ''}`} onClick={() => act(() => post(`/api/investigations/${i.id}/proposals`, { finding_id: p.finding_id, decision: dcs }), 'Decision recorded').then(s.reload)}>{dcs === 'approve' ? 'Approve' : 'Reject'}</button>)}</div></div>)}
        {r ? <ResultView r={r} onRef={showRef} /> : TERMINAL.includes(i.state) ? <Empty title="No result" /> : <div className="card"><Loading n={3} /><p className="muted">Running… this page refreshes automatically.</p></div>}
      </div><div className="col">
        <div className="card"><h2>Execution plan & tool receipts</h2>{(r?.plan || []).length > 0 && <ol>{r.plan.map((p: string, k: number) => <li key={k}>{p}</li>)}</ol>}
          <ul className="timeline">{i.tool_executions.map(t => <li key={t.seq}><button className="b" onClick={() => showRef(t.seq)}><b>#{t.seq} {t.tool}</b></button> <Badge v={t.status === 'ok' ? 'ok' : t.status} cls={t.status === 'denied' ? 'red' : t.status === 'error' ? 'orange' : 'green'} /> <small>{t.duration_ms}ms</small><br /><small>{t.output_summary}</small></li>)}</ul><small className="muted">{i.note}</small></div>
        <div className="card"><h2>Usage</h2><dl className="kv"><dt>Cost</dt><dd>${Number(i.cost_usd || 0).toFixed(4)}</dd><dt>Tokens</dt><dd>{i.usage?.input_tokens ?? 0} in / {i.usage?.output_tokens ?? 0} out</dd><dt>Started</dt><dd>{fmtDate(i.started_at)}</dd><dt>Finished</dt><dd>{fmtDate(i.finished_at)}</dd></dl></div>
        <div className="card"><h2>Reviewer feedback</h2>{(i.reviewer_feedback || []).map((f: any, k: number) => <div key={k} className="ev neutral"><Badge v={f.rating} /> <small>{f.name} · {rel(f.at)}</small><br />{f.note}</div>)}
          {TERMINAL.includes(i.state) && <form className="col" onSubmit={onSubmit(async d => { await act(() => post(`/api/investigations/${i.id}/feedback`, d), 'Feedback saved'); s.reload(); })}><select className="i" name="rating"><option value="correct">Correct</option><option value="partially_correct">Partially correct</option><option value="incorrect">Incorrect</option><option value="unsupported_claims">Unsupported claims</option><option value="missed_prerequisite">Missed prerequisite</option></select><input className="i" name="note" placeholder="Note" /><button className="btn">Submit feedback</button></form>}</div>
      </div></div></>;
  }}</Load>;
}

export function CopilotDrawer({ onClose, onOpen }: { onClose: () => void; onOpen: (id: string) => void }) {
  const [busy, setBusy] = useState(false); const [res, setRes] = useState<Investigation | null>(null); const [err, setErr] = useState<unknown>(null); const [q, setQ] = useState('');
  const ask = async (question: string) => {
    setBusy(true); setErr(null); setRes(null);
    try {
      const inv = await post('/api/copilot', { question }); let i: Investigation | null = null;
      for (let n = 0; n < 60; n++) { i = await get<Investigation>(`/api/investigations/${inv.id}`); if (TERMINAL.includes(i.state)) break; await new Promise(r => setTimeout(r, 1000)); }
      setRes(i);
    } catch (e) { setErr(e); } finally { setBusy(false); }
  };
  const SUGGEST = ['Which production Java services require action first?', 'What changed in our stack since yesterday?', 'Which projects have insufficient evidence for assessment?', 'Which projects still run an old image after the fix was merged?', 'Why did priority increase?'];
  return <aside className="drawer" aria-label="Security Copilot"><div className="dh"><Icon n="spark" /><h2 style={{ flex: 1 }}>Security Copilot</h2><button className="btn ghost" aria-label="Close" onClick={onClose}>✕</button></div>
    <div className="db"><p className="muted" style={{ marginBottom: 10 }}>Answers use only projects you can access, with citations to tool receipts. It cannot change data.</p>
      <div className="pill-row" style={{ marginBottom: 12 }}>{SUGGEST.map(x => <button key={x} className="b blue" onClick={() => { setQ(x); ask(x); }}>{x}</button>)}</div>
      <form className="row" onSubmit={e => { e.preventDefault(); if (q.trim()) ask(q); }}><input className="i" value={q} onChange={e => setQ(e.target.value)} placeholder="Ask about your portfolio…" required style={{ flex: 1 }} /><button className="btn primary" disabled={busy}>Ask</button></form>
      <div style={{ marginTop: 14 }}>{busy && <Loading n={3} />}{!!err && <ErrorState error={err} />}
        {res && (res.result ? <div className="card"><p><b>{res.result.summary}</b></p>{(res.result.claims || []).map((c: any, k: number) => <div key={k} className={`ev ${c.stance}`}>{c.statement} <small>{(c.evidence || []).map((e: any) => `#${e.ref}`).join(' ')}</small></div>)}<small className="muted">{(res.result.limitations || []).join(' ')}</small><div style={{ marginTop: 8 }}><button className="btn sm" onClick={() => onOpen(res.id)}>Open workspace</button></div></div> : <div className="notice warn">{res.state}: {res.error || 'no result'}</div>)}</div></div></aside>;
}

export function Agents() {
  const q = useQuery(); const nav = useNavigate(); const { act, modal } = useUi();
  const s = useLoad(() => Promise.all([get<Project[]>('/api/projects'), get('/api/agent-policies' + qs({ project_id: q.project_id }))]), [q.project_id]);
  return <Load s={s}>{([projects, pol]) => <>
    <PageHead title="AI agent control plane" sub="Workflow selection, model/provider policy, allowed data classes, project-scoped tools, limits, budgets and approval rules. Provider connectivity is separate from workflow readiness.">
      <select className="i" style={{ maxWidth: 240 }} value={q.project_id || ''} onChange={e => nav('/agents' + qs({ project_id: e.target.value }))}><option value="">Organization defaults</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></PageHead>
    <div className="grid g3" style={{ marginBottom: 16 }}>
      <div className="card stat"><span className="l">Configured provider</span><span className="v" style={{ fontSize: 20 }}>{pol.provider.configured}</span><span className="l">{pol.provider.model} · effort {pol.provider.effort}</span></div>
      <div className="card stat"><span className="l">Anthropic API key</span><span><Badge v={pol.provider.anthropic_key_configured ? `configured (${pol.provider.key_source})` : 'missing'} cls={pol.provider.anthropic_key_configured ? 'green' : 'orange'} /></span>
        <div className="row" style={{ marginTop: 6 }}><button className="btn sm" onClick={() => modal(close => <form className="form" onSubmit={onSubmit(async d => { await act(() => put('/api/ai/credentials', d), 'Key stored encrypted'); close(); s.reload(); })}><h2>Anthropic API key</h2><p className="muted">Sealed with the server master key; never returned to the browser, logs or models. A server-level ANTHROPIC_API_KEY takes precedence.</p><label className="f">API key<input className="i" name="api_key" type="password" autoComplete="off" required /></label><div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn" onClick={close}>Cancel</button><button className="btn primary">Store</button></div></form>)}>Set key</button>
          <button className="btn sm" onClick={async () => { const r = await act(() => post('/api/ai/test')); modal(close => <><h2>Connection test: {r.ok ? 'ok' : 'failed'}</h2><pre className="code">{JSON.stringify(r, null, 2)}</pre><div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn" onClick={close}>Close</button></div></>); }}>Test connection</button>
          {pol.provider.key_source === 'organization' && pol.provider.anthropic_key_configured && <button className="btn sm danger" onClick={() => act(() => del('/api/ai/credentials'), 'Key removed').then(s.reload)}>Remove</button>}</div></div>
      <div className="card stat"><span className="l">Approval rules</span><span className="v" style={{ fontSize: 20 }}>human approval</span><span className="l">for applicability changes; agents cannot mutate findings</span></div></div>
    {pol.workflows.map((w: string) => { const e = pol.effective[w]; return <form key={w + (q.project_id || '')} className="card form" style={{ marginBottom: 12 }} onSubmit={onSubmit(async d => { await act(() => put(`/api/agent-policies/${w}`, { ...d, project_id: q.project_id || undefined, provider: d.provider || null, model: d.model || undefined }), 'Policy saved (new version)'); s.reload(); })}>
      <div className="head"><h2 className="grow">{label(w)}</h2><span className="b">policy {e.version}</span></div>
      <div className="form two" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
        <label className="f">Provider<select className="i" name="provider" defaultValue={e.provider || ''}><option value="">inherit ({pol.provider.configured})</option><option value="anthropic">anthropic (Claude)</option><option value="offline">offline deterministic</option></select></label>
        <label className="f">Model<input className="i" name="model" defaultValue={e.model || ''} placeholder={pol.provider.model} /></label>
        <label className="f">Max tool calls<input className="i" type="number" name="max_tool_calls" defaultValue={e.max_tool_calls} /></label><label className="f">Timeout (s)<input className="i" type="number" name="timeout_s" defaultValue={e.timeout_s} /></label>
        <label className="f">Budget per run (USD)<input className="i" type="number" step="0.1" name="budget_usd" defaultValue={e.budget_usd} /></label>
        <label className="f" style={{ gridColumn: 'span 3' }}>Allowed data classes<span className="row">{['public', 'internal', 'confidential', 'restricted'].map(c => <label key={c} className="row"><input type="checkbox" name="allowed_data_classes" data-multi="1" value={c} defaultChecked={e.allowed_data_classes.includes(c)} /> {c}</label>)}</span></label></div>
      <div><small className="muted">Tools:</small><div className="pill-row">{pol.workflow_tools[w].map((t: string) => <label key={t} className="b" title={pol.tools[t]}><input type="checkbox" name="tools" data-multi="1" value={t} defaultChecked={!e.tools || e.tools.includes(t)} /> {t}</label>)}</div></div>
      <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Save {label(w)} policy</button></div></form>; })}
  </>}</Load>;
}
