import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { get, patch, post, qs, type Project, type ProjectDetail } from '../api';
import { Badge, Empty, Load, PageHead, Table, Tabs, fmtDate, fmtDay, label, onSubmit, rel, useConfirm, useLoad, useQuery, useUi } from '../ui';

const AT: [string, string][] = [['/automation', 'Alerts'], ['/automation/rules', 'Routing & SLA rules'], ['/automation/policies', 'Priority & SLA policy'], ['/automation/channels', 'Channels'], ['/automation/schedules', 'Schedules'], ['/automation/jobs', 'Jobs'], ['/automation/deliveries', 'Deliveries']];
const AutoHead = ({ title, sub }: { title: string; sub: string }) => <><PageHead title={title} sub={sub} /><Tabs items={AT} /></>;

export function Alerts() {
  const q = useQuery(); const { act, modal } = useUi();
  const s = useLoad(() => get('/api/alerts' + qs({ state: q.state })), [q.state]);
  const doAct = (id: string, action: string, body = {}) => act(() => post(`/api/alerts/${id}/${action}`, body), `Alert ${action}d`).then(s.reload);
  return <><AutoHead title="Automation center" sub="Rules, schedules, runs, approvals and deliveries. A routing rule, a delivery channel and a delivery attempt are separate records." />
    <div className="row" style={{ marginBottom: 10 }}>{['', 'open', 'acknowledged', 'snoozed', 'resolved'].map(x => <Link key={x} className={`b ${(q.state || '') === x ? 'blue' : ''}`} to={'/automation' + qs({ state: x })}>{x || 'all'}</Link>)}</div>
    <Load s={s}>{alerts => alerts.length ? alerts.map((a: any) => <div key={a.id} className="card" style={{ marginBottom: 10 }}>
      <div className="head"><div className="grow"><b>{a.title}</b><br /><small>{label(a.trigger)} · {rel(a.created_at)} · {a.occurrences} occurrence(s) (deduplicated){a.escalated_at && ' · escalated'}</small></div><Badge v={a.state} />{a.priority && <Badge v={a.priority} cls={a.priority} />}</div>
      {a.body?.why ? <dl className="kv"><dt>Deployment</dt><dd>{a.body.deployment || '—'}</dd><dt>Version</dt><dd>{a.body.observed_version} → {a.body.fixed_version || 'unknown'}</dd><dt>Why</dt><dd>{a.body.why}</dd><dt>Evidence</dt><dd>{a.body.evidence || '—'}</dd><dt>Action</dt><dd>{a.body.action}</dd><dt>Owner / due</dt><dd>{a.body.owner} · {a.body.due}</dd></dl> : <p style={{ whiteSpace: 'pre-wrap' }}>{a.body?.text}</p>}
      <div className="pill-row" style={{ margin: '8px 0' }}>{(a.deliveries || []).map((d: any) => <span key={d.id} className={`b ${d.status}`} title={d.last_error || JSON.stringify(d.receipt || {})}>{d.channel}: {d.status} ({d.attempts})</span>)}</div>
      <div className="row">{a.finding_id && <Link className="btn sm" to={`/findings/${a.finding_id}`}>Finding</Link>}
        {a.state === 'open' && <><button className="btn sm primary" onClick={() => doAct(a.id, 'acknowledge')}>Acknowledge</button>
          <button className="btn sm" onClick={() => modal(close => <form className="form" onSubmit={onSubmit(d => { close(); doAct(a.id, 'snooze', { until: new Date(Date.now() + Number(d.hours) * 3600e3).toISOString() }); })}><h2>Snooze alert</h2><label className="f">Hours (max 720)<input className="i" type="number" name="hours" defaultValue={24} min={1} max={720} /></label><div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn" onClick={close}>Cancel</button><button className="btn primary">Snooze</button></div></form>)}>Snooze…</button></>}
        {a.state !== 'resolved' ? <button className="btn sm" onClick={() => doAct(a.id, 'resolve')}>Resolve</button> : <button className="btn sm" onClick={() => doAct(a.id, 'reopen')}>Reopen</button>}</div></div>) : <Empty title="No alerts">Rules have not matched any events yet.</Empty>}</Load></>;
}

export function Rules() {
  const { act } = useUi(); const [dry, setDry] = useState<any>(null);
  const s = useLoad(() => Promise.all([get('/api/alert-rules'), get('/api/channels'), get<Project[]>('/api/projects'), get('/api/policies')]), []);
  return <><AutoHead title="Routing & SLA" sub="Triggers, conditions (project/environment, applicability, exploitation, priority), routing, grouping, quiet hours with critical bypass, and escalation." />
    <Load s={s}>{([{ triggers, rules }, channels, projects, pol]) => {
      const body = (form: HTMLFormElement) => { const f = new FormData(form); const g = (k: string) => String(f.get(k) || ''); return { name: g('name') || 'rule', project_id: g('project_id') || undefined, triggers: f.getAll('triggers'), conditions: { min_priority: g('min_priority') || undefined, production_only: f.get('production_only') === 'on' }, actions: [{ type: 'notify', channel_id: g('channel_id') }, ...(f.get('ticket') === 'on' ? [{ type: 'ticket', provider: 'internal' }] : [])], grouping_window_s: Number(g('grouping_window_s') || 0), quiet_hours: g('qs') ? { start: g('qs'), end: g('qe'), timezone: g('qtz') } : undefined, critical_bypass: f.get('critical_bypass') === 'on' }; };
      return <div className="grid g21"><div className="col">
        {rules.map((r: any) => <div key={r.id} className="card"><div className="head"><h3 className="grow">{r.name}</h3>{r.project ? <span className="b">{r.project}</span> : <span className="b">org-wide</span>}<label className="row"><input type="checkbox" defaultChecked={r.enabled} onChange={e => act(() => patch(`/api/alert-rules/${r.id}`, { enabled: e.target.checked }), 'Rule updated')} /> enabled</label></div>
          <dl className="kv"><dt>Triggers</dt><dd>{r.triggers.map((t: string) => <span key={t} className="b">{t}</span>)}</dd><dt>Conditions</dt><dd><code>{JSON.stringify(r.conditions)}</code></dd><dt>Actions</dt><dd>{r.actions.map((a: any, i: number) => <span key={i} className="b blue">{a.type}{a.channel_id ? ':' + (channels.find((c: any) => c.id === a.channel_id)?.name || a.channel_id) : a.provider ? ':' + a.provider : ''}</span>)}</dd>
            <dt>Grouping</dt><dd>{r.grouping_window_s ? r.grouping_window_s + 's window' : 'immediate'}</dd><dt>Quiet hours</dt><dd>{r.quiet_hours ? `${r.quiet_hours.start}–${r.quiet_hours.end} ${r.quiet_hours.timezone}` : 'none'}{r.critical_bypass && ' · P0/P1 bypass'}</dd><dt>Escalation</dt><dd>{r.escalation ? `after ${r.escalation.after_s}s` : 'none'}</dd></dl></div>)}
        {!rules.length && <Empty title="No rules" />}
        <div className="card"><h2>Effective SLA</h2><p className="muted">Edit under <Link to="/automation/policies">Priority & SLA policy</Link>. Version {pol.effective.sla.version}{pol.effective.sla.calendar ? ` · business hours ${pol.effective.sla.calendar.start}–${pol.effective.sla.calendar.end} ${pol.effective.sla.calendar.timezone}` : ' · calendar hours'}.</p></div></div>
        <form className="card form" id="rf" onSubmit={async e => { e.preventDefault(); await act(() => post('/api/alert-rules', body(e.currentTarget)), 'Rule created'); s.reload(); }}><h2>New rule</h2>
          <label className="f">Name<input className="i" name="name" required /></label>
          <label className="f">Project<select className="i" name="project_id"><option value="">Organization-wide</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
          <label className="f">Triggers<select className="i" name="triggers" multiple size={6} defaultValue={['finding.created']}>{triggers.map((t: string) => <option key={t}>{t}</option>)}</select></label>
          <label className="f">Minimum priority<select className="i" name="min_priority"><option value="">any</option>{['P0', 'P1', 'P2', 'P3'].map(x => <option key={x}>{x}</option>)}</select></label>
          <label className="row"><input type="checkbox" name="production_only" defaultChecked /> Production only</label>
          <label className="f">Notify channel<select className="i" name="channel_id">{channels.map((c: any) => <option key={c.id} value={c.id}>{c.name} ({c.kind})</option>)}</select></label>
          <label className="row"><input type="checkbox" name="ticket" /> Also create internal ticket</label>
          <label className="f">Grouping window (s)<input className="i" type="number" name="grouping_window_s" defaultValue={0} /></label>
          <div className="form two"><label className="f">Quiet start<input className="i" name="qs" placeholder="22:00" /></label><label className="f">Quiet end<input className="i" name="qe" placeholder="07:00" /></label></div>
          <label className="f">Quiet-hours timezone<input className="i" name="qtz" defaultValue="Asia/Ho_Chi_Minh" /></label>
          <label className="row"><input type="checkbox" name="critical_bypass" defaultChecked /> P0/P1 bypass quiet hours</label>
          <div className="row" style={{ justifyContent: 'space-between' }}><button type="button" className="btn" onClick={async () => setDry(await act(() => post('/api/alert-rules/test', body(document.getElementById('rf') as HTMLFormElement))))}>Dry run</button><button className="btn primary">Create rule</button></div>
          {dry && <div className="notice info">{dry.would_match} open finding(s) would match now. {dry.note}</div>}</form></div>;
    }}</Load></>;
}

export function Policies() {
  const q = useQuery(); const nav = useNavigate(); const { act } = useUi();
  const s = useLoad(() => Promise.all([get<Project[]>('/api/projects'), get('/api/policies' + qs({ project_id: q.project_id }))]), [q.project_id]);
  return <><AutoHead title="Priority & SLA policy" sub="Versioned, deterministic policies. Saving creates a new version and re-scores findings; each finding records the version it was scored with. P0 always requires exploitation evidence in production, and unknown severity may not score below low." />
    <Load s={s}>{([projects, pol]) => {
      const pr = pol.effective.priority, sla = pol.effective.sla, cal = sla.calendar || {};
      const Num = ({ name, v }: { name: string; v: number }) => <input className="i" type="number" step={1} name={name} defaultValue={v} style={{ maxWidth: 90 }} />;
      const groups: [string, string[]][] = [['severity_points', ['critical', 'high', 'medium', 'low', 'unknown']], ['exploitation_points', ['observed_in_env', 'actively_exploited', 'kev_listed', 'poc_public']], ['exposure_points', ['internet', 'partner', 'internal', 'isolated']], ['criticality_points', ['critical', 'high', 'medium', 'low']], ['thresholds', ['P0', 'P1', 'P2', 'P3']]];
      return <div key={q.project_id || 'org'}>
        <div className="row" style={{ marginBottom: 12 }}><select className="i" style={{ maxWidth: 260 }} value={q.project_id || ''} onChange={e => nav('/automation/policies' + qs({ project_id: e.target.value }))}><option value="">Organization default</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name} (override)</option>)}</select><span className="b">priority v{pr.version} ({pr.scope || 'built-in'})</span><span className="b">SLA v{sla.version} ({sla.scope || 'built-in'})</span></div>
        <div className="grid g2"><form className="card form" onSubmit={onSubmit(async d => { const def: Record<string, any> = {}; for (const [k, v] of Object.entries(d)) { if (v === undefined) continue; const [g, kk] = k.split('.'); if (kk) (def[g] ||= {})[kk] = v; else def[g] = v; } await act(() => post('/api/policies/priority', { project_id: q.project_id || undefined, definition: def }), 'Priority policy saved; findings are being re-scored'); s.reload(); })}>
          <h2>Priority points</h2>{groups.map(([g, keys]) => <div key={g}><b>{label(g)}</b><div className="row">{keys.map(k => <label key={k} className="f">{k}<Num name={`${g}.${k}`} v={pr[g][k]} /></label>)}</div></div>)}
          <div className="row"><label className="f">production<Num name="production_points" v={pr.production_points} /></label><label className="f">verified control<Num name="verified_control_points" v={pr.verified_control_points} /></label></div>
          <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Save priority policy</button></div></form>
        <form className="card form" onSubmit={onSubmit(async d => { const def: Record<string, any> = { hours: { P0: d['hours.P0'], P1: d['hours.P1'], P2: d['hours.P2'], P3: d['hours.P3'], P4: null }, non_production_multiplier: d.non_production_multiplier }; if (d.business) def.calendar = { type: 'business', timezone: d.timezone, start: d.start, end: d.end, days: (d.days || []).map(Number), holidays: String(d.holidays || '').split(',').map(x => x.trim()).filter(Boolean) }; await act(() => post('/api/policies/sla', { project_id: q.project_id || undefined, definition: def }), 'SLA policy saved; due dates are being recomputed'); s.reload(); })}>
          <h2>SLA</h2><div className="row">{['P0', 'P1', 'P2', 'P3'].map(k => <label key={k} className="f">{k} hours<Num name={`hours.${k}`} v={sla.hours[k]} /></label>)}</div>
          <label className="f">Non-production multiplier<Num name="non_production_multiplier" v={sla.non_production_multiplier} /></label>
          <label className="row"><input type="checkbox" name="business" defaultChecked={cal.type === 'business'} /> Count business hours only</label>
          <div className="row"><label className="f">Timezone<input className="i" name="timezone" defaultValue={cal.timezone || 'Asia/Ho_Chi_Minh'} /></label><label className="f">Start<input className="i" name="start" defaultValue={cal.start || '09:00'} style={{ maxWidth: 90 }} /></label><label className="f">End<input className="i" name="end" defaultValue={cal.end || '18:00'} style={{ maxWidth: 90 }} /></label></div>
          <div className="row">{['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((dn, i) => <label key={dn} className="row"><input type="checkbox" name="days" data-multi="1" value={i} defaultChecked={(cal.days || [1, 2, 3, 4, 5]).includes(i)} /> {dn}</label>)}</div>
          <label className="f">Holidays (YYYY-MM-DD, comma-separated)<input className="i" name="holidays" defaultValue={(cal.holidays || []).join(', ')} /></label>
          <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Save SLA policy</button></div></form></div>
        <div className="card" style={{ marginTop: 16 }}><h2>History</h2><Table rows={pol.stored.filter((x: any) => ['priority', 'sla'].includes(x.kind))} empty="Using built-in v1 defaults." cols={[{ label: 'Kind', render: (x: any) => x.kind }, { label: 'Version', render: (x: any) => x.version }, { label: 'Scope', render: (x: any) => x.project_id ? projects.find(p => p.id === x.project_id)?.key || x.project_id : 'organization' }, { label: 'Active', render: (x: any) => x.active ? <Badge v="active" cls="green" /> : null }, { label: 'Created', render: (x: any) => fmtDate(x.created_at) }]} /></div></div>;
    }}</Load></>;
}

export function Channels() {
  const { act, modal, toast } = useUi(); const [kind, setKind] = useState('email');
  const s = useLoad(() => get('/api/channels'), []);
  return <><AutoHead title="Alert channels" sub="Email (SMTP), Slack, Microsoft Teams, signed webhooks, SIEM collectors and in-app. Webhook URLs, collector credentials and SMTP passwords are stored encrypted server-side and never returned." />
    <div className="grid g21"><div><Load s={s}>{channels => <Table rows={channels} cols={[
      { label: 'Name', render: (c: any) => <><b>{c.name}</b><br /><small>{c.kind}{c.config?.url_host && ' · ' + c.config.url_host}{c.config?.to?.length ? ' · ' + c.config.to.join(', ') : ''}{c.config?.format ? ' · ' + c.config.format : ''}</small></> },
      { label: 'Secret', render: (c: any) => c.secret_name ? <small>{c.secret_name} · fp {c.fingerprint}</small> : '—' },
      { label: 'Enabled', render: (c: any) => <Badge v={c.enabled ? 'enabled' : 'disabled'} cls={c.enabled ? 'green' : ''} /> },
      { label: '', render: (c: any) => <button className="btn sm" onClick={async () => { try { const r = await post(`/api/channels/${c.id}/test`); modal(close => <><h2>Test delivery: {r.outcome}</h2><pre className="code">{JSON.stringify(r.receipt, null, 2)}</pre><div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn" onClick={close}>Close</button></div></>); } catch (e) { toast((e as Error).message, true); } }}>Send test</button> }]} />}</Load>
      <p className="muted" style={{ marginTop: 8 }}>"Send test" performs a real send and shows the provider receipt. A provider accepting a message is not proof of inbox delivery.</p></div>
      <form className="card form" onSubmit={onSubmit(async d => {
        const r = await act(() => post('/api/channels', { ...d, kind, to: d.to ? String(d.to).split(',').map((x: string) => x.trim()) : [], smtp_host: d.smtp_host || undefined }));
        if (r.signing_key) modal(close => <><h2>Webhook signing key</h2><p>{r.signing_key_note}</p><pre className="code">{r.signing_key}</pre><div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn" onClick={() => { close(); s.reload(); }}>Done</button></div></>); else s.reload();
      })}><h2>New channel</h2>
        <label className="f">Kind<select className="i" value={kind} onChange={e => setKind(e.target.value)}><option value="email">Email (SMTP)</option><option value="slack">Slack incoming webhook</option><option value="teams">Teams workflow webhook</option><option value="webhook">Signed webhook</option><option value="siem">SIEM (Splunk HEC / JSON collector)</option><option value="in_app">In-app</option></select></label>
        <label className="f">Name<input className="i" name="name" required /></label>
        {['slack', 'teams', 'webhook', 'siem'].includes(kind) && <label className="f">URL (HTTPS)<input className="i" name="url" type="url" autoComplete="off" required /></label>}
        {kind === 'siem' && <><label className="f">Collector credential (stored encrypted)<input className="i" name="collector_token" type="password" autoComplete="off" required /></label><label className="f">Format<select className="i" name="format"><option value="splunk_hec">Splunk HEC</option><option value="json">Generic JSON (Bearer)</option></select></label><label className="f">Index (optional)<input className="i" name="index" /></label></>}
        {kind === 'email' && <><label className="f">Recipients (comma-separated)<input className="i" name="to" /></label><label className="f">SMTP host (blank = server default)<input className="i" name="smtp_host" /></label></>}
        <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Create</button></div></form></div></>;
}

export function Schedules() {
  const { act } = useUi(); const nav = useNavigate(); const confirm = useConfirm();
  const s = useLoad(() => Promise.all([get('/api/schedules'), get('/api/channels')]), []);
  const doAct = async (id: string, a: string) => { const r = await act(() => post(`/api/schedules/${id}/${a}`, {}), a === 'run-now' ? 'Job queued (recurring schedule unchanged)' : 'Updated'); if (r?.job_id) nav('/automation/jobs'); else s.reload(); };
  return <><AutoHead title="Schedules" sub="Durable, timezone/DST-aware schedules. next_run_at is stored in UTC with the original timezone. Browser sessions never drive execution." />
    <Load s={s}>{([{ job_types, schedules }, channels]) => <div className="grid g21"><div className="col">{schedules.map((x: any) => <div key={x.id} className="card"><div className="head"><h3 className="grow">{x.name}</h3>{x.paused ? <Badge v="paused" cls="orange" /> : <Badge v="active" cls="green" />}</div>
      <dl className="kv"><dt>Job</dt><dd>{label(x.job_type)} {x.project ? `· ${x.project}` : '· org-wide'}</dd><dt>When</dt><dd>{x.frequency} at {x.local_time}{x.weekday != null && ' on ' + ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][x.weekday]} ({x.timezone})</dd><dt>Next run</dt><dd>{fmtDate(x.next_run_at)} <small>({rel(x.next_run_at)}; UTC {new Date(x.next_run_at).toISOString().slice(0, 16)})</small></dd><dt>Last success</dt><dd>{x.last_success_at ? fmtDate(x.last_success_at) : 'never'}</dd><dt>Policies</dt><dd>overlap: {x.overlap_policy} · missed: {x.missed_run_policy} · retries: {x.retry_budget} · timeout {x.timeout_s}s</dd><dt>Owner</dt><dd>{x.owner_name || '—'}</dd></dl>
      {(x.recent_runs || []).length > 0 && <div className="pill-row" style={{ marginTop: 8 }}>{x.recent_runs.map((r: any) => <span key={r.id} className={`b ${r.status}`} title={r.last_error || ''}>{fmtDate(r.scheduled_for)} {r.status}</span>)}</div>}
      <div className="row" style={{ marginTop: 10 }}><button className="btn sm primary" onClick={() => doAct(x.id, 'run-now')}>Run now</button><button className="btn sm" onClick={() => doAct(x.id, x.paused ? 'resume' : 'pause')}>{x.paused ? 'Resume' : 'Pause'}</button><button className="btn sm danger" onClick={() => confirm('Archive this schedule? History is retained.', () => doAct(x.id, 'archive'), true)}>Archive</button></div></div>)}</div>
      <form className="card form" onSubmit={onSubmit(async d => { const body = { ...d, weekday: d.weekday === '' ? undefined : Number(d.weekday), params: d.job_type === 'daily_report' ? { language: d.language, timezone: d.timezone, channel_ids: d.channel_id ? [d.channel_id] : [] } : {} }; await act(() => post('/api/schedules', body), 'Schedule created'); s.reload(); })}><h2>New schedule</h2>
        <label className="f">Name<input className="i" name="name" required /></label><label className="f">Job<select className="i" name="job_type">{job_types.map((j: string) => <option key={j}>{j}</option>)}</select></label>
        <div className="form two"><label className="f">Frequency<select className="i" name="frequency"><option>daily</option><option>weekly</option><option>hourly</option></select></label><label className="f">Local time<input className="i" name="local_time" defaultValue="08:00" /></label></div>
        <div className="form two"><label className="f">Timezone (IANA)<input className="i" name="timezone" defaultValue="Asia/Ho_Chi_Minh" /></label><label className="f">Weekday (weekly)<select className="i" name="weekday"><option value="">—</option>{['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'].map((dn, i) => <option key={dn} value={i}>{dn}</option>)}</select></label></div>
        <div className="form two"><label className="f">Missed runs<select className="i" name="missed_run_policy"><option>run_once</option><option>skip</option><option>run_all</option></select></label><label className="f">Overlap<select className="i" name="overlap_policy"><option>skip</option><option>queue</option><option>allow</option></select></label></div>
        <label className="f">Report language (daily_report)<select className="i" name="language"><option value="vi">Tiếng Việt (default)</option><option value="en">English</option></select></label>
        <label className="f">Report channel<select className="i" name="channel_id"><option value="">—</option>{channels.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
        <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Create</button></div></form></div>}</Load></>;
}

export function Jobs() {
  const q = useQuery(); const { act } = useUi();
  const s = useLoad(() => get('/api/jobs' + qs({ status: q.status, type: q.type })), [q.status, q.type]);
  return <><AutoHead title="Jobs & deliveries" sub="Durable queue with leases, fencing, idempotency keys, bounded retries with jitter and a dead-letter state. Operators can cancel or replay." />
    <Load s={s}>{r => <><div className="grid g4" style={{ marginBottom: 12 }}><div className="card stat"><span className="l">Dead-letter</span><span className="v">{r.stats.dead_letter}</span></div><div className="card stat"><span className="l">Oldest ready job lag</span><span className="v">{r.stats.oldest_ready_lag_s}s</span></div></div>
      <div className="row" style={{ marginBottom: 10 }}>{['', 'queued', 'running', 'succeeded', 'failed', 'dead', 'cancelled'].map(x => <Link key={x} className={`b ${(q.status || '') === x ? 'blue' : ''}`} to={'/automation/jobs' + qs({ status: x })}>{x || 'all'}</Link>)}</div>
      <Table rows={r.items} empty="No jobs. Schedules materialize jobs at their next occurrence." cols={[
        { label: 'Job', render: (j: any) => <><b>{label(j.type)}</b><br /><small className="mono">{j.id}</small></> }, { label: 'Status', render: (j: any) => <Badge v={j.status} /> }, { label: 'Attempts', render: (j: any) => `${j.attempts}/${j.max_attempts}` },
        { label: 'Scheduled for', render: (j: any) => j.scheduled_for ? fmtDate(j.scheduled_for) : '—' }, { label: 'Finished', render: (j: any) => j.finished_at ? rel(j.finished_at) : j.status === 'queued' ? `runs ${rel(j.run_after)}` : '—' },
        { label: 'Error', render: (j: any) => j.last_error ? <small style={{ color: 'var(--red)' }}>{j.last_error.slice(0, 160)}</small> : null },
        { label: '', render: (j: any) => ['queued', 'running'].includes(j.status) ? <button className="btn sm" onClick={() => act(() => post(`/api/jobs/${j.id}/cancel`), 'Cancelled').then(s.reload)}>Cancel</button> : ['dead', 'failed', 'cancelled'].includes(j.status) ? <button className="btn sm" onClick={() => act(() => post(`/api/jobs/${j.id}/replay`), 'Replayed').then(s.reload)}>Replay</button> : null }]} /></>}</Load></>;
}

export function Deliveries() {
  const { act } = useUi(); const s = useLoad(() => get('/api/deliveries'), []);
  return <><AutoHead title="Deliveries" sub="Each delivery attempt per channel with provider receipt, retry count and dead-letter replay." />
    <Load s={s}>{ds => <Table rows={ds} empty="No deliveries." cols={[
      { label: 'Alert', render: (d: any) => <>{(d.title || '').slice(0, 90)}{d.is_test && <> <Badge v="test" cls="blue" /></>}</> }, { label: 'Channel', render: (d: any) => <>{d.channel} <small>{d.kind}</small></> }, { label: 'Status', render: (d: any) => <Badge v={d.status} /> }, { label: 'Attempts', render: (d: any) => d.attempts },
      { label: 'Receipt / error', render: (d: any) => d.last_error ? <small style={{ color: 'var(--red)' }}>{d.last_error}</small> : <small>{JSON.stringify(d.provider_receipt || {}).slice(0, 120)}</small> }, { label: 'Updated', render: (d: any) => rel(d.updated_at) },
      { label: '', render: (d: any) => ['dead', 'failed'].includes(d.status) ? <button className="btn sm" onClick={() => act(() => post(`/api/deliveries/${d.id}/replay`), 'Replay queued').then(s.reload)}>Replay</button> : null }]} />}</Load></>;
}

export function Reports() {
  const s = useLoad(() => get('/api/reports'), []);
  return <><PageHead title="Reports" sub="Daily report in Vietnamese by default (08:00 Asia/Ho_Chi_Minh). Material changes only; THN coverage reported separately; failed ingestion produces an incomplete-coverage notice." />
    <Load s={s}>{rs => <Table rows={rs} onRow={(r: any) => `/reports/${r.id}`} empty="No reports yet. Use Automation → Schedules → Run now on the daily report." cols={[{ label: 'Period', render: (r: any) => `${fmtDate(r.period_start)} → ${fmtDate(r.period_end)}` }, { label: 'Language', render: (r: any) => r.language }, { label: 'Coverage', render: (r: any) => <Badge v={r.coverage_status} /> }, { label: 'Material changes', render: (r: any) => r.content?.material ?? 0 }, { label: 'Created', render: (r: any) => rel(r.created_at) }]} />}</Load></>;
}
export function Report() {
  const { id = '' } = useParams(); const s = useLoad(() => get(`/api/reports/${id}`), [id]);
  return <Load s={s}>{r => <><PageHead title="Daily report" sub={`${fmtDate(r.period_start)} → ${fmtDate(r.period_end)} · ${r.language}`}><Badge v={r.coverage_status} /></PageHead>
    {r.coverage_status === 'incomplete' && <div className="notice warn" style={{ marginBottom: 12 }}>Incomplete coverage: {(r.content.failures || []).join('; ')}</div>}
    <div className="card"><pre className="code" style={{ whiteSpace: 'pre-wrap', maxHeight: 'none' }}>{r.rendered_text}</pre></div></>}</Load>;
}

export function Integrations() {
  const q = useQuery(); const { act, toast } = useUi(); const confirm = useConfirm();
  const s = useLoad(() => Promise.all([get('/api/connectors'), get('/api/connections'), get<Project[]>('/api/projects'), get('/api/org/secrets').catch(() => [])]), []);
  const doAct = async (id: string, a: string) => { const r = await act(() => post(`/api/connections/${id}/${a}`)); if (a === 'test' || a === 'reconnect') toast(r.ok ? `OK: ${r.detail}` : `Failed: ${r.error}`, !r.ok); else toast(a === 'sync' ? 'Sync queued' : 'Disconnected'); setTimeout(s.reload, 600); };
  return <><PageHead title="Integrations & data sources" sub="Each adapter advertises supported resources, least-privilege permissions and limits. Health, freshness and last sync are recorded; a disconnected source cannot produce observations." />
    <Load s={s}>{([cat, conns, projects, secrets]) => <>
      <div className="card" style={{ marginBottom: 16 }}><h2>Connections</h2><Table rows={conns} empty="No connections." cols={[
        { label: 'Name', render: (c: any) => <><b>{c.name}</b><br /><small>{c.kind}{c.project ? ' · ' + c.project : ' · org'}</small></> }, { label: 'Status', render: (c: any) => <Badge v={c.status} /> }, { label: 'Last success', render: (c: any) => c.last_success_at ? rel(c.last_success_at) : 'never' },
        { label: 'Credential', render: (c: any) => c.secret_name ? <small>{c.secret_name} (fp {c.fingerprint})</small> : '—' }, { label: 'Last error', render: (c: any) => c.last_error ? <small style={{ color: 'var(--red)' }}>{c.last_error.slice(0, 140)}</small> : null },
        { label: '', render: (c: any) => <div className="row"><button className="btn sm" onClick={() => doAct(c.id, 'test')}>Test</button>{cat.find((k: any) => k.kind === c.kind)?.syncable && <button className="btn sm" onClick={() => doAct(c.id, 'sync')}>Sync</button>}{c.status === 'disconnected' ? <button className="btn sm" onClick={() => doAct(c.id, 'reconnect')}>Reconnect</button> : <button className="btn sm danger" onClick={() => confirm('Disconnect? Future access stops and observations from this source become stale (history retained).', () => doAct(c.id, 'disconnect'), true)}>Disconnect</button>}</div> }]} /></div>
      <div className="grid g21"><div className="grid g2">{cat.map((c: any) => <div key={c.kind} className="card"><div className="head"><h3 className="grow">{c.label}</h3><Badge v={c.category} cls="blue" /></div><ul style={{ margin: '0 0 8px', paddingLeft: 18 }}>{c.capabilities.map((x: string) => <li key={x}>{x}</li>)}</ul><small><b>Resources:</b> {c.resource_types.join(', ')}<br /><b>Permissions:</b> {c.permissions.join('; ')}<br /><b>Limits:</b> {c.limits}</small></div>)}</div>
        <form className="card form" onSubmit={onSubmit(async d => { let config = {}; try { config = d.config ? JSON.parse(d.config) : {}; } catch { toast('Config must be JSON', true); return; } const r = await act(() => post('/api/connections', { kind: d.kind, name: d.name, project_id: d.project_id || undefined, config, secret_value: d.secret_value || undefined, secret_id: d.secret_id || undefined })); toast(r.test.ok ? `Connected: ${r.test.detail}` : `Created but test failed: ${r.test.error}`, !r.test.ok); setTimeout(s.reload, 800); })}><h2>New connection</h2>
          <label className="f">Kind<select className="i" name="kind">{cat.map((c: any) => <option key={c.kind} value={c.kind}>{c.label}</option>)}</select></label><label className="f">Name<input className="i" name="name" required /></label>
          <label className="f">Project scope<select className="i" name="project_id" defaultValue={q.project_id || ''}><option value="">Organization</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
          <label className="f">Config (JSON, non-secret)<textarea className="i" name="config" placeholder='{"owner":"org","repo":"app"}  |  {"region":"ap-southeast-1","resource_types":["lambda:function"],"environment_id":"production","freshness_hours":48}' /></label>
          <label className="f">Credential (stored encrypted; never shown again)<input className="i" name="secret_value" type="password" autoComplete="off" /></label>
          <label className="f">…or existing secret<select className="i" name="secret_id"><option value="">—</option>{secrets.map((x: any) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label>
          <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Create & test</button></div></form></div></>}</Load></>;
}

const PIPELINES: Record<string, (base: string, svc: string) => string> = {
  github: (base, svc) => `# .github/workflows/sentra.yml — reviewed example; pin actions to commit SHAs in your fork.\nname: sentra\non:\n  push: { branches: [main] }\n  pull_request: {}            # fork PRs do not receive secrets (pull_request, not pull_request_target)\npermissions: { contents: read }\njobs:\n  sbom:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: Build image\n        id: build\n        run: |\n          docker build -t app:\${{ github.sha }} .\n          echo "digest=$(docker inspect --format='{{.Id}}' app:\${{ github.sha }})" >> "$GITHUB_OUTPUT"\n      - name: Generate CycloneDX SBOM (Syft)\n        uses: anchore/sbom-action@v0\n        with: { image: "app:\${{ github.sha }}", format: cyclonedx-json, output-file: sbom.cdx.json }\n      - name: Upload to Sentra and evaluate gate\n        if: github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository\n        env:\n          SENTRA_URL: ${base}\n          SENTRA_TOKEN: \${{ secrets.SENTRA_TOKEN }}\n        run: node scripts/sentra-ci.mjs upload --sbom sbom.cdx.json --service ${svc} --digest "\${{ steps.build.outputs.digest }}" --commit "\${{ github.sha }}" --wait --fail-mode open`,
  gitlab: (base, svc) => `# .gitlab-ci.yml — contract preview (GitHub Actions is the tested path)\nsentra_sbom:\n  image: node:24\n  variables: { SENTRA_URL: "${base}" }\n  script:\n    - syft "$IMAGE" -o cyclonedx-json > sbom.cdx.json\n    - node scripts/sentra-ci.mjs upload --sbom sbom.cdx.json --service ${svc} --digest "$IMAGE_DIGEST" --commit "$CI_COMMIT_SHA" --wait --fail-mode open`,
  jenkins: (base, svc) => `// Jenkinsfile — contract preview\npipeline { agent any\n  environment { SENTRA_URL = '${base}'; SENTRA_TOKEN = credentials('sentra-token') }\n  stages { stage('SBOM') { steps {\n    sh 'syft "$IMAGE" -o cyclonedx-json > sbom.cdx.json'\n    sh 'node scripts/sentra-ci.mjs upload --sbom sbom.cdx.json --service ${svc} --digest "$IMAGE_DIGEST" --commit "$GIT_COMMIT" --wait --fail-mode open'\n  } } } }`,
  azure: (base, svc) => `# azure-pipelines.yml — contract preview\nsteps:\n- script: syft "$(IMAGE)" -o cyclonedx-json > sbom.cdx.json\n- script: node scripts/sentra-ci.mjs upload --sbom sbom.cdx.json --service ${svc} --digest "$(IMAGE_DIGEST)" --commit "$(Build.SourceVersion)" --wait --fail-mode open\n  env: { SENTRA_URL: "${base}", SENTRA_TOKEN: $(SENTRA_TOKEN) }`,
};
export function CiSetup() {
  const q = useQuery(); const nav = useNavigate(); const { act, modal } = useUi(); const confirm = useConfirm();
  const ps = useLoad(() => get<Project[]>('/api/projects'), []);
  const pid = q.project_id || ps.data?.[0]?.id; const ci = q.ci || 'github';
  const s = useLoad(async () => { if (!pid) return null; const p = await get<ProjectDetail>(`/api/projects/${pid}`); const canTok = p.my_permissions.includes('ci_tokens:manage'); const [tokens, pol] = await Promise.all([canTok ? get(`/api/projects/${pid}/ci-tokens`) : [], get('/api/policies')]); return { p, canTok, tokens, pol }; }, [pid]);
  return <><PageHead title="CI/CD integration" sub="Upload an SBOM per build with commit, run URL and immutable digest; receive a receipt; poll a deterministic gate; record deployments separately after rollout." />
    <Load s={ps}>{projects => !pid ? <Empty title="No projects" /> : <Load s={s}>{d => { if (!d) return null; const { p, canTok, tokens, pol } = d;
      const gate = pol.stored.find((x: any) => x.kind === 'gate' && x.active && x.project_id === pid)?.definition || pol.gate_default; const svc = p.services[0]?.key || 'api';
      return <><div className="row" style={{ marginBottom: 12 }}><select className="i" style={{ maxWidth: 260 }} value={pid} onChange={e => nav('/ci?project_id=' + e.target.value)}>{projects.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></div>
        <div className="grid g2"><div className="card"><h2>Gate policy</h2><form key={pid} className="form" onSubmit={onSubmit(d2 => act(() => post('/api/policies/gate', { project_id: pid, mode: d2.mode, fail_mode: d2.fail_mode, timeout_s: d2.timeout_s, block_on: { min_severity: d2.min_severity, only_new: d2.only_new, exploitation: d2.kev ? ['kev_listed', 'actively_exploited'] : [] } }), 'Gate policy saved (new version)'))}>
          <div className="form two"><label className="f">Mode<select className="i" name="mode" defaultValue={gate.mode}><option value="observe">Observe only</option><option value="block_new">Block new policy violations</option></select></label>
            <label className="f">When Sentra is unavailable<select className="i" name="fail_mode" defaultValue={gate.fail_mode}><option value="open">Fail open (build continues)</option><option value="closed">Fail closed (build fails)</option></select></label>
            <label className="f">Block at severity ≥<select className="i" name="min_severity" defaultValue={gate.block_on.min_severity}>{['critical', 'high', 'medium'].map(x => <option key={x}>{x}</option>)}</select></label><label className="f">Timeout (s)<input className="i" type="number" name="timeout_s" defaultValue={gate.timeout_s} /></label></div>
          <label className="row"><input type="checkbox" name="only_new" defaultChecked={gate.block_on.only_new} /> Only findings new vs. production baseline</label><label className="row"><input type="checkbox" name="kev" defaultChecked={!!gate.block_on.exploitation?.length} /> Also block KEV / actively exploited</label>
          <p className="muted">Exit codes: 0 pass/warn, 1 policy fail, 2 Sentra unavailable (mapped by fail mode). AI output never changes a gate decision. Approved, unexpired gate exceptions are honored.</p>
          {p.my_permissions.includes('project:manage') && <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Save gate policy</button></div>}</form></div>
          <div className="card"><div className="head"><h2 className="grow">Scoped CI tokens</h2>{canTok && <button className="btn sm primary" onClick={() => modal(close => <TokenForm p={p} close={close} onDone={s.reload} />)}>New token</button>}</div>
            {canTok ? <Table rows={tokens} empty="No tokens." cols={[{ label: 'Name', render: (t: any) => <>{t.name}<br /><small className="mono">{t.prefix}…</small></> }, { label: 'Scopes', render: (t: any) => t.scopes.join(', ') }, { label: 'Expires', render: (t: any) => fmtDay(t.expires_at) }, { label: 'Last used', render: (t: any) => t.last_used_at ? rel(t.last_used_at) : 'never' }, { label: '', render: (t: any) => t.revoked_at ? <Badge v="revoked" cls="red" /> : <button className="btn sm danger" onClick={() => confirm('Revoke this token? Pipelines using it will fail immediately.', () => act(() => post(`/api/ci-tokens/${t.id}/revoke`), 'Revoked').then(s.reload), true)}>Revoke</button> }]} /> : <p className="muted">You need ci_tokens:manage on this project.</p>}
            <p className="muted" style={{ marginTop: 8 }}>Tokens are hashed at rest, project-scoped (optionally service-scoped), expiring and revocable. A token cannot read other projects' findings.</p></div></div>
        <div className="card" style={{ marginTop: 16 }}><h2>Pipeline</h2><Tabs items={[[`/ci?project_id=${pid}&ci=github`, 'GitHub Actions (tested CLI path)'], [`/ci?project_id=${pid}&ci=gitlab`, 'GitLab CI (preview)'], [`/ci?project_id=${pid}&ci=jenkins`, 'Jenkins (preview)'], [`/ci?project_id=${pid}&ci=azure`, 'Azure DevOps (preview)']]} />
          {ci !== 'github' && <div className="notice warn" style={{ marginBottom: 10 }}>Contract preview: this adapter is planned. Only the GitHub Actions path is integration-tested.</div>}
          <pre className="code">{PIPELINES[ci]?.(location.origin, svc)}</pre><p className="muted">The CLI <code>scripts/sentra-ci.mjs</code> ships with Sentra. Ecosystem examples (PHP/Composer, Node.js, Java/Maven, .NET, Docker, Terraform) live under <code>ci/</code>.</p></div></>; }}</Load>}</Load></>;
}
function TokenForm({ p, close, onDone }: { p: ProjectDetail; close: () => void; onDone: () => void }) {
  const { act } = useUi(); const [tok, setTok] = useState<any>(null);
  if (tok) return <><h2>Token created</h2><p>{tok.note}</p><pre className="code">{tok.token}</pre><div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn" onClick={() => { close(); onDone(); }}>Done</button></div></>;
  return <form className="form" onSubmit={onSubmit(async d => setTok(await act(() => post(`/api/projects/${p.id}/ci-tokens`, { ...d, service_id: d.service_id || undefined }))))}><h2>New CI token</h2>
    <label className="f">Name<input className="i" name="name" required defaultValue="github-actions" /></label><label className="f">Service scope<select className="i" name="service_id"><option value="">all services</option>{p.services.map(x => <option key={x.id} value={x.id}>{x.key}</option>)}</select></label>
    <label className="f">Expires in (days)<input className="i" type="number" name="expires_in_days" defaultValue={90} /></label><div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn" onClick={close}>Cancel</button><button className="btn primary">Create</button></div></form>;
}
export function Evaluation() {
  const { id = '' } = useParams(); const s = useLoad(() => get(`/api/v1/policy-evaluations/${id}`), [id]);
  return <Load s={s}>{e => <><PageHead title="Gate evaluation" sub={`${e.mode} · fail ${e.fail_mode} · policy v${e.policy_version ?? 'default'} · exit code ${e.exit_code}`}><Badge v={e.decision} cls={e.decision === 'fail' ? 'red' : e.decision === 'warn' ? 'orange' : 'green'} /></PageHead>
    <div className="card"><dl className="kv">{Object.entries(e.summary).map(([k, v]) => <div key={k} style={{ display: 'contents' }}><dt>{label(k)}</dt><dd>{String(v)}</dd></div>)}</dl></div>
    <div className="card" style={{ marginTop: 12 }}><h2>Violations</h2><Table rows={e.violations} empty="No violations." cols={[{ label: 'Advisory', render: (v: any) => v.advisory_id }, { label: 'Package', render: (v: any) => `${v.package}@${v.version}` }, { label: 'Severity', render: (v: any) => <Badge v={v.severity} /> }, { label: 'Exploitation', render: (v: any) => <Badge v={v.exploitation} /> }, { label: 'New', render: (v: any) => v.new ? 'yes' : 'baseline' }, { label: 'Rule', render: (v: any) => v.rule }, { label: 'Exception', render: (v: any) => v.excepted ? <Badge v="excepted" cls="green" /> : null }]} /></div></>}</Load>;
}
