import { useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, get, patch, post, qs, type Project } from '../api';
import { useMe } from '../Shell';
import { Badge, Load, PageHead, SavedViews, Table, Tabs, fmtDate, label, onSubmit, rel, safeHref, useConfirm, useLoad, useQuery, useUi } from '../ui';

const ADT: [string, string][] = [['/admin', 'Members'], ['/admin/invitations', 'Invitations'], ['/admin/mappings', 'Keycloak role mapping'], ['/admin/secrets', 'Secrets'], ['/admin/settings', 'Settings']];
const ORG_ROLES = ['member', 'security_analyst', 'management_viewer', 'auditor', 'org_admin'];
const PROJECT_ROLES = ['viewer', 'developer', 'devops', 'tech_lead', 'project_owner'];

export function Members() {
  const { me } = useMe(); const { act } = useUi(); const confirm = useConfirm();
  const s = useLoad(() => get('/api/org/members'), []); const isAdmin = me.organization?.role === 'org_admin';
  return <><PageHead title="SSO & access" sub="Keycloak authenticates; Sentra authorizes. Organization roles plus per-project roles; removal revokes sessions immediately; background tasks re-check access at execution." /><Tabs items={ADT} />
    <Load s={s}>{ms => <Table rows={ms} cols={[
      { label: 'Member', render: (m: any) => <><b>{m.display_name}</b> {m.disabled && <Badge v="disabled" cls="red" />}<br /><small>{m.email} · {m.issuer === 'dev' ? 'dev identity' : 'Keycloak'}</small></> },
      { label: 'Org role', render: (m: any) => isAdmin ? <select className="i" defaultValue={m.org_role} onChange={e => act(() => patch(`/api/org/members/${m.id}`, { org_role: e.target.value }), 'Role updated')}>{ORG_ROLES.map(r => <option key={r}>{r}</option>)}</select> : label(m.org_role) },
      { label: 'Source', render: (m: any) => m.source },
      { label: 'Projects', render: (m: any) => <div className="pill-row">{(m.projects || []).map((p: any) => <span key={p.project_id} className="b">{p.project}: {label(p.role)}</span>)}</div> },
      { label: 'Last login', render: (m: any) => rel(m.last_login_at) },
      { label: '', render: (m: any) => isAdmin && m.id !== me.identity?.id ? <><button className="btn sm" onClick={() => act(() => patch(`/api/org/members/${m.id}`, { disabled: !m.disabled }), 'Updated; sessions revoked').then(s.reload)}>{m.disabled ? 'Enable' : 'Disable'}</button> <button className="btn sm danger" onClick={() => confirm('Remove this member? Their sessions end now.', () => act(() => api('DELETE', `/api/org/members/${m.id}`), 'Removed').then(s.reload), true)}>Remove</button></> : null }]} />}</Load></>;
}

export function Invitations() {
  const { act } = useUi(); const s = useLoad(() => Promise.all([get('/api/org/invitations'), get<Project[]>('/api/projects')]), []);
  return <><PageHead title="Invitations" sub="Default onboarding policy: invitation only. Successful SSO alone grants no project access." /><Tabs items={ADT} />
    <Load s={s}>{([inv, projects]) => <div className="grid g21"><Table rows={inv} empty="No invitations." cols={[{ label: 'Email', render: (i: any) => i.email }, { label: 'Org role', render: (i: any) => i.org_role }, { label: 'Projects', render: (i: any) => (i.project_roles || []).map((p: any) => `${projects.find(x => x.id === p.project_id)?.key || p.project_id}:${p.role}`).join(', ') }, { label: 'Status', render: (i: any) => i.accepted_at ? <Badge v="accepted" cls="green" /> : new Date(i.expires_at) < new Date() ? <Badge v="expired" /> : <Badge v="pending" cls="orange" /> }]} />
      <form className="card form" onSubmit={onSubmit(async d => { await act(() => post('/api/org/invitations', { email: d.email, org_role: d.org_role, project_roles: d.project_id ? [{ project_id: d.project_id, role: d.role }] : [] }), 'Invitation created'); s.reload(); })}><h2>Invite</h2>
        <label className="f">Email<input className="i" name="email" type="email" required /></label><label className="f">Org role<select className="i" name="org_role">{ORG_ROLES.map(r => <option key={r}>{r}</option>)}</select></label>
        <label className="f">Project<select className="i" name="project_id"><option value="">—</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label><label className="f">Project role<select className="i" name="role">{PROJECT_ROLES.map(r => <option key={r}>{r}</option>)}</select></label>
        <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Invite</button></div></form></div>}</Load></>;
}

export function Mappings() {
  const { act } = useUi(); const s = useLoad(() => Promise.all([get('/api/org/role-mappings'), get<Project[]>('/api/projects')]), []);
  return <><PageHead title="Keycloak group & role mapping" sub="Map Keycloak groups or client roles to organization and project roles. Shared realm, application-managed membership." /><Tabs items={ADT} />
    <Load s={s}>{([maps, projects]) => <div className="grid g21"><Table rows={maps} empty="No mappings." cols={[{ label: 'Claim', render: (m: any) => m.claim }, { label: 'Value', render: (m: any) => <code>{m.value}</code> }, { label: 'Org role', render: (m: any) => m.org_role || '—' }, { label: 'Project role', render: (m: any) => m.project_id ? `${projects.find(p => p.id === m.project_id)?.key || m.project_id}: ${m.project_role}` : '—' }, { label: '', render: (m: any) => <button className="btn sm danger" onClick={() => act(() => api('DELETE', `/api/org/role-mappings/${m.id}`), 'Deleted').then(s.reload)}>Delete</button> }]} />
      <form className="card form" onSubmit={onSubmit(async d => { await act(() => post('/api/org/role-mappings', Object.fromEntries(Object.entries(d).filter(([, v]) => v))), 'Mapping added'); s.reload(); })}><h2>New mapping</h2>
        <label className="f">Claim<select className="i" name="claim"><option value="groups">groups</option><option value="client_roles">client_roles</option></select></label><label className="f">Value<input className="i" name="value" required placeholder="sentra-security" /></label>
        <label className="f">Org role<select className="i" name="org_role"><option value="">—</option>{ORG_ROLES.map(r => <option key={r}>{r}</option>)}</select></label>
        <label className="f">Project<select className="i" name="project_id"><option value="">—</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label><label className="f">Project role<select className="i" name="project_role"><option value="">—</option>{PROJECT_ROLES.map(r => <option key={r}>{r}</option>)}</select></label>
        <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Add</button></div></form></div>}</Load></>;
}

export function Secrets() {
  const { act } = useUi(); const s = useLoad(() => get('/api/org/secrets'), []);
  return <><PageHead title="Secret references" sub="Credentials are sealed with AES-256-GCM using the server master key. Values are never returned, logged, exported or sent to models." /><Tabs items={ADT} />
    <div className="grid g21"><Load s={s}>{xs => <Table rows={xs} empty="No secrets." cols={[{ label: 'Name', render: (x: any) => x.name }, { label: 'Fingerprint', render: (x: any) => <code>{x.fingerprint}</code> }, { label: 'Created', render: (x: any) => fmtDate(x.created_at) }, { label: 'Rotated', render: (x: any) => x.rotated_at ? fmtDate(x.rotated_at) : '—' }]} />}</Load>
      <form className="card form" onSubmit={onSubmit(async (d, f) => { await act(() => post('/api/org/secrets', d), 'Saved'); f.reset(); s.reload(); })}><h2>Create or rotate</h2><label className="f">Name<input className="i" name="name" required /></label><label className="f">Value<input className="i" name="value" type="password" required autoComplete="off" /></label><div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Save</button></div></form></div></>;
}

export function Settings() {
  const { act } = useUi(); const s = useLoad(() => get('/api/org'), []);
  return <><PageHead title="Organization settings" sub="Onboarding policy, defaults and retention (enforced daily; findings and evidence are never purged)." /><Tabs items={ADT} />
    <Load s={s}>{org => <form className="card form two" style={{ maxWidth: 720 }} onSubmit={onSubmit(d => act(() => patch('/api/org/settings', d), 'Saved'))}>
      <label className="f">Onboarding policy<select className="i" name="onboarding_policy" defaultValue={org.settings.onboarding_policy}><option value="invite_only">Invitation only</option><option value="group_mapping_only">Keycloak group mapping only</option></select></label>
      <label className="f">Default timezone<input className="i" name="default_timezone" defaultValue={org.settings.default_timezone || 'Asia/Ho_Chi_Minh'} /></label>
      <label className="f">Report language<select className="i" name="report_language" defaultValue={org.settings.report_language === 'en' ? 'en' : 'vi'}><option value="vi">Vietnamese</option><option value="en">English</option></select></label>
      <label className="f">Retention (days, min 30)<input className="i" type="number" name="retention_days" defaultValue={org.settings.retention_days || 730} /></label>
      <div className="full row" style={{ justifyContent: 'flex-end' }}><button className="btn primary">Save</button></div></form>}</Load></>;
}

export function Audit() {
  const q = useQuery(); const nav = useNavigate();
  const s = useLoad(() => Promise.all([get('/api/org/audit' + qs({ action: q.action, target: q.target, before: q.before })), get('/api/org/audit/verify')]), [q.action, q.target, q.before]);
  return <><PageHead title="Audit trail" sub="Append-only, hash-chained events for logins, access changes, data changes, agent decisions, exports and deliveries." />
    <SavedViews page="audit" query={q} base="/audit" />
    <Load s={s}>{([r, v]) => <>
      <div className={`notice ${v.ok ? 'ok' : 'err'}`} style={{ marginBottom: 12 }}>Hash chain {v.ok ? 'verified' : 'BROKEN at sequence ' + v.broken_at} across {v.checked} events{v.anchored_at_seq ? ` (continuing from archived period ending at #${v.anchored_at_seq})` : ''}.</div>
      <form className="row" style={{ marginBottom: 12 }} onSubmit={onSubmit(d => nav('/audit' + qs(d)))}><input className="i" name="action" placeholder="action prefix, e.g. finding." defaultValue={q.action} style={{ maxWidth: 240 }} /><input className="i" name="target" placeholder="target or project id" defaultValue={q.target} style={{ maxWidth: 240 }} /><button className="btn">Filter</button></form>
      <Table rows={r.items.map((e: any) => ({ ...e, id: String(e.seq) }))} cols={[{ label: '#', render: (e: any) => e.seq }, { label: 'When', render: (e: any) => fmtDate(e.created_at) }, { label: 'Actor', render: (e: any) => <>{e.actor_name || e.actor_id || 'system'}<br /><small>{e.actor_type}</small></> }, { label: 'Action', render: (e: any) => <code>{e.action}</code> }, { label: 'Target', render: (e: any) => <>{e.target_type}<br /><small className="mono">{e.target_id}</small></> }, { label: 'Data', render: (e: any) => <small className="mono">{JSON.stringify(e.data).slice(0, 160)}</small> }, { label: 'Hash', render: (e: any) => <small className="mono">{e.hash.slice(0, 10)}</small> }]} />
      {r.next_before && <div className="row" style={{ justifyContent: 'flex-end', marginTop: 10 }}><button className="btn sm" onClick={() => nav('/audit' + qs({ ...q, before: r.next_before }))}>Older</button></div>}</>}</Load></>;
}

/** Minimal Markdown → React (headings, lists, tables, bold, code, links). Produces elements, never raw HTML. */
function inline(s: string): ReactNode[] {
  const out: ReactNode[] = []; const re = /\*\*(.+?)\*\*|`([^`]+)`|\[([^\]]+)\]\((https?:[^)]+)\)/g; let last = 0; let m: RegExpExecArray | null; let k = 0;
  while ((m = re.exec(s))) { if (m.index > last) out.push(s.slice(last, m.index)); if (m[1]) out.push(<b key={k++}>{m[1]}</b>); else if (m[2]) out.push(<code key={k++}>{m[2]}</code>); else out.push(<a key={k++} href={safeHref(m[4])} target="_blank" rel="noopener noreferrer">{m[3]}</a>); last = re.lastIndex; }
  if (last < s.length) out.push(s.slice(last)); return out;
}
export function Markdown({ md, filter = '' }: { md: string; filter?: string }) {
  const blocks: ReactNode[] = []; const lines = md.split('\n'); let i = 0; let k = 0; const f = filter.toLowerCase();
  const keep = (text: string) => !f || text.toLowerCase().includes(f);
  while (i < lines.length) {
    const l = lines[i];
    if (/^\|/.test(l)) { const rows: string[][] = []; while (i < lines.length && /^\|/.test(lines[i])) { if (!/^\|[\s:|-]+\|$/.test(lines[i])) rows.push(lines[i].split('|').slice(1, -1).map(c => c.trim())); i++; } if (rows.some(r => keep(r.join(' ')))) blocks.push(<div key={k++} className="tablewrap"><table><tbody>{rows.filter(r => keep(r.join(' ')) || rows.indexOf(r) === 0).map((r, ri) => <tr key={ri}>{r.map((c, ci) => <td key={ci}>{inline(c)}</td>)}</tr>)}</tbody></table></div>); continue; }
    if (/^\s*([-*]|\d+\.) /.test(l)) { const items: string[] = []; while (i < lines.length && /^\s*([-*]|\d+\.) /.test(lines[i])) items.push(lines[i++].replace(/^\s*([-*]|\d+\.) /, '')); const kept = items.filter(keep); if (kept.length) blocks.push(<ul key={k++}>{kept.map((t, ti) => <li key={ti}>{inline(t)}</li>)}</ul>); continue; }
    const h = /^(#{1,4}) (.*)/.exec(l);
    if (h) { const Tag = (['h1', 'h2', 'h3', 'h4'] as const)[h[1].length - 1]; blocks.push(<Tag key={k++}>{inline(h[2])}</Tag>); }
    else if (l.trim() && keep(l)) blocks.push(<p key={k++}>{inline(l)}</p>);
    i++;
  }
  return <>{blocks}</>;
}
export function Requirements() {
  const [f, setF] = useState('');
  const s = useLoad(async () => Promise.all([fetch('/product-requirements.md').then(r => r.text()), fetch('/feature-matrix.md').then(r => (r.ok ? r.text() : ''))]), []);
  return <><PageHead title="Product requirements" sub="The authoritative 32-section specification and the live feature matrix (Implemented / Tested / Connected / Production validated)."><input className="i" placeholder="Search requirements" style={{ maxWidth: 260 }} value={f} onChange={e => setF(e.target.value)} /><a className="btn" href="/product-requirements.md" download>Download</a></PageHead>
    <Load s={s}>{([md, matrix]) => <div className="grid g21"><div className="card md"><Markdown md={md} filter={f} /></div><div className="card md"><Markdown md={matrix} /></div></div>}</Load></>;
}
