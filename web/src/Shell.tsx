import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { api, get, post, qs, setCsrf, type Me } from './api';
import { Icon, label, Loading, useUi, ErrorState } from './ui';
import { CopilotDrawer } from './pages/ai';

const MeCtx = createContext<{ me: Me; refresh: () => Promise<void> }>(null as unknown as { me: Me; refresh: () => Promise<void> });
export const useMe = () => useContext(MeCtx);
export const can = (me: Me, perm: string) => me.org_permissions.includes(perm);

const NAV: [string, [string, string, string][]][] = [
  ['Workspace', [['/', 'Overview', 'grid'], ['/projects', 'Projects', 'folder'], ['/findings', 'Findings', 'flag'], ['/advisories', 'Advisories', 'shield'], ['/investigations', 'AI investigations', 'spark'], ['/analysis', 'Live AI analysis', 'file'], ['/assets', 'Assets & inventory', 'box']]],
  ['Operations', [['/drift', 'Deployment drift', 'git'], ['/campaigns', 'Remediation', 'check'], ['/automation', 'Automation center', 'activity'], ['/reports', 'Reports', 'chart']]],
  ['Manage', [['/coverage', 'Coverage', 'globe'], ['/integrations', 'Integrations', 'plug'], ['/ci', 'CI/CD setup', 'code'], ['/agents', 'AI agents', 'layers'], ['/admin', 'SSO & access', 'users'], ['/audit', 'Audit', 'lock'], ['/requirements', 'Requirements', 'book']]],
];

export function Session({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null); const [err, setErr] = useState<unknown>(null);
  const refresh = async () => { try { const m = await api<Me>('GET', '/api/me'); setCsrf(m.csrf_token); setMe(m); } catch (e) { setErr(e); } };
  useEffect(() => { refresh(); }, []);
  if (err && (err as { status?: number }).status !== 401) return <div className="content"><ErrorState error={err} /></div>;
  if (!me) return <div className="content"><Loading /></div>;
  return <MeCtx.Provider value={{ me, refresh }}>{children}</MeCtx.Provider>;
}

export function Shell({ children }: { children: ReactNode }) {
  const { me } = useMe(); const { modal } = useUi(); const nav = useNavigate(); const loc = useLocation();
  const [copilot, setCopilot] = useState(false); const [count, setCount] = useState<number | null>(null);
  const initials = (me.identity?.display_name || '?').split(/\s+/).map(s => s[0]).join('').slice(0, 2).toUpperCase();
  useEffect(() => { get('/api/findings?limit=1').then(r => setCount(r.total)).catch(() => {}); }, [loc.pathname]);
  if (!me.organization) return <div className="content"><div className="state denied"><h3>No organization access</h3><p>You are signed in as {me.identity?.email || me.identity?.display_name}, but you have no organization membership. Ask an administrator for an invitation. Signing in does not grant access to projects automatically.</p></div></div>;
  const logout = async () => { const r = await post('/api/auth/logout'); if (r.end_session_url) location.href = r.end_session_url; else { location.hash = '#/login'; location.reload(); } };
  return <>
    {me.auth_method === 'dev' && <div className="devbanner" role="note">Development identity mode — signed in without Keycloak. Never enable AUTH_MODE=dev in production.</div>}
    <div className="shell">
      <nav className="sidebar" aria-label="Primary">
        <Link className="brand" to="/"><Icon n="shield" s={30} /><span><b>sentra</b><small>SECURITY INTELLIGENCE</small></span></Link>
        <div className="orgbox"><span className="sq">{me.organization.name[0]}</span><span><div>{me.organization.name}</div><small>{label(me.organization.role)}</small></span></div>
        {NAV.map(([g, items]) => <div key={g}><div className="navgroup">{g}</div>{items.map(([to, t, i]) =>
          <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => 'navlink' + (isActive ? ' active' : '')}><Icon n={i} /><span>{t}</span>{to === '/findings' && count != null && <span className="count">{count}</span>}</NavLink>)}</div>)}
        <div className="foot">Data-backed workspace. Synthetic demo records are labeled <span className="b synthetic">synthetic</span>.</div>
      </nav>
      <div className="main">
        <header className="topbar">
          <div className="crumbs">{me.organization.name}</div>
          <GlobalSearch />
          <div className="spacer" />
          <button className="btn" onClick={() => setCopilot(true)}><Icon n="spark" s={15} /> Ask Copilot</button>
          <Link className="btn ghost" to="/notifications" aria-label="Notifications"><Icon n="bell" />{me.unread_notifications > 0 && <span className="b">{me.unread_notifications}</span>}</Link>
          <button className="btn ghost" aria-label="Toggle theme" onClick={() => { document.documentElement.classList.toggle('light'); localStorage.setItem('sentra-theme', document.documentElement.classList.contains('light') ? 'light' : 'dark'); }}><Icon n="sun" /></button>
          <button className="avatar" title={me.identity?.display_name} aria-label="Account menu" onClick={() => modal(close => <>
            <h2>{me.identity?.display_name}</h2><p className="muted">{me.identity?.email} · {label(me.organization?.role)} · signed in via {me.auth_method}</p>
            <div style={{ margin: '14px 0' }}><b>Project roles</b><div className="pill-row" style={{ marginTop: 6 }}>{Object.entries(me.project_roles).map(([p, r]) => <span key={p} className="b">{p.replace('prj_', '')}: {label(r)}</span>)}{!Object.keys(me.project_roles).length && 'Organization-wide role only'}</div></div>
            <div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn" onClick={close}>Close</button><button className="btn danger" onClick={logout}>Sign out</button></div></>)}>{initials}</button>
        </header>
        <main className="content" id="content" tabIndex={-1}>{children}</main>
      </div>
    </div>
    {copilot && <CopilotDrawer onClose={() => setCopilot(false)} onOpen={(id) => { setCopilot(false); nav(`/investigations/${id}`); }} />}
  </>;
}

function GlobalSearch() {
  const [q, setQ] = useState(''); const [res, setRes] = useState<[string, string][] | null>(null);
  useEffect(() => {
    if (q.trim().length < 2) { setRes(null); return; }
    const t = setTimeout(async () => {
      const r = await get('/api/search' + qs({ q }));
      setRes([...r.projects.map((p: any) => [`/projects/${p.id}`, `Project · ${p.name}`]), ...r.findings.map((f: any) => [`/findings/${f.id}`, `Finding · ${f.advisory_id} · ${f.package} (${f.project})`]), ...r.advisories.map((a: any) => [`/advisories/${encodeURIComponent(a.id)}`, `Advisory · ${a.id} ${a.title || ''}`]), ...r.components.map((c: any) => [`/components/${c.id}`, `Package · ${c.name}@${c.version || '?'}`])]);
    }, 220);
    return () => clearTimeout(t);
  }, [q]);
  return <div className="search"><Icon n="search" s={15} /><input value={q} onChange={e => setQ(e.target.value)} onBlur={() => setTimeout(() => setRes(null), 200)} placeholder="Search projects, findings, advisories, packages…" aria-label="Global search" autoComplete="off" />
    {res && <div className="results">{res.length ? res.map(([h, l]) => <Link key={h} to={h} onClick={() => setQ('')}>{l}</Link>) : <div className="muted" style={{ padding: 8 }}>No matches in your scope.</div>}</div>}</div>;
}
