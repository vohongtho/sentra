import { api, post, setCsrf } from '../api';
import { Badge, Icon, label, Load, useLoad, useQuery } from '../ui';

interface Status { mode: string; keycloak_configured: boolean; dev_mode_warning: string | null }
interface DevIdentity { id: string; display_name: string; email: string; org_role: string; projects: { project: string; role: string }[] | null }

export function Login() {
  const q = useQuery(); const ret = q.return || '/';
  const s = useLoad(async () => {
    const st = await api<Status>('GET', '/api/auth/status', undefined, { allow401: true });
    const ids = st.mode === 'dev' ? (await api<{ identities: DevIdentity[] }>('GET', '/api/auth/dev/identities', undefined, { allow401: true })).identities : [];
    return { st, ids };
  }, []);
  const devLogin = async (id: string) => { const r = await post<{ csrf_token: string }>('/api/auth/dev/login', { identity_id: id }); setCsrf(r.csrf_token); location.hash = '#' + ret; location.reload(); };
  return <div className="login"><div className="card">
    <div className="row" style={{ marginBottom: 14 }}><Icon n="shield" s={34} /><div><h1 style={{ fontSize: 26 }}>sentra</h1><small className="muted">Security Intelligence &amp; Alarm Platform</small></div></div>
    <Load s={s}>{({ st, ids }) => <>
      {st.keycloak_configured
        ? <><a className="btn primary" style={{ width: '100%', justifyContent: 'center', padding: 11 }} href={`/api/auth/login?return_to=${encodeURIComponent(ret)}`}><Icon n="lock" s={15} /> Sign in with Keycloak</a><p className="muted" style={{ marginTop: 8, fontSize: 12.5 }}>Single sign-on through your organization's Keycloak realm (Authorization Code + PKCE). Sentra keeps tokens server-side.</p></>
        : <div className="notice warn">Keycloak is not configured on this server (KEYCLOAK_ISSUER / KEYCLOAK_CLIENT_ID).</div>}
      {st.mode === 'dev' && <div style={{ marginTop: 20 }}><div className="notice warn" style={{ marginBottom: 10 }}>{st.dev_mode_warning}</div>
        <div className="col">{ids.map(i => <button key={i.id} className="btn" data-dev={i.id} style={{ justifyContent: 'space-between' }} onClick={() => devLogin(i.id)}>
          <span><b>{i.display_name}</b> <small className="muted">{i.email}</small></span>
          <span className="pill-row"><Badge v={i.org_role} cls="blue" />{(i.projects || []).map(p => <span key={p.project} className="b">{p.project}: {label(p.role)}</span>)}</span></button>)}</div></div>}
    </>}</Load>
  </div></div>;
}
