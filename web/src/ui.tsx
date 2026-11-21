import { createContext, useCallback, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ApiError, api, get, post, qs } from './api';

// ---------------------------------------------------------------- formatting
export const fmtDate = (d?: string | null) => (d ? new Date(d).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');
export const fmtDay = (d?: string | null) => (d ? new Date(d).toLocaleDateString(undefined, { dateStyle: 'medium' }) : '—');
export function rel(d?: string | null): string {
  if (!d) return '—';
  const s = (Date.now() - new Date(d).getTime()) / 1000, a = Math.abs(s);
  const f = a < 60 ? `${Math.round(a)}s` : a < 3600 ? `${Math.round(a / 60)}m` : a < 86400 ? `${Math.round(a / 3600)}h` : `${Math.round(a / 86400)}d`;
  return s >= 0 ? `${f} ago` : `in ${f}`;
}
export const label = (s?: string | null) => String(s ?? '').replace(/_/g, ' ');
export const shortDigest = (d?: string | null) => (d ? d.replace(/^sha256:/, '').slice(0, 12) : '—');
export const pct = (x?: number | null) => (x == null ? '—' : `${Math.round(x * 100)}%`);
/** Only http(s) links from data become links; anything else (javascript:, data:) is inert. */
export const safeHref = (u?: string | null) => (/^https?:\/\//i.test(String(u || '')) ? String(u) : '#');

// ---------------------------------------------------------------- small components
export function Badge({ v, cls }: { v?: string | null; cls?: string }) { return v ? <span className={`b ${cls ?? v}`}>{label(v)}</span> : null; }
export const Synth = ({ on }: { on?: boolean }) => (on ? <span className="b synthetic" title="Synthetic demonstration data">synthetic</span> : null);
const PATHS: Record<string, string> = { grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z', shield: 'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z', folder: 'M3 7h7l2-3h8v15H3z', flag: 'M5 22V3h13l-3 5 3 5H5', spark: 'M12 3l2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5z', box: 'M12 3l9 5-9 5-9-5zM3 8v9l9 5 9-5V8M12 13v9', git: 'M6 3v12a4 4 0 0 0 4 4h8M18 5v5a4 4 0 0 1-4 4H6', check: 'M5 12l4 4L19 6', bell: 'M6 9a6 6 0 0 1 12 0v6l2 3H4l2-3zM10 21h4', chart: 'M4 21V10h4v11M10 21V3h4v18M16 21V7h4v14', globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M3 12h18M12 3c-5 5-5 13 0 18 5-5 5-13 0-18', plug: 'M8 3v5M16 3v5M5 8h14v4a7 7 0 0 1-14 0zM12 19v3', search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM16 16l5 5', code: 'M8 6l-6 6 6 6M16 6l6 6-6 6', activity: 'M3 12h4l3-8 4 16 3-8h4', lock: 'M6 10h12v11H6zM8 10V6a4 4 0 0 1 8 0v4', sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M12 1v3M12 20v3M1 12h3M20 12h3', book: 'M4 4h7a3 3 0 0 1 3 3v14a2 2 0 0 0-2-2H4zM20 4h-7a3 3 0 0 0-3 3', layers: 'M12 3l9 5-9 5-9-5zM3 13l9 5 9-5', users: 'M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8M2 21v-3c0-5 12-5 12 0v3M16 4c5 0 5 7 0 7M17 15c4 0 5 2 5 6', file: 'M5 3h9l5 5v13H5zM14 3v6h5' };
export function Icon({ n, s = 17 }: { n: string; s?: number }) {
  return <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={PATHS[n] ?? PATHS.box} /></svg>;
}
export const Loading = ({ n = 5 }: { n?: number }) => <div aria-busy="true" aria-label="Loading">{Array.from({ length: n }, (_, i) => <div key={i} className="skeleton" />)}</div>;
export const Empty = ({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) => <div className="state"><h3>{title}</h3>{children && <p>{children}</p>}{action && <div style={{ marginTop: 12 }}>{action}</div>}</div>;
export function ErrorState({ error }: { error: unknown }) {
  const e = error as ApiError;
  if (e?.status === 403 || e?.code === 'NO_ACCESS') return <div className="state denied" role="alert"><h3>Permission denied</h3><p>{e.message}</p></div>;
  if (e?.status === 404) return <div className="state denied" role="alert"><h3>Not found or not accessible</h3><p>{e.message}</p></div>;
  if (e?.status === 503) return <div className="state error" role="alert"><h3>Dependency unavailable</h3><p>{e.message}</p></div>;
  return <div className="state error" role="alert"><h3>Something went wrong</h3><p>{(e as Error)?.message ?? String(error)}</p></div>;
}
export function PageHead({ title, sub, children }: { title: ReactNode; sub?: ReactNode; children?: ReactNode }) {
  return <div className="pagehead"><div className="grow"><h1>{title}</h1>{sub && <p>{sub}</p>}</div>{children}</div>;
}
export function Tabs({ items }: { items: [string, string][] }) {
  const loc = useLocation(); const cur = loc.pathname + loc.search;
  return <nav className="tabs" role="tablist">{items.map(([to, t]) => { const active = cur === to || loc.pathname === to; return <Link key={to} to={to} role="tab" aria-selected={active} className={active ? 'active' : ''}>{t}</Link>; })}</nav>;
}

export interface Col<T> { label: string; render: (r: T) => ReactNode }
export function Table<T extends { id?: string }>({ cols, rows, onRow, empty = 'No records.' }: { cols: Col<T>[]; rows: T[] | null | undefined; onRow?: (r: T) => string; empty?: ReactNode }) {
  const nav = useNavigate();
  if (!rows?.length) return <Empty title={typeof empty === 'string' ? empty : 'No records.'}>{typeof empty === 'string' ? null : empty}</Empty>;
  return <div className="tablewrap"><table><thead><tr>{cols.map(c => <th key={c.label} scope="col">{c.label}</th>)}</tr></thead>
    <tbody>{rows.map((r, i) => <tr key={r.id ?? i} className={onRow ? 'clickable' : ''} tabIndex={onRow ? 0 : undefined}
      onClick={onRow ? (e) => { if ((e.target as HTMLElement).closest('a,button,input,select,label')) return; nav(onRow(r)); } : undefined}
      onKeyDown={onRow ? (e) => { if (e.key === 'Enter') nav(onRow(r)); } : undefined}>{cols.map(c => <td key={c.label}>{c.render(r)}</td>)}</tr>)}</tbody></table></div>;
}
export function Pager({ total, limit, offset }: { total: number; limit: number; offset: number }) {
  const loc = useLocation(); const q = Object.fromEntries(new URLSearchParams(loc.search));
  if (total <= limit) return null;
  return <div className="row" style={{ justifyContent: 'flex-end', marginTop: 12 }}><span className="muted">{offset + 1}–{Math.min(total, offset + limit)} of {total}</span>
    {offset > 0 && <Link className="btn sm" to={loc.pathname + qs({ ...q, offset: Math.max(0, offset - limit) })}>Previous</Link>}
    {offset + limit < total && <Link className="btn sm" to={loc.pathname + qs({ ...q, offset: offset + limit })}>Next</Link>}</div>;
}

// ---------------------------------------------------------------- data loading
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [state, set] = useState<{ data: T | null; error: unknown; loading: boolean }>({ data: null, error: null, loading: true });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    set(s => ({ ...s, loading: true, error: null }));
    fn().then(data => live && set({ data, error: null, loading: false }), error => live && set({ data: null, error, loading: false }));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { ...state, reload: useCallback(() => setTick(t => t + 1), []) };
}
/** Renders loading/error states, then children with loaded data. */
export function Load<T>({ s, children }: { s: { data: T | null; error: unknown; loading: boolean }; children: (d: T) => ReactNode }) {
  if (s.error) return (s.error as ApiError).status === 401 ? null : <ErrorState error={s.error} />;
  if (s.loading && !s.data) return <Loading />;
  return <>{children(s.data as T)}</>;
}
export function useQuery() { const loc = useLocation(); return Object.fromEntries(new URLSearchParams(loc.search)) as Record<string, string>; }

// ---------------------------------------------------------------- forms
export function formObj(form: HTMLFormElement): Record<string, any> {
  const o: Record<string, any> = {};
  for (const node of Array.from(form.elements)) {
    const el = node as HTMLInputElement; const type: string = el.type;
    if (!el.name || el.disabled) continue;
    if (type === 'checkbox') { if (el.dataset.multi) { (o[el.name] ||= []); if (el.checked) o[el.name].push(el.value); } else o[el.name] = el.checked; }
    else if (type === 'number') o[el.name] = el.value === '' ? undefined : Number(el.value);
    else if (node instanceof HTMLSelectElement && node.multiple) o[el.name] = Array.from(node.selectedOptions).map(x => x.value);
    else if (type !== 'file' && type !== 'submit' && type !== 'button') o[el.name] = el.value;
  }
  return o;
}
export const onSubmit = (fn: (d: Record<string, any>, form: HTMLFormElement) => unknown) => (e: FormEvent<HTMLFormElement>) => { e.preventDefault(); fn(formObj(e.currentTarget), e.currentTarget); };

// ---------------------------------------------------------------- toasts, modals, actions
interface Toast { id: number; msg: string; err: boolean }
interface UiCtx { toast: (m: string, err?: boolean) => void; modal: (node: (close: () => void) => ReactNode) => void; act: <T>(fn: () => Promise<T>, ok?: string) => Promise<T> }
const Ctx = createContext<UiCtx>(null as unknown as UiCtx);
export const useUi = () => useContext(Ctx);
export function UiProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [modals, setModals] = useState<{ id: number; render: (close: () => void) => ReactNode }[]>([]);
  const seq = useRef(0);
  const toast = useCallback((msg: string, err = false) => { const id = ++seq.current; setToasts(t => [...t, { id, msg, err }]); setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), err ? 7000 : 3500); }, []);
  const modal = useCallback((render: (close: () => void) => ReactNode) => { const id = ++seq.current; setModals(m => [...m, { id, render }]); }, []);
  const act = useCallback(async <T,>(fn: () => Promise<T>, ok?: string) => { try { const r = await fn(); if (ok) toast(ok); return r; } catch (e) { toast((e as Error).message, true); throw e; } }, [toast]);
  return <Ctx.Provider value={{ toast, modal, act }}>{children}
    {modals.map(m => { const close = () => setModals(x => x.filter(y => y.id !== m.id)); return <div key={m.id} className="modal-bg" onClick={(e) => { if (e.target === e.currentTarget) close(); }}><div className="modal" role="dialog" aria-modal="true">{m.render(close)}</div></div>; })}
    <div id="toast" role="status" aria-live="polite">{toasts.map(t => <div key={t.id} className={t.err ? 'err' : ''}>{t.msg}</div>)}</div>
  </Ctx.Provider>;
}
export function ConfirmModal({ message, danger, onConfirm, close }: { message: string; danger?: boolean; onConfirm: () => void; close: () => void }) {
  return <><h2>Confirm</h2><p style={{ margin: '10px 0 14px' }}>{message}</p><div className="row" style={{ justifyContent: 'flex-end' }}><button className="btn" onClick={close}>Cancel</button><button className={`btn ${danger ? 'danger' : 'primary'}`} onClick={() => { close(); onConfirm(); }}>Confirm</button></div></>;
}
export function useConfirm() { const { modal } = useUi(); return (message: string, onConfirm: () => void, danger = false) => modal(close => <ConfirmModal message={message} danger={danger} onConfirm={onConfirm} close={close} />); }

// ---------------------------------------------------------------- saved views
export function SavedViews({ page, query, base }: { page: string; query: Record<string, string>; base: string }) {
  const { act, modal } = useUi();
  const s = useLoad(() => get<{ id: string; name: string; query: Record<string, string> }[]>('/api/me/views' + qs({ page })), [page]);
  return <div className="row" style={{ marginBottom: 10 }}>
    {(s.data || []).map(v => <span key={v.id} className="row" style={{ gap: 2 }}><Link className="b blue" to={base + qs(v.query)}>{v.name}</Link><button className="btn sm ghost" aria-label={`Delete view ${v.name}`} onClick={() => act(() => api('DELETE', `/api/me/views/${v.id}`), 'View deleted').then(s.reload)}>×</button></span>)}
    <button className="btn sm" onClick={() => modal(close => <form onSubmit={onSubmit(async d => { await act(() => post('/api/me/views', { page, name: d.name || 'View', query }), 'View saved'); close(); s.reload(); })}><h2>Save view</h2><input className="i" name="name" placeholder="Name" autoFocus /><div className="row" style={{ justifyContent: 'flex-end', marginTop: 12 }}><button type="button" className="btn" onClick={close}>Cancel</button><button className="btn primary">Save</button></div></form>)}>Save current view</button>
  </div>;
}
export const PRIORITY = ({ p }: { p?: string }) => <Badge v={p} cls={p} />;
