// Typed API client. The session lives in an HttpOnly cookie; mutations carry the CSRF token from /api/me.
export class ApiError extends Error {
  constructor(public status: number, public code: string | undefined, message: string, public details?: unknown) { super(message); }
}

let csrf = '';
export const setCsrf = (t: string) => { csrf = t; };
type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export async function api<T = any>(method: Method, path: string, body?: unknown, opts: { allow401?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
  const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
  const text = await res.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { message: text }; }
  if (res.status === 401 && !opts.allow401) {
    if (!location.hash.startsWith('#/login')) location.hash = '#/login?return=' + encodeURIComponent(location.hash.slice(1) || '/');
    throw new ApiError(401, data?.error, data?.message || 'Sign in required.');
  }
  if (!res.ok) throw new ApiError(res.status, data?.error, data?.message || `Request failed (${res.status})`, data?.details);
  return data as T;
}
export const get = <T = any>(p: string) => api<T>('GET', p);
export const post = <T = any>(p: string, b: unknown = {}) => api<T>('POST', p, b);
export const put = <T = any>(p: string, b: unknown = {}) => api<T>('PUT', p, b);
export const patch = <T = any>(p: string, b: unknown = {}) => api<T>('PATCH', p, b);
export const del = <T = any>(p: string) => api<T>('DELETE', p);
export function qs(o: Record<string, unknown> = {}): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  const s = p.toString(); return s ? '?' + s : '';
}

// ---------------------------------------------------------------- domain types (subset used by the UI)
export type Priority = 'P0' | 'P1' | 'P2' | 'P3' | 'P4';
export interface Me {
  identity: { id: string; display_name: string; email?: string } | null;
  auth_method: 'keycloak' | 'dev';
  csrf_token: string;
  organization: { id: string; slug: string; name: string; role: string } | null;
  project_roles: Record<string, string>;
  org_permissions: string[];
  unread_notifications: number;
}
export interface Env { id: string; key: string; is_production: boolean; exposure?: string; timezone?: string }
export interface Project {
  id: string; key: string; name: string; description?: string; criticality: string; exposure: string; data_classification: string;
  tags: string[]; archived_at?: string | null; owner_name?: string; my_role?: string; ecosystems?: string[] | null; environments?: Env[] | null;
  open_findings?: number; urgent_findings?: number; last_inventory_at?: string | null;
}
export interface ProjectDetail extends Project {
  owner: { id: string; display_name: string } | null;
  services: { id: string; key: string; name: string; team?: string }[];
  environments: Env[];
  deployments: { id: string; service: string; environment: string; digest: string; version?: string; deployed_at: string }[];
  connections: { id: string; name: string; kind: string; status: string }[];
  members: { identity_id: string; role: string; display_name: string; email?: string }[];
  finding_counts: { open: number; urgent: number; verified: number };
  onboarding_steps: { step: string; done: boolean; at: string | null }[];
  protected_note: string;
  my_permissions: string[];
}
export interface FindingRow {
  id: string; project_id: string; project_key: string; advisory_id: string; advisory_title?: string; is_synthetic: boolean; package: string; ecosystem: string;
  observed_version?: string; fixed_version?: string; severity: string; applicability: string; exploitation: string; priority: Priority; status: string;
  verification_status: string; environment?: string; is_production?: boolean; service?: string; sla_due_at?: string; owner?: string;
}
export interface Paged<T> { total: number; limit: number; offset: number; items: T[] }
export interface Evidence { id: string; kind: string; stance: 'supporting' | 'counter' | 'missing' | 'neutral'; summary: string; source_ref?: string; data?: any }
export interface FindingDetail extends FindingRow {
  purl: string; cvss_vector?: string; cvss_score?: number; advisory_revision: number; applicability_justification?: string; last_evaluated_at: string; last_evaluation_reason?: string;
  digest?: string; commit_sha?: string; deployed_at?: string; asset_id?: string; team?: string; priority_explanation: { factor: string; value: string; points: number; note?: string }[];
  priority_policy_version: number; evidence: Evidence[]; events: any[]; tickets: any[]; pull_requests: any[]; exceptions: any[]; signals: any[]; related: any[];
  investigations: any[]; references_json: { type?: string; url: string }[]; permissions: string[]; allowed_transitions: string[]; timezone?: string; first_seen_at: string;
}
export interface Investigation {
  id: string; workflow: string; state: string; question?: string; provider: string; model: string; prompt_version: string; policy_version: string; tool_version: string;
  inputs: any; scope: { project_ids: string[] }; result: any; error?: string; usage: any; cost_usd: number; started_at?: string; finished_at?: string;
  reviewer_feedback: any[]; tool_executions: { seq: number; tool: string; output_summary: string; status: string; duration_ms: number }[]; note: string;
}
