// Deterministic, versioned priority + SLA + lifecycle policy. No AI involvement.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none', 'unknown'];
export const APPLICABILITY = ['affected', 'not_affected', 'under_investigation', 'unknown'];
export const EXPLOITATION = ['none_known', 'poc_public', 'kev_listed', 'actively_exploited', 'observed_in_env'];
export const STATUSES = ['new', 'triaged', 'assigned', 'in_progress', 'fix_available', 'deployed', 'verification_pending', 'verified_fixed', 'false_positive', 'accepted_risk', 'paused'];
export const CLOSED_STATUSES = ['verified_fixed', 'false_positive', 'accepted_risk'];

export const DEFAULT_PRIORITY_POLICY = {
  version: 1,
  severity_points: { critical: 40, high: 30, medium: 18, low: 8, none: 0, unknown: 22 },
  exploitation_points: { observed_in_env: 40, actively_exploited: 35, kev_listed: 30, poc_public: 12, none_known: 0 },
  epss_points: [{ min: 0.5, points: 12 }, { min: 0.1, points: 6 }],
  production_points: 10,
  exposure_points: { internet: 10, partner: 5, internal: 2, isolated: 0 },
  criticality_points: { critical: 8, high: 5, medium: 2, low: 0 },
  verified_control_points: -10,
  thresholds: { P0: 85, P1: 65, P2: 45, P3: 25 },
  // P0 additionally requires exploitation evidence in a production environment — a Critical CVSS alone is never P0.
  p0_requires: ['exploitation_evidence', 'production'],
};

export function computePriority(input, policy = DEFAULT_PRIORITY_POLICY) {
  const f = [];
  const add = (factor, value, points, note) => f.push({ factor, value, points, ...(note ? { note } : {}) });
  if (input.applicability === 'not_affected') {
    add('applicability', 'not_affected', 0, 'Assessed not affected with recorded justification; informational only.');
    return { priority: 'P4', score: 0, factors: f, policy_version: policy.version };
  }
  add('severity', input.severity || 'unknown', policy.severity_points[input.severity] ?? policy.severity_points.unknown, input.severity === 'unknown' || !input.severity ? 'Unknown severity is treated as uncertainty, not low risk.' : undefined);
  const exp = input.exploitation || 'none_known';
  if (policy.exploitation_points[exp]) add('exploitation', exp, policy.exploitation_points[exp]);
  if (input.epss != null) { const e = policy.epss_points.find(x => input.epss >= x.min); if (e) add('epss', Number(input.epss).toFixed(3), e.points, 'EPSS is a probability estimate, not evidence of exploitation.'); }
  if (input.production) add('environment', 'production', policy.production_points);
  else add('environment', 'non-production', 0);
  add('exposure', input.exposure || 'internal', policy.exposure_points[input.exposure || 'internal'] ?? 2);
  add('criticality', input.criticality || 'medium', policy.criticality_points[input.criticality || 'medium'] ?? 2);
  if (input.verified_control) add('verified_control', input.verified_control, policy.verified_control_points, 'Reviewed compensating control with evidence.');
  if (input.applicability === 'unknown' || input.applicability === 'under_investigation') add('applicability', input.applicability, 0, 'Applicability not yet established; priority is not reduced for uncertainty.');
  if (input.version_unknown) add('evidence_quality', 'version_unknown', 0, 'Observed version missing — coverage gap.');
  const score = f.reduce((s, x) => s + x.points, 0);
  const t = policy.thresholds;
  let priority = score >= t.P0 ? 'P0' : score >= t.P1 ? 'P1' : score >= t.P2 ? 'P2' : score >= t.P3 ? 'P3' : 'P4';
  const hasExploit = ['actively_exploited', 'kev_listed', 'observed_in_env'].includes(exp);
  if (priority === 'P0' && !(hasExploit && input.production)) { priority = 'P1'; add('p0_gate', 'not_met', 0, 'P0 requires exploitation evidence in production; capped at P1.'); }
  return { priority, score, factors: f, policy_version: policy.version };
}

export const DEFAULT_SLA_POLICY = {
  version: 1,
  hours: { P0: 48, P1: 168, P2: 720, P3: 2160, P4: null },
  non_production_multiplier: 2,
  clock: {
    starts: 'finding first assessed as affected/unknown/under_investigation (first_seen_at)',
    pauses: 'status=paused (waiting on vendor fix or approved freeze) — paused time is excluded',
    stops: 'verified_fixed, false_positive, or accepted_risk (approved, unexpired)',
    calendar: 'calendar hours; due dates rendered in the environment timezone',
  },
};
export function slaDue(priority, production, startIso, policy = DEFAULT_SLA_POLICY) {
  const h = policy.hours[priority]; if (h == null) return null;
  const hours = production ? h : h * policy.non_production_multiplier;
  return new Date(new Date(startIso).getTime() + hours * 3600_000).toISOString();
}

// Allowed manual transitions. verified_fixed is reachable only via the verification service (system actor).
const T = {
  new: ['triaged', 'assigned', 'in_progress', 'false_positive', 'accepted_risk', 'paused'],
  triaged: ['assigned', 'in_progress', 'false_positive', 'accepted_risk', 'paused'],
  assigned: ['in_progress', 'fix_available', 'false_positive', 'accepted_risk', 'paused'],
  in_progress: ['fix_available', 'assigned', 'false_positive', 'accepted_risk', 'paused'],
  fix_available: ['deployed', 'in_progress', 'paused'],
  deployed: ['verification_pending', 'in_progress'],
  verification_pending: ['in_progress'],
  verified_fixed: ['new'],
  false_positive: ['new'],
  accepted_risk: ['new'],
  paused: ['triaged', 'assigned', 'in_progress', 'fix_available'],
};
export function canTransition(from, to, { system = false } = {}) {
  if (system && to === 'verified_fixed') return from === 'verification_pending' || from === 'deployed';
  if (system && ['new', 'verification_pending', 'deployed', 'in_progress', 'fix_available'].includes(to)) return true;
  return (T[from] || []).includes(to);
}
export const REQUIRES_REASON = ['false_positive', 'accepted_risk', 'paused', 'new'];

// ---------------------------------------------------------------- business-hours SLA calendars
// calendar: { type: 'business', timezone, days: [1..5] (0=Sun), start: 'HH:MM', end: 'HH:MM', holidays: ['YYYY-MM-DD'] }
import { zonedToUtc, localParts } from './timezone.mjs';
export function addBusinessHours(startIso, hours, cal) {
  let remaining = hours * 3600_000;
  const [sh, sm] = cal.start.split(':').map(Number), [eh, em] = cal.end.split(':').map(Number);
  let cursor = new Date(startIso);
  for (let i = 0; i < 3660 && remaining > 0; i++) {
    const l = localParts(cursor, cal.timezone);
    const ymd = `${l.year}-${String(l.month).padStart(2, '0')}-${String(l.day).padStart(2, '0')}`;
    const open = zonedToUtc(l.year, l.month, l.day, sh, sm, cal.timezone), close = zonedToUtc(l.year, l.month, l.day, eh, em, cal.timezone);
    const working = cal.days.includes(l.weekday) && !(cal.holidays || []).includes(ymd);
    if (working && cursor < close) {
      const from = cursor > open ? cursor : open;
      const avail = close - from;
      if (avail >= remaining) return new Date(from.getTime() + remaining).toISOString();
      remaining -= avail;
    }
    // jump to the start of the next local day
    const next = new Date(Date.UTC(l.year, l.month - 1, l.day + 1));
    cursor = zonedToUtc(next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate(), 0, 0, cal.timezone);
  }
  throw new Error('SLA calendar has no working time within 10 years');
}
export function slaDueWithPolicy(priority, production, startIso, policy = DEFAULT_SLA_POLICY) {
  const h = policy.hours?.[priority]; if (h == null) return null;
  const hours = production ? h : h * (policy.non_production_multiplier || 1);
  if (policy.calendar?.type === 'business') return addBusinessHours(startIso, hours, policy.calendar);
  return new Date(new Date(startIso).getTime() + hours * 3600_000).toISOString();
}
export function validatePriorityPolicy(def) {
  const p = { ...DEFAULT_PRIORITY_POLICY, ...def };
  for (const k of ['severity_points', 'exploitation_points', 'exposure_points', 'criticality_points', 'thresholds']) p[k] = { ...DEFAULT_PRIORITY_POLICY[k], ...(def[k] || {}) };
  const nums = [...Object.values(p.severity_points), ...Object.values(p.exploitation_points), ...Object.values(p.exposure_points), ...Object.values(p.criticality_points), ...Object.values(p.thresholds), p.production_points, p.verified_control_points];
  if (nums.some(n => typeof n !== 'number' || !Number.isFinite(n) || Math.abs(n) > 500)) throw new Error('All policy points must be numbers within ±500.');
  const t = p.thresholds; if (!(t.P0 > t.P1 && t.P1 > t.P2 && t.P2 > t.P3)) throw new Error('Thresholds must satisfy P0 > P1 > P2 > P3.');
  if (p.severity_points.unknown < p.severity_points.low) throw new Error('Unknown severity may not score below low: unknown is not low risk.');
  p.p0_requires = ['exploitation_evidence', 'production']; // fixed rule, not configurable
  return p;
}
export function validateSlaPolicy(def) {
  const p = { ...DEFAULT_SLA_POLICY, ...def, hours: { ...DEFAULT_SLA_POLICY.hours, ...(def.hours || {}) } };
  for (const [k, v] of Object.entries(p.hours)) if (v !== null && !(Number.isFinite(v) && v > 0 && v <= 87600)) throw new Error(`SLA hours for ${k} must be positive or null.`);
  if (!(p.non_production_multiplier >= 1 && p.non_production_multiplier <= 10)) throw new Error('non_production_multiplier must be 1–10.');
  if (p.calendar) {
    const c = p.calendar;
    if (c.type !== 'business') throw new Error('calendar.type must be business');
    if (!/^\d{2}:\d{2}$/.test(c.start) || !/^\d{2}:\d{2}$/.test(c.end) || c.start >= c.end) throw new Error('calendar start/end must be HH:MM with start < end.');
    if (!Array.isArray(c.days) || !c.days.length || c.days.some(d => !(d >= 0 && d <= 6))) throw new Error('calendar.days must list weekdays 0–6.');
    if ((c.holidays || []).some(h => !/^\d{4}-\d{2}-\d{2}$/.test(h))) throw new Error('holidays must be YYYY-MM-DD.');
    try { new Intl.DateTimeFormat('en', { timeZone: c.timezone }); } catch { throw new Error('calendar.timezone must be an IANA timezone.'); }
  }
  return p;
}
