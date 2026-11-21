// Timezone/DST-aware schedule computation using the platform IANA database (Intl).
// next_run_at is stored in UTC; local wall time + timezone are the source of truth.

const dtfCache = new Map();
function dtf(tz) {
  if (!dtfCache.has(tz)) dtfCache.set(tz, new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', weekday: 'short' }));
  return dtfCache.get(tz);
}
export function isValidTimeZone(tz) { try { dtf(tz); return true; } catch { return false; } }
export function localParts(date, tz) {
  const p = Object.fromEntries(dtf(tz).formatToParts(date).map(x => [x.type, x.value]));
  const wd = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }[p.weekday];
  return { year: +p.year, month: +p.month, day: +p.day, hour: +p.hour, minute: +p.minute, second: +p.second, weekday: wd };
}
function offsetMs(date, tz) {
  const l = localParts(date, tz);
  return Date.UTC(l.year, l.month - 1, l.day, l.hour, l.minute, l.second) - Math.floor(date.getTime() / 1000) * 1000;
}
/** Convert a local wall-clock time to a UTC Date. Non-existent times (DST gap) shift forward; ambiguous times pick the earlier instant. */
export function zonedToUtc(year, month, day, hour, minute, tz) {
  const naive = Date.UTC(year, month - 1, day, hour, minute);
  const o1 = offsetMs(new Date(naive), tz);
  let t = naive - o1;
  const o2 = offsetMs(new Date(t), tz);
  if (o2 !== o1) t = naive - o2;
  const l = localParts(new Date(t), tz);
  if (l.hour !== hour || l.minute !== minute) {
    // DST gap: wall time does not exist; run at the first valid instant after the gap.
    return new Date(naive - Math.min(o1, o2));
  }
  // ambiguous (fall back): prefer the earlier instant
  const earlier = t - 3600_000; const le = localParts(new Date(earlier), tz);
  if (le.hour === hour && le.minute === minute && le.day === day) return new Date(earlier);
  return new Date(t);
}
/**
 * Next occurrence strictly after `after`.
 * frequency: hourly (uses minute of local_time) | daily | weekly (requires weekday 0-6)
 */
export function nextOccurrence({ frequency, local_time = '08:00', weekday = null, timezone }, after = new Date()) {
  if (!isValidTimeZone(timezone)) throw new Error(`Invalid IANA timezone: ${timezone}`);
  const [hh, mm] = local_time.split(':').map(Number);
  if (!(hh >= 0 && hh < 24 && mm >= 0 && mm < 60)) throw new Error('local_time must be HH:MM');
  if (frequency === 'hourly') {
    const base = new Date(Math.floor(after.getTime() / 60000) * 60000);
    for (let i = 0; i <= 120; i++) {
      const c = new Date(base.getTime() + i * 60000);
      if (c > after && localParts(c, timezone).minute === mm) return c;
    }
  }
  if (frequency === 'weekly' && (weekday == null || weekday < 0 || weekday > 6)) throw new Error('weekly schedules require weekday 0-6');
  const l = localParts(after, timezone);
  for (let i = 0; i < 9; i++) {
    const d = new Date(Date.UTC(l.year, l.month - 1, l.day + i));
    const cand = zonedToUtc(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate(), hh, mm, timezone);
    if (cand <= after) continue;
    if (frequency === 'weekly' && localParts(cand, timezone).weekday !== weekday) continue;
    return cand;
  }
  throw new Error('Unable to compute next occurrence');
}
/** All occurrences in (from, to] — used for missed-run policies. Bounded to 500. */
export function occurrencesBetween(spec, from, to) {
  const out = []; let cur = from;
  while (out.length < 500) { const n = nextOccurrence(spec, cur); if (n > to) break; out.push(n); cur = n; }
  return out;
}
export function formatLocal(date, tz, lang = 'en') {
  return new Intl.DateTimeFormat(lang === 'vi' ? 'vi-VN' : 'en-GB', { timeZone: tz, dateStyle: 'medium', timeStyle: 'short' }).format(date);
}
