// Daily report (default Vietnamese, 08:00 Asia/Ho_Chi_Minh, previous 24h). Material changes only.
// THN coverage is a separate section with a precisely scoped "no material items" message. Ingestion failures produce an
// incomplete-coverage notice, never a successful zero-findings report. The report never claims all software is safe.
import { id } from '../util.mjs';
import { CONNECTORS } from '../connectors/index.mjs';
import { formatLocal } from '../domain/timezone.mjs';
import { enqueue } from '../jobs/queue.mjs';

const T = {
  vi: {
    title: (d) => `Báo cáo bảo mật hằng ngày — ${d}`,
    period: (a, b, tz) => `Phạm vi: ${a} → ${b} (${tz})`,
    portfolio: 'Danh mục dự án — thay đổi đáng chú ý',
    newFindings: (n) => `${n} phát hiện mới ảnh hưởng`,
    prioUp: (n) => `${n} phát hiện tăng mức ưu tiên`,
    verified: (n) => `${n} khắc phục đã được xác minh trên môi trường`,
    breached: (n) => `${n} phát hiện quá hạn SLA`,
    noMaterial: 'Không có thay đổi đáng chú ý trong danh mục trong 24 giờ qua đối với các dự án và nguồn dữ liệu được giám sát. Điều này không có nghĩa là toàn bộ phần mềm đều an toàn.',
    thn: 'The Hacker News — 24 giờ qua',
    thnNone: (n) => `Không tìm thấy mục nào liên quan đến thành phần trong kho phần mềm trong ${n} bài viết của The Hacker News trong 24 giờ qua. Phạm vi kiểm tra chỉ gồm nguồn tin này; không suy ra rằng phần mềm an toàn.`,
    thnItem: 'Có thể liên quan (chưa xác minh với nguồn chính thức)',
    incomplete: 'CẢNH BÁO: Báo cáo chưa đầy đủ',
    incompleteBody: (s) => `Không thể thu thập dữ liệu từ: ${s}. Kết quả bên dưới không bao gồm các nguồn này và KHÔNG được hiểu là không có rủi ro.`,
    coverage: (n) => `${n} khoảng trống về độ bao phủ (SBOM thiếu, dữ liệu cũ, kết nối lỗi).`,
    synthetic: 'Lưu ý: có dữ liệu minh họa tổng hợp (SYNTHETIC).',
  },
  en: {
    title: (d) => `Daily security report — ${d}`,
    period: (a, b, tz) => `Period: ${a} → ${b} (${tz})`,
    portfolio: 'Portfolio — material changes',
    newFindings: (n) => `${n} new affected finding(s)`,
    prioUp: (n) => `${n} finding(s) increased in priority`,
    verified: (n) => `${n} remediation(s) verified in environment`,
    breached: (n) => `${n} finding(s) breached SLA`,
    noMaterial: 'No material portfolio changes in the past 24 hours for monitored projects and sources. This does not mean all software is safe.',
    thn: 'The Hacker News — past 24 hours',
    thnNone: (n) => `No items relevant to inventoried components were found in ${n} The Hacker News article(s) from the past 24 hours. Scope is limited to this source; it does not imply software is safe.`,
    thnItem: 'Potentially relevant (not yet verified against primary sources)',
    incomplete: 'WARNING: Incomplete coverage',
    incompleteBody: (s) => `Data could not be collected from: ${s}. Results below exclude these sources and must NOT be read as no risk.`,
    coverage: (n) => `${n} coverage gap(s) (missing SBOMs, stale data, failed connectors).`,
    synthetic: 'Note: includes SYNTHETIC demonstration data.',
  },
};

export async function generateDailyReport(app, { orgId, language = 'vi', timezone = 'Asia/Ho_Chi_Minh', scheduledFor = new Date().toISOString(), scheduleId = null, jobId = null }) {
  const db = app.db; const L = T[language] || T.vi;
  const end = new Date(scheduledFor); const start = new Date(end.getTime() - 86400000);
  const failures = [];
  // Refresh intelligence before reporting; record failures as coverage gaps.
  const conns = await db.query(`SELECT * FROM connections WHERE org_id=$1 AND kind IN ('osv','kev','epss','thn') AND status <> 'disabled'`, [orgId]);
  let thnItems = null;
  for (const c of conns) {
    try {
      if (c.kind === 'thn') thnItems = await CONNECTORS.thn.fetchItems(app, c);
      else if (app.cfg.externalFeeds) await CONNECTORS[c.kind].sync(app, c);
      await db.query(`UPDATE connections SET status='connected', last_success_at=now(), last_check_at=now(), last_error=NULL WHERE id=$1`, [c.id]);
    } catch (e) { failures.push(`${c.name} (${e.message})`); await db.query(`UPDATE connections SET status='failed', last_check_at=now(), last_error=$2 WHERE id=$1`, [c.id, e.message]); }
  }
  if (!conns.some(c => c.kind === 'thn')) failures.push('The Hacker News feed (not configured)');
  const ev = async (kind, extra = '') => (await db.query(`SELECT fe.*, f.project_id, p.key AS project_key, f.advisory_id, c.name AS package, f.priority, e.key AS env, a.is_synthetic FROM finding_events fe JOIN findings f ON f.id=fe.finding_id JOIN projects p ON p.id=f.project_id JOIN components c ON c.id=f.component_id JOIN advisories a ON a.id=f.advisory_id LEFT JOIN environments e ON e.id=f.environment_id
     WHERE f.org_id=$1 AND fe.kind=$2 AND fe.created_at > $3 AND fe.created_at <= $4 ${extra} ORDER BY f.priority`, [orgId, kind, start.toISOString(), end.toISOString()]));
  const created = (await ev('created')).filter(e => ['affected', 'under_investigation', 'unknown'].includes(e.data?.applicability));
  const prioUp = (await ev('reassessed')).filter(e => e.from_value && e.to_value && e.to_value < e.from_value);
  const verified = await ev('verification', `AND fe.to_value='verified_fixed'`);
  const breached = await db.query(`SELECT f.id, p.key AS project_key, f.advisory_id, c.name AS package, f.priority, f.sla_due_at FROM findings f JOIN projects p ON p.id=f.project_id JOIN components c ON c.id=f.component_id WHERE f.org_id=$1 AND f.sla_due_at > $2 AND f.sla_due_at <= $3 AND f.status NOT IN ('verified_fixed','false_positive','accepted_risk')`, [orgId, start.toISOString(), end.toISOString()]);
  const { orgCoverage } = await import('./coverage.mjs');
  const cov = await orgCoverage(db, (await db.query('SELECT id FROM projects WHERE org_id=$1 AND archived_at IS NULL', [orgId])).map(r => r.id));
  const gaps = cov.reduce((s, p) => s + p.gaps.filter(g => g.severity === 'high').length, 0);
  // THN relevance: keyword match against inventoried component names (discovery context only)
  let thn = null;
  if (thnItems) {
    const recent = thnItems.filter(i => { const d = Date.parse(i.published); return !isNaN(d) && d > start.getTime() && d <= end.getTime(); });
    const names = (await db.query(`SELECT DISTINCT lower(split_part(regexp_replace(c.name, '^.*[:/]', ''), ' ', 1)) AS n FROM components c JOIN observations o ON o.component_id=c.id WHERE o.org_id=$1`, [orgId])).map(r => r.n).filter(n => n && n.length >= 4 && !['core', 'common', 'utils', 'client', 'server', 'http', 'node', 'test'].includes(n));
    const relevant = recent.map(i => ({ ...i, matches: names.filter(n => new RegExp(`\\b${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(`${i.title} ${i.description}`)) })).filter(i => i.matches.length);
    thn = { scanned: recent.length, relevant };
  }
  const material = created.length + prioUp.length + verified.length + breached.length;
  const fmt = (d) => formatLocal(d, timezone, language);
  const lines = [L.title(formatLocal(end, timezone, language).split(',')[0]), L.period(fmt(start), fmt(end), timezone), ''];
  if (failures.length) lines.push(`⚠ ${L.incomplete}`, L.incompleteBody(failures.join('; ')), '');
  lines.push(`## ${L.portfolio}`);
  if (!material) lines.push(L.noMaterial);
  else {
    if (created.length) { lines.push(`- ${L.newFindings(created.length)}`); for (const e of created.slice(0, 15)) lines.push(`  • ${e.priority} ${e.project_key}/${e.env || '-'}: ${e.advisory_id} — ${e.package}`); }
    if (prioUp.length) { lines.push(`- ${L.prioUp(prioUp.length)}`); for (const e of prioUp.slice(0, 10)) lines.push(`  • ${e.project_key}: ${e.advisory_id} ${e.from_value}→${e.to_value} (${e.reason})`); }
    if (verified.length) lines.push(`- ${L.verified(verified.length)}`);
    if (breached.length) { lines.push(`- ${L.breached(breached.length)}`); for (const b of breached.slice(0, 10)) lines.push(`  • ${b.priority} ${b.project_key}: ${b.advisory_id} — ${b.package}`); }
  }
  if (gaps) lines.push(`- ${L.coverage(gaps)}`);
  lines.push('', `## ${L.thn}`);
  if (!thn) lines.push(L.incompleteBody('The Hacker News'));
  else if (!thn.relevant.length) lines.push(L.thnNone(thn.scanned));
  else for (const i of thn.relevant.slice(0, 10)) lines.push(`- ${i.title} — ${L.thnItem}; ${i.matches.join(', ')} — ${i.link}`);
  if ([...created, ...prioUp].some(e => e.is_synthetic)) lines.push('', L.synthetic);
  const coverage_status = failures.length ? 'incomplete' : 'complete';
  const rid = id('rpt');
  const content = { created: created.length, priority_increases: prioUp.length, verified: verified.length, sla_breached: breached.length, high_coverage_gaps: gaps, thn, failures, material };
  await db.query(`INSERT INTO report_runs (id, org_id, schedule_id, job_id, kind, language, period_start, period_end, coverage_status, content, rendered_text) VALUES ($1,$2,$3,$4,'daily_portfolio',$5,$6,$7,$8,$9,$10)`,
    [rid, orgId, scheduleId, jobId, language, start.toISOString(), end.toISOString(), coverage_status, content, lines.join('\n')]);
  // deliver to report channels
  const channelIds = (await db.one('SELECT params FROM schedules WHERE id=$1', [scheduleId]))?.params?.channel_ids || [];
  for (const chId of channelIds) {
    const did = id('dlv');
    await db.query(`INSERT INTO alerts (id, org_id, dedupe_key, trigger, title, body) VALUES ($1,$2,$3,'report.daily',$4,$5) ON CONFLICT (org_id, dedupe_key) DO NOTHING`, [`alt_${rid}`, orgId, `report|${rid}`, lines[0] + (failures.length ? ' — ' + L.incomplete : ''), { text: lines.slice(1).join('\n') }]);
    await db.query(`INSERT INTO deliveries (id, org_id, alert_id, report_run_id, channel_id, dedupe_key) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, [did, orgId, `alt_${rid}`, rid, chId, `report|${rid}|${chId}`]);
    await enqueue(db, { type: 'deliver', orgId, payload: { delivery_id: did, recipients: [] }, idempotencyKey: `deliver:${did}` });
  }
  return { report_id: rid, coverage_status, material };
}
