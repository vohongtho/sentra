// Ecosystem-specific version comparison and OSV-style affected-range evaluation.
// Deterministic code owns matching; AI never decides version applicability.
//
// Supported comparators (see docs/COVERAGE.md for the published matrix):
//   semver  – npm, cargo, go, nuget (4-part tolerated), composer (stability suffixes)
//   pep440  – PyPI
//   maven   – Maven/Gradle (ComparableVersion semantics, simplified qualifier table)
//   rubygems
//   rpm     – rpmvercmp with epoch, tilde and caret (Amazon Linux, RHEL, Fedora, SUSE)
//   deb     – dpkg ordering with epoch and tilde (Debian, Ubuntu)
//   apk     – Alpine (suffix ordering _alpha<_beta<_pre<_rc<(none)<_cvs<_svn<_git<_hg<_p, plus -rN)
//   generic – numeric/alpha token comparison (used only when nothing better applies; flagged in results)

export const ECOSYSTEMS = {
  npm: { osv: 'npm', purl: 'npm', comparator: 'semver', label: 'JavaScript / Node.js (npm, yarn, pnpm)' },
  pypi: { osv: 'PyPI', purl: 'pypi', comparator: 'pep440', label: 'Python (PyPI)' },
  maven: { osv: 'Maven', purl: 'maven', comparator: 'maven', label: 'Java / JVM (Maven, Gradle)' },
  composer: { osv: 'Packagist', purl: 'composer', comparator: 'semver', label: 'PHP (Composer / Packagist)' },
  go: { osv: 'Go', purl: 'golang', comparator: 'semver', label: 'Go modules' },
  cargo: { osv: 'crates.io', purl: 'cargo', comparator: 'semver', label: 'Rust (crates.io)' },
  nuget: { osv: 'NuGet', purl: 'nuget', comparator: 'semver', label: '.NET (NuGet)' },
  rubygems: { osv: 'RubyGems', purl: 'gem', comparator: 'rubygems', label: 'Ruby (RubyGems)' },
  deb: { osv: 'Debian', purl: 'deb', comparator: 'deb', label: 'Debian / Ubuntu packages' },
  rpm: { osv: 'Red Hat', purl: 'rpm', comparator: 'rpm', label: 'RPM (Amazon Linux, RHEL, Fedora, SUSE)' },
  apk: { osv: 'Alpine', purl: 'apk', comparator: 'apk', label: 'Alpine packages' },
  hex: { osv: 'Hex', purl: 'hex', comparator: 'semver', label: 'Erlang / Elixir (Hex)' },
  pub: { osv: 'Pub', purl: 'pub', comparator: 'semver', label: 'Dart (Pub)' },
  swift: { osv: 'SwiftURL', purl: 'swift', comparator: 'semver', label: 'Swift (SwiftPM)' },
  cran: { osv: 'CRAN', purl: 'cran', comparator: 'generic', label: 'R (CRAN)' },
  cpan: { osv: null, purl: 'cpan', comparator: 'generic', label: 'Perl (CPAN)' },
  conan: { osv: null, purl: 'conan', comparator: 'generic', label: 'C/C++ (Conan)' },
  generic: { osv: null, purl: 'generic', comparator: 'generic', label: 'Generic / product' },
};

const OSV_TO_ECO = Object.fromEntries(Object.entries(ECOSYSTEMS).filter(([, v]) => v.osv).map(([k, v]) => [v.osv.toLowerCase(), k]));
Object.assign(OSV_TO_ECO, { ubuntu: 'deb', 'amazon linux': 'rpm', almalinux: 'rpm', 'rocky linux': 'rpm', suse: 'rpm', opensuse: 'rpm', 'red hat': 'rpm', mageia: 'rpm', 'photon os': 'rpm', wolfi: 'apk', chainguard: 'apk', packagist: 'composer', pypi: 'pypi' });
const PURL_TO_ECO = Object.fromEntries(Object.entries(ECOSYSTEMS).map(([k, v]) => [v.purl, k]));
PURL_TO_ECO.github = 'generic';

export function ecosystemFromOsv(name) {
  if (!name) return 'generic';
  const base = String(name).split(':')[0].trim().toLowerCase();
  return OSV_TO_ECO[base] || 'generic';
}
export const ecosystemFromPurlType = (t) => PURL_TO_ECO[String(t || '').toLowerCase()] || 'generic';
export const comparatorFor = (eco) => (ECOSYSTEMS[eco] || ECOSYSTEMS.generic).comparator;

// ------------------------------------------------------------------ semver (tolerant)
function parseSemver(v) {
  let s = String(v).trim().replace(/^[v=]+/i, '');
  const build = s.indexOf('+'); if (build >= 0) s = s.slice(0, build);
  // composer stability suffixes: 1.0.0-beta2, 1.0.0RC1, dev-master
  let pre = '';
  const m = /^(\d+(?:\.\d+)*)(?:[-.]?((?:alpha|beta|rc|a|b|dev|patch|pl|p|preview|pre)[\w.-]*|[-][\w.-]+))?$/i.exec(s);
  if (!m) return null;
  const nums = m[1].split('.').map(Number);
  if (m[2]) pre = m[2].replace(/^-/, '');
  return { nums, pre };
}
function cmpPreIds(a, b) {
  const pa = a.split(/[.-]/), pb = b.split(/[.-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (pa[i] === undefined) return -1; if (pb[i] === undefined) return 1;
    const na = /^\d+$/.test(pa[i]), nb = /^\d+$/.test(pb[i]);
    if (na && nb) { const d = Number(pa[i]) - Number(pb[i]); if (d) return Math.sign(d); }
    else if (na) return -1; else if (nb) return 1;
    else if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}
export function compareSemver(a, b) {
  const x = parseSemver(a), y = parseSemver(b);
  if (!x || !y) return compareGeneric(a, b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    const d = (x.nums[i] || 0) - (y.nums[i] || 0); if (d) return Math.sign(d);
  }
  // composer "patch"/"pl"/"p" are post-releases (sort after final)
  const post = (p) => /^(patch|pl|p)\d*/i.test(p);
  if (x.pre === y.pre) return 0;
  if (!x.pre) return post(y.pre) ? -1 : 1;
  if (!y.pre) return post(x.pre) ? 1 : -1;
  return cmpPreIds(x.pre.toLowerCase(), y.pre.toLowerCase());
}

// ------------------------------------------------------------------ PEP 440
const PEP_RE = /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/i;
function parsePep(v) {
  const m = PEP_RE.exec(String(v).trim().toLowerCase()); if (!m) return null;
  const preMap = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };
  return {
    epoch: Number(m[1] || 0), release: m[2].split('.').map(Number),
    pre: m[3] ? [preMap[m[3]], Number(m[4] || 0)] : null,
    post: m[5] != null ? Number(m[5]) : m[6] ? Number(m[7] || 0) : null,
    dev: m[8] ? Number(m[9] || 0) : null,
    local: m[10] || null,
  };
}
export function comparePep440(a, b) {
  const x = parsePep(a), y = parsePep(b);
  if (!x || !y) return compareGeneric(a, b);
  if (x.epoch !== y.epoch) return Math.sign(x.epoch - y.epoch);
  for (let i = 0; i < Math.max(x.release.length, y.release.length); i++) { const d = (x.release[i] || 0) - (y.release[i] || 0); if (d) return Math.sign(d); }
  // key: pre segment; dev-only releases sort before pre-releases
  const preKey = (p) => (p.pre ? [1, ...p.pre] : p.post == null && p.dev != null ? [0, 0, 0] : [2, 0, 0]);
  const kx = preKey(x), ky = preKey(y);
  for (let i = 0; i < 3; i++) if (kx[i] !== ky[i]) return Math.sign(kx[i] - ky[i]);
  const postKey = (p) => (p.post == null ? -1 : p.post);
  if (postKey(x) !== postKey(y)) return Math.sign(postKey(x) - postKey(y));
  const devKey = (p) => (p.dev == null ? Infinity : p.dev);
  if (devKey(x) !== devKey(y)) return devKey(x) < devKey(y) ? -1 : 1;
  if (x.local === y.local) return 0;
  if (!x.local) return -1; if (!y.local) return 1;
  return cmpPreIds(x.local, y.local);
}

// ------------------------------------------------------------------ Maven ComparableVersion (simplified)
const MVN_Q = { alpha: 1, a: 1, beta: 2, b: 2, milestone: 3, m: 3, rc: 4, cr: 4, snapshot: 5, '': 6, ga: 6, final: 6, release: 6, sp: 7 };
function mavenTokens(v) {
  const out = [];
  const s = String(v).trim().toLowerCase();
  let cur = '', isDigit = null;
  const push = () => { if (cur !== '') out.push(isDigit ? Number(cur) : cur); cur = ''; };
  for (const ch of s) {
    if (ch === '.' || ch === '-' || ch === '_') { push(); isDigit = null; continue; }
    const d = ch >= '0' && ch <= '9';
    if (isDigit !== null && d !== isDigit) push();
    isDigit = d; cur += ch;
  }
  push();
  // trim trailing zero / release qualifiers ("1.0.0" == "1" ; "1.0-final" == "1")
  while (out.length > 1 && (out[out.length - 1] === 0 || ['', 'ga', 'final', 'release'].includes(out[out.length - 1]))) out.pop();
  return out;
}
function mvnItemCmp(a, b) {
  if (a === undefined && b === undefined) return 0;
  if (a === undefined) return typeof b === 'number' ? (b === 0 ? 0 : -1) : -mvnItemCmp(b, undefined);
  if (b === undefined) {
    if (typeof a === 'number') return a === 0 ? 0 : 1;
    const q = MVN_Q[a]; return q === undefined ? 1 : Math.sign(q - MVN_Q['']);
  }
  if (typeof a === 'number' && typeof b === 'number') return Math.sign(a - b);
  if (typeof a === 'number') return 1; // number > qualifier
  if (typeof b === 'number') return -1;
  const qa = MVN_Q[a], qb = MVN_Q[b];
  if (qa !== undefined && qb !== undefined) return Math.sign(qa - qb);
  if (qa !== undefined) return -1; // known qualifiers sort before unknown
  if (qb !== undefined) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}
export function compareMaven(a, b) {
  const x = mavenTokens(a), y = mavenTokens(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const c = mvnItemCmp(x[i], y[i]); if (c) return c; }
  return 0;
}

// ------------------------------------------------------------------ RubyGems
export function compareRubyGems(a, b) {
  const seg = (v) => String(v).trim().replace(/-/g, '.pre.').split(/\.|(?<=\d)(?=[a-z])|(?<=[a-z])(?=\d)/i).filter(Boolean).map(s => (/^\d+$/.test(s) ? Number(s) : s));
  const x = seg(a), y = seg(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i] ?? 0, q = y[i] ?? 0;
    if (p === q) continue;
    if (typeof p === 'number' && typeof q === 'number') return Math.sign(p - q);
    if (typeof p === 'string' && typeof q === 'number') return -1; // prerelease < release
    if (typeof p === 'number' && typeof q === 'string') return 1;
    return p < q ? -1 : 1;
  }
  return 0;
}

// ------------------------------------------------------------------ RPM (rpmvercmp)
export function rpmvercmp(a, b) {
  if (a === b) return 0;
  let i = 0, j = 0;
  const isAlnum = (c) => /[A-Za-z0-9]/.test(c);
  while (i < a.length || j < b.length) {
    while (i < a.length && !isAlnum(a[i]) && a[i] !== '~' && a[i] !== '^') i++;
    while (j < b.length && !isAlnum(b[j]) && b[j] !== '~' && b[j] !== '^') j++;
    if (a[i] === '~' || b[j] === '~') { if (a[i] !== '~') return 1; if (b[j] !== '~') return -1; i++; j++; continue; }
    if (a[i] === '^' || b[j] === '^') {
      if (i >= a.length) return -1; if (j >= b.length) return 1;
      if (a[i] !== '^') return 1; if (b[j] !== '^') return -1; i++; j++; continue;
    }
    if (!(i < a.length && j < b.length)) break;
    const numeric = /\d/.test(a[i]);
    const re = numeric ? /\d/ : /[A-Za-z]/;
    let si = i, sj = j;
    while (i < a.length && re.test(a[i])) i++;
    while (j < b.length && re.test(b[j])) j++;
    let sa = a.slice(si, i), sb = b.slice(sj, j);
    if (sb === '') return numeric ? 1 : -1;
    if (numeric) {
      sa = sa.replace(/^0+/, ''); sb = sb.replace(/^0+/, '');
      if (sa.length !== sb.length) return sa.length > sb.length ? 1 : -1;
    }
    if (sa !== sb) return sa > sb ? 1 : -1;
  }
  if (i >= a.length && j >= b.length) return 0;
  return i >= a.length ? -1 : 1;
}
function splitEVR(v) {
  let s = String(v).trim(); let epoch = 0;
  const c = s.indexOf(':'); if (c > 0 && /^\d+$/.test(s.slice(0, c))) { epoch = Number(s.slice(0, c)); s = s.slice(c + 1); }
  const d = s.lastIndexOf('-');
  return d > 0 ? { epoch, version: s.slice(0, d), release: s.slice(d + 1) } : { epoch, version: s, release: '' };
}
export function compareRpm(a, b) {
  const x = splitEVR(a), y = splitEVR(b);
  if (x.epoch !== y.epoch) return Math.sign(x.epoch - y.epoch);
  const v = rpmvercmp(x.version, y.version); if (v) return v;
  if (!x.release || !y.release) return 0; // release unspecified => compare only version
  return rpmvercmp(x.release, y.release);
}

// ------------------------------------------------------------------ Debian (dpkg)
function debOrder(c) { if (c === '~') return -1; if (c === undefined || c === '') return 0; if (/[A-Za-z]/.test(c)) return c.charCodeAt(0); return c.charCodeAt(0) + 256; }
function debPart(a, b) {
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !/\d/.test(a[i])) || (j < b.length && !/\d/.test(b[j]))) {
      const ac = i < a.length && !/\d/.test(a[i]) ? a[i] : '';
      const bc = j < b.length && !/\d/.test(b[j]) ? b[j] : '';
      const d = debOrder(ac) - debOrder(bc); if (d) return Math.sign(d);
      if (ac) i++; if (bc) j++;
    }
    while (a[i] === '0') i++; while (b[j] === '0') j++;
    while (i < a.length && /\d/.test(a[i]) && j < b.length && /\d/.test(b[j])) { if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j); i++; j++; }
    if (i < a.length && /\d/.test(a[i])) return 1;
    if (j < b.length && /\d/.test(b[j])) return -1;
    if (firstDiff) return Math.sign(firstDiff);
  }
  return 0;
}
export function compareDeb(a, b) {
  const x = splitEVR(a), y = splitEVR(b);
  if (x.epoch !== y.epoch) return Math.sign(x.epoch - y.epoch);
  return debPart(x.version, y.version) || debPart(x.release || '0', y.release || '0');
}

// ------------------------------------------------------------------ Alpine apk
const APK_SUFFIX = { alpha: -4, beta: -3, pre: -2, rc: -1, '': 0, cvs: 1, svn: 2, git: 3, hg: 4, p: 5 };
function parseApk(v) {
  const m = /^(\d+(?:\.\d+)*)([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$/.exec(String(v).trim());
  if (!m) return null;
  const suf = (m[3].match(/_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)/g) || []).map(s => { const mm = /_([a-z]+)(\d*)/.exec(s); return [APK_SUFFIX[mm[1]], Number(mm[2] || 0)]; });
  return { nums: m[1].split('.').map(Number), letter: m[2], suf, rel: Number(m[4] || 0) };
}
export function compareApk(a, b) {
  const x = parseApk(a), y = parseApk(b);
  if (!x || !y) return compareGeneric(a, b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) { const d = (x.nums[i] ?? -1) - (y.nums[i] ?? -1); if (d) return Math.sign(d); }
  if (x.letter !== y.letter) return x.letter < y.letter ? -1 : 1;
  for (let i = 0; i < Math.max(x.suf.length, y.suf.length); i++) {
    const p = x.suf[i] || [0, 0], q = y.suf[i] || [0, 0];
    if (p[0] !== q[0]) return Math.sign(p[0] - q[0]); if (p[1] !== q[1]) return Math.sign(p[1] - q[1]);
  }
  return Math.sign(x.rel - y.rel);
}

// ------------------------------------------------------------------ generic
export function compareGeneric(a, b) {
  const tok = (v) => String(v).toLowerCase().match(/\d+|[a-z]+/g) || [];
  const x = tok(a), y = tok(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i], q = y[i];
    if (p === undefined) return -1; if (q === undefined) return 1;
    const np = /^\d/.test(p), nq = /^\d/.test(q);
    if (np && nq) { const d = Number(p) - Number(q); if (d) return Math.sign(d); }
    else if (np !== nq) return np ? 1 : -1;
    else if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

const COMPARATORS = { semver: compareSemver, pep440: comparePep440, maven: compareMaven, rubygems: compareRubyGems, rpm: compareRpm, deb: compareDeb, apk: compareApk, generic: compareGeneric };
export function compareVersions(eco, a, b) { return COMPARATORS[comparatorFor(eco)](a, b); }

/**
 * Evaluate a version against OSV-style ranges.
 * @returns {{status:'affected'|'not_affected'|'unknown', reason:string, fixed?:string, comparator:string, range?:object}}
 */
export function evaluateRanges(eco, version, ranges) {
  const comparator = comparatorFor(eco);
  if (version == null || version === '' || /^(unknown|latest|\*)$/i.test(version)) {
    return { status: 'unknown', reason: 'Observed version is missing; applicability cannot be determined from version evidence.', comparator };
  }
  const cmp = (a, b) => compareVersions(eco, a, b);
  let sawRange = false; let fixedCandidates = [];
  for (const r of ranges) {
    if ((r.versions || []).some(v => String(v) === String(version))) {
      const fx = (r.events || []).filter(e => e.fixed).map(e => e.fixed);
      return { status: 'affected', reason: `Version ${version} is explicitly listed as affected.`, fixed: fx.sort(cmp).find(f => cmp(f, version) > 0), comparator, range: r };
    }
    if (r.range_type === 'GIT') continue; // commit ranges need source evidence, not package versions
    const events = r.events || [];
    if (!events.length) continue;
    sawRange = true;
    // OSV: evaluate events in sorted order; introduced "0" means earliest.
    const sorted = [...events].sort((p, q) => {
      const vp = p.introduced ?? p.fixed ?? p.last_affected ?? p.limit, vq = q.introduced ?? q.fixed ?? q.last_affected ?? q.limit;
      if (vp === '0') return -1; if (vq === '0') return 1;
      return cmp(vp, vq);
    });
    let affected = false; let lastFixed;
    for (const e of sorted) {
      if (e.introduced != null) { if (e.introduced === '0' || cmp(version, e.introduced) >= 0) affected = true; }
      else if (e.fixed != null) { if (cmp(version, e.fixed) >= 0) affected = false; else if (affected) { lastFixed = e.fixed; break; } }
      else if (e.last_affected != null) { if (cmp(version, e.last_affected) > 0) affected = false; else if (affected) break; }
      else if (e.limit != null) { if (cmp(version, e.limit) >= 0) affected = false; }
    }
    fixedCandidates.push(...events.filter(e => e.fixed).map(e => e.fixed));
    if (affected) {
      const fixed = lastFixed || fixedCandidates.sort(cmp).find(f => cmp(f, version) > 0);
      return { status: 'affected', reason: `Version ${version} falls inside an affected ${r.range_type} range (${describeEvents(events)}) using the ${comparator} comparator.`, fixed, comparator, range: r };
    }
  }
  if (!sawRange) return { status: 'unknown', reason: 'Advisory has no machine-evaluable version range for this package.', comparator };
  return { status: 'not_affected', reason: `Version ${version} is outside all affected ranges using the ${comparator} comparator.`, comparator };
}
export function describeEvents(events) {
  return events.map(e => (e.introduced != null ? `introduced ${e.introduced}` : e.fixed != null ? `fixed ${e.fixed}` : e.last_affected != null ? `last affected ${e.last_affected}` : `limit ${e.limit}`)).join(', ');
}
