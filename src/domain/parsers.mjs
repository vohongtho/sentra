// Import parsers: CycloneDX JSON, SPDX 2.x JSON, Trivy JSON, SARIF 2.1, CSV/JSON/YAML inventory,
// and lockfile/manifest parsers used by stack discovery. All return a normalized document:
//   { format, components:[{purl, ecosystem, name, version, kind, direct, dependency_path, cpe, distro, architecture, ref}],
//     edges:[[parentRef, childRef]], findings:[...scanner results], errors:[{row, field, message}], metadata:{} }
// Missing versions stay null (Unknown); parsers never invent versions.
import YAML from 'yaml';
import { readXlsxRows } from './xlsx.mjs';
import { componentFromPurl, purlFor } from './purl.mjs';
import { ecosystemFromOsv, ECOSYSTEMS } from './versions.mjs';

export class ParseError extends Error { constructor(msg, errors = []) { super(msg); this.errors = errors; } }

export function detectFormat(text, filename = '') {
  const f = filename.toLowerCase();
  if (f.endsWith('package-lock.json')) return 'npm-lock';
  if (f.endsWith('composer.lock')) return 'composer-lock';
  if (f.endsWith('requirements.txt')) return 'requirements';
  if (f.endsWith('go.mod')) return 'go-mod';
  if (f.endsWith('pom.xml')) return 'pom';
  if (f.endsWith('gemfile.lock')) return 'gemfile-lock';
  if (f.endsWith('cargo.lock')) return 'cargo-lock';
  if (/dockerfile$/i.test(f)) return 'dockerfile';
  if (f.endsWith('.csv')) return 'csv';
  if (f.endsWith('.xlsx')) return 'xlsx';
  if (f.endsWith('.yaml') || f.endsWith('.yml')) return 'yaml';
  const t = text.trimStart();
  if (t.startsWith('{') || t.startsWith('[')) {
    let j; try { j = JSON.parse(text); } catch { return 'invalid-json'; }
    if (j.bomFormat === 'CycloneDX') return 'cyclonedx';
    if (j.spdxVersion) return 'spdx';
    if (j.SchemaVersion && j.Results) return 'trivy';
    if (j.$schema?.includes('sarif') || j.version === '2.1.0' && j.runs) return 'sarif';
    if (j.lockfileVersion) return 'npm-lock';
    if (j.packages && j['content-hash']) return 'composer-lock';
    return 'json';
  }
  if (/^[\w"]+,/.test(t)) return 'csv';
  return 'yaml';
}

export function parseDocument(text, { filename = '', format } = {}) {
  const fmt = format || detectFormat(text, filename);
  switch (fmt) {
    case 'cyclonedx': return parseCycloneDX(JSON.parse(text));
    case 'spdx': return parseSPDX(JSON.parse(text));
    case 'trivy': return parseTrivy(JSON.parse(text));
    case 'sarif': return parseSarif(JSON.parse(text));
    case 'json': return parseInventoryRows(JSON.parse(text), 'json');
    case 'yaml': { let y; try { y = YAML.parse(text, { maxAliasCount: 50 }); } catch (e) { throw new ParseError('Invalid YAML: ' + e.message); } return parseInventoryRows(y, 'yaml'); }
    case 'csv': return parseInventoryRows(parseCsv(text), 'csv');
    case 'xlsx': return parseInventoryRows(readXlsxRows(Buffer.from(text, 'base64')), 'xlsx');
    case 'npm-lock': return parseNpmLock(JSON.parse(text));
    case 'composer-lock': return parseComposerLock(JSON.parse(text));
    case 'requirements': return parseRequirements(text);
    case 'go-mod': return parseGoMod(text);
    case 'pom': return parsePom(text);
    case 'gemfile-lock': return parseGemfileLock(text);
    case 'cargo-lock': return parseCargoLock(text);
    case 'dockerfile': return parseDockerfile(text);
    case 'invalid-json': throw new ParseError('Document is not valid JSON.');
    default: throw new ParseError(`Unsupported format: ${fmt}`);
  }
}

const doc = (format, extra = {}) => ({ format, components: [], edges: [], findings: [], errors: [], metadata: {}, ...extra });
const kindFromCdx = (t) => ({ framework: 'framework', application: 'application', 'operating-system': 'runtime', platform: 'runtime', container: 'application', firmware: 'os_package' }[t] || 'library');

export function parseCycloneDX(j) {
  if (j.bomFormat !== 'CycloneDX') throw new ParseError('Not a CycloneDX document.');
  if (!/^1\.[2-6]$/.test(String(j.specVersion))) throw new ParseError(`Unsupported CycloneDX specVersion ${j.specVersion}; supported 1.2–1.6.`);
  const out = doc('cyclonedx', { metadata: { serialNumber: j.serialNumber, specVersion: j.specVersion, timestamp: j.metadata?.timestamp, root: j.metadata?.component?.name, rootVersion: j.metadata?.component?.version } });
  const rootRef = j.metadata?.component?.['bom-ref'];
  const directRefs = new Set((j.dependencies || []).find(d => d.ref === rootRef)?.dependsOn || []);
  const walk = (list, parentPath = []) => (list || []).forEach((c, i) => {
    const row = out.components.length + 1;
    if (!c.name) { out.errors.push({ row, field: 'name', message: 'Component without name skipped.' }); return; }
    let comp = c.purl ? componentFromPurl(c.purl) : null;
    if (c.purl && !comp) out.errors.push({ row, field: 'purl', message: `Invalid purl "${c.purl}"; synthesized generic identity.` });
    if (!comp) comp = { purl: purlFor('generic', c.group ? `${c.group}/${c.name}` : c.name, c.version || null), ecosystem: 'generic', name: c.name, version: c.version || null, kind: kindFromCdx(c.type) };
    if (!comp.version && c.version) comp.version = c.version;
    comp.kind = c.type === 'library' ? comp.kind : kindFromCdx(c.type);
    comp.cpe = c.cpe || null;
    comp.ref = c['bom-ref'] || comp.purl;
    comp.direct = rootRef && j.dependencies ? directRefs.has(comp.ref) : null;
    comp.dependency_path = parentPath;
    const arch = (c.properties || []).find(p => /arch/i.test(p.name))?.value; if (arch) comp.architecture = arch;
    out.components.push(comp);
    if (c.components) walk(c.components, [...parentPath, comp.name]);
  });
  walk(j.components);
  for (const d of j.dependencies || []) for (const child of d.dependsOn || []) out.edges.push([d.ref, child]);
  // vulnerabilities embedded (CycloneDX VEX / scanner output)
  for (const v of j.vulnerabilities || []) for (const a of v.affects || []) out.findings.push({ id: v.id, ref: a.ref, source: v.source?.name, severity: v.ratings?.[0]?.severity, state: v.analysis?.state });
  computePaths(out);
  return out;
}

export function parseSPDX(j) {
  if (!/^SPDX-2\.[23]$/.test(j.spdxVersion)) throw new ParseError(`Unsupported SPDX version ${j.spdxVersion}; supported SPDX-2.2/2.3 JSON.`);
  const out = doc('spdx', { metadata: { name: j.name, created: j.creationInfo?.created, namespace: j.documentNamespace } });
  const describes = new Set(j.documentDescribes || (j.relationships || []).filter(r => r.relationshipType === 'DESCRIBES').map(r => r.relatedSpdxElement));
  const direct = new Set((j.relationships || []).filter(r => describes.has(r.spdxElementId) && r.relationshipType === 'DEPENDS_ON').map(r => r.relatedSpdxElement));
  (j.packages || []).forEach((p, i) => {
    if (describes.has(p.SPDXID)) return; // the described application itself
    const purlRef = (p.externalRefs || []).find(r => r.referenceType === 'purl')?.referenceLocator;
    const cpe = (p.externalRefs || []).find(r => /cpe/.test(r.referenceType))?.referenceLocator || null;
    let comp = purlRef ? componentFromPurl(purlRef) : null;
    if (!comp) { comp = { purl: purlFor('generic', p.name, p.versionInfo || null), ecosystem: 'generic', name: p.name, version: p.versionInfo || null, kind: 'library' }; if (!purlRef) out.errors.push({ row: i + 1, field: 'externalRefs', message: `Package "${p.name}" has no purl; matched only by generic identity.` }); }
    if (!comp.version && p.versionInfo && p.versionInfo !== 'NOASSERTION') comp.version = p.versionInfo;
    comp.cpe = cpe; comp.ref = p.SPDXID; comp.direct = direct.size ? direct.has(p.SPDXID) : null; comp.dependency_path = [];
    out.components.push(comp);
  });
  for (const r of j.relationships || []) if (r.relationshipType === 'DEPENDS_ON') out.edges.push([r.spdxElementId, r.relatedSpdxElement]);
  computePaths(out);
  return out;
}

const TRIVY_ECO = { npm: 'npm', yarn: 'npm', pnpm: 'npm', 'node-pkg': 'npm', pip: 'pypi', pipenv: 'pypi', poetry: 'pypi', 'python-pkg': 'pypi', jar: 'maven', pom: 'maven', gradle: 'maven', composer: 'composer', gomod: 'go', gobinary: 'go', cargo: 'cargo', 'rust-binary': 'cargo', nuget: 'nuget', 'dotnet-core': 'nuget', bundler: 'rubygems', gemspec: 'rubygems', debian: 'deb', ubuntu: 'deb', alpine: 'apk', amazon: 'rpm', redhat: 'rpm', centos: 'rpm', rocky: 'rpm', alma: 'rpm', 'oracle': 'rpm', suse: 'rpm' };
export function parseTrivy(j) {
  const out = doc('trivy', { metadata: { artifact: j.ArtifactName, type: j.ArtifactType, os: j.Metadata?.OS, digest: j.Metadata?.RepoDigests?.[0] || j.Metadata?.ImageID } });
  const distro = j.Metadata?.OS ? `${j.Metadata.OS.Family}:${j.Metadata.OS.Name}` : null;
  const seen = new Map();
  for (const r of j.Results || []) {
    const eco = TRIVY_ECO[r.Type] || 'generic';
    const add = (name, version, purl, extra = {}) => {
      let comp = purl ? componentFromPurl(purl) : null;
      if (!comp) comp = { purl: purlFor(eco, name, version, eco === 'rpm' || eco === 'deb' || eco === 'apk' ? { distro } : undefined), ecosystem: eco, name, version, kind: ['deb', 'rpm', 'apk'].includes(eco) ? 'os_package' : 'library', distro: ['deb', 'rpm', 'apk'].includes(eco) ? distro : null };
      if (!seen.has(comp.purl)) { comp.dependency_path = []; comp.direct = null; comp.ref = comp.purl; Object.assign(comp, extra); seen.set(comp.purl, comp); out.components.push(comp); }
      return seen.get(comp.purl);
    };
    for (const p of r.Packages || []) add(p.Name, p.Version ? (p.Release ? `${p.Epoch ? p.Epoch + ':' : ''}${p.Version}-${p.Release}` : p.Version) : null, p.Identifier?.PURL, { architecture: p.Arch || null });
    for (const v of r.Vulnerabilities || []) {
      const c = add(v.PkgName, v.InstalledVersion || null, v.PkgIdentifier?.PURL);
      out.findings.push({ id: v.VulnerabilityID, ref: c.purl, fixed: v.FixedVersion || null, severity: (v.Severity || '').toLowerCase(), source: 'trivy', title: v.Title });
    }
    for (const m of r.Misconfigurations || []) out.findings.push({ id: m.ID, kind: 'misconfiguration', target: r.Target, severity: (m.Severity || '').toLowerCase(), title: m.Title, source: 'trivy' });
    for (const s of r.Secrets || []) out.findings.push({ id: s.RuleID, kind: 'secret', target: r.Target, severity: (s.Severity || '').toLowerCase(), title: s.Title, source: 'trivy', line: s.StartLine });
  }
  return out;
}

export function parseSarif(j) {
  if (!Array.isArray(j.runs)) throw new ParseError('SARIF document has no runs.');
  const out = doc('sarif');
  for (const run of j.runs) {
    const tool = run.tool?.driver?.name || 'unknown';
    for (const r of run.results || []) {
      const loc = r.locations?.[0]?.physicalLocation;
      out.findings.push({ id: r.ruleId, kind: 'code', source: tool, severity: { error: 'high', warning: 'medium', note: 'low' }[r.level] || 'unknown', title: r.message?.text?.slice(0, 300), target: loc?.artifactLocation?.uri, line: loc?.region?.startLine });
    }
  }
  out.metadata.note = 'SARIF results are recorded as code findings; they do not contribute package inventory.';
  return out;
}

// Inventory rows: [{ecosystem|type, name, version, purl?, kind?, direct?, architecture?}]
const ECO_ALIASES = { php: 'composer', packagist: 'composer', java: 'maven', gradle: 'maven', node: 'npm', javascript: 'npm', typescript: 'npm', yarn: 'npm', pnpm: 'npm', python: 'pypi', pip: 'pypi', ruby: 'rubygems', gem: 'rubygems', golang: 'go', rust: 'cargo', crates: 'cargo', dotnet: 'nuget', '.net': 'nuget', debian: 'deb', ubuntu: 'deb', amazonlinux: 'rpm', 'amazon linux': 'rpm', rhel: 'rpm', alpine: 'apk' };
export function normalizeEcosystem(v) {
  const s = String(v || '').trim().toLowerCase();
  if (ECOSYSTEMS[s]) return s;
  if (ECO_ALIASES[s]) return ECO_ALIASES[s];
  const fromOsv = ecosystemFromOsv(v); return fromOsv;
}
export function parseInventoryRows(data, format) {
  const rows = Array.isArray(data) ? data : Array.isArray(data?.components) ? data.components : null;
  if (!rows) throw new ParseError('Expected an array of components or {components:[...]}.');
  if (rows.length > 50000) throw new ParseError('Too many rows (max 50,000 per import).');
  const out = doc(format);
  rows.forEach((r, i) => {
    const row = i + 1;
    if (!r || typeof r !== 'object') { out.errors.push({ row, message: 'Row is not an object.' }); return; }
    let comp = r.purl ? componentFromPurl(String(r.purl)) : null;
    if (r.purl && !comp) { out.errors.push({ row, field: 'purl', message: 'Invalid purl.' }); return; }
    if (!comp) {
      if (!r.name) { out.errors.push({ row, field: 'name', message: 'name is required when purl is absent.' }); return; }
      const eco = normalizeEcosystem(r.ecosystem || r.type || 'generic');
      if (r.ecosystem && eco === 'generic' && String(r.ecosystem).toLowerCase() !== 'generic') out.errors.push({ row, field: 'ecosystem', message: `Unknown ecosystem "${r.ecosystem}"; stored as generic (no version-range matching).`, severity: 'warning' });
      const version = r.version == null || r.version === '' ? null : String(r.version);
      comp = { purl: purlFor(eco, String(r.name), version, r.distro ? { distro: r.distro } : undefined), ecosystem: eco, name: String(r.name), version, kind: r.kind || (['deb', 'rpm', 'apk'].includes(eco) ? 'os_package' : 'library'), distro: r.distro || null };
    }
    if (!comp.version) out.errors.push({ row, field: 'version', message: `Version missing for ${comp.name}; recorded as Unknown.`, severity: 'warning' });
    comp.direct = r.direct == null || r.direct === '' ? null : ['true', '1', 'yes', true].includes(typeof r.direct === 'string' ? r.direct.toLowerCase() : r.direct);
    comp.architecture = r.architecture || r.arch || comp.architecture || null;
    comp.dependency_path = []; comp.ref = comp.purl;
    if (r.service) comp.service = String(r.service);
    if (r.version_kind) comp.version_kind = r.version_kind;
    out.components.push(comp);
  });
  return out;
}

export function parseCsv(text) {
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; continue; }
    if (c === '"') q = true; else if (c === ',') { row.push(cell); cell = ''; } else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; } else cell += c;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  const nonEmpty = rows.filter(r => r.some(c => c.trim() !== ''));
  if (!nonEmpty.length) return [];
  const header = nonEmpty[0].map(h => h.trim().toLowerCase());
  return nonEmpty.slice(1).map(r => Object.fromEntries(header.map((h, i) => [h, (r[i] ?? '').trim()])));
}

// ------------------------------------------------------------------ lockfiles / manifests (stack discovery)
export function parseNpmLock(j) {
  const out = doc('npm-lock');
  const pkgs = j.packages || {};
  const rootDeps = new Set(Object.keys({ ...(pkgs['']?.dependencies || {}), ...(pkgs['']?.devDependencies || {}) }));
  for (const [path, p] of Object.entries(pkgs)) {
    if (!path) continue;
    const name = p.name || path.split('node_modules/').pop();
    const chain = path.split('node_modules/').filter(Boolean).map(s => s.replace(/\/$/, ''));
    out.components.push({ purl: purlFor('npm', name, p.version || null), ecosystem: 'npm', name, version: p.version || null, kind: 'library', direct: chain.length === 1 && rootDeps.has(name), dependency_path: chain.slice(0, -1), dev: !!p.dev, ref: path });
  }
  if (!Object.keys(pkgs).length && j.dependencies) for (const [name, p] of Object.entries(j.dependencies)) out.components.push({ purl: purlFor('npm', name, p.version), ecosystem: 'npm', name, version: p.version, kind: 'library', direct: null, dependency_path: [] });
  return out;
}
export function parseComposerLock(j) {
  const out = doc('composer-lock');
  for (const [list, dev] of [[j.packages || [], false], [j['packages-dev'] || [], true]]) for (const p of list) out.components.push({ purl: purlFor('composer', p.name, String(p.version).replace(/^v/, '')), ecosystem: 'composer', name: p.name, version: String(p.version).replace(/^v/, ''), kind: /laravel\/framework|symfony\/symfony/.test(p.name) ? 'framework' : 'library', direct: null, dependency_path: [], dev });
  return out;
}
export function parseRequirements(text) {
  const out = doc('requirements');
  text.split(/\r?\n/).forEach((line, i) => {
    const l = line.replace(/#.*/, '').trim(); if (!l || l.startsWith('-')) return;
    const m = /^([A-Za-z0-9_.\-\[\]]+)\s*(==|===|>=|~=|<=|>|<)?\s*([^;\s]+)?/.exec(l);
    if (!m) { out.errors.push({ row: i + 1, message: 'Unparsed requirement line.' }); return; }
    const name = m[1].replace(/\[.*\]/, '').toLowerCase();
    const pinned = m[2] === '==' || m[2] === '===';
    out.components.push({ purl: purlFor('pypi', name, pinned ? m[3] : null), ecosystem: 'pypi', name, version: pinned ? m[3] : null, declared_constraint: m[2] ? `${m[2]}${m[3]}` : null, version_kind: 'declared', kind: 'library', direct: true, dependency_path: [] });
  });
  return out;
}
export function parseGoMod(text) {
  const out = doc('go-mod');
  const goVer = /^go\s+(\S+)/m.exec(text)?.[1];
  if (goVer) out.components.push({ purl: purlFor('generic', 'go-toolchain', goVer), ecosystem: 'generic', name: 'go', version: goVer, kind: 'runtime', direct: true, dependency_path: [], version_kind: 'declared' });
  const re = /^\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+(v[\w.\-+]+)(\s*\/\/\s*indirect)?/gm; let m;
  while ((m = re.exec(text))) out.components.push({ purl: purlFor('go', m[1], m[2]), ecosystem: 'go', name: m[1], version: m[2], kind: 'library', direct: !m[3], dependency_path: [] });
  return out;
}
export function parsePom(text) {
  const out = doc('pom');
  const props = {}; for (const m of text.matchAll(/<properties>([\s\S]*?)<\/properties>/g)) for (const p of m[1].matchAll(/<([\w.\-]+)>([^<]*)<\/\1>/g)) props[p[1]] = p[2].trim();
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = /<groupId>([^<]+)<\/groupId>/.exec(m[1])?.[1]?.trim(), a = /<artifactId>([^<]+)<\/artifactId>/.exec(m[1])?.[1]?.trim();
    let v = /<version>([^<]+)<\/version>/.exec(m[1])?.[1]?.trim() || null;
    if (v && /^\$\{(.+)\}$/.test(v)) v = props[/^\$\{(.+)\}$/.exec(v)[1]] || null;
    if (g && a) out.components.push({ purl: purlFor('maven', `${g}:${a}`, v), ecosystem: 'maven', name: `${g}:${a}`, version: v, kind: /spring-boot|spring-core|solr/.test(a) ? 'framework' : 'library', direct: true, dependency_path: [], version_kind: 'declared' });
  }
  return out;
}
export function parseGemfileLock(text) {
  const out = doc('gemfile-lock'); const specs = /GEM[\s\S]*?specs:\n([\s\S]*?)(\n\S|$)/.exec(text)?.[1] || '';
  for (const m of specs.matchAll(/^ {4}([\w\-.]+) \(([^)]+)\)$/gm)) out.components.push({ purl: purlFor('rubygems', m[1], m[2]), ecosystem: 'rubygems', name: m[1], version: m[2], kind: 'library', direct: null, dependency_path: [] });
  return out;
}
export function parseCargoLock(text) {
  const out = doc('cargo-lock');
  for (const m of text.matchAll(/\[\[package\]\]\s*\nname = "([^"]+)"\s*\nversion = "([^"]+)"/g)) out.components.push({ purl: purlFor('cargo', m[1], m[2]), ecosystem: 'cargo', name: m[1], version: m[2], kind: 'library', direct: null, dependency_path: [] });
  return out;
}
export function parseDockerfile(text) {
  const out = doc('dockerfile');
  for (const m of text.matchAll(/^\s*FROM\s+(?:--platform=(\S+)\s+)?(\S+)/gim)) {
    const ref = m[2]; if (/^[a-z0-9_-]+$/i.test(ref) && !ref.includes(':')) continue; // stage alias
    const [nameTag, digest] = ref.split('@'); const i = nameTag.lastIndexOf(':');
    const name = i > nameTag.lastIndexOf('/') ? nameTag.slice(0, i) : nameTag; const tag = i > nameTag.lastIndexOf('/') ? nameTag.slice(i + 1) : 'latest';
    out.components.push({ purl: `pkg:docker/${name}@${encodeURIComponent(digest || tag)}`, ecosystem: 'generic', name: `image:${name}`, version: tag, kind: 'runtime', direct: true, dependency_path: [], image_digest: digest || null, platform: m[1] || null, note: digest ? 'Pinned by digest.' : 'Tag only; a tag is mutable and does not identify the image.' });
  }
  return out;
}

function computePaths(out) {
  if (!out.edges.length) return;
  const parents = new Map();
  for (const [p, c] of out.edges) { if (!parents.has(c)) parents.set(c, p); }
  const byRef = new Map(out.components.map(c => [c.ref, c]));
  for (const c of out.components) {
    const path = []; let cur = parents.get(c.ref); const seen = new Set();
    while (cur && !seen.has(cur) && path.length < 25) { seen.add(cur); const pc = byRef.get(cur); if (!pc) break; path.unshift(pc.name); cur = parents.get(cur); }
    if (path.length) c.dependency_path = path;
    if (c.direct == null && parents.has(c.ref)) c.direct = !byRef.has(parents.get(c.ref));
  }
}
