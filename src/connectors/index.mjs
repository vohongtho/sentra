// Connector registry. Each adapter advertises capabilities, resource types, permissions and limits, implements a real
// health check and sync, and records health/freshness. A disconnected source never produces a successful observation.
import { id, sha256, badRequest, AppError } from '../util.mjs';
import { safeFetch } from '../notify/safe-fetch.mjs';
import { getSecretValue } from '../services/secrets.mjs';
import { upsertAdvisory, upsertSignal } from '../services/advisories.mjs';
import { recordSnapshot } from '../services/inventory.mjs';
import { parseDocument } from '../domain/parsers.mjs';
import { ECOSYSTEMS } from '../domain/versions.mjs';
import { purlFor, componentFromPurl } from '../domain/purl.mjs';
import { emit, RetryableError } from '../jobs/runtime.mjs';
import { log } from '../log.mjs';

const net = (app) => ({ allowPrivate: app.cfg.allowPrivateWebhookTargets, allowHttp: app.cfg.allowPrivateWebhookTargets, timeoutMs: 20000, maxBytes: 30_000_000 });
async function getJson(app, url, init = {}, tries = 3) {
  for (let i = 1; ; i++) {
    const r = await safeFetch(url, init, net(app));
    if (r.ok) return r.json();
    if ((r.status === 429 || r.status >= 500) && i < tries) { await new Promise(res => setTimeout(res, 500 * 2 ** i + Math.random() * 300)); continue; }
    throw new AppError(502, 'UPSTREAM_ERROR', `${new URL(url).host} responded ${r.status}`);
  }
}
const secretOf = async (app, conn) => (conn.secret_id ? getSecretValue(app.db, conn.org_id, conn.secret_id) : null);

// ------------------------------------------------------------------ OSV
const osv = {
  kind: 'osv', label: 'OSV.dev advisories', category: 'intelligence',
  capabilities: ['Incremental advisory sync for packages present in inventory', 'Aliases (CVE/GHSA/vendor)', 'Revisions and withdrawals'],
  resource_types: Object.entries(ECOSYSTEMS).filter(([, v]) => v.osv).map(([k]) => k), permissions: ['Public API; no credentials'], limits: 'querybatch ≤1000 queries/request; detail fetch per vulnerability.',
  needsSecret: false,
  async test(app, conn) { const j = await getJson(app, `${conn.config.api_base || 'https://api.osv.dev'}/v1/query`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' }) }); return { ok: true, detail: `${(j.vulns || []).length} sample vulnerabilities returned` }; },
  async sync(app, conn, helpers) {
    const base = conn.config.api_base || 'https://api.osv.dev';
    const comps = await app.db.query(`SELECT DISTINCT c.ecosystem, c.name, c.version FROM components c JOIN observations o ON o.component_id=c.id WHERE o.org_id=$1 AND c.version IS NOT NULL`, [conn.org_id]);
    const queries = comps.filter(c => ECOSYSTEMS[c.ecosystem]?.osv && !['deb', 'rpm', 'apk'].includes(c.ecosystem)).map(c => ({ package: { name: c.name, ecosystem: ECOSYSTEMS[c.ecosystem].osv }, version: c.version.replace(/^v/, c.ecosystem === 'go' ? 'v' : '') }));
    const ids = new Map();
    for (let i = 0; i < queries.length; i += 500) {
      const j = await getJson(app, `${base}/v1/querybatch`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries: queries.slice(i, i + 500) }) });
      for (const r of j.results || []) for (const v of r.vulns || []) ids.set(v.id, v.modified);
      if (await helpers?.isCancelled?.()) return { cancelled: true };
    }
    let updated = 0, unchanged = 0;
    for (const [vid, modified] of ids) {
      const known = await app.db.one(`SELECT a.modified_at FROM advisory_aliases al JOIN advisories a ON a.id=al.advisory_id WHERE al.alias=$1`, [vid]);
      if (known?.modified_at && modified && new Date(known.modified_at) >= new Date(modified)) { unchanged++; continue; }
      const adv = await getJson(app, `${base}/v1/vulns/${encodeURIComponent(vid)}`);
      const r = await app.db.tx(t => upsertAdvisory(t, adv, { source: 'osv' }));
      if (r.changed) updated++; else unchanged++;
    }
    return { queried_packages: queries.length, vulnerabilities: ids.size, updated, unchanged };
  },
};

// ------------------------------------------------------------------ CISA KEV
const kev = {
  kind: 'kev', label: 'CISA Known Exploited Vulnerabilities', category: 'intelligence',
  capabilities: ['KEV listing signal (separate from EPSS/PoC/observed exploitation)'], resource_types: ['CVE'], permissions: ['Public feed'], limits: 'Full catalogue download (~1-2 MB).', needsSecret: false,
  url: (c) => c.config.feed_url || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  async test(app, conn) { const j = await getJson(app, this.url(conn)); return { ok: true, detail: `catalog ${j.catalogVersion}, ${j.count} entries` }; },
  async sync(app, conn) {
    const j = await getJson(app, this.url(conn));
    const known = new Set((await app.db.query(`SELECT alias FROM advisory_aliases WHERE alias LIKE 'CVE-%'`)).map(r => r.alias));
    let matched = 0;
    for (const v of j.vulnerabilities || []) if (known.has(v.cveID)) { await upsertSignal(app.db, v.cveID, 'kev', { present: true, date_added: v.dateAdded, due_date: v.dueDate, ransomware: v.knownRansomwareCampaignUse, catalog_version: j.catalogVersion }, 'cisa-kev'); matched++; }
    return { catalog_version: j.catalogVersion, catalog_entries: j.count, matched };
  },
};

// ------------------------------------------------------------------ FIRST EPSS
const epss = {
  kind: 'epss', label: 'FIRST EPSS scores', category: 'intelligence',
  capabilities: ['EPSS probability + percentile (estimate, not evidence of exploitation)'], resource_types: ['CVE'], permissions: ['Public API'], limits: '≤100 CVEs per request.', needsSecret: false,
  async test(app, conn) { const j = await getJson(app, `${conn.config.api_base || 'https://api.first.org'}/data/v1/epss?cve=CVE-2021-44228`); return { ok: true, detail: `status ${j.status}` }; },
  async sync(app, conn) {
    const cves = (await app.db.query(`SELECT DISTINCT alias FROM advisory_aliases WHERE alias LIKE 'CVE-%'`)).map(r => r.alias);
    let n = 0;
    for (let i = 0; i < cves.length; i += 100) {
      const j = await getJson(app, `${conn.config.api_base || 'https://api.first.org'}/data/v1/epss?cve=${cves.slice(i, i + 100).join(',')}`);
      for (const d of j.data || []) { await upsertSignal(app.db, d.cve, 'epss', { score: Number(d.epss), percentile: Number(d.percentile), date: d.date }, 'first-epss'); n++; }
    }
    return { cves: cves.length, scored: n };
  },
};

// ------------------------------------------------------------------ The Hacker News (discovery context only)
export function parseRss(xml) {
  const items = [];
  for (const m of xml.matchAll(/<item>([\s\S]*?)<\/item>/g)) {
    const g = (tag) => { const r = new RegExp(`<${tag}>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?</${tag}>`).exec(m[1]); return r ? r[1].trim() : ''; };
    items.push({ title: g('title'), link: g('link'), published: g('pubDate'), description: g('description').replace(/<[^>]+>/g, '').slice(0, 500) });
  }
  return items;
}
const thn = {
  kind: 'thn', label: 'The Hacker News (RSS)', category: 'intelligence',
  capabilities: ['Discovery/context for the daily report; claims must be verified against primary sources'], resource_types: ['news'], permissions: ['Public RSS'], limits: 'Latest ~50 items.', needsSecret: false,
  url: (c) => c.config.feed_url || 'https://feeds.feedburner.com/TheHackersNews',
  async fetchItems(app, conn) { const r = await safeFetch(this.url(conn), {}, net(app)); if (!r.ok) throw new AppError(502, 'UPSTREAM_ERROR', `THN feed ${r.status}`); return parseRss(r.text); },
  async test(app, conn) { const items = await this.fetchItems(app, conn); return { ok: true, detail: `${items.length} items` }; },
  async sync(app, conn) { const items = await this.fetchItems(app, conn); await app.db.query('UPDATE connections SET cursor=$2 WHERE id=$1', [conn.id, { items: items.slice(0, 60), fetched_at: new Date().toISOString() }]); return { items: items.length }; },
};

// ------------------------------------------------------------------ GitHub repository discovery
const MANIFESTS = /(^|\/)(package-lock\.json|composer\.lock|requirements\.txt|go\.mod|pom\.xml|Gemfile\.lock|Cargo\.lock|Dockerfile)$/;
const IAC = /(\.tf$|(^|\/)docker-compose\.ya?ml$|(^|\/)(k8s|kubernetes|helm|charts)\/.*\.ya?ml$|template\.ya?ml$|(^|\/)\.github\/workflows\/.*\.ya?ml$)/;
const github = {
  kind: 'github', label: 'GitHub repository', category: 'inventory',
  capabilities: ['Read manifests/lockfiles/Dockerfiles/IaC for stack discovery (declared versions)', 'Issues for remediation tickets', 'PR merge webhooks'],
  resource_types: ['repository contents (read)', 'issues (write, optional)'], permissions: ['Fine-grained token: Contents read-only; Issues read/write only if ticketing is enabled; Metadata read'], limits: 'Up to 60 manifest files, 1 MB each, per sync.',
  needsSecret: true,
  headers: (token) => ({ Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Sentra' }),
  async test(app, conn) { const tok = await secretOf(app, conn); const j = await getJson(app, `${conn.config.api_base || 'https://api.github.com'}/repos/${conn.config.owner}/${conn.config.repo}`, { headers: this.headers(tok) }); return { ok: true, detail: `${j.full_name} (default branch ${j.default_branch})` }; },
  async listFiles(app, conn) {
    const tok = await secretOf(app, conn); const base = conn.config.api_base || 'https://api.github.com'; const { owner, repo } = conn.config;
    const ref = conn.config.ref || (await getJson(app, `${base}/repos/${owner}/${repo}`, { headers: this.headers(tok) })).default_branch;
    const tree = await getJson(app, `${base}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`, { headers: this.headers(tok) });
    const paths = (tree.tree || []).filter(t => t.type === 'blob' && (MANIFESTS.test(t.path) || IAC.test(t.path)) && !/node_modules\//.test(t.path) && (t.size || 0) < 1_000_000).slice(0, 60);
    const files = [];
    for (const p of paths) {
      const r = await safeFetch(`${base}/repos/${owner}/${repo}/contents/${p.path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(ref)}`, { headers: { ...this.headers(tok), Accept: 'application/vnd.github.raw' } }, net(app));
      if (r.ok) files.push({ path: p.path, content: r.text, sha: p.sha });
    }
    return { ref, commit: tree.sha, files };
  },
  async sync(app, conn) {
    const { ref, commit, files } = await this.listFiles(app, conn);
    const parsed = { format: 'repository', components: [], edges: [], errors: [], metadata: {} };
    const iac = [];
    for (const f of files) {
      if (IAC.test(f.path) && !MANIFESTS.test(f.path)) { iac.push(f.path); continue; }
      try { const d = parseDocument(f.content, { filename: f.path }); for (const c of d.components) parsed.components.push({ ...c, version_kind: 'declared', manifest: f.path }); } catch (e) { parsed.errors.push({ file: f.path, message: e.message }); }
    }
    const snap = await app.db.tx(t => recordSnapshot(t, { orgId: conn.org_id, projectId: conn.project_id, source: `connector:${conn.id}`, method: 'repository_scan', parsed, contentSha256: 'sha256:' + sha256(files.map(f => f.sha).join(',')), versionKind: 'declared' }));
    return { ref, commit, manifests: files.length - iac.length, iac_files: iac, components: snap.componentCount, snapshot_id: snap.snapshotId, errors: parsed.errors };
  },
};

// ------------------------------------------------------------------ AWS read-only inventory
const aws = {
  kind: 'aws', label: 'AWS (read-only, selected resource types)', category: 'inventory',
  capabilities: ['Lambda: runtime + architecture per function', 'EC2: instance architecture, platform, AMI', 'ECR: image digests for allowlisted repositories'],
  resource_types: ['lambda:function', 'ec2:instance', 'ecr:image'], permissions: ['lambda:ListFunctions', 'ec2:DescribeInstances', 'ecr:DescribeImages (allowlisted repositories)'], limits: 'One region per connection; pagination bounded to 1000 resources.',
  needsSecret: false,
  async clients(app, conn) {
    const creds = conn.secret_id ? JSON.parse(await secretOf(app, conn)) : undefined;
    const base = { region: conn.config.region || 'us-east-1', ...(creds ? { credentials: { accessKeyId: creds.access_key_id, secretAccessKey: creds.secret_access_key, sessionToken: creds.session_token } } : {}), ...(conn.config.endpoint ? { endpoint: conn.config.endpoint } : {}) };
    const [{ LambdaClient, ListFunctionsCommand }, { EC2Client, DescribeInstancesCommand }, { ECRClient, DescribeImagesCommand }] = await Promise.all([import('@aws-sdk/client-lambda'), import('@aws-sdk/client-ec2'), import('@aws-sdk/client-ecr')]);
    return { lambda: new LambdaClient(base), ec2: new EC2Client(base), ecr: new ECRClient(base), ListFunctionsCommand, DescribeInstancesCommand, DescribeImagesCommand };
  },
  async test(app, conn) { const c = await this.clients(app, conn); const r = await c.lambda.send(new c.ListFunctionsCommand({ MaxItems: 1 })); return { ok: true, detail: `Lambda reachable (${(r.Functions || []).length} sampled)` }; },
  async sync(app, conn) {
    const c = await this.clients(app, conn); const types = conn.config.resource_types || ['lambda:function', 'ec2:instance'];
    const assets = [];
    if (types.includes('lambda:function')) { let marker; do { const r = await c.lambda.send(new c.ListFunctionsCommand({ Marker: marker })); for (const f of r.Functions || []) assets.push({ kind: 'function', identifier: f.FunctionArn, name: f.FunctionName, architecture: (f.Architectures || ['x86_64'])[0], attributes: { runtime: f.Runtime, last_modified: f.LastModified, identity: f.Role || undefined }, components: f.Runtime ? [runtimeComponent(f.Runtime)] : [] }); marker = r.NextMarker; } while (marker && assets.length < 1000); }
    if (types.includes('ec2:instance')) { let next; do { const r = await c.ec2.send(new c.DescribeInstancesCommand({ NextToken: next })); for (const res of r.Reservations || []) for (const i of res.Instances || []) assets.push({ kind: 'server', identifier: i.InstanceId, name: (i.Tags || []).find(t => t.Key === 'Name')?.Value || i.InstanceId, architecture: i.Architecture === 'arm64' ? 'arm64' : 'x86_64', os: i.PlatformDetails, attributes: { image_id: i.ImageId, state: i.State?.Name, type: i.InstanceType, identity: i.IamInstanceProfile?.Arn || undefined }, components: [] }); next = r.NextToken; } while (next && assets.length < 1000); }
    if (types.includes('ecr:image')) for (const repo of conn.config.ecr_repositories || []) { const r = await c.ecr.send(new c.DescribeImagesCommand({ repositoryName: repo, maxResults: 100 })); for (const im of r.imageDetails || []) assets.push({ kind: 'container_image', identifier: `${repo}@${im.imageDigest}`, name: `${repo}:${(im.imageTags || ['untagged'])[0]}`, attributes: { digest: im.imageDigest, pushed_at: im.imagePushedAt, tags: im.imageTags }, components: [] }); }
    return persistAssets(app, conn, assets, 'aws_api');
  },
};
function runtimeComponent(rt) {
  const m = /^(nodejs|python|java|dotnet|ruby|go|provided)(\d[\d.]*)?/.exec(rt) || [];
  const name = { nodejs: 'node', python: 'python', java: 'java', dotnet: 'dotnet', ruby: 'ruby' }[m[1]] || rt;
  const version = (m[2] || '').replace(/\.x$/, '') || null;
  return { purl: purlFor('generic', `aws-lambda-runtime/${name}`, version), ecosystem: 'generic', name: `${name} (Lambda managed runtime)`, version, kind: 'runtime', version_kind: 'runtime', direct: null, dependency_path: [] };
}
async function persistAssets(app, conn, assets, method) {
  let snaps = 0;
  await app.db.tx(async (t) => {
    for (const a of assets) {
      const row = (await t.query(`INSERT INTO assets (id, org_id, kind, identifier, name, architecture, os, attributes, last_observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
        ON CONFLICT (org_id, kind, identifier) DO UPDATE SET name=EXCLUDED.name, architecture=EXCLUDED.architecture, os=EXCLUDED.os, attributes=EXCLUDED.attributes, last_observed_at=now() RETURNING id`, [id('ast'), conn.org_id, a.kind, a.identifier, a.name, a.architecture || null, a.os || null, a.attributes || {}]))[0];
      if (conn.project_id) await t.query(`INSERT INTO asset_projects (asset_id, project_id, environment_id) VALUES ($1,$2,$3) ON CONFLICT (asset_id, project_id) DO UPDATE SET environment_id=COALESCE(EXCLUDED.environment_id, asset_projects.environment_id)`, [row.id, conn.project_id, conn.config.environment_id || null]);
      if (a.components?.length && conn.project_id) { await recordSnapshot(t, { orgId: conn.org_id, projectId: conn.project_id, assetId: row.id, environmentId: conn.config.environment_id || null, source: `connector:${conn.id}`, method, parsed: { format: method, components: a.components, edges: [] }, contentSha256: 'sha256:' + sha256(JSON.stringify(a.components)), versionKind: 'runtime', confidence: 'verified' }); snaps++; }
    }
  });
  return { assets: assets.length, snapshots: snaps };
}

// ------------------------------------------------------------------ Dependency-Track
const dependencyTrack = {
  kind: 'dependency_track', label: 'OWASP Dependency-Track', category: 'inventory',
  capabilities: ['Import component inventory of a Dependency-Track project version'], resource_types: ['project components'], permissions: ['API key with VIEW_PORTFOLIO'], limits: '500 components/page, 20 pages.', needsSecret: true,
  async test(app, conn) { const key = await secretOf(app, conn); const j = await getJson(app, `${conn.config.api_base}/api/version`, { headers: { 'X-Api-Key': key } }); return { ok: true, detail: `Dependency-Track ${j.version}` }; },
  async sync(app, conn) {
    const key = await secretOf(app, conn); const comps = [];
    for (let page = 1; page <= 20; page++) {
      const j = await getJson(app, `${conn.config.api_base}/api/v1/component/project/${encodeURIComponent(conn.config.project_uuid)}?pageSize=500&pageNumber=${page}`, { headers: { 'X-Api-Key': key } });
      for (const c of j) { const comp = c.purl ? componentFromPurl(c.purl) : { purl: purlFor('generic', c.name, c.version), ecosystem: 'generic', name: c.name, version: c.version || null, kind: 'library' }; if (comp) comps.push({ ...comp, direct: null, dependency_path: [] }); }
      if (j.length < 500) break;
    }
    return persistAssets(app, conn, [{ kind: 'application', identifier: `dtrack:${conn.config.project_uuid}`, name: conn.config.display_name || `Dependency-Track ${conn.config.project_uuid}`, components: comps }], 'dependency_track');
  },
};

// ------------------------------------------------------------------ Azure DevOps (ticketing only) & notification channels are described here for the capability matrix
const azureDevops = { kind: 'azure_devops', label: 'Azure DevOps Boards', category: 'ticketing', capabilities: ['Create/close Product Backlog Items for remediation ownership'], resource_types: ['work items'], permissions: ['PAT: Work Items (Read & write)'], limits: 'Per-finding idempotent creation.', needsSecret: true, async test(app, conn) { const { adapterFor } = await import('../services/tickets.mjs'); const r = await (await adapterFor(app, conn)).test(); if (!r.ok) throw new AppError(502, 'UPSTREAM_ERROR', `Azure DevOps responded ${r.status}`); return { ok: true, detail: 'project reachable' }; } };

// ------------------------------------------------------------------ Wazuh (runtime packages via syscollector)
const WAZUH_FORMAT = { rpm: 'rpm', deb: 'deb', apk: 'apk', pypi: 'pypi', npm: 'npm' };
function wazuhDistro(os) {
  const plat = String(os?.platform || '').toLowerCase(); const major = String(os?.major || os?.version || '').split('.')[0];
  const fam = { amzn: 'amzn', amazon: 'amzn', centos: 'centos', rhel: 'rhel', rocky: 'rocky', almalinux: 'almalinux', ubuntu: 'ubuntu', debian: 'debian', alpine: 'alpine' }[plat];
  return fam && major ? `${fam}-${fam === 'ubuntu' ? String(os.version || '').split(' ')[0].split('.').slice(0, 2).join('.') : major}` : null;
}
const wazuh = {
  kind: 'wazuh', label: 'Wazuh (runtime packages)', category: 'inventory',
  capabilities: ['Installed OS and language packages per active agent (syscollector)', 'Agent OS, distribution and architecture for backport matching'],
  resource_types: ['agents', 'syscollector packages'], permissions: ['Wazuh API user with read-only RBAC on agents:read and syscollector:read'], limits: 'Up to 200 agents and 5,000 packages per agent per sync.',
  needsSecret: true,
  async token(app, conn) {
    const cred = JSON.parse(await secretOf(app, conn));
    const r = await safeFetch(`${conn.config.api_base}/security/user/authenticate`, { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(`${cred.user}:${cred.password}`).toString('base64') } }, net(app));
    if (!r.ok) throw new AppError(502, 'UPSTREAM_ERROR', `Wazuh authentication failed (${r.status})`);
    return r.json().data.token;
  },
  async test(app, conn) { const t = await this.token(app, conn); const j = await getJson(app, `${conn.config.api_base}/agents?status=active&limit=1`, { headers: { Authorization: `Bearer ${t}` } }); return { ok: true, detail: `${j.data.total_affected_items} active agent(s)` }; },
  async sync(app, conn) {
    const t = await this.token(app, conn); const H = { headers: { Authorization: `Bearer ${t}` } };
    const agents = (await getJson(app, `${conn.config.api_base}/agents?status=active&limit=200&select=id,name,os,ip`, H)).data.affected_items.filter(a => a.id !== '000');
    const assets = [];
    for (const a of agents) {
      const pk = (await getJson(app, `${conn.config.api_base}/syscollector/${encodeURIComponent(a.id)}/packages?limit=5000`, H)).data.affected_items;
      const distro = wazuhDistro(a.os); const arch = /aarch64|arm64/.test(a.os?.arch || '') ? 'arm64' : a.os?.arch ? 'x86_64' : null;
      const components = pk.map(p => { const eco = WAZUH_FORMAT[p.format] || 'generic'; const isOs = ['rpm', 'deb', 'apk'].includes(eco); return { purl: purlFor(eco, p.name, p.version || null, isOs && distro ? { distro } : undefined), ecosystem: eco, name: p.name, version: p.version || null, kind: isOs ? 'os_package' : 'library', distro: isOs ? distro : null, architecture: arch, direct: null, dependency_path: [] }; });
      assets.push({ kind: 'server', identifier: `wazuh:${a.id}:${a.name}`, name: a.name, architecture: arch, os: [a.os?.name, a.os?.version].filter(Boolean).join(' '), attributes: { wazuh_agent_id: a.id, ip: a.ip }, components });
    }
    return persistAssets(app, conn, assets, 'wazuh_syscollector');
  },
};

// ------------------------------------------------------------------ DefectDojo (external findings as references)
const defectDojo = {
  kind: 'defectdojo', label: 'DefectDojo (findings)', category: 'findings',
  capabilities: ['Import active DefectDojo findings for a product as linked external references', 'Link to Sentra findings by CVE/GHSA alias and component'],
  resource_types: ['findings (read)'], permissions: ['API v2 token of a user with read access to the product'], limits: '1,000 findings per sync (paged by 100).',
  needsSecret: true,
  async test(app, conn) { const key = await secretOf(app, conn); const j = await getJson(app, `${conn.config.api_base}/api/v2/findings/?limit=1&product=${encodeURIComponent(conn.config.product_id)}`, { headers: { Authorization: `Token ${key}` } }); return { ok: true, detail: `${j.count} findings in product` }; },
  async sync(app, conn) {
    if (!conn.project_id) throw new AppError(400, 'PROJECT_REQUIRED', 'DefectDojo connections must be project-scoped.');
    const key = await secretOf(app, conn); let url = `${conn.config.api_base}/api/v2/findings/?active=true&limit=100&product=${encodeURIComponent(conn.config.product_id)}`;
    let n = 0, linked = 0;
    for (let page = 0; url && page < 10; page++) {
      const j = await getJson(app, url, { headers: { Authorization: `Token ${key}` } });
      for (const f of j.results || []) {
        const vids = [...new Set([...(f.vulnerability_ids || []).map(v => v.vulnerability_id), f.cve].filter(Boolean))];
        const match = vids.length ? await app.db.one(`SELECT fi.id FROM findings fi JOIN components c ON c.id=fi.component_id WHERE fi.project_id=$1 AND fi.advisory_id IN (SELECT advisory_id FROM advisory_aliases WHERE alias = ANY($2)) AND ($3::text IS NULL OR c.name ILIKE '%' || $3) ORDER BY fi.priority LIMIT 1`, [conn.project_id, vids, f.component_name || null]) : null;
        await app.db.query(`INSERT INTO external_findings (id, org_id, project_id, connection_id, external_id, title, severity, vulnerability_ids, component, component_version, state, url, linked_finding_id, seen_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now()) ON CONFLICT (connection_id, external_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, state=EXCLUDED.state, linked_finding_id=EXCLUDED.linked_finding_id, seen_at=now()`,
        [id('xf'), conn.org_id, conn.project_id, conn.id, String(f.id), f.title, String(f.severity || '').toLowerCase(), JSON.stringify(vids), f.component_name || null, f.component_version || null, f.active ? (f.verified ? 'verified' : 'active') : 'inactive', `${conn.config.api_base}/finding/${f.id}`, match?.id || null]);
        n++; if (match) linked++;
      }
      url = j.next || null;
    }
    return { imported: n, linked_to_sentra_findings: linked, note: 'DefectDojo states are references only; Sentra remains the source of truth for lifecycle.' };
  },
};

export const CONNECTORS = { osv, kev, epss, thn, github, aws, dependency_track: dependencyTrack, azure_devops: azureDevops, wazuh, defectdojo: defectDojo };
export function connectorCatalog() {
  return Object.values(CONNECTORS).map(c => ({ kind: c.kind, label: c.label, category: c.category, capabilities: c.capabilities, resource_types: c.resource_types, permissions: c.permissions, limits: c.limits, needs_secret: c.needsSecret, syncable: !!c.sync }));
}

export async function testConnection(app, conn) {
  const c = CONNECTORS[conn.kind]; if (!c) throw badRequest('Unknown connector kind.');
  try {
    const r = await c.test(app, conn);
    await app.db.query(`UPDATE connections SET status='connected', last_check_at=now(), last_error=NULL WHERE id=$1`, [conn.id]);
    return { ok: true, ...r };
  } catch (e) {
    await app.db.query(`UPDATE connections SET status='failed', last_check_at=now(), last_error=$2 WHERE id=$1`, [conn.id, String(e.message).slice(0, 500)]);
    return { ok: false, error: e.message };
  }
}

export async function syncConnection(app, conn, helpers) {
  const c = CONNECTORS[conn.kind];
  if (!c?.sync) throw new AppError(400, 'NOT_SYNCABLE', `${conn.kind} has no sync capability.`);
  if (['disconnected', 'disabled'].includes(conn.status)) throw new AppError(409, 'CONNECTION_DISCONNECTED', 'A disconnected source cannot produce observations. Reconnect it first.');
  try {
    const result = await c.sync(app, conn, helpers);
    await app.db.query(`UPDATE connections SET status='connected', last_check_at=now(), last_success_at=now(), last_error=NULL WHERE id=$1`, [conn.id]);
    log.info('connector_synced', { kind: conn.kind, connection_id: conn.id, result });
    return result;
  } catch (e) {
    await app.db.query(`UPDATE connections SET status='failed', last_check_at=now(), last_error=$2 WHERE id=$1`, [conn.id, String(e.message).slice(0, 500)]);
    await emit(app.db, conn.org_id, 'connector.failed', { connection_id: conn.id, connection_name: conn.name, kind: conn.kind, project_id: conn.project_id, summary: `Connector ${conn.name} (${conn.kind}) failed: ${e.message}` });
    throw e instanceof AppError && e.status < 500 ? e : new RetryableError(e.message);
  }
}

/** Disconnect: stop access, mark observations from this source stale, preserve history. */
export async function disconnect(app, conn) {
  await app.db.tx(async (t) => {
    await t.query(`UPDATE connections SET status='disconnected', last_error='Disconnected by user' WHERE id=$1`, [conn.id]);
    await t.query(`UPDATE observations SET stale=true WHERE source=$1`, [`connector:${conn.id}`]);
    await emit(t, conn.org_id, 'inventory.stale', { connection_id: conn.id, project_id: conn.project_id, summary: `Observations from ${conn.name} are stale after disconnect; assessments relying on them are incomplete.` });
  });
}
