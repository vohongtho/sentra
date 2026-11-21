// Package URL (purl) parsing/formatting — https://github.com/package-url/purl-spec
import { ecosystemFromPurlType, ECOSYSTEMS } from './versions.mjs';

export function parsePurl(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;
  let rest = purl.slice(4);
  let subpath = null, qualifiers = {};
  const hash = rest.indexOf('#'); if (hash >= 0) { subpath = rest.slice(hash + 1); rest = rest.slice(0, hash); }
  const q = rest.indexOf('?');
  if (q >= 0) {
    for (const kv of rest.slice(q + 1).split('&')) { const [k, v] = kv.split('='); if (k) qualifiers[k.toLowerCase()] = decodeURIComponent(v || ''); }
    rest = rest.slice(0, q);
  }
  let version = null;
  const at = rest.lastIndexOf('@');
  if (at > rest.indexOf('/')) { version = decodeURIComponent(rest.slice(at + 1)); rest = rest.slice(0, at); }
  const parts = rest.split('/').map(decodeURIComponent);
  const type = parts.shift()?.toLowerCase();
  if (!type || !parts.length) return null;
  const name = parts.pop();
  const namespace = parts.length ? parts.join('/') : null;
  return { type, namespace, name, version, qualifiers, subpath };
}

export function formatPurl({ type, namespace, name, version, qualifiers }) {
  const enc = (s) => encodeURIComponent(s).replace(/%2F/gi, '/').replace(/%40/g, '%40');
  let s = `pkg:${type}/`;
  if (namespace) s += namespace.split('/').map(p => encodeURIComponent(p)).join('/') + '/';
  s += encodeURIComponent(name);
  if (version) s += '@' + encodeURIComponent(version);
  const q = Object.entries(qualifiers || {}).filter(([, v]) => v != null && v !== '').sort();
  if (q.length) s += '?' + q.map(([k, v]) => `${k}=${enc(String(v))}`).join('&');
  return s;
}

/** Normalize to the internal component identity. */
export function componentFromPurl(purl, extra = {}) {
  const p = parsePurl(purl);
  if (!p) return null;
  const ecosystem = ecosystemFromPurlType(p.type);
  // OSV package names: maven group:artifact, npm @scope/name, composer vendor/name, go full module path
  let name = p.name;
  if (p.namespace) {
    if (ecosystem === 'maven') name = `${p.namespace}:${p.name}`;
    else if (['npm', 'composer', 'go', 'swift'].includes(ecosystem)) name = `${p.namespace}/${p.name}`;
  }
  const distro = p.qualifiers.distro || null;
  return {
    purl: formatPurl({ ...p, qualifiers: pick(p.qualifiers, ['arch', 'distro', 'epoch']) }),
    ecosystem, namespace: p.namespace, name, version: p.version || null,
    kind: ['deb', 'rpm', 'apk'].includes(ecosystem) ? 'os_package' : 'library',
    distro, architecture: p.qualifiers.arch || null, ...extra,
  };
}

export function purlFor(ecosystem, name, version, qualifiers) {
  const type = (ECOSYSTEMS[ecosystem] || ECOSYSTEMS.generic).purl;
  let namespace = null, n = name;
  if (ecosystem === 'maven' && name.includes(':')) [namespace, n] = name.split(':');
  else if (['npm', 'composer', 'go', 'swift'].includes(ecosystem) && name.includes('/')) { const i = name.lastIndexOf('/'); namespace = name.slice(0, i); n = name.slice(i + 1); }
  return formatPurl({ type, namespace, name: n, version, qualifiers });
}
const pick = (o, keys) => Object.fromEntries(Object.entries(o).filter(([k]) => keys.includes(k)));
