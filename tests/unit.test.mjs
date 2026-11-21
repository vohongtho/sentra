import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions, evaluateRanges, ecosystemFromOsv } from '../src/domain/versions.mjs';
import { parseDocument, parseCsv } from '../src/domain/parsers.mjs';
import { parsePurl, componentFromPurl } from '../src/domain/purl.mjs';
import { nextOccurrence, occurrencesBetween } from '../src/domain/timezone.mjs';
import { computePriority, canTransition, slaDue } from '../src/domain/policy.mjs';
import { cvss3Score } from '../src/services/advisories.mjs';
import { redact, redactText } from '../src/log.mjs';
import { isPrivateAddress } from '../src/notify/safe-fetch.mjs';
import { normDistro, normArch } from '../src/services/matching.mjs';
import { csvCell } from '../src/util.mjs';

const lt = (eco, a, b) => assert.equal(compareVersions(eco, a, b), -1, `${eco}: ${a} < ${b}`);
const eq = (eco, a, b) => assert.equal(compareVersions(eco, a, b), 0, `${eco}: ${a} == ${b}`);
// Credential-shaped fixtures are assembled at runtime so no literal key-like strings live in the repository.
const fake = (prefix, n = 20) => prefix + 'X'.repeat(n);

test('semver/npm ordering incl. prereleases', () => { lt('npm', '1.2.3', '1.10.0'); lt('npm', '1.0.0-rc.1', '1.0.0'); lt('npm', '1.0.0-alpha', '1.0.0-alpha.1'); lt('npm', '1.0.0-alpha.beta', '1.0.0-beta'); eq('npm', 'v2.0.0', '2.0.0'); });
test('PEP 440 ordering (dev < pre < final < post)', () => { lt('pypi', '1.0.dev1', '1.0a1'); lt('pypi', '1.0a1', '1.0b2'); lt('pypi', '1.0rc1', '1.0'); lt('pypi', '1.0', '1.0.post1'); lt('pypi', '1!0.5', '1!1.0'); lt('pypi', '2.0', '1!0.1'); eq('pypi', '1.0', '1.0.0'); });
test('Maven ComparableVersion qualifiers', () => { lt('maven', '1.0-alpha', '1.0-beta'); lt('maven', '1.0-rc1', '1.0'); lt('maven', '1.0-SNAPSHOT', '1.0'); lt('maven', '1.0', '1.0-sp1'); eq('maven', '1.0', '1.0.0'); eq('maven', '1.0-final', '1'); lt('maven', '2.9', '2.10'); });
test('RPM rpmvercmp with epoch, tilde, distro release', () => { lt('rpm', '1.20.0-1.amzn2023.0.5', '1.20.0-1.amzn2023.0.10'); lt('rpm', '2.0-1', '1:1.0-1'); lt('rpm', '1.0~rc1-1', '1.0-1'); lt('rpm', '3.0.8-1.amzn2023.0.9', '3.0.8-1.amzn2023.0.12'); });
test('Debian dpkg ordering with backport tilde', () => { lt('deb', '1.2.3-1~deb12u1', '1.2.3-1'); lt('deb', '2.0', '1:1.0'); lt('deb', '1.0a', '1.0b'); lt('deb', '1.0~beta', '1.0'); });
test('Alpine apk and RubyGems', () => { lt('apk', '3.1.4-r2', '3.1.4-r10'); lt('apk', '1.0_rc1', '1.0'); lt('apk', '1.0', '1.0_p1'); lt('rubygems', '1.0.0.pre', '1.0.0'); lt('rubygems', '1.9', '1.10'); });

test('OSV range evaluation: affected, fixed, last_affected, explicit, unknown, multiple intervals', () => {
  const r = [{ range_type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }];
  assert.equal(evaluateRanges('npm', '4.17.20', r).status, 'affected');
  assert.equal(evaluateRanges('npm', '4.17.20', r).fixed, '4.17.21');
  assert.equal(evaluateRanges('npm', '4.17.21', r).status, 'not_affected');
  const m = [{ range_type: 'ECOSYSTEM', events: [{ introduced: '2.0-beta9' }, { fixed: '2.15.0' }] }];
  assert.equal(evaluateRanges('maven', '2.15.0', m).status, 'not_affected');
  assert.equal(evaluateRanges('maven', '2.0', m).status, 'affected');
  const la = [{ range_type: 'ECOSYSTEM', events: [{ introduced: '1.0' }, { last_affected: '1.4' }] }];
  assert.equal(evaluateRanges('pypi', '1.4', la).status, 'affected');
  assert.equal(evaluateRanges('pypi', '1.4.1', la).status, 'not_affected');
  assert.equal(evaluateRanges('npm', '1.0.0', [{ range_type: 'SEMVER', events: [], versions: ['1.0.0'] }]).status, 'affected');
  assert.equal(evaluateRanges('npm', null, r).status, 'unknown');
  assert.equal(evaluateRanges('npm', '1.0.0', [{ range_type: 'GIT', events: [{ introduced: 'abc' }] }]).status, 'unknown');
  const multi = [{ range_type: 'ECOSYSTEM', events: [{ introduced: '1.0' }, { fixed: '1.2' }, { introduced: '2.0' }, { fixed: '2.3' }] }];
  assert.equal(evaluateRanges('npm', '1.5.0', multi).status, 'not_affected');
  assert.equal(evaluateRanges('npm', '2.1.0', multi).status, 'affected');
  assert.equal(evaluateRanges('npm', '2.1.0', multi).fixed, '2.3');
});
test('ecosystem mapping from OSV names incl. distributions', () => { assert.equal(ecosystemFromOsv('Amazon Linux:2023'), 'rpm'); assert.equal(ecosystemFromOsv('Debian:12'), 'deb'); assert.equal(ecosystemFromOsv('Packagist'), 'composer'); assert.equal(ecosystemFromOsv('crates.io'), 'cargo'); assert.equal(normDistro('amzn-2023'), 'amazonlinux:2023'); assert.equal(normDistro('amazonlinux:2023'), 'amazonlinux:2023'); assert.equal(normArch('aarch64'), 'arm64'); });

test('purl parsing for scoped npm, maven, composer, rpm qualifiers', () => {
  assert.equal(componentFromPurl('pkg:npm/%40acme/xml-parser@2.7.0').name, '@acme/xml-parser');
  assert.equal(componentFromPurl('pkg:maven/org.example/core-lib@2.14.1').name, 'org.example:core-lib');
  assert.equal(componentFromPurl('pkg:composer/acme/http-client@7.3.0').name, 'acme/http-client');
  const r = componentFromPurl('pkg:rpm/amzn/openssl-libs@3.0.8-1.amzn2023.0.9?arch=aarch64&distro=amzn-2023');
  assert.equal(r.ecosystem, 'rpm'); assert.equal(r.architecture, 'aarch64'); assert.equal(r.distro, 'amzn-2023');
  assert.equal(parsePurl('not-a-purl'), null);
});

test('CycloneDX parsing: direct/transitive, paths, invalid input, missing versions', () => {
  const doc = { bomFormat: 'CycloneDX', specVersion: '1.5', metadata: { component: { 'bom-ref': 'root', name: 'app' } }, components: [{ 'bom-ref': 'a', name: 'a', version: '1.0.0', purl: 'pkg:npm/a@1.0.0' }, { 'bom-ref': 'b', name: 'b', version: '2.0.0', purl: 'pkg:npm/b@2.0.0' }, { name: 'nover' }], dependencies: [{ ref: 'root', dependsOn: ['a'] }, { ref: 'a', dependsOn: ['b'] }] };
  const p = parseDocument(JSON.stringify(doc));
  assert.equal(p.format, 'cyclonedx');
  const a = p.components.find(c => c.name === 'a'), b = p.components.find(c => c.name === 'b');
  assert.equal(a.direct, true); assert.equal(b.direct, false); assert.deepEqual(b.dependency_path, ['a']);
  assert.equal(p.components.find(c => c.name === 'nover').version, null);
  assert.throws(() => parseDocument(JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '9.9' })), /Unsupported CycloneDX/);
  assert.throws(() => parseDocument('{not json'), /not valid JSON/);
});
test('SPDX, Trivy, CSV, YAML, lockfiles, Dockerfile', () => {
  const spdx = parseDocument(JSON.stringify({ spdxVersion: 'SPDX-2.3', documentDescribes: ['SPDXRef-app'], packages: [{ SPDXID: 'SPDXRef-app', name: 'app' }, { SPDXID: 'SPDXRef-x', name: 'x', versionInfo: '1.2.3', externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:pypi/x@1.2.3' }] }], relationships: [{ spdxElementId: 'SPDXRef-app', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-x' }] }));
  assert.equal(spdx.components.length, 1); assert.equal(spdx.components[0].ecosystem, 'pypi'); assert.equal(spdx.components[0].direct, true);
  const trivy = parseDocument(JSON.stringify({ SchemaVersion: 2, ArtifactName: 'img', Metadata: { OS: { Family: 'amazon', Name: '2023' } }, Results: [{ Type: 'amazon', Packages: [{ Name: 'openssl-libs', Version: '3.0.8', Release: '1.amzn2023.0.9', Arch: 'aarch64' }], Vulnerabilities: [{ VulnerabilityID: 'SYNTH-X', PkgName: 'openssl-libs', InstalledVersion: '3.0.8-1.amzn2023.0.9', Severity: 'HIGH' }] }] }));
  assert.equal(trivy.components[0].ecosystem, 'rpm'); assert.equal(trivy.components[0].version, '3.0.8-1.amzn2023.0.9'); assert.equal(trivy.findings.length, 1);
  const csv = parseDocument('ecosystem,name,version,direct\nnpm,express,4.18.2,true\nphp,acme/x,,\n,,1.0,\n', { filename: 'inv.csv' });
  assert.equal(csv.components.length, 2); assert.equal(csv.components[1].ecosystem, 'composer'); assert.equal(csv.components[1].version, null);
  assert.ok(csv.errors.some(e => e.row === 3 && e.field === 'name'));
  const y = parseDocument('components:\n  - ecosystem: maven\n    name: com.acme:x\n    version: "1.0"\n', { filename: 'inv.yaml' });
  assert.equal(y.components[0].name, 'com.acme:x');
  const lock = parseDocument(JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { a: '^1' } }, 'node_modules/a': { version: '1.0.0' }, 'node_modules/a/node_modules/b': { version: '2.0.0' } } }), { filename: 'package-lock.json' });
  assert.equal(lock.components.find(c => c.name === 'a').direct, true); assert.deepEqual(lock.components.find(c => c.name === 'b').dependency_path, ['a']);
  const req = parseDocument('django==4.2.1\nrequests>=2\n', { filename: 'requirements.txt' });
  assert.equal(req.components[0].version, '4.2.1'); assert.equal(req.components[1].version, null);
  const df = parseDocument('FROM node:20-alpine AS build\nFROM build\nFROM nginx@sha256:' + 'a'.repeat(64) + '\n', { filename: 'Dockerfile' });
  assert.equal(df.components.length, 2); assert.match(df.components[0].note, /mutable/);
  assert.deepEqual(parseCsv('a,b\n"x,1","y""z"\n'), [{ a: 'x,1', b: 'y"z' }]);
});

test('timezone schedules: Asia/Ho_Chi_Minh 08:00, DST gap and overlap, weekly, missed runs', () => {
  assert.equal(nextOccurrence({ frequency: 'daily', local_time: '08:00', timezone: 'Asia/Ho_Chi_Minh' }, new Date('2026-11-21T00:30:00Z')).toISOString(), '2026-11-21T01:00:00.000Z');
  assert.equal(nextOccurrence({ frequency: 'daily', local_time: '02:30', timezone: 'America/New_York' }, new Date('2026-03-07T12:00:00Z')).toISOString(), '2026-03-08T07:30:00.000Z');
  assert.equal(nextOccurrence({ frequency: 'daily', local_time: '01:30', timezone: 'America/New_York' }, new Date('2026-10-31T12:00:00Z')).toISOString(), '2026-11-01T05:30:00.000Z');
  assert.equal(nextOccurrence({ frequency: 'weekly', weekday: 1, local_time: '09:00', timezone: 'Europe/London' }, new Date('2026-11-21T12:00:00Z')).toISOString(), '2026-11-23T09:00:00.000Z');
  assert.throws(() => nextOccurrence({ frequency: 'weekly', local_time: '09:00', timezone: 'UTC' }), /weekday/);
  assert.throws(() => nextOccurrence({ frequency: 'daily', local_time: '09:00', timezone: 'Mars/Base' }), /timezone/);
  assert.equal(occurrencesBetween({ frequency: 'daily', local_time: '08:00', timezone: 'Asia/Ho_Chi_Minh' }, new Date('2026-11-18T02:00:00Z'), new Date('2026-11-21T02:00:00Z')).length, 3);
});

test('priority policy: explainable, P0 needs exploitation in production, unknown is not low', () => {
  const crit = computePriority({ severity: 'critical', applicability: 'affected', exploitation: 'none_known', production: true, exposure: 'internet', criticality: 'critical' });
  assert.notEqual(crit.priority, 'P0');
  const uat = computePriority({ severity: 'critical', applicability: 'affected', exploitation: 'kev_listed', production: false, exposure: 'internet', criticality: 'critical' });
  assert.equal(uat.priority, 'P1'); assert.ok(uat.factors.some(f => f.factor === 'p0_gate'));
  assert.equal(computePriority({ severity: 'critical', applicability: 'affected', exploitation: 'kev_listed', production: true, exposure: 'internet', criticality: 'high' }).priority, 'P0');
  const unk = computePriority({ severity: 'unknown', applicability: 'unknown', exploitation: 'none_known', production: true, exposure: 'internal', criticality: 'medium' });
  const low = computePriority({ severity: 'low', applicability: 'affected', exploitation: 'none_known', production: true, exposure: 'internal', criticality: 'medium' });
  assert.ok(unk.score > low.score);
  assert.equal(computePriority({ severity: 'critical', applicability: 'not_affected' }).priority, 'P4');
  assert.equal(slaDue('P1', false, '2026-01-01T00:00:00Z'), '2026-01-15T00:00:00.000Z');
});
test('lifecycle: verified_fixed only via system verification', () => {
  assert.equal(canTransition('deployed', 'verified_fixed'), false);
  assert.equal(canTransition('verification_pending', 'verified_fixed', { system: true }), true);
  assert.equal(canTransition('new', 'triaged'), true);
  assert.equal(canTransition('verified_fixed', 'new'), true);
});
test('CVSS 3.1 base score calculator', () => { assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10); assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8); assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'), 5.9); });
test('secret redaction in logs, evidence and model inputs', () => {
  const gh = fake('ghp_'), ant = fake('sk-ant-'), aws = 'AK' + 'IA' + 'Q'.repeat(16), pw = 'hunter' + '2pass';
  const s = redactText(`token ${gh} key ${ant} id ${aws} ${'pass' + 'word'}: ${pw}`);
  for (const v of [gh, ant, aws, pw]) assert.ok(!s.includes(v), v.slice(0, 6));
  assert.deepEqual(redact({ api_key: 'x', nested: { ['pass' + 'word']: 'y', ok: 'z' } }), { api_key: '[redacted]', nested: { ['pass' + 'word']: '[redacted]', ok: 'z' } });
});
test('SSRF guard classifies private, loopback, link-local and metadata addresses', () => { for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '::1', 'fd00::1', '::ffff:10.0.0.1', '100.64.0.1']) assert.ok(isPrivateAddress(ip), ip); assert.ok(!isPrivateAddress('8.8.8.8')); });
test('CSV export cells are protected against formula injection', () => { assert.equal(csvCell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"'); assert.equal(csvCell('@SUM(1)'), "'@SUM(1)"); assert.equal(csvCell('safe'), 'safe'); });
