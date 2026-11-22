# Feature matrix

Status as of 21 November 2026. Statuses are cumulative and independent:

- **Implemented**: the code exists and runs in the application.
- **Tested**: covered by automated tests in `tests/`. There are 62 tests: 60 pass on embedded PGlite with 2 skipped (they need PostgreSQL); the previous 61 all pass on PostgreSQL 16 running as a non-superuser. The React frontend type-checks under `tsc --strict`, and all 50 routes were exercised in a browser.
- **Connected**: exercised against a real running system rather than a test double.
- **Production validated**: run on production infrastructure with production data. Nothing has reached this state.

A test double is a local HTTP server shaped like the provider's public API. It proves Sentra's side of the contract, not the provider's behavior.

## Identity and access

| Capability | Implemented | Tested | Connected | Notes |
|---|---|---|---|---|
| Keycloak OIDC Authorization Code + PKCE; state, nonce, issuer, audience, signature, expiry | yes | yes (mock IdP signing real JWTs) | yes: Keycloak 26.0, browser login run standalone and inside `docker compose` | |
| BFF sessions, HttpOnly cookie, no tokens in the browser | yes | yes | yes | |
| Refresh (a failed refresh ends the session) and RP-initiated logout | yes | yes (mock IdP) | no | |
| Back-channel logout | yes | yes (mock IdP) | no | |
| CSRF (synchronizer token, Origin, Sec-Fetch-Site) | yes | yes | n/a | |
| Organization and project roles, enforced in APIs, exports, search and agent tools | yes | yes | n/a | |
| PostgreSQL row-level security on 40 tenant tables (`migrations/002`) | yes | yes (PostgreSQL, non-superuser role) | n/a | API requests run on a connection with `app.org_id` set; workers are unscoped. PGlite runs as a superuser, so RLS does not apply there. |
| Invitations, group and client-role mapping | yes | yes | yes (group mapping with the live realm) | |
| Role changes apply on the next request; disabling a member revokes sessions; background runs re-check access | yes | yes | n/a | |
| Development identity mode, refused in production | yes | yes | n/a | |

## Inventory and ingestion

| Capability | Implemented | Tested | Connected | Notes |
|---|---|---|---|---|
| Organization → project → service → environment → deployment model; shared assets | yes | yes | n/a | |
| Onboarding wizard with per-step completion | yes | partly | n/a | Completing it never marks a project "protected" |
| CycloneDX 1.2–1.6, SPDX 2.2/2.3, Trivy, SARIF, CSV, JSON, YAML, **XLSX** | yes | yes | n/a | XLSX reads the first sheet, uses cached values only and has a 50 MB expansion cap. `.xls` and `.xlsm` are rejected. |
| Lockfile and manifest discovery (npm, Composer, pip, Go, Maven, Bundler, Cargo, Dockerfile) | yes | yes | n/a | Not supported: yarn/pnpm lockfiles, Gradle and NuGet lock files |
| Import workbench: dry run, row errors, diff, idempotent commit, receipt | yes | yes | n/a | |
| Immutable snapshots, content hash, object storage | yes | yes | filesystem; Docker volume in compose | S3 adapter not run against a bucket |
| Overrides with reason, approver ≠ requester, expiry | yes | partly | n/a | Recorded and approved, but not yet applied to matching |
| Stale observations after disconnect or freshness breach | yes | yes | n/a | |

## CI/CD

| Capability | Implemented | Tested | Connected | Notes |
|---|---|---|---|---|
| `/api/v1` ingestion, deployment and policy-evaluation contracts | yes | yes | n/a | `openapi-v1.yaml` |
| Scoped, expiring, revocable CI tokens; idempotent receipts | yes | yes | n/a | No workload identity yet |
| Deterministic gate (observe / block_new, fail-open / fail-closed, production baseline, exceptions) | yes | yes | n/a | |
| `scripts/sentra-ci.mjs` | yes | yes (run as a subprocess) | no | |
| GitHub Actions workflow | yes | the CLI it calls is tested | no | Not run on GitHub-hosted runners |
| GitLab CI, Jenkins, Azure DevOps | contract preview | no | no | |

## Intelligence and matching

| Capability | Implemented | Tested | Connected | Notes |
|---|---|---|---|---|
| OSV advisories, aliases, revisions, withdrawn/rejected/disputed | yes | yes | n/a | |
| Comparators: semver family, PEP 440, Maven, RubyGems, RPM, Debian, Alpine | yes | yes | n/a | CRAN, CPAN and Conan are partial (generic comparator) |
| Distribution backports and architecture-limited advisories | yes | yes | n/a | |
| Re-evaluation on advisory revision without a new build | yes | yes | n/a | |
| OSV, CISA KEV and FIRST EPSS sync | yes | `scripts/live-feeds-check.mjs` | **yes**: live services on 21 Nov 2026. OSV returned 78 vulnerabilities for 12 package queries; KEV catalog 2026.11.20 matched CVE-2021-44228/45046; EPSS scored 50 CVEs. The pipeline produced 50 findings, with Log4Shell at P0 (KEV, production) and correct fixed versions. | Run on demand; needs network access only |
| The Hacker News RSS | yes | yes (failure path) | yes (feed fetched during tests) | Relevance is a keyword match and is labeled unverified |

## Findings, policy, alerts, tickets, remediation

| Capability | Implemented | Tested | Connected | Notes |
|---|---|---|---|---|
| Separate severity, applicability, exploitation, priority, workflow and verification fields | yes | yes | n/a | |
| Priority policy, versioned and editable per organization and project | yes | yes | n/a | P0 always requires exploitation in production; unknown severity may not score below low |
| SLA policy: editable hours, non-production multiplier, **business-hours calendars** (timezone, workdays, holidays), pause/resume | yes | yes | n/a | |
| Lifecycle; `verified_fixed` only via verification; reopen on contradiction | yes | yes | n/a | |
| Risk acceptance: approver ≠ requester, automatic reopen on expiry | yes | yes | n/a | |
| Alert rules, dedupe, quiet hours with P0/P1 bypass, snooze expiry, outbox retries, dead letter, replay | yes | yes | n/a | Grouping and escalation are untested |
| In-app, signed webhook, **SIEM (Splunk HEC / JSON collector)** | yes | yes (local receivers) | no | |
| Email (SMTP) | yes | no automated test | **yes**: Mailpit SMTP server in `docker compose`; message received | Not tried against an external provider |
| Slack and Teams | yes | no | no | |
| Internal, GitHub Issues and Azure DevOps tickets; GitHub webhook with replay protection | yes | internal tickets and webhook tested | no | |
| **Draft remediation PRs** (npm, Composer, PyPI, Maven manifests; draft only; never merged) | yes | yes (GitHub test double) | no | Lockfiles are left to the repository's CI |
| **Renovate PR linking** (only when the target version is outside the affected range) | yes | yes | no | |
| Campaigns from shared root causes | yes | no | n/a | |
| **CycloneDX 1.5 VEX export** with explicit state mapping | yes | yes | n/a | |
| **Attack paths** (exposure → environment → service → asset → finding, plus identity and downstream edges; verified vs inferred) | yes | yes | n/a | Identity and downstream edges come only from recorded asset attributes |

## Connectors

| Connector | Implemented | Tested | Connected |
|---|---|---|---|
| GitHub repository discovery | yes | no | no |
| AWS (Lambda, EC2, ECR; records execution role / instance profile as identity) | yes | no | no |
| Dependency-Track | yes | yes (test double) | no |
| **Wazuh** (agents + syscollector packages, distro- and arch-aware) | yes | yes (test double) | no |
| **DefectDojo** (findings as linked references) | yes | yes (test double) | no |

## AI agents

| Capability | Implemented | Tested | Connected | Notes |
|---|---|---|---|---|
| Eight workflows (submitted-evidence analysis, discovery, research, impact, remediation, verification, portfolio, Copilot) | yes | evidence analysis, impact and Copilot | n/a | Evidence analysis replaces the handoff's Live AI analysis |
| Provider key stored by an admin through the UI (sealed), with a real connection test | yes | yes (Messages API test double) | no | A server `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` (Console OAuth bearer, also tested) takes precedence. A Claude.ai subscription cannot be used. |
| Tool authorization, untrusted-content wrapping, injection resistance | yes | yes | n/a | |
| Claim validation, "not affected" guard, human approval | yes | yes | n/a | |
| Budgets, cancellation, checkpoints, reruns | yes | budget and checkpoint writes | n/a | Resume after a crash is untested |
| Claude provider (`claude-opus-5-5`, effort, strict tools, refusal fallback) | yes | yes (Messages API test double) | **no** | No paid call was made |
| Evaluation dataset and harness | yes | yes | offline only | 5/5 on the offline planner, which was built against these cases |

## Operations

| Capability | Implemented | Tested | Connected | Notes |
|---|---|---|---|---|
| Durable queue, scheduler (timezone/DST, missed-run and overlap policies), outbox | yes | yes | n/a | |
| Vietnamese daily report with an incomplete-coverage notice | yes | yes | n/a | |
| **Retention enforcement** with audit archival and anchored chain verification | yes | yes | n/a | Daily schedule; findings and evidence are never purged |
| Migrations safe under concurrent startup (advisory lock) | yes | yes (compose: API + worker started together) | n/a | Bug found and fixed during the compose run |
| Health, readiness, metrics, structured logs with redaction | yes | partly | n/a | No Prometheus/OpenTelemetry export |
| Backup and restore | procedure + `verify-restore.mjs` | yes, once | n/a | Object store backup not exercised |
| Docker image and **full `docker compose up`** | yes | yes | n/a | The compose run found two bugs, both fixed: a migration race and object-store volume permissions |
| Vercel adapter | yes | no | no | Workers cannot run on Vercel |
| Rate limiting | per instance, in memory | no | n/a | Not shared across instances |

## Frontend

| Capability | Implemented | Tested | Notes |
|---|---|---|---|
| React 19 + TypeScript (strict) SPA built with Vite | yes | `tsc` strict passes; 50 routes opened in a browser with zero console errors | `web/src` |
| Handoff UI parity and deep-link compatibility | yes | yes | `UI-PARITY.md`; the claude.ai artifact URL itself requires a sign-in and could not be opened here |
| Loading, empty, error, permission-denied and stale states; shareable filtered URLs; saved views | yes | yes (browser) | |

## What remains

These are limits of this environment and of evidence, not unbuilt features:

- **No credentials were available for external services.** Not connected: GitHub, Azure DevOps, AWS, Slack, Teams, an external SMTP provider, Splunk, Wazuh, DefectDojo, Dependency-Track, and a paid Claude evaluation. Each is implemented and, where noted, tested against a test double. Supplying credentials makes each one testable with the existing **Test** and **Sync** actions.
- **Production validation** requires a production environment, data and authorization.
