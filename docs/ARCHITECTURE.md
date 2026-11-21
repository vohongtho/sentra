# Architecture

Sentra is a modular monolith: one Node.js 24 codebase that runs as the API/BFF, as the worker and scheduler, or as both. PostgreSQL holds all state, including the job queue and the outbox. Keycloak is the identity provider. The browser gets a static ES-module SPA and an opaque session cookie.

```
browser ──HTTPS──▶ API/BFF (src/server.mjs, RUN_WORKERS=false)
                     │  sessions, CSRF, RBAC, REST /api, /api/v1 CI contracts
                     ▼
                PostgreSQL ◀──── worker + scheduler (same image, RUN_WORKERS=true RUN_SCHEDULER=true)
   jobs · outbox · findings · audit …        │ matching, verification, deliveries, connectors, agents
                     ▲                        ▼
               object store            Keycloak · OSV/KEV/EPSS · SMTP/Slack/Teams/webhooks · GitHub · Azure DevOps · AWS · Claude
```

## Decisions

### ADR-1: React + TypeScript SPA, Node.js modular-monolith backend

The frontend is React 19 with TypeScript in strict mode (`web/src`), built by Vite into static files in `public/`. The API server and Vercel serve those files as-is. A hash router keeps URLs shareable and maps the v2 handoff's deep links (`#/ops/...`, `#/ai-config`, ...) onto the product routes. The built bundle has no inline scripts, so the CSP stays `script-src 'self'`.

The backend stays on the handoff's Node.js ESM stack, which the spec allows ("choose the backend based on existing code"). It is plain JavaScript with no TypeScript. The deterministic domain code compensates with validation at every API boundary and 61 behavioral tests.

The first version of this build shipped a vanilla-JS SPA to match the handoff. It was replaced by the React port. Page structure, routes and API calls are unchanged, and all routes were re-verified in a browser after the port.

### ADR-2: PostgreSQL for the queue, scheduler and outbox

The spec asks for a queue but doesn't name one. Jobs live in the `jobs` table and are claimed with `FOR UPDATE SKIP LOCKED`. Each claim takes a lease and increments a fencing counter, so a worker whose lease expired cannot complete or checkpoint the job (`src/jobs/queue.mjs`; tested in `e2e.test.mjs`, "queue: lease expiry recovery…"). Domain changes write to `outbox` inside the same transaction, and a dispatcher turns events into jobs. Delivery is therefore at-least-once, and every handler is idempotent by design. Examples: `idempotency_key` on jobs, `dedupe_key` on findings, alerts and deliveries, and `ON CONFLICT` on tickets.

Rejected: Redis/BullMQ or SQS. Either adds a second stateful system to back up and restore consistently, and the expected load is far below what PostgreSQL handles. Revisit if the job rate makes `jobs` a write hotspot.

### ADR-3: Embedded PGlite for development and tests

With no `DATABASE_URL`, the app runs on PGlite (PostgreSQL compiled to WASM) in-process. The same migrations and SQL run on both. The suite passes on PGlite and on PostgreSQL 16.16. That second run found a real difference: node-postgres encodes JS arrays as Postgres array literals, which broke JSONB writes. `src/db.mjs` now normalizes it.

PGlite has one connection, so `src/db.mjs` serializes access with a mutex. Production refuses to start without PostgreSQL.

### ADR-4: Deterministic code decides, agents propose

Authorization, version comparison, priority, SLA, gate decisions, dedupe and verification are plain functions in `src/domain/` and `src/services/`. Agents call scoped tools and return a structured result. A claim with no valid tool receipt is moved to `unsupported_claims` and marks the run partial. A "not affected" conclusion without deterministic or counter-evidence is downgraded. Applicability changes wait for a human with `findings:triage`.

### ADR-5: Findings exist only for deployed or observed inventory

An SBOM upload creates an artifact and a snapshot and runs the gate. It does not create findings, because a build isn't a deployment. Findings come from the current deployment per service and environment, or from asset observations. The dedupe key is advisory + package + project + scope, so an upgrade to another vulnerable version updates the same finding, and a shared asset gets one finding per project.

### ADR-6: Shared realm, application-managed membership

One Keycloak realm. Organization and project roles live in Sentra (`memberships`, `project_access`), fed by invitations or by group/client-role mappings. A dedicated realm per customer is justified when the customer must own MFA policy, federation (their own IdP), or session lifetimes independently. Sentra supports that through `KEYCLOAK_ISSUER` per deployment, not per organization.

### ADR-7: Row-level security as defense in depth

Application authorization (`requireProject`, `accessibleProjectIds` in `src/authz.mjs`) is the primary control, and the cross-project tests exercise it through the API, CSV export, assets, agent tools and background runs.

`migrations/002_rls_retention.sql` adds a second layer. It enables and forces PostgreSQL RLS on 40 tenant tables, with a policy that admits a row only when `org_id` matches the connection's `app.org_id` setting, or when the setting is empty. Every authenticated API request runs on its own pooled connection with `app.org_id` set (`db.scoped()` in `src/db.mjs`), and the connection is reset on release. A query that forgets the application check still cannot read or write another organization's rows. `tests/rls.test.mjs` shows this with raw SQL on a scoped connection.

Workers, the scheduler and migrations use unscoped connections, because they legitimately cross organizations (a revised advisory reassesses every tenant's inventory). Organization isolation therefore rests on application code for those paths.

Two conditions, both deliberate:

- Superusers bypass RLS. The application must connect as a non-superuser that owns the schema. The test harness does this, and `OPERATIONS.md` requires it.
- Embedded PGlite runs as a superuser, so RLS is inactive in development and in the default test run.

Cost: each authenticated request holds one extra pooled connection for its duration, so the default pool is 20.

## Modules

| Directory | Responsibility |
|---|---|
| `src/auth/` | OIDC BFF, sessions, refresh, logout, back-channel logout, dev identities, CI-token authentication |
| `src/authz.mjs` | Role → permission matrix, project scope resolution |
| `src/domain/` | Version comparators and OSV range evaluation, purl, parsers, priority/SLA/lifecycle policy, timezone math |
| `src/services/inventory.mjs` | Snapshots, observations, dependency edges, diffs, deployed-inventory view |
| `src/services/advisories.mjs` | OSV upsert, revisions, aliases, CVSS 3.x score, exploitation signals |
| `src/services/matching.mjs` | Project assessment, finding upsert, verification, CI gate matches |
| `src/services/ingestion.mjs` | `/api/v1` contracts, gate policy |
| `src/services/alerts.mjs`, `src/notify/` | Rules → alerts → deliveries; senders; SSRF-safe fetch |
| `src/services/tickets.mjs` | Internal, GitHub and Azure DevOps tickets; GitHub webhook |
| `src/services/reports.mjs`, `coverage.mjs`, `findings.mjs`, `secrets.mjs` | As named |
| `src/connectors/` | OSV, KEV, EPSS, THN, GitHub, AWS, Dependency-Track, Azure DevOps |
| `src/ai/` | Tool definitions and authorization, agent runtime, Claude provider, offline planner |
| `src/jobs/` | Queue, worker, outbox dispatcher, scheduler, handler wiring |
| `src/api/` | HTTP routes (core, security, ops) |
| `public/` | SPA |

## Data model

`migrations/001_core.sql` defines 45 tables; `002_rls_retention.sql` adds `audit_archives`, `external_findings` and the RLS policies. The relationships that matter:

- `organizations` 1─* `projects` 1─* `services`, `environments`, `repositories`, `ci_tokens`.
- `assets` *─* `projects` through `asset_projects`, each link optionally pinned to an environment.
- `artifacts` (unique per project + digest) 1─* `inventory_snapshots` 1─* `observations` *─1 `components` (unique `purl`).
- `deployments` link service + environment + artifact. `is_current` marks the live one, and history is kept.
- `advisories` 1─* `advisory_revisions`, `affected_ranges`; `advisory_aliases` maps CVE/GHSA/vendor IDs to the canonical ID; `exploit_signals` holds KEV/EPSS/PoC/vendor/observed separately.
- `findings` (unique org + dedupe key) 1─* `evidence`, `finding_events`, `tickets`, `pull_requests`, `risk_exceptions`.
- `investigations` 1─* `tool_executions`; `agent_policies` per org/project/workflow.
- `alert_rules` → `alerts` (unique dedupe key) → `deliveries` (unique dedupe key) → `channels`.
- `schedules` → `jobs` (unique occurrence key `sched:<id>:<utc>`); `outbox`; `report_runs`.
- `audit_events` is append-only, with `prev_hash` → `hash` per organization.

Snapshots and observations are never updated except the `stale` flag. History is preserved when a source disconnects.

## Events

Emitted through the outbox: `inventory.updated`, `artifact.scanned`, `deployment.recorded`, `advisory.updated`, `finding.created`, `finding.priority_changed`, `finding.exploitation_changed`, `finding.not_affected`, `deployment.newly_affected`, `fix.available`, `verification.failed`, `verification.contradicted`, `remediation.verified`, `investigation.completed`, `sla.breached`, `sla.approaching`, `connector.failed`, `inventory.stale`, `job.dead_lettered`, `delivery.dead_lettered`, `schedule.occurrences_skipped`.
