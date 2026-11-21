# Operations

## Deployment layout

Run the same image twice against one PostgreSQL database:

| Process | Settings | Notes |
|---|---|---|
| API/BFF | `RUN_WORKERS=false RUN_SCHEDULER=false` | Stateless; scale horizontally. Rate limiting is per instance (in memory). |
| Worker + scheduler | `RUN_WORKERS=true RUN_SCHEDULER=true` | Several workers are safe: claims use `SKIP LOCKED` and fencing, and occurrence keys are unique. Running the scheduler on several instances is also safe for the same reason, but one is enough. |

Vercel can host the SPA and the API (`api/index.mjs`, `vercel.json`). Serverless functions cannot run the worker or scheduler, so a long-running worker container is still required. Without it, nothing is matched, delivered or reported.

Run the application as a **non-superuser** PostgreSQL role that owns the schema. Superusers bypass row-level security. Migrations take an advisory lock, so API and worker processes can start simultaneously. Before the lock was added, the first full `docker compose up` collided on this.

Required in production (`SENTRA_ENV=production` refuses to start otherwise):

- PostgreSQL (`DATABASE_URL` or `PG*` variables).
- `SENTRA_MASTER_KEY`, 32 random bytes in base64.
- Keycloak settings. `AUTH_MODE=dev` and `KEYCLOAK_ALLOW_HTTP` are rejected.
- An HTTPS `APP_ORIGIN`.

Without `SENTRA_MASTER_KEY` (development only), a per-process key is generated. Stored credentials and sessions become unreadable after a restart, and `/api/ready` reports `secret_sealing: ephemeral_key`.

`GET /api/health` is liveness only. `GET /api/ready` checks the database and worker/scheduler heartbeats. `GET /api/metrics` (signed in, org scope) returns queue depth by type and status, dead-letter count, oldest ready job lag, outbox backlog, deliveries by status over 24 h, AI runs and cost over 30 days, and seconds since each connector's last success.

## Local stack

```bash
cp env.example .env        # fill in the four required placeholders (see env.example)
docker compose up --build
# Sentra http://localhost:8080 · Keycloak http://localhost:8081 · Mailpit http://localhost:8025
```

The Keycloak client credential in `.env` must equal the `secret` of the `sentra` client in `keycloak/sentra-realm.json`. The realm's users are for local use only.

This stack was run in full on 21 November 2026. Results:

- `/api/ready` reported a durable sealing key, Keycloak configured, and the separate worker heartbeating.
- A Keycloak login as `alice` mapped to `org_admin` through the `sentra-admins` group.
- An email channel test arrived in Mailpit.

The run surfaced two bugs, both fixed: concurrent migrations from the API and worker, and a root-owned object-store volume.

## Sizing and measured performance

Measured with `scripts/benchmark.mjs 10 300 200` on one WSL2 laptop (Node 24.12): 10 projects × 4 services × 2 environments, 300 components per artifact, 200 advisories, producing 8,012 findings and 12,012 observations.

| Measurement | PGlite (in-process) | PostgreSQL 16 (Docker, localhost) |
|---|---|---|
| 40 SBOM ingestions + 80 deployments, including matching, evidence and alert routing for 8,012 new findings | 63 s | 118 s |
| Advisory revision → reassessment of affected projects | 94 ms | 77 ms |
| Findings list, 20 paged queries, p95 | 22 ms | 17 ms |
| Portfolio dashboard | 199 ms | 365 ms |

The first row is a burst of brand-new findings, and its cost is roughly 12 sequential statements per new finding, so PostgreSQL over a socket is slower than in-process PGlite. Batching the per-finding writes and alert evaluation is the next optimization. Steady state is mostly unchanged findings, which are skipped with one bulk update per assessment.

These numbers are single-run measurements on a laptop with one worker. They are not a capacity guarantee. Re-run the benchmark on target hardware before committing to a supported scale.

## Backup and restore

What must be backed up together:

1. PostgreSQL. This is all business state, including the queue, outbox, audit chain and sealed credentials.
2. The object store (SBOM and import originals, referenced by `inventory_snapshots.object_key` and `ingestions.object_key`).
3. `SENTRA_MASTER_KEY`, kept separately in your secret manager. Without it, sealed credentials and sessions cannot be decrypted. Findings, inventory and audit remain readable.

Procedure exercised on 21 November 2026 against PostgreSQL 16.16:

```bash
pg_dump -Fc "$SOURCE_DB" > sentra.dump          # 2.5 MB for 8,012 findings
createdb sentra_restore && pg_restore -d sentra_restore --no-owner sentra.dump
node scripts/verify-restore.mjs postgres://…/sentra_restore
```

Results: finding, audit-event, job and outbox counts matched the source. The audit hash chain verified for all 136 events. The app booted on the restored database, and the scheduler and worker resumed.

Not exercised: object-store restore, point-in-time recovery, and a restore under load. No recovery time or recovery point objective has been measured, so none is claimed.

Jobs that were `running` at backup time are reclaimed after their lease expires (120 s). Handlers are idempotent, so a replayed job doesn't duplicate findings, alerts, deliveries or tickets.

## Upgrade and rollback

Migrations are forward-only SQL files in `migrations/`, applied in order at startup or with `node src/migrate-cli.mjs`, each in its own transaction and recorded in `schema_migrations`.

1. Back up as above.
2. Deploy the new image to the worker first with `RUN_WORKERS=false` to apply migrations, or run `migrate-cli`.
3. Roll the API instances, then re-enable workers.

Rollback means restoring the pre-upgrade backup. Down-migrations are not provided. Write additive migrations (new columns nullable, no drops in the same release) so the previous image keeps working against the new schema during a rolling deploy.

## Retention

`organizations.settings.retention_days` (minimum 30, default 730) is enforced by the daily **Retention** schedule (`src/services/retention.mjs`). Past the cutoff it deletes:

- notifications
- finished deliveries, jobs and processed outbox rows
- resolved alerts
- report runs
- tool-execution transcripts of finished investigations
- webhook receipts
- inventory snapshots that are neither the latest for their artifact or asset nor backing a current deployment

Findings, evidence, finding events, advisories and current inventory are never deleted.

Audit events past the cutoff are written as one JSON archive to the object store (`<org>/audit-archive/<from>-<to>.json`), recorded in `audit_archives` with the last hash, then deleted. Chain verification continues from that anchor. Keep the archives with your object-store backups; they are the only remaining copy of those events.

## Access revocation and incidents

- Remove or disable a member in **SSO & access**. Their sessions are revoked immediately, and agent runs they started re-check access before every tool call.
- Revoke CI tokens in **CI/CD setup**. Revocation takes effect on the next request.
- To rotate a stored credential, create the secret again under the same name. Channels and connections that reference it pick up the new value.
- Suspected `SENTRA_MASTER_KEY` exposure: rotate every stored credential at its provider, set a new key, re-enter the credentials, and revoke all sessions (`UPDATE sessions SET revoked_at=now()`).
- Keycloak back-channel logout revokes Sentra sessions by `sid` or `sub` when the realm client's back-channel URL can reach the API.

## Troubleshooting

| Symptom | Check |
|---|---|
| No findings after uploads | Uploads alone don't create findings. Is a deployment recorded? See **Project → Deployments**. |
| Findings never update | `/api/ready` → `workers`. If stale, the worker process is down. |
| Alerts not delivered | **Automation → Deliveries** shows the last error and attempts. Dead deliveries can be replayed. |
| Login loops back to sign-in | `APP_ORIGIN` must exactly match the Keycloak redirect URI origin. Cookies are `Secure` when the origin is HTTPS. |
| "No organization access" after login | Expected for users without an invitation or a group mapping. |
| Webhook test fails with `URL_BLOCKED` | The URL resolves to a private address. Use a public HTTPS endpoint. `ALLOW_PRIVATE_WEBHOOK_TARGETS` is for test environments only. |
