# Sentra — Security Intelligence & Alarm Platform

Sentra connects vulnerability advisories to what each project actually deploys. Two examples of what it does:

- An SBOM upload from CI becomes an immutable artifact snapshot. Recording a deployment makes that artifact the inventory of an environment. When an advisory matches it, Sentra opens a deduplicated finding with evidence, an explainable priority, an SLA, an owner, an alert and a ticket.
- The finding stays open after a fix is merged. It closes only when an artifact without the vulnerable version is verified as deployed to that environment.

This is a runnable, tested development build. It has not been production validated. `docs/FEATURE-MATRIX.md` lists, per capability, what is implemented, tested, and connected to a real system.

## Run it

Requirements: Node.js 24. Docker is optional.

```bash
npm ci
npm run dev            # builds the React UI, then serves http://localhost:8080 with embedded PostgreSQL (PGlite) and synthetic demo data
npm test               # 62 tests; TEST_DATABASE_URL=postgres://… runs them on real PostgreSQL (incl. RLS)
npm run typecheck      # strict TypeScript check of the React frontend
```

`npm run dev` uses development identity mode: you pick a seeded user on the sign-in page instead of logging in through Keycloak. To use Keycloak locally, start the realm in `keycloak/` (see `docs/KEYCLOAK.md`) or run the full stack:

```bash
cp env.example .env    # fill in the placeholders
docker compose up --build
```

Without a credential, investigations run on the offline deterministic planner. With `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`, an OAuth token for a Claude Console organization) they use `claude-opus-5-5`. An admin can also store an API key in the UI under **AI agents**. A Claude.ai Pro/Max subscription cannot authenticate API calls. Model calls are billed to the Console organization.

## Verified in this build

- **Tests:** 62 automated tests. 60 pass on PGlite, with 2 RLS tests skipped because they need PostgreSQL. The earlier 61 all passed on PostgreSQL 16.16 running as a non-superuser.
- **Frontend:** React + TypeScript, strict type check clean. All 50 routes and the handoff's deep links were opened in a browser with no console errors (`docs/UI-PARITY.md`).
- **Keycloak:** browser logins through a real Keycloak 26.0 realm succeeded, standalone and in `docker compose`, with group-to-role mapping applied.
- **Docker:** the full `docker compose up` stack runs (PostgreSQL, Keycloak, Mailpit, API, worker). Test email was delivered to its SMTP server.
- **Backup:** a `pg_dump`/`pg_restore` round trip preserved all counts, and the audit hash chain verified.
- **Reference projects:** releases and licenses were checked against the GitHub API (`docs/RESEARCH.md`).

The tests cover:
- version ordering and OSV ranges, and all importers including XLSX
- timezone/DST scheduling and business-hours SLAs
- cross-project access denial and RLS
- the Keycloak flow (against a mock IdP signing real JWTs)
- CI ingestion idempotency and token revocation
- alert dedupe with webhook retries
- verified closure, and reopen on rollback
- advisory revisions and editable policies
- VEX export, attack paths and draft PRs
- the Wazuh, DefectDojo, SIEM and Renovate integrations (against test doubles)
- retention with audit archival
- queue fencing
- the CI CLI as a subprocess
- the Claude tool loop (against a Messages API test double)

## Not done

No credentials were available for GitHub, Azure DevOps, AWS, Slack, Teams, Splunk, Wazuh, DefectDojo, Dependency-Track or a paid Claude evaluation. Those integrations are implemented and, where noted, tested against test doubles, but not connected. Nothing has been production validated. Details are in `docs/FEATURE-MATRIX.md`.

## Layout

```
src/            server, auth, authz, domain logic, services, connectors, agents, jobs, API routes
migrations/     PostgreSQL schema (47 tables) and row-level security policies
web/            React + TypeScript frontend (Vite)
public/         built frontend, product requirements, feature matrix
tests/          node:test suites
scripts/        sentra-ci.mjs (CI client), eval-agents, benchmark, verify-restore, smoke
ci/             GitHub Actions (tested CLI path), GitLab, Jenkins, Azure DevOps (contract previews)
keycloak/       local realm
fixtures/       agent evaluation dataset
docs/           ARCHITECTURE, FEATURE-MATRIX, UI-PARITY, OPERATIONS, KEYCLOAK, AGENTS, INTEGRATIONS, RESEARCH, DEMO, openapi-v1.yaml
```

The product specification this build implements is `public/product-requirements.md`, copied unchanged from the v2 handoff. It is also readable inside the app under **Requirements**.
