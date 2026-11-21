# Security Intelligence & Alarm Platform — Full Product Master Prompt

Version: 1.0  
Language: English  
Purpose: Instruct an AI engineering agent or development team to research, design, implement, test, and deliver a complete security intelligence product.

## 1. Your Role and Mission

Act as a Principal Product Engineer, Security Architect, UX Designer, and AI Systems Engineer. Own the delivery of a working product called **Security Intelligence & Alarm Platform**.

Build a platform that helps organizations manage vulnerabilities and security risk across multiple projects, services, repositories, cloud accounts, assets, deployments, and environments. Connect security intelligence to actual software inventory, deployment evidence, ownership, remediation, and verified closure.

AI agents must investigate project context and produce evidence-backed results through tools. A chat interface or an LLM summary alone does not satisfy this requirement.

Deliver functioning software, not only a proposal, static dashboard, or collection of disconnected prototypes. Work incrementally, maintaining a runnable application throughout implementation. Never describe mocked data, disconnected integrations, or untested functionality as production-ready.

## 2. Execution Rules

1. Inspect the existing workspace, repository instructions, implementation, and dependencies before changing code.
2. Preserve unrelated user changes. Adapt to an existing technology stack when practical.
3. Produce a concise product specification, architecture decisions, data model, and implementation backlog before major implementation.
4. Make reasonable reversible decisions and document assumptions. Ask only when a missing decision materially affects scope, external authority, cost, or architecture.
5. Implement a working end-to-end slice before expanding breadth.
6. Test behavior appropriate to its risk. Report actual results, not intended results.
7. Keep a feature matrix with statuses: Planned, Implemented, Tested, Connected, and Production validated. Distinguish these states.
8. If credentials are unavailable, complete the connector, configuration validation, fixtures, and contract tests. Mark the integration as disconnected in the UI.
9. Use clearly labeled synthetic data for local demonstrations. Never invent real CVEs or exploitation claims.
10. Do not silently remove requirements to claim completion. Track incomplete work and blockers explicitly.
11. Do not publish, purchase services, merge changes, or deploy production without the necessary authorization.

## 3. Product Outcomes and Users

The product must answer:

- Which projects and production deployments are affected by a newly disclosed vulnerability?
- What evidence supports the conclusion, and what remains unknown?
- Which findings require action first, and why?
- Who owns the remediation and when is it due?
- Has a fix actually reached the affected environment?
- Which projects have insufficient security coverage or stale inventory?
- Which shared components create risk across multiple projects?

Support Organization Administrators, Security Analysts, Project Owners, Tech Leads, Developers, DevOps Engineers, Management Viewers, and Auditors.

Measure actionable alert rate, time to first assessment, acknowledgement time, remediation time, overdue remediation, verified closure rate, inventory freshness, connector health, and AI investigation quality. Define metric populations and timestamps; avoid misleading averages across incomparable finding types.

## 4. Multi-Organization and Multi-Project Model

Model Organization → Project → Service → Environment → Deployment, with explicit links to repositories, artifacts, assets, teams, and policies.

- **Project:** business ownership and delivery scope.
- **Service:** an application or independently managed workload.
- **Repository:** source control location; services may span repositories or a monorepo.
- **Artifact:** immutable build output identified by digest or equivalent identity.
- **Deployment:** an artifact deployed to a specific environment.
- **Asset:** server, container workload, database, managed service, or infrastructure resource.
- **Component:** runtime, OS package, library, framework, or product found in an artifact or asset.

Support shared infrastructure and components without creating unrelated duplicate assets. A finding affecting a shared asset must remain linked to every relevant project while respecting authorization boundaries.

Projects require owners, teams, business criticality, data classification, environments, exposure, notification routing, remediation policy, and custom metadata. Provide project templates, bulk onboarding, tags, archival, ownership transfer, and saved views.

Start with logical tenant isolation backed by systematic authorization checks. Evaluate database row-level security as defense in depth. Do not claim hard isolation merely because queries include an organization ID.

## 5. Mandatory Keycloak SSO

Keycloak is the required identity provider from the first release.

- Use OpenID Connect Authorization Code Flow with PKCE.
- Prefer a Backend-for-Frontend pattern. Keep tokens server-side and use secure, HttpOnly browser session cookies with appropriate SameSite settings.
- Do not store access or refresh tokens in localStorage.
- Do not implement an independent application password system.
- Validate state, nonce, issuer, audience, signature, token lifetime, and permitted signing algorithms as applicable.
- Support JWKS key rotation, refresh, session expiry, logout, and back-channel logout where supported and configured.
- Protect cookie-authenticated mutations against CSRF.
- Manage MFA, identity federation, and authentication policy through Keycloak.

Map Keycloak subjects, groups, and client roles to application organizations, teams, and roles. Apply project-level authorization in the backend for APIs, exports, searches, reports, evidence, and agent tool execution. Never trust a client-provided organization ID as proof of access.

Provide a configurable onboarding or invitation policy. Successful SSO must not automatically grant access to every project. Define removal and role-change behavior, including existing sessions and background tasks.

Separate human sessions from CI and connector identities. Use scoped service accounts or workload identity where supported. Support credential rotation and revocation.

Default to a shared realm with application-managed organization/project membership for the initial product. Document when a dedicated customer realm is justified. Include local Keycloak configuration and a sample realm; document production configuration separately.

## 6. Input, Onboarding, and Inventory Management

Provide a project onboarding wizard:

1. Enter project metadata, owner, and criticality.
2. Define services and environments.
3. Connect repositories, CI, or cloud accounts, or upload inventory.
4. Run stack discovery.
5. Review evidence, conflicts, and missing information.
6. Confirm inventory and configure policies and routing.

Support manual forms, CSV/JSON/YAML imports, CycloneDX/SPDX SBOMs, scanner reports, supported SARIF inputs, REST ingestion, and signed CI/deployment webhooks. Add XLSX import if justified after core import flows work.

Imports need preview, schema validation, column mapping when necessary, row-level errors, dry-run, idempotency, upsert behavior, job progress, and provenance. Validate file size and type, safely process archives, and prevent spreadsheet formula injection in exports.

Each inventory observation must record source, collection method, timestamp, environment, component identity, version evidence, confidence category, and relevant commit/artifact/asset identifiers. Preserve immutable snapshots and change history.

Show manual-versus-automated conflicts explicitly. Support overrides with a reason, reviewer, and expiry. Define source precedence per field rather than assuming every cloud or repository observation is authoritative.

Missing or stale inventory is a visible coverage problem, not evidence that no vulnerability exists.

## 7. Stack Discovery and Ecosystem Coverage

Discover languages, runtimes, frameworks, libraries, OS packages, databases, middleware, infrastructure, and deployment configuration.

Support adapters for PHP/Composer; Java/JVM/Maven/Gradle; JavaScript/TypeScript/Node.js/npm/yarn/pnpm; Python; Ruby; Go; Rust; .NET/NuGet; and additional ecosystems as scanner/parser coverage permits. Include C/C++, Swift, Kotlin, Scala, Perl, R, and others in the published coverage matrix, explicitly marking unsupported or partial capabilities.

Inspect manifests, lockfiles, Dockerfiles, Compose files, Kubernetes/Helm manifests, Terraform, CloudFormation/CDK/SAM, server configuration, and CI files where authorized.

Distinguish:

- Declared version, resolved build version, artifact version, and observed runtime version.
- Runtime vulnerability versus framework, library, application, or OS vulnerability.
- Direct versus transitive dependencies.
- Installed component versus actively used process.
- Container tag versus immutable image digest.
- ARM64 versus x86_64 and relevant platform conditions.

Track dependency paths, package URLs, vendor package identifiers, distribution versions, and CPE mappings where appropriate. Do not treat CPE matching as universally precise.

Prioritize Linux/Amazon Linux, AWS, Docker/Kubernetes, MySQL, Keycloak, Nginx, Redis, Kafka, Java/Solr, Node.js Lambda, PHP/Beanstalk, and common enterprise infrastructure without excluding other technologies.

## 8. Security Intelligence and Advisory Ingestion

Use primary vendor advisories, OSV, GitHub Security Advisories, CVE/NVD, CISA KEV, EPSS, AWS ALAS/security bulletins, and relevant distribution advisories. Use The Hacker News for discovery and context, verifying material technical claims against primary sources when available.

Implement incremental synchronization, cursors/checkpoints, rate limits, retries with backoff, source health, data provenance, advisory revisions, and alias handling across CVE/GHSA/vendor IDs. Handle rejected, withdrawn, disputed, and revised records explicitly.

Retain affected ranges, fixed versions, severity source, CVSS version/vector, prerequisites, architecture, configuration conditions, exploit evidence, mitigations, and source publication/update times.

Do not equate a public PoC, EPSS probability, KEV listing, and confirmed exploitation in the user's environment. Store these as separate signals.

Reassess stored inventories when advisories change, even if no new build occurs. Record why each reassessment was triggered.

Use ecosystem-specific version comparison and vendor backport information. Generic semantic versioning and string comparison are insufficient for all package systems.

## 9. AI Agents and Investigation Workflows

Build agents as tool-using workflows with structured outputs, persistent state, evidence references, and bounded execution.

### 9.1 Project Discovery Agent

Analyze repositories, manifests, IaC, artifacts, and authorized inventory. Propose service boundaries, software inventory, deployment relationships, and missing information. Present a reviewable onboarding result rather than silently modifying confirmed inventory.

### 9.2 Advisory Research Agent

Read official advisories and extract affected versions, fixed versions, prerequisites, mitigations, and exploitation status. Cite claims and preserve ambiguity or contradictory sources.

### 9.3 Impact Investigation Agent

Investigate a specific vulnerability–component–deployment combination. Inspect package presence, vendor versions/backports, architecture, enabled features, exposure, and dependency paths. Use supported static analysis or runtime evidence for reachability when available.

Distinguish component presence, potential reachability, confirmed exploitation prerequisites, and observed compromise. Do not collapse these into one confidence score.

Return applicability, supporting evidence, counter-evidence, missing evidence, analysis limitations, and next actions. Failure to find a call in source is not sufficient to conclude non-applicability when reflection, dynamic loading, generated code, or incomplete coverage is possible.

### 9.4 Remediation Planning Agent

Recommend a verified fixed release or mitigation, assess compatibility, identify affected dependent services, and generate test, rollout, and rollback plans. Explain when a simple dependency bump is insufficient.

With separately granted permissions, create a branch and draft PR, update manifests/lockfiles/base images, and run builds/scans in an isolated environment. Do not merge or deploy production automatically.

### 9.5 Verification Agent

Verify the fixed artifact or package on the intended environment, including required restart/redeployment. Link verification to an artifact digest, asset identity, timestamp, and scan coverage. A merged PR or completed ticket does not prove deployment.

### 9.6 Portfolio and Campaign Agent

Identify shared vulnerable dependencies/base images and propose remediation campaigns across projects. Explain project-specific rollout order, ownership, blockers, and expected benefit without inventing precise risk reductions.

### 9.7 Security Copilot

Support natural-language questions such as:

- Which production Java services require action first?
- Does this advisory affect TTS, and what evidence supports that?
- Which projects still run an old image after the fix was merged?
- Why did this finding increase in priority?
- What changed in our stack since yesterday?
- Which projects have insufficient evidence for assessment?

Apply authorization before retrieval and tool access. Include scope, citations, freshness, and limits in answers. Require action-specific permission for mutations.

### 9.8 Agent Runtime Requirements

- States: Queued, Running, Waiting for evidence, Waiting for approval, Completed, Partial, Failed, Cancelled.
- Persistent checkpoints, safe retries, cancellation, timeouts, concurrency quotas, and per-organization cost budgets.
- Version prompts, models, tools, policies, and investigation inputs.
- Preserve reviewable tool actions and evidence; do not expose private chain-of-thought.
- Treat repository text, advisories, logs, and retrieved documents as untrusted data. Prevent prompt injection from granting tool permissions.
- Do not execute repository scripts with production credentials.
- Keep secret values out of model inputs, logs, and evidence displays.
- Use deterministic code for authorization, package/version matching, SLA calculation, policy gates, and deduplication.
- Support a configurable model provider interface; do not assume all source code may leave the organization.
- Reuse cached evidence only when its scope, permissions, and freshness remain valid.

## 10. Product Differentiators

Implement these as user-visible workflows:

1. **Investigate this CVE:** paste an advisory and obtain a portfolio impact assessment with evidence.
2. **Explain why affected:** display exact package/deployment evidence and applicable prerequisites.
3. **What changed?:** explain priority changes caused by advisory revisions, new exposure, configuration drift, or deployment changes.
4. **Stack and deployment drift:** compare source, build, artifact, deployment, and observed runtime.
5. **Shared-component blast radius:** identify affected projects through common images, services, and dependencies.
6. **Remediation campaigns:** coordinate one root-cause fix across multiple services.
7. **Verified closure:** confirm the fix on the intended environment before closing.
8. **Coverage and blind spots:** show where assessments cannot be trusted because data is missing or stale.
9. **Project security knowledge:** preserve reviewed architecture assumptions and custom controls with evidence, expiry, and revalidation triggers.
10. **Attack-path exploration:** in an advanced phase, show verified and inferred relationships from exposed endpoint to service, identity, and downstream asset. Clearly label inferred edges and unknown prerequisites.

Example: an ALB frontend supporting HTTP/2 does not establish that the backend Nginx speaks HTTP/2. Evaluate the actual vulnerable component and its configuration. An ARM64 observation is relevant only if the specific advisory excludes that architecture. Do not generalize either fact into an overall safety claim.

## 11. Findings, Risk, and Remediation Lifecycle

Maintain separate fields for technical severity, applicability, exploitation status, business priority, workflow status, and verification status.

Applicability: Affected, Not affected, Under investigation, Unknown. Where exporting VEX, map these states to the selected standard explicitly and retain evidence and justification.

Use a versioned, explainable priority policy combining severity, active exploitation, KEV, EPSS, exposure, production status, asset criticality, prerequisites, verified controls, and evidence quality. Preserve Unknown as uncertainty rather than treating it as reduced risk.

Do not automatically classify every Critical CVE as P0 or reduce severity merely because a dependency is transitive. Define consistent rules and show the contributing factors.

Lifecycle: New → Triaged → Assigned → In progress → Fix available → Deployed → Verification pending → Verified fixed. Support reopening, false positives, accepted risk, expiring exceptions, and paused work with reasons.

Configure SLA by priority/environment/project using calendars and time zones. Define when clocks start, pause, resume, and stop. Risk acceptance needs scope, approver, rationale, expiry, and re-evaluation triggers.

Deduplicate using vulnerability aliases, component identity, location, artifact/deployment context, and scanner identifiers. Preserve individual occurrences while grouping common root causes. Do not globally merge identical CVEs across unrelated assets.

## 12. Alerts, Scheduled Reports, and Playbooks

Provide a rule builder with triggers, conditions, actions, routing, escalation, and test execution.

Triggers include new affected findings, active exploitation updates, priority increases, newly affected deployments, available fixes, approaching/breached SLA, failed verification, stale inventory, and broken connectors.

Actions include in-app notifications, email, Slack/Teams webhooks, ticket creation, investigation jobs, verification jobs, and escalation. Integrate on-call tooling through adapters when configured.

Implement grouping, deduplication, snooze expiry, quiet hours, acknowledgement, delivery retries, delivery history, and dead-letter handling. Define which critical alerts bypass quiet hours. Avoid notification loops and duplicate tickets.

Every actionable alert includes project, service, environment, affected version, fixed version if known, exploitation status, evidence, recommended action, owner, deadline, and deep links.

Send scheduled reports in Vietnamese by default, with configurable language and time zone. Use Asia/Ho_Chi_Minh for the initial daily 08:00 report. Report material changes without repeatedly listing unchanged items.

Separate the general portfolio report from THN coverage. If no material items are found in THN's past-24-hour coverage, state that precise scope. Never claim all software is safe. If ingestion fails, report incomplete coverage rather than reporting zero findings as a successful assessment.

## 13. Dashboard and UX

Build responsive, accessible, data-backed screens with loading, empty, error, stale-data, and permission-denied states. Include pagination, search, filters, saved views, shareable URLs, bulk actions, and clear confirmation for sensitive actions.

Required screens:

- **Portfolio Overview:** project risk, actively exploited findings, overdue work, coverage, and trends.
- **Projects:** ownership, stack, environments, criticality, and freshness.
- **Project Detail:** overview, services, inventory, deployments, findings, investigations, policies, integrations, and activity.
- **Finding Detail:** why affected, evidence, dependency path, sources, priority explanation, remediation, ticket/PR, and timeline.
- **Investigation Workspace:** scoped question, execution plan, tool progress, evidence, limitations, reviewer feedback, and rerun actions.
- **Asset/Component Detail:** versions, architecture, provenance, relationships, affected deployments, and history.
- **Deployment Drift:** expected versus deployed versus observed state.
- **Remediation Campaigns:** cross-project progress, owners, blockers, and verification.
- **Automation Center:** rules, schedules, runs, approvals, and deliveries.
- **Coverage Dashboard:** missing SBOMs, stale observations, failed connectors, unsupported analysis, and unowned assets.
- **Administration:** memberships, role mapping, connections, secret references, policies, retention, and audit.

Every aggregate metric must drill down to its supporting records. Do not use a single opaque security score as the only executive view. Show risk alongside coverage and uncertainty.

## 14. CI/CD Integration

Deliver a complete GitHub Actions integration first, then expand through adapters to Azure DevOps, GitLab CI, and Jenkins.

On pull requests: detect manifest changes, compare SBOMs, ingest SCA/SAST/secret/IaC results as supported, distinguish new findings from baseline, and publish a concise summary with remediation links.

On build: associate scan results and SBOM with commit SHA, CI run, and immutable artifact digest. On deployment: record target environment and trigger re-evaluation or verification.

Policy gates must be deterministic and configurable. Define blocking conditions, expiring exceptions, and fail-open/fail-closed behavior for unavailable services. Do not block all builds merely because an LLM job is slow or unavailable. Do not allow an LLM response to override authorization or policy.

Provide example pipelines for PHP/Composer, Node.js, Java/Maven, .NET/NuGet, Docker, and Terraform. Verify scanner coverage rather than assuming one scanner supports all checks for all ecosystems.

Use short-lived/scoped authentication where supported, protect fork-PR secrets, redact logs, and pin trusted tooling to reviewed versions or digests.

## 15. External Integrations

Priorities:

- GitHub repositories, PRs, Issues, and Actions.
- Azure DevOps Boards/PBI for remediation ownership.
- Email and Slack/Teams webhooks.
- AWS read-only inventory, starting with explicitly selected supported resource types.
- Optional Dependency-Track, DefectDojo, Renovate, Wazuh, SIEM, and monitoring adapters.

Each connector requires capability documentation, least-privilege permissions, secure credential references, health checks, retry behavior, audit, rate limits, and disconnect/revocation handling.

Ticket synchronization needs stable external IDs, idempotency, explicit state mapping, conflict handling, and loop prevention. An external ticket becoming Done does not prove a finding is verified fixed.

Choose one authoritative owner for each field and lifecycle state when integrating another findings platform. Do not operate two unsynchronized sources of truth.

Expose versioned REST APIs, OpenAPI documentation, scoped ingestion credentials, signed webhooks, replay protection, and outbound event subscriptions.

## 16. Architecture and Storage

Prefer a modular monolith initially: React/TypeScript frontend, backend API/BFF, asynchronous workers, PostgreSQL, a queue, object storage for SBOM/evidence, and Keycloak. Choose the backend based on existing code or team fit; explain the decision. Isolate AI/scanner execution only where justified.

Modules: Identity, Organizations, Projects, Inventory, Intelligence, Matching, Investigations, Findings, Remediation, Notifications, Integrations, Policies, Reporting, and Audit.

Avoid unnecessary microservices and mandatory graph/vector databases. Use appropriate relational structures first; introduce specialized storage only with demonstrated needs.

Core entities include organizations, identities, memberships, teams, project access, projects, services, environments, repositories, assets, observations, components, dependency edges, SBOMs, artifacts, deployments, advisories, advisory revisions, affected ranges, matches, findings, evidence, investigations, agent runs, tool executions, policies, evaluations, exceptions, remediation campaigns, tickets, alerts, deliveries, connections, CI runs, webhook receipts, and audit events.

Define foreign keys, uniqueness, indexes, tenant boundaries, retention, immutable snapshots, schema migrations, and safe archival. Use an outbox or equivalent reliable event handoff where database changes trigger background work. Design workers for at-least-once delivery and idempotent execution.

Events include inventory.updated, artifact.scanned, deployment.recorded, advisory.updated, finding.created, finding.priority_changed, investigation.completed, alert.triggered, sla.breached, and remediation.verified.

## 17. Security and Operations

Protect secrets through a secret manager or encrypted credential store with managed keys. Never expose them in evidence, exports, logs, prompts, or browser storage.

Implement tenant-aware access controls, audit trails, TLS, secure cookies, CSRF protection, input validation, rate limits, secure uploads, dependency hygiene, and backup/restore. Protect URL-fetching connectors against SSRF, unsafe redirects, and unauthorized internal network access. Restrict untrusted job execution and outbound connectivity.

Ship local Docker Compose, Keycloak realm configuration, migrations, environment templates, seed data, health/readiness endpoints, structured logs, correlation IDs, queue metrics, ingestion lag, agent cost metrics, and delivery failure monitoring.

Document data retention, disaster recovery assumptions, upgrade/rollback procedures, access revocation, and incident handling. Make deployment sizing and supported scale explicit and validate them with a representative benchmark. Do not invent performance or availability guarantees.

## 18. Research and Reuse Requirements

Research official repositories and documentation before choosing integrations:

| Reference | Repository | Learn or evaluate |
|---|---|---|
| Dependency-Track | https://github.com/DependencyTrack/dependency-track | Portfolio, SBOM, component analysis, policy, VEX |
| DefectDojo | https://github.com/DefectDojo/django-DefectDojo | Finding normalization, deduplication, workflow |
| NVIDIA Vulnerability Analysis | https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis | Tool-based exploitability investigation |
| Security Lab Taskflow Agent | https://github.com/GitHubSecurityLab/seclab-taskflow-agent | Agent workflow, checkpointing, evidence review |
| Tracecat | https://github.com/TracecatHQ/tracecat | Security automation and case workflows |
| Trivy | https://github.com/aquasecurity/trivy | Vulnerability, secret, misconfiguration scanning |
| Syft | https://github.com/anchore/syft | Artifact inventory and SBOM generation |
| Renovate | https://github.com/renovatebot/renovate | Dependency update automation |
| Wazuh | https://github.com/wazuh/wazuh | Endpoint/runtime observations |
| Keycloak | https://github.com/keycloak/keycloak | Identity and SSO |

For each selected component record the inspected release/commit, verified capabilities, API compatibility, licensing, Community/Enterprise limitations, operational cost, and integration boundaries. Features and licenses may change; verify current official material. Do not treat reference projects as interchangeable complete solutions or copy code without checking its license.

## 19. Testing and AI Evaluation

Implement meaningful unit, integration, and end-to-end tests for:

- Keycloak login/logout and denied access.
- Cross-tenant/project access, including agents, exports, and shared assets.
- Version comparison, affected ranges, aliases, and vendor backports.
- Import validation, duplicate delivery, and idempotency.
- Advisory revisions and re-evaluation.
- Alert grouping, routing, retries, and escalation.
- Ticket sync without loops.
- Queue failure, checkpoint recovery, and cancellation.
- Artifact/deployment identity and post-deploy verification.
- Prompt injection, secret redaction, and tool authorization.

Create a labeled evaluation dataset containing affected, not affected, and insufficient-evidence cases. Measure unsupported claims, evidence correctness, missed prerequisites, cost, and latency. Re-run evaluations when changing models, prompts, tools, or policies.

An agent reviewing another agent is a quality control step, not independent proof. Require reliable evidence and human review for policy-defined consequential decisions.

## 20. Delivery Milestones

### Milestone 1 — Foundation

Keycloak SSO, authorization, organizations/projects/services/environments, manual/import inventory, audit, and working UI.

### Milestone 2 — Security Workflow

SBOM/scanner ingestion, advisory synchronization, matching, findings, policy, dashboard, and a working notification channel.

### Milestone 3 — AI Investigation

Project discovery, advisory research, deployment-specific investigation, evidence workspace, and authorized Copilot.

### Milestone 4 — Remediation and Delivery

CI integration, artifact/deployment tracking, PBI/GitHub tickets, campaigns, draft-PR integration where authorized, and verification.

### Milestone 5 — Operational Readiness

Selected AWS inventory, scheduled reports, recovery, observability, backup/restore validation, performance checks, and security review.

For each milestone provide scope, dependencies, acceptance criteria, runnable demonstration, tests, deployment instructions, limitations, and remaining backlog. Do not invent calendar estimates without team and capacity assumptions.

## 21. Mandatory End-to-End Demonstration

Use clearly labeled synthetic projects and advisories or verified public examples:

1. Sign in through Keycloak as two users with different project access.
2. Onboard two projects with different stacks and at least UAT/Production environments.
3. Import SBOM or scanner results tied to artifacts.
4. Ingest an advisory and identify relevant deployments.
5. Run an agent investigation showing evidence and unknowns.
6. Generate an explainable priority and notify the correct owner once.
7. Create a remediation ticket with traceable links.
8. Record a merged fix while keeping the production finding open.
9. Record deployment of the fixed artifact.
10. Verify the correct environment and close only with sufficient evidence.
11. Show the complete audit timeline and updated dashboard.
12. Break a connector and demonstrate a coverage warning rather than a false safe result.

## 22. Required Deliverables and Completion Standard

Deliver:

- Product requirements and feature acceptance matrix.
- Source code and reproducible local setup.
- Architecture decisions, data model, migrations, and API contracts.
- Functional dashboard and all critical user flows.
- Keycloak configuration and role mapping documentation.
- Working scanner/CI/notification integration for the first vertical slice.
- Agent workflow definitions, tool schemas, output contracts, and evaluation cases.
- Integration permission guides and configuration examples.
- Automated test results and a demonstration script.
- Deployment, operations, backup/restore, upgrade, and troubleshooting documentation.
- An explicit list of disconnected, experimental, unsupported, and unfinished capabilities.

The product is complete only when the implemented scope works through the full lifecycle with real persistence, authorization, background execution, and verifiable integrations. Distinguish a runnable development build, an integration-tested release, and a production-validated deployment.

Begin by inspecting the workspace, recording assumptions, and producing the implementation plan. Then build and verify the first end-to-end milestone, continuing through authorized work rather than stopping after presenting the plan.


# Version 2 — Operational Product Addendum
Updated: 21 November 2026. This addendum extends all preceding requirements; it does not remove the original scope.

## 23. Project operational workspace
Provide project-scoped onboarding, data sources, CI/CD, environments, policy, notifications, schedules and activity. Draft configurations are isolated by project. Organization templates may be inherited with explicit overrides. Show effective settings and who changed them. Shared assets respect all relevant project permissions.

The onboarding sequence is metadata → services/environments → connection method → discovery preview → conflict review → inventory confirmation → policy/routing → first verified ingestion. Record completion independently for each connection. Never mark a project protected merely because a wizard was completed.

## 24. CI ingestion and policy contracts
Implement versioned endpoints POST /api/v1/ingestions/sbom, GET /api/v1/ingestions/{id}, POST /api/v1/deployments and GET /api/v1/policy-evaluations/{id}. These names are proposed API contracts, not currently implemented routes.
SBOM ingestion accepts a supported validated CycloneDX or SPDX document plus organization/project/service/environment IDs, commit, branch, CI run URL, application version, immutable artifact digest and source timestamp. Return 202 with an ingestion ID and status URL. Reject scope mismatches and oversized or malformed inputs. Use an idempotency key and return the original receipt for a duplicate.
Deployment events must establish the artifact actually rolled out to the named environment. Uploaded build data alone is not proof of a deployment.

Deliver reviewed, pinned pipeline examples for GitHub Actions, GitLab CI, Jenkins and Azure DevOps. Start with GitHub Actions as a fully tested integration. Support ecosystem-specific SBOM tools rather than claiming uniform scanner coverage. The wizard generates copyable configuration only for supported, verified adapters; planned adapters display contracts instead.
Use short-lived identity where supported or a scoped, expiring CI token stored in the CI secret manager. Support rotation and revocation. No ingestion token may read unrelated project findings. Fork-PR jobs must not receive protected credentials.
Define baseline versus new findings, exception expiry, deterministic blocking conditions, timeout, exit codes and explicit fail-open/fail-closed choice. A slow AI job must not silently override a gate. Reassess stored inventory on new advisory revisions without requiring another build.

## 25. Connectors and import workbench
Support repository connectors, selected AWS resources, restricted runtime collectors, SBOM uploads, scanner imports, Dependency-Track and reviewed manual observations. Each adapter advertises supported resource types, permissions and limits.
Configuration includes project scope, resource allowlist, secret reference, freshness threshold, field precedence, disconnect policy and health state. User-provided URLs require SSRF and redirect controls.
Show dry-run preview, mapping, row-level errors, accepted/rejected counts, immutable source receipt, snapshot diff and review queue. A disconnected source cannot produce a successful observation. Preserve history after disconnect according to retention policy while stopping future access.
Resolve collisions using field-specific precedence; manual overrides require reason, approver and expiry.

## 26. Notification operations
Support email, Slack, Teams, signed webhooks and on-call adapters. Secrets remain server-side. Separate a routing rule from the delivery channel and from an individual delivery attempt.
Test delivery performs a real send only on an authorized user action; display provider receipt and outcome. Never show a successful test from a fixture.
Routing includes project/environment, applicability, exploitation, priority, freshness and SLA conditions, owner/team, grouping window, quiet hours, timezone, critical bypass policy and escalation.
Use an outbox, deduplication key, bounded retries with jitter, dead-letter queue, operator replay, stable alert IDs and webhook signature/replay protection. Distinguish accepted by provider from delivered to recipient where the provider supports receipts.
Alert body includes affected deployment, observed/fixed version, evidence, why this matters, recommended action, owner and due date. Redact secrets and sensitive evidence.
Acknowledge, snooze, resolve and reopen actions are audited. Ticket completion never automatically verifies remediation.

## 27. Durable scheduling
Job families: advisory sync, inventory reassessment, stack collection, connector health, verification, daily report and SLA evaluation.
Each schedule has owner, project scope, IANA timezone, frequency, local time, next_run_at UTC, last attempt/success, timeout, retry budget, overlap policy and missed-run policy. Weekly schedules also require a weekday.
Calculate next run with timezone/DST-aware code. Support pause/resume, Run now, edit and archive. Run now creates a persistent job and does not alter the recurring schedule unless explicitly selected.
Scheduler emits durable queue jobs with a lease, fencing or equivalent concurrency protection, stable occurrence ID and idempotency. Workers execute at least once with safe duplicate handling. Browser sessions never drive execution.
Monitor scheduler heartbeat, missed occurrences, ingestion lag, dead-letter backlog and delivery failures. An ingestion failure generates an incomplete-report notice rather than a false zero-risk report.
Default Vietnamese daily report: 08:00 Asia/Ho_Chi_Minh, past 24 hours, material changes, with a no-material-new-items message scoped precisely to THN coverage. Never claim that all software is safe.

## 28. Agent control plane
Expose workflow selection, model/provider policy, allowed data classes, project-scoped tool permissions, max tool calls, wall-clock timeout, run cost budget and approval rules.
Show execution state, tool action summaries, evidence receipts, missing evidence, structured conclusions, policy/model/prompt versions, usage and reviewer feedback. Do not expose private chain-of-thought.
Provider connectivity is distinct from investigation workflow readiness. Test connection must record a real provider result; the current live module can analyze submitted evidence but has no automated repository or cloud connector.
Authorization, version comparisons, policy gates, SLA, dedupe and allowed actions are deterministic backend responsibilities. Retrieved content cannot grant permissions. Deny writes without the appropriate approval context.
Allow reruns on new evidence or advisory revision, retaining previous results and change explanations.

## 29. Required operational UI and state behavior
Operations command center; project onboarding; source configuration; CI/CD handoff; alert channels; routing and escalation; schedules; jobs and deliveries; AI agent policy; SSO/access; complete requirements.
Existing portfolio, findings, inventory, drift, investigations, campaigns, reports and audit views remain in scope.
Every live resource supports loading, empty, permission denied, validation error, unavailable dependency, stale and partial states. List views require scope filters and pagination. Aggregates drill into records. On mobile, navigation scrolls and forms stack without clipping.
Use explicit capability states: UI prototype, backend implemented, integration tested, connected and production validated. Do not merge these into a single Ready badge.

## 30. Implementation status as of this artifact
| Capability | Actual status |
|---|---|
| Existing project/findings/drift/campaign views | Synthetic interaction prototype |
| Operations forms and project draft configuration | Interactive UI; session-local drafts only |
| CI/CD handoff | Contract preview only; ingestion/gate APIs not implemented |
| Sources / AWS / repositories / Dependency-Track | Design and configuration UI; not connected |
| Alert channels and routing | Draft UI; no messages sent |
| Schedules and jobs | Draft/state model UI; no durable scheduler or queue |
| Live AI submitted-evidence analysis | Backend code exists; requires configured authentication, storage and provider |
| Automated AI project discovery / investigation tools | Required workflow; not implemented |
| Keycloak | Adapter exists; realm configuration/live test absent; owner allowlist only |
| Multi-organization/project RBAC | Required; not implemented |
| S3-compatible persistence | Adapter exists; credentials/bucket not configured |
| Production readiness | Not achieved |

Browser draft saving must never imply server persistence or activate external work. No secret values belong in browser drafts. This artifact is for product review and implementation handoff; offline operation does not enable the hosted API.

## 31. Acceptance scenarios for operational release
1. Two users in different project roles cannot read each other's unauthorized inventory, evidence, exports or agent results.
2. A CI upload creates one immutable receipt and one assessment despite duplicate requests; a revoked token fails.
3. An advisory revision re-evaluates the last deployed inventory without another CI build.
4. A matching P1 production finding sends exactly one correctly routed alert; transient provider failure retries without duplicate tickets.
5. A missed daily schedule applies its configured catch-up policy and preserves original scheduled occurrence time.
6. Daily report sends a scoped no-new-items message on a successful empty run, and an incomplete-coverage message on source failure.
7. An AI tool request outside project scope is denied; prompt injection cannot expand permissions.
8. A proposed fix remains open until the intended deployed artifact is verified, and contradictory evidence reopens review.
9. A disconnected connector marks observations stale and creates an operational warning without inventing a safe result.
10. Restoring the database, object store and queue state from backups is tested against documented recovery objectives.

## 32. Deployment boundaries and release gates
Vercel hosts the frontend and bounded API/BFF. PostgreSQL holds tenant/project state; private object storage holds SBOM/evidence; a durable queue, scheduler and workers execute scans, investigations and deliveries. Keycloak remains the identity provider. Select managed or self-hosted services based on operating constraints; do not create paid resources without scope authorization.
Release gates: migrations and rollback checked; cross-project authorization tested; one actual CI ingestion + matching + alert + deployed-fix verification slice passes; scheduler recovery and delivery retry verified; provider/data permissions approved; backup/restore tested; deployment protection and secret management checked. Calendar estimates require team capacity.
