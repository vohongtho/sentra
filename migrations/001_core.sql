-- Sentra core schema. PostgreSQL 15+ (also runs on embedded PGlite for development/tests).
-- Tenant boundary: every business row carries org_id; project-scoped rows carry project_id.
-- Authorization is enforced in application code (src/authz.mjs); see docs/ARCHITECTURE.md for the RLS evaluation.

CREATE TABLE organizations (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  settings JSONB NOT NULL DEFAULT '{}'::jsonb,       -- onboarding policy, default timezone/language, retention
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Human identities come from Keycloak (issuer+subject). No passwords are stored.
CREATE TABLE identities (
  id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT,
  display_name TEXT,
  groups JSONB NOT NULL DEFAULT '[]'::jsonb,
  disabled BOOLEAN NOT NULL DEFAULT false,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (issuer, subject)
);

-- org_role: org_admin | security_analyst | member | management_viewer | auditor
CREATE TABLE memberships (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  org_role TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'manual',               -- manual | invitation | group_mapping
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, identity_id)
);

CREATE TABLE invitations (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  org_role TEXT NOT NULL,
  project_roles JSONB NOT NULL DEFAULT '[]'::jsonb,     -- [{project_id, role}]
  invited_by TEXT REFERENCES identities(id),
  expires_at TIMESTAMPTZ NOT NULL,
  accepted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Keycloak group/client-role -> application role mapping.
CREATE TABLE role_mappings (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  claim TEXT NOT NULL,                                  -- groups | client_roles
  value TEXT NOT NULL,
  org_role TEXT,
  project_id TEXT,
  project_role TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE teams (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  email TEXT,
  UNIQUE (org_id, name)
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,                                  -- sha256 of opaque cookie value
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  idp_session_id TEXT,                                  -- Keycloak "sid" for back-channel logout
  tokens_sealed TEXT,                                   -- AES-GCM sealed refresh/id tokens (server-side only)
  access_expires_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  auth_method TEXT NOT NULL,                            -- keycloak | dev
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX sessions_identity ON sessions(identity_id);
CREATE INDEX sessions_sid ON sessions(idp_session_id);

-- ---------------------------------------------------------------- projects
CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  owner_identity_id TEXT REFERENCES identities(id),
  team_id TEXT REFERENCES teams(id),
  criticality TEXT NOT NULL DEFAULT 'medium',           -- low|medium|high|critical
  data_classification TEXT NOT NULL DEFAULT 'internal', -- public|internal|confidential|restricted
  exposure TEXT NOT NULL DEFAULT 'internal',            -- internet|partner|internal|isolated
  tags JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  onboarding JSONB NOT NULL DEFAULT '{}'::jsonb,        -- per-step completion; never implies "protected"
  archived_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, key)
);

-- project_role: project_owner | tech_lead | developer | devops | viewer
CREATE TABLE project_access (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  granted_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, identity_id)
);

CREATE TABLE services (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'application',
  repository_id TEXT,
  owner_team_id TEXT REFERENCES teams(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, key)
);

CREATE TABLE environments (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key TEXT NOT NULL,                                     -- uat | production | ...
  name TEXT NOT NULL,
  is_production BOOLEAN NOT NULL DEFAULT false,
  exposure TEXT NOT NULL DEFAULT 'internal',
  timezone TEXT NOT NULL DEFAULT 'Asia/Ho_Chi_Minh',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, key)
);

CREATE TABLE repositories (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,                                -- github | gitlab | azure | other
  full_name TEXT NOT NULL,
  default_branch TEXT DEFAULT 'main',
  connection_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, provider, full_name)
);

-- Assets may be shared across projects through asset_projects.
CREATE TABLE assets (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                                     -- server|container_workload|database|managed_service|load_balancer|function
  identifier TEXT NOT NULL,                               -- e.g. arn, hostname, cluster/ns/workload
  name TEXT NOT NULL,
  architecture TEXT,                                      -- x86_64 | arm64 | unknown
  os TEXT,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  criticality TEXT NOT NULL DEFAULT 'medium',
  owner_team_id TEXT REFERENCES teams(id),
  last_observed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, kind, identifier)
);
CREATE TABLE asset_projects (
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  environment_id TEXT REFERENCES environments(id) ON DELETE SET NULL,
  PRIMARY KEY (asset_id, project_id)
);

-- ---------------------------------------------------------------- artifacts & deployments
CREATE TABLE artifacts (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  service_id TEXT REFERENCES services(id) ON DELETE SET NULL,
  digest TEXT NOT NULL,                                   -- sha256:... immutable identity
  name TEXT,
  tag TEXT,                                               -- mutable label; never identity
  version TEXT,
  commit_sha TEXT,
  branch TEXT,
  ci_run_url TEXT,
  built_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, digest)
);

CREATE TABLE deployments (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  asset_id TEXT REFERENCES assets(id),
  deployed_at TIMESTAMPTZ NOT NULL,
  recorded_by TEXT,                                       -- identity id or ci token id
  source TEXT NOT NULL DEFAULT 'api',
  is_current BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX deployments_current ON deployments(project_id, service_id, environment_id) WHERE is_current;

-- ---------------------------------------------------------------- inventory
CREATE TABLE components (
  id TEXT PRIMARY KEY,
  purl TEXT NOT NULL UNIQUE,                              -- versioned package URL (or synthesized identity)
  ecosystem TEXT NOT NULL,                                -- npm|maven|pypi|composer|go|cargo|nuget|rubygems|deb|rpm|apk|generic|...
  namespace TEXT,
  name TEXT NOT NULL,
  version TEXT,                                           -- NULL => unknown version
  kind TEXT NOT NULL DEFAULT 'library',                   -- library|framework|runtime|os_package|application|product
  cpe TEXT,
  distro TEXT                                             -- e.g. amazonlinux:2023, debian:12
);
CREATE INDEX components_eco_name ON components(ecosystem, name);

-- Immutable snapshots: one per ingestion of a source for an artifact/asset.
CREATE TABLE inventory_snapshots (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  artifact_id TEXT REFERENCES artifacts(id),
  asset_id TEXT REFERENCES assets(id),
  source TEXT NOT NULL,                                   -- ci_sbom|upload|manual|connector:<id>|discovery
  collection_method TEXT NOT NULL,
  format TEXT,                                            -- cyclonedx|spdx|trivy|csv|json|yaml|sarif
  content_sha256 TEXT NOT NULL,
  object_key TEXT,                                        -- raw document in object storage
  component_count INT NOT NULL DEFAULT 0,
  collected_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE observations (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  snapshot_id TEXT NOT NULL REFERENCES inventory_snapshots(id) ON DELETE CASCADE,
  component_id TEXT NOT NULL REFERENCES components(id),
  artifact_id TEXT REFERENCES artifacts(id),
  asset_id TEXT REFERENCES assets(id),
  environment_id TEXT REFERENCES environments(id),
  service_id TEXT REFERENCES services(id),
  version_kind TEXT NOT NULL DEFAULT 'resolved',          -- declared|resolved|artifact|runtime
  direct BOOLEAN,                                         -- NULL => unknown
  dependency_path JSONB NOT NULL DEFAULT '[]'::jsonb,
  architecture TEXT,
  confidence TEXT NOT NULL DEFAULT 'reported',            -- verified|reported|inferred
  source TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  stale BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX observations_component ON observations(component_id);
CREATE INDEX observations_snapshot ON observations(snapshot_id);
CREATE INDEX observations_project ON observations(project_id);

CREATE TABLE dependency_edges (
  snapshot_id TEXT NOT NULL REFERENCES inventory_snapshots(id) ON DELETE CASCADE,
  parent_component_id TEXT NOT NULL REFERENCES components(id),
  child_component_id TEXT NOT NULL REFERENCES components(id),
  PRIMARY KEY (snapshot_id, parent_component_id, child_component_id)
);

CREATE TABLE inventory_overrides (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target TEXT NOT NULL,                                   -- e.g. component purl / asset field
  field TEXT NOT NULL,
  value JSONB NOT NULL,
  reason TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  approved_by TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- intelligence
CREATE TABLE advisories (
  id TEXT PRIMARY KEY,                                    -- canonical id (CVE preferred, else GHSA/OSV/vendor)
  source TEXT NOT NULL,                                   -- osv|manual|synthetic|vendor
  title TEXT,
  summary TEXT,
  details TEXT,
  severity TEXT,                                          -- critical|high|medium|low|none|unknown
  cvss_vector TEXT,
  cvss_version TEXT,
  cvss_score NUMERIC,
  status TEXT NOT NULL DEFAULT 'published',               -- published|withdrawn|rejected|disputed
  published_at TIMESTAMPTZ,
  modified_at TIMESTAMPTZ,
  current_revision INT NOT NULL DEFAULT 1,
  is_synthetic BOOLEAN NOT NULL DEFAULT false,
  references_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  prerequisites JSONB NOT NULL DEFAULT '[]'::jsonb,       -- [{kind:'architecture'|'config'|'feature', value, note}]
  mitigations JSONB NOT NULL DEFAULT '[]'::jsonb,
  raw JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE advisory_aliases (
  alias TEXT PRIMARY KEY,
  advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE
);

CREATE TABLE advisory_revisions (
  advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
  revision INT NOT NULL,
  modified_at TIMESTAMPTZ,
  content_sha256 TEXT NOT NULL,
  change_summary JSONB NOT NULL DEFAULT '[]'::jsonb,
  raw JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (advisory_id, revision)
);

CREATE TABLE affected_ranges (
  id TEXT PRIMARY KEY,
  advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  range_type TEXT NOT NULL,                               -- ECOSYSTEM|SEMVER|GIT
  events JSONB NOT NULL DEFAULT '[]'::jsonb,              -- OSV events [{introduced},{fixed},{last_affected}]
  versions JSONB NOT NULL DEFAULT '[]'::jsonb,            -- explicit affected versions
  distro TEXT,                                            -- backport context
  architectures JSONB,                                    -- NULL => all
  database_specific JSONB
);
CREATE INDEX affected_ranges_pkg ON affected_ranges(ecosystem, package_name);

-- Separate exploitation signals; never merged.
CREATE TABLE exploit_signals (
  id TEXT PRIMARY KEY,
  advisory_id TEXT NOT NULL,                              -- canonical or alias (CVE)
  kind TEXT NOT NULL,                                     -- kev|epss|public_poc|vendor_exploited|observed_in_env
  value JSONB NOT NULL,
  source TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  UNIQUE (advisory_id, kind, source)
);

-- ---------------------------------------------------------------- findings
CREATE TABLE policies (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE, -- NULL => org default
  kind TEXT NOT NULL,                                     -- priority|sla|gate
  version INT NOT NULL,
  definition JSONB NOT NULL,
  active BOOLEAN NOT NULL DEFAULT true,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  advisory_id TEXT NOT NULL REFERENCES advisories(id),
  component_id TEXT NOT NULL REFERENCES components(id),
  service_id TEXT REFERENCES services(id),
  environment_id TEXT REFERENCES environments(id),
  deployment_id TEXT REFERENCES deployments(id),
  artifact_id TEXT REFERENCES artifacts(id),
  asset_id TEXT REFERENCES assets(id),
  dedupe_key TEXT NOT NULL,
  root_cause_key TEXT NOT NULL,                           -- groups occurrences (advisory+package+fixed)
  severity TEXT NOT NULL,
  applicability TEXT NOT NULL DEFAULT 'under_investigation', -- affected|not_affected|under_investigation|unknown
  applicability_justification TEXT,
  exploitation TEXT NOT NULL DEFAULT 'none_known',        -- none_known|poc_public|kev_listed|actively_exploited|observed_in_env
  priority TEXT NOT NULL,                                 -- P0..P4
  priority_explanation JSONB NOT NULL DEFAULT '[]'::jsonb,
  priority_policy_version INT,
  status TEXT NOT NULL DEFAULT 'new',
  status_reason TEXT,
  verification_status TEXT NOT NULL DEFAULT 'not_started', -- not_started|pending|verified|failed|contradicted
  observed_version TEXT,
  fixed_version TEXT,
  owner_identity_id TEXT REFERENCES identities(id),
  owner_team_id TEXT REFERENCES teams(id),
  sla_due_at TIMESTAMPTZ,
  sla_paused_at TIMESTAMPTZ,
  sla_paused_seconds INT NOT NULL DEFAULT 0,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_evaluation_reason TEXT,
  closed_at TIMESTAMPTZ,
  campaign_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, dedupe_key)
);
CREATE INDEX findings_project ON findings(project_id, status);
CREATE INDEX findings_root ON findings(root_cause_key);

CREATE TABLE finding_events (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                                     -- created|status|priority|reassessed|evidence|verification|ticket|comment
  from_value TEXT,
  to_value TEXT,
  reason TEXT,
  actor TEXT,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX finding_events_f ON finding_events(finding_id, created_at);

CREATE TABLE evidence (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
  investigation_id TEXT,
  kind TEXT NOT NULL,                                     -- package_presence|version_match|architecture|config|deployment|runtime|advisory_citation|counter|missing
  stance TEXT NOT NULL DEFAULT 'supporting',              -- supporting|counter|missing|neutral
  summary TEXT NOT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  source_ref TEXT,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX evidence_finding ON evidence(finding_id);

CREATE TABLE risk_exceptions (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
  advisory_id TEXT,
  kind TEXT NOT NULL,                                     -- accepted_risk|false_positive|gate_exception
  scope JSONB NOT NULL DEFAULT '{}'::jsonb,
  rationale TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  approved_by TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  reevaluate_on JSONB NOT NULL DEFAULT '["advisory.updated","exploitation.changed"]'::jsonb,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE campaigns (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  root_cause_key TEXT,
  description TEXT,
  owner_identity_id TEXT REFERENCES identities(id),
  status TEXT NOT NULL DEFAULT 'active',
  plan JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tickets (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,                                 -- github|azure_devops|internal
  connection_id TEXT,
  external_id TEXT,
  external_url TEXT,
  idempotency_key TEXT NOT NULL UNIQUE,
  external_state TEXT,
  mapped_state TEXT,
  last_synced_at TIMESTAMPTZ,
  last_sync_origin TEXT,                                   -- sentra|external (loop prevention)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pull_requests (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  url TEXT,
  state TEXT NOT NULL,                                     -- draft|open|merged|closed
  merged_at TIMESTAMPTZ,
  merge_commit_sha TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- AI investigations
CREATE TABLE investigations (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE, -- NULL only for portfolio scope
  workflow TEXT NOT NULL,                                 -- discovery|advisory_research|impact|remediation|verification|portfolio|copilot
  question TEXT,
  inputs JSONB NOT NULL DEFAULT '{}'::jsonb,
  scope JSONB NOT NULL DEFAULT '{}'::jsonb,               -- authorized project ids at creation time
  state TEXT NOT NULL DEFAULT 'queued',                   -- queued|running|waiting_evidence|waiting_approval|completed|partial|failed|cancelled
  provider TEXT,
  model TEXT,
  prompt_version TEXT,
  policy_version TEXT,
  tool_version TEXT,
  result JSONB,
  error TEXT,
  usage JSONB NOT NULL DEFAULT '{}'::jsonb,
  cost_usd NUMERIC NOT NULL DEFAULT 0,
  checkpoint JSONB,
  previous_id TEXT,
  rerun_reason TEXT,
  reviewer_feedback JSONB NOT NULL DEFAULT '[]'::jsonb,
  cancel_requested BOOLEAN NOT NULL DEFAULT false,
  requested_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);

CREATE TABLE tool_executions (
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  seq INT NOT NULL,
  tool TEXT NOT NULL,
  input JSONB NOT NULL,
  output_summary TEXT,
  output JSONB,
  status TEXT NOT NULL,                                   -- ok|denied|error
  duration_ms INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (investigation_id, seq)
);

CREATE TABLE agent_policies (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
  workflow TEXT NOT NULL,
  definition JSONB NOT NULL,                              -- provider, model, allowed_data_classes, tools, max_tool_calls, timeout_s, budget_usd, approval
  version INT NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX agent_policies_scope ON agent_policies(org_id, COALESCE(project_id, ''), workflow);

CREATE TABLE knowledge_items (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'assumption',                -- assumption|control|architecture
  evidence_ref TEXT,
  reviewed_by TEXT,
  expires_at TIMESTAMPTZ,
  revalidate_on JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- integrations & secrets
CREATE TABLE secrets (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  sealed TEXT NOT NULL,                                   -- AES-256-GCM sealed value, never returned via API
  fingerprint TEXT NOT NULL,                              -- last 4 chars hash for UI confirmation
  created_by TEXT,
  rotated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

CREATE TABLE connections (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                                     -- osv|kev|epss|thn|github|azure_devops|aws|dependency_track|smtp|slack|teams|webhook
  name TEXT NOT NULL,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,              -- non-secret settings, resource allowlist, freshness, precedence
  secret_id TEXT REFERENCES secrets(id),
  status TEXT NOT NULL DEFAULT 'disconnected',            -- disconnected|connected|degraded|failed|disabled
  last_check_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_error TEXT,
  cursor JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ci_tokens (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  service_id TEXT REFERENCES services(id),
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  scopes JSONB NOT NULL DEFAULT '["ingest:sbom","deployments:write","policy:read"]'::jsonb,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ingestions (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL,
  kind TEXT NOT NULL,                                     -- sbom|import|scanner
  status TEXT NOT NULL DEFAULT 'accepted',                -- accepted|processing|completed|failed|rejected
  receipt JSONB NOT NULL,
  request_meta JSONB NOT NULL DEFAULT '{}'::jsonb,
  object_key TEXT,
  snapshot_id TEXT,
  evaluation_id TEXT,
  error TEXT,
  stats JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  UNIQUE (project_id, idempotency_key)
);

CREATE TABLE policy_evaluations (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  ingestion_id TEXT,
  policy_id TEXT,
  policy_version INT,
  status TEXT NOT NULL DEFAULT 'pending',                 -- pending|completed|error
  decision TEXT,                                          -- pass|fail|warn
  mode TEXT,                                              -- observe|block_new
  fail_mode TEXT,                                         -- open|closed
  exit_code INT,
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  violations JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE webhook_receipts (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  delivery_id TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider, delivery_id)
);

-- ---------------------------------------------------------------- notifications
CREATE TABLE channels (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                                     -- in_app|email|slack|teams|webhook
  name TEXT NOT NULL,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,              -- recipients etc (non-secret)
  secret_id TEXT REFERENCES secrets(id),                  -- webhook URL / signing key
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alert_rules (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  triggers JSONB NOT NULL,                                -- event types
  conditions JSONB NOT NULL DEFAULT '{}'::jsonb,          -- environments, priorities, applicability, exploitation, production_only
  actions JSONB NOT NULL DEFAULT '[]'::jsonb,             -- [{type:'notify',channel_id},{type:'ticket',connection_id},{type:'investigate',workflow}]
  route_to JSONB NOT NULL DEFAULT '{}'::jsonb,            -- owner|team|identity ids
  grouping_window_s INT NOT NULL DEFAULT 0,
  quiet_hours JSONB,                                      -- {start:'22:00', end:'07:00', timezone}
  critical_bypass BOOLEAN NOT NULL DEFAULT true,
  escalation JSONB,                                       -- {after_s, channel_id}
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
  rule_id TEXT REFERENCES alert_rules(id) ON DELETE SET NULL,
  dedupe_key TEXT NOT NULL,
  trigger TEXT NOT NULL,
  finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body JSONB NOT NULL,
  priority TEXT,
  state TEXT NOT NULL DEFAULT 'open',                     -- open|acknowledged|snoozed|resolved
  snoozed_until TIMESTAMPTZ,
  acknowledged_by TEXT,
  acknowledged_at TIMESTAMPTZ,
  escalated_at TIMESTAMPTZ,
  occurrences INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, dedupe_key)
);

CREATE TABLE deliveries (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  alert_id TEXT REFERENCES alerts(id) ON DELETE CASCADE,
  report_run_id TEXT,
  channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  dedupe_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending',                 -- pending|sending|accepted|delivered|failed|dead|held
  attempts INT NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_error TEXT,
  provider_receipt JSONB,
  is_test BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notifications (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  alert_id TEXT REFERENCES alerts(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  link TEXT,
  read_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- scheduling, queue, outbox
CREATE TABLE schedules (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  job_type TEXT NOT NULL,                                 -- advisory_sync|inventory_reassessment|stack_collection|connector_health|verification|daily_report|sla_evaluation
  owner_identity_id TEXT REFERENCES identities(id),
  timezone TEXT NOT NULL,
  frequency TEXT NOT NULL,                                -- hourly|daily|weekly
  local_time TEXT NOT NULL DEFAULT '08:00',               -- HH:MM (hourly uses :MM)
  weekday INT,                                            -- 0=Sunday .. 6 (weekly only)
  params JSONB NOT NULL DEFAULT '{}'::jsonb,
  next_run_at TIMESTAMPTZ NOT NULL,                       -- UTC
  last_attempt_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  timeout_s INT NOT NULL DEFAULT 600,
  retry_budget INT NOT NULL DEFAULT 3,
  overlap_policy TEXT NOT NULL DEFAULT 'skip',            -- skip|queue|allow
  missed_run_policy TEXT NOT NULL DEFAULT 'run_once',     -- skip|run_once|run_all
  paused BOOLEAN NOT NULL DEFAULT false,
  archived_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  org_id TEXT,
  project_id TEXT,
  type TEXT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key TEXT UNIQUE,                            -- e.g. schedule occurrence id
  schedule_id TEXT,
  scheduled_for TIMESTAMPTZ,                              -- original occurrence time
  status TEXT NOT NULL DEFAULT 'queued',                  -- queued|running|succeeded|failed|dead|cancelled
  priority INT NOT NULL DEFAULT 100,
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 5,
  run_after TIMESTAMPTZ NOT NULL DEFAULT now(),
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  fence INT NOT NULL DEFAULT 0,
  checkpoint JSONB,
  result JSONB,
  last_error TEXT,
  cancel_requested BOOLEAN NOT NULL DEFAULT false,
  correlation_id TEXT,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);
CREATE INDEX jobs_ready ON jobs(status, run_after, priority);

CREATE TABLE outbox (
  id BIGSERIAL PRIMARY KEY,
  org_id TEXT,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at TIMESTAMPTZ,
  attempts INT NOT NULL DEFAULT 0,
  last_error TEXT
);
CREATE INDEX outbox_pending ON outbox(id) WHERE processed_at IS NULL;

CREATE TABLE report_runs (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  schedule_id TEXT,
  job_id TEXT,
  kind TEXT NOT NULL,                                     -- daily_portfolio|thn_coverage
  language TEXT NOT NULL DEFAULT 'vi',
  period_start TIMESTAMPTZ NOT NULL,
  period_end TIMESTAMPTZ NOT NULL,
  coverage_status TEXT NOT NULL,                          -- complete|incomplete
  content JSONB NOT NULL,
  rendered_text TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE saved_views (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  page TEXT NOT NULL,
  name TEXT NOT NULL,
  query JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE draft_configs (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  section TEXT NOT NULL,
  data JSONB NOT NULL,
  updated_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, section)
);

-- Append-only audit with hash chain for tamper evidence.
CREATE TABLE audit_events (
  seq BIGSERIAL PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  org_id TEXT,
  project_id TEXT,
  actor_id TEXT,
  actor_type TEXT NOT NULL,                               -- user|ci|system|agent|connector
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  correlation_id TEXT,
  prev_hash TEXT,
  hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_org ON audit_events(org_id, seq);
CREATE INDEX audit_target ON audit_events(target_type, target_id);

CREATE TABLE system_heartbeats (
  component TEXT PRIMARY KEY,                             -- scheduler|worker:<id>
  beat_at TIMESTAMPTZ NOT NULL,
  info JSONB NOT NULL DEFAULT '{}'::jsonb
);
