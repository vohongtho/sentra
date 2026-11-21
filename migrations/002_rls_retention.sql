-- Defense in depth: PostgreSQL row-level security on tenant tables.
-- Request-scoped connections set app.org_id (src/db.mjs scoped()); rows of other organizations are invisible to them
-- even if application authorization were bypassed. Connections that do not set app.org_id (workers, scheduler,
-- migrations) are unrestricted, because they legitimately cross organizations (e.g. global advisory reassessment).
-- FORCE applies the policies to the table owner too. Superusers always bypass RLS: run the app as a non-superuser.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['projects','services','environments','repositories','assets','artifacts','deployments',
    'inventory_snapshots','observations','findings','evidence','risk_exceptions','campaigns','tickets','pull_requests',
    'investigations','agent_policies','knowledge_items','secrets','connections','ci_tokens','ingestions',
    'policy_evaluations','channels','alert_rules','alerts','deliveries','notifications','schedules','report_runs',
    'saved_views','draft_configs','memberships','invitations','role_mappings','teams','inventory_overrides','policies']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I USING (
        coalesce(current_setting('app.org_id', true), '') = '' OR org_id = current_setting('app.org_id', true)
      ) WITH CHECK (
        coalesce(current_setting('app.org_id', true), '') = '' OR org_id = current_setting('app.org_id', true)
      )$p$, t);
  END LOOP;
END $$;

-- audit_events: org rows visible only to that org; global (NULL org) rows visible to everyone.
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_events USING (
  coalesce(current_setting('app.org_id', true), '') = '' OR org_id IS NULL OR org_id = current_setting('app.org_id', true)
) WITH CHECK (
  coalesce(current_setting('app.org_id', true), '') = '' OR org_id IS NULL OR org_id = current_setting('app.org_id', true)
);

-- Retention: archived audit periods. Verification of the remaining chain starts from the last archived hash.
CREATE TABLE audit_archives (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  through_seq BIGINT NOT NULL,
  last_hash TEXT NOT NULL,
  event_count INT NOT NULL,
  object_key TEXT NOT NULL,
  archived_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_archives_org ON audit_archives(org_id, through_seq DESC);

-- Remediation pull requests opened by Sentra (draft PR workflow) and Renovate links.
ALTER TABLE pull_requests ADD COLUMN IF NOT EXISTS branch TEXT;
ALTER TABLE pull_requests ADD COLUMN IF NOT EXISTS created_by TEXT;
ALTER TABLE pull_requests ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual'; -- manual|sentra_draft|github_webhook|renovate

-- External findings reported by other platforms (DefectDojo). Kept as references, not merged into Sentra findings.
CREATE TABLE external_findings (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  connection_id TEXT NOT NULL,
  external_id TEXT NOT NULL,
  title TEXT,
  severity TEXT,
  vulnerability_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  component TEXT,
  component_version TEXT,
  state TEXT,
  url TEXT,
  linked_finding_id TEXT,
  seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (connection_id, external_id)
);
ALTER TABLE external_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON external_findings USING (coalesce(current_setting('app.org_id', true), '') = '' OR org_id = current_setting('app.org_id', true));
