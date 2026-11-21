# Integrations: permissions and configuration

Credentials are entered once, sealed with `SENTRA_MASTER_KEY`, and never returned by the API. The UI shows the secret's name and an 8-character fingerprint. User-supplied URLs (webhooks, `api_base`, `feed_url`) must be HTTPS and must not resolve to private, loopback, link-local or metadata addresses. Redirects are not followed.

A connection's `config` is non-secret JSON. Every inventory connector accepts `environment_id` (environment key or ID) and `freshness_hours`. Past the freshness window, the health job marks the connector's observations stale and raises `inventory.stale`. **Disconnect** stops access, marks observations stale and keeps history.

| Connector | Least privilege | Config | Status |
|---|---|---|---|
| OSV.dev | none (public API) | optional `api_base` | Implemented; not connected |
| CISA KEV | none (public feed) | optional `feed_url` | Implemented; not connected |
| FIRST EPSS | none (public API) | optional `api_base` | Implemented; not connected |
| The Hacker News | none (public RSS) | optional `feed_url` | Implemented; feed fetched once |
| GitHub repository | Fine-grained token on the selected repositories: Contents read, Metadata read. Add Issues read/write for tickets. Draft remediation PRs additionally need Contents write and Pull requests write. | `owner`, `repo`, optional `ref` | Implemented; not connected |
| GitHub webhook (inbound) | Repository webhook, events `issues` and `pull_request`, secret in `GITHUB_WEBHOOK_SECRET`, URL `/api/webhooks/github` | n/a | Implemented; not connected |
| Azure DevOps Boards | PAT scoped to Work Items (Read & write) on one project | `organization`, `project`, optional `work_item_type` (default Product Backlog Item), `area_path`, `done_state` | Implemented; not connected |
| AWS | IAM role or user with `lambda:ListFunctions`, `ec2:DescribeInstances`, and `ecr:DescribeImages` on the listed repositories only. Credentials from the default AWS chain, or a secret `{"access_key_id","secret_access_key","session_token"}`. | `region`, `resource_types` (subset of `lambda:function`, `ec2:instance`, `ecr:image`), `ecr_repositories`, `environment_id`; must be project-scoped | Implemented; not connected |
| Dependency-Track | API key with `VIEW_PORTFOLIO` | `api_base`, `project_uuid`, optional `display_name` | Tested against a test double |
| Email (SMTP) | An SMTP account that can send from `SMTP_FROM` | channel `to`, optional `smtp_host`/`smtp_port`/`smtp_user` and password | Implemented; not connected |
| Slack | Incoming webhook URL for one channel | URL (stored as a secret) | Implemented; not connected |
| Microsoft Teams | Workflows "post to channel when a webhook request is received" URL | URL (stored as a secret) | Implemented; not connected |
| Wazuh | API user with read-only RBAC for `agents:read` and `syscollector:read`; stored as a JSON secret with `user` and its credential | `api_base`, `environment_id`; must be project-scoped | Tested against a test double |
| DefectDojo | API v2 key of a user who can read the product | `api_base`, `product_id`; must be project-scoped | Tested against a test double |
| SIEM (Splunk HEC or JSON collector) | HEC key scoped to one index, or a bearer key for a JSON collector | channel: `url`, `format` (`splunk_hec`/`json`), optional `index`, `sourcetype` | Tested against a local receiver |
| Signed webhook | Your endpoint | URL; signing key generated and shown once | Tested against a local receiver |

The AWS connector records Lambda managed runtimes as `generic` components (for example `node (Lambda managed runtime)@20`). That data shows coverage and runtime age. It is not matched against package advisories.

## Verifying a webhook signature

```js
const [ts, sig] = [req.headers['x-sentra-timestamp'], req.headers['x-sentra-signature']];   // sig = "v1=<hex>"
const expected = 'v1=' + crypto.createHmac('sha256', SIGNING_KEY).update(`${ts}.${rawBody}`).digest('hex');
const fresh = Math.abs(Date.now() / 1000 - Number(ts)) < 300;
if (!fresh || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) reject();
// X-Sentra-Delivery is stable across retries: use it to drop duplicates.
```

## Tickets and source of truth

Sentra owns finding state. External tickets mirror it one way:

- A ticket is created once per finding, provider and connection (idempotency key). Repeated requests return the same ticket.
- Sentra closes linked tickets after verified remediation and marks the change as its own, so the resulting inbound webhook is ignored.
- A ticket closed externally is recorded on the finding timeline with the note that it does not verify remediation. The finding's status does not change.
- A merged PR whose body contains `fnd_<id>` moves the finding to `fix_available`. It stays open until the deployed artifact is verified.

## Draft remediation PRs

From a finding with a known fixed version, **Create draft PR** edits one manifest through the GitHub API and opens a draft pull request:

- `package.json` / `composer.json`: the direct dependency becomes `^<fixed>`. A transitive npm package gets an `overrides` entry, with a note that upgrading the parent is preferable.
- `requirements.txt`: the pinned line.
- `pom.xml`: a literal `<version>`.

The PR is refused, with an explanation, when a bump is insufficient. That covers Composer transitive packages, unpinned Python packages, and Maven versions coming from a property or BOM.

Sentra never runs package managers or repository scripts and never merges. The PR body lists lockfile regeneration, tests, rollout and rollback, and carries `Sentra-Finding: <id>`, so a later merge moves the finding to *fix available*. Closure still requires the deployed artifact to be verified.

## Renovate

Renovate (AGPL-3.0) is not embedded. Install it on the repository as usual and register the repository on the project (`POST /api/projects/{id}/repositories`). Through the GitHub webhook, Sentra recognizes PRs by `renovate[bot]` or `renovate/*` branches and parses "Update dependency <pkg> to v<version>". It links the PR to open findings for that package only when the target version evaluates as outside the affected range. A PR to a still-affected version is reported as skipped.

## Wazuh and DefectDojo

Wazuh syscollector packages become runtime observations on one asset per agent. The asset carries the agent's distribution (for example `amzn-2023`) and architecture, so distribution-specific and architecture-limited advisories evaluate correctly.

DefectDojo findings are stored as external references (**Project → External findings**). Each is linked to a Sentra finding when an advisory alias and the component match. Sentra remains the source of truth for lifecycle; DefectDojo states are never written back.

The exact API paths used for Wazuh and DefectDojo are listed in `RESEARCH.md`. They follow those projects' public conventions and have not been run against real servers.
