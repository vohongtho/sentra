# UI parity with the v2 handoff

The goal referenced a claude.ai artifact URL for the UI. From this environment that page returns "Sign in to view this page", and the Claude Docs API denies access. Its content could not be read. The handoff package states that `OPEN-UI.html` is the standalone version of the interactive UI, so parity was checked against it.

The handoff UI's route table was extracted from `source/public/*.js` (22 product routes plus the 11 Operations Studio pages). Each row below names the Sentra route that replaces it. Every Sentra route listed was opened in a browser on 21 November 2026 with seeded data: it rendered without an error state, and the console stayed empty. Old handoff links (`#/ops/...`, `#/ai-config`, ...) redirect to the new routes.

| Handoff screen | Handoff route | Sentra route | Notes |
|---|---|---|---|
| Overview / Command center | `#/overview`, `#/ops/control` | `/` | Live portfolio data instead of illustrative numbers |
| Projects | `#/projects` | `/projects` | |
| Project detail | `#/project` | `/projects/:id` + 10 tabs | Adds inventory, deployments, import, access, knowledge, attack paths, external findings, activity |
| Project onboarding | `#/ops/onboard` | `/projects/new`, `/projects/:id/onboarding` | Steps are persisted server-side, not browser drafts |
| Findings | `#/findings` | `/findings` | |
| Finding detail | `#/finding` | `/findings/:id` | |
| AI investigations | `#/investigation` | `/investigations`, `/investigations/:id` | |
| Live AI analysis | `#/analysis` | `/analysis` | Submitted-evidence workflow with deterministic matching |
| AI configuration | `#/ai-config`, `#/ops/agents` | `/agents` | |
| API credentials | `#/ai-credentials` | `/agents` (key dialog + connection test) | Key sealed server-side; never returned |
| Saved assessments | `#/ai-history` | `/investigations` | |
| Synthetic demo lab | `#/lab` | seeded synthetic organization | All synthetic records are labeled |
| Assets & inventory | `#/asset` | `/assets`, `/assets/:id`, `/components/:id` | |
| Deployment drift | `#/drift` | `/drift` | |
| Remediation | `#/campaign` | `/campaigns` | |
| Automations | `#/automation` | `/automation` (alerts, rules, policies, channels, schedules, jobs, deliveries) | |
| Reports | `#/report` | `/reports`, `/reports/:id` | |
| Coverage | `#/coverage` | `/coverage` | |
| Integrations / Data sources | `#/ops/sources` | `/integrations` | |
| CI/CD setup | `#/ops/pipeline` | `/ci` | |
| Alert channels | `#/ops/channels` | `/automation/channels` | |
| Routing & SLA | `#/ops/routing` | `/automation/rules`, `/automation/policies` | |
| Schedules | `#/ops/schedules` | `/automation/schedules` | |
| Jobs & deliveries | `#/ops/jobs` | `/automation/jobs`, `/automation/deliveries` | |
| SSO & access | `#/ops/access` | `/admin` (+ invitations, role mapping, secrets, settings) | |
| Settings | `#/settings` | `/admin/settings` | |
| Audit | `#/audit` | `/audit` | |
| Product requirements | `#/ops/requirements` | `/requirements` | Includes the live feature matrix |

Visual language was kept: dark surface, lime accent, DM Sans/Manrope, the grouped sidebar (Workspace / Operations / Manage), card layout and badge colors.

If the claude.ai artifact differs from `OPEN-UI.html`, those differences are unknown here. Sharing the artifact publicly, or exporting its HTML into the repository, would allow the comparison.
