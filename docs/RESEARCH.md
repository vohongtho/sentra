# Reference projects (spec §18)

Release, license and activity data below were retrieved from the GitHub REST API (`/repos/{repo}` and `/repos/{repo}/releases/latest`) on 21 November 2026. No source code from these projects was copied into Sentra. Integration happens over each project's API or data formats only.

| Project | Inspected release | Published | License (GitHub SPDX) | How Sentra relates to it |
|---|---|---|---|---|
| DependencyTrack/dependency-track | 5.2.2 | 2026-11-18 | Apache-2.0 | Inventory source. The connector reads `GET /api/v1/component/project/{uuid}` with an `X-Api-Key`. That path is the v4 REST API, and I have **not** confirmed it is unchanged in 5.x. Test against a 5.x instance before connecting. |
| DefectDojo/django-DefectDojo | 3.5.202 | 2026-11-20 | BSD-3-Clause | Findings source. The connector reads `GET /api/v2/findings/` with `Authorization: Token …` and imports active findings as scanner observations. Sentra stays the source of truth for lifecycle, and DefectDojo states are not written back. |
| NVIDIA-AI-Blueprints/vulnerability-analysis | 3.0.0 | 2026-08-19 | Apache-2.0 | Design reference only. Its idea of checklist-driven, tool-based exploitability investigation matches Sentra's impact workflow. Not a dependency. |
| GitHubSecurityLab/seclab-taskflow-agent | v0.5.1 | 2026-10-16 | MIT | Design reference for checkpointed task flows and reviewable evidence. Not a dependency. |
| TracecatHQ/tracecat | 1.5.2 | 2026-11-20 | AGPL-3.0 | Not used. AGPL-3.0 would impose source-disclosure obligations if its code were incorporated into a network service. Sentra's case/alert workflow is its own. |
| aquasecurity/trivy | v0.76.2 | 2026-11-05 | Apache-2.0 | Input format. Trivy JSON and SARIF reports are importable. Recommended for IaC/misconfiguration scanning in CI. |
| anchore/syft | v1.57.2 | 2026-11-16 | Apache-2.0 | Recommended CycloneDX generator in the CI examples, run in the customer's pipeline, not inside Sentra. |
| renovatebot/renovate | 44.257.9 | 2026-11-21 | AGPL-3.0 | Not embedded. Sentra recognizes Renovate pull requests through the GitHub webhook and links them to findings for the bumped package. Running Renovate is the customer's choice and under their license terms. |
| wazuh/wazuh | v4.14.10 | 2026-11-09 | NOASSERTION | Runtime package source via the Wazuh server API (`POST /security/user/authenticate`, then `GET /syscollector/{agent_id}/packages`). GitHub reports no single SPDX license (the repository mixes GPL-2.0 and other terms), so check licensing before redistributing any Wazuh component. Sentra only calls its API. |
| keycloak/keycloak | 26.8.2 | 2026-11-05 | Apache-2.0 | Identity provider. The live check used the `quay.io/keycloak/keycloak:26.0` image. Re-run the OIDC checks on 26.8.x before production. |

Community versus enterprise limits were not assessed for any project. Licenses and APIs change, so re-check them at adoption time.

Endpoint paths for DefectDojo, Wazuh and Splunk HEC come from their public API conventions as I know them. The adapters are tested against local test doubles shaped to those conventions, not against real servers, and are marked "not connected" in the feature matrix.
