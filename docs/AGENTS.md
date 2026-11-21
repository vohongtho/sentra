# AI agents

## Runtime

An investigation is a row in `investigations` plus a job. The worker runs it under the requester's *current* permissions, inside the project scope frozen at creation. States: `queued`, `running`, `waiting_evidence`, `waiting_approval`, `completed`, `partial`, `failed`, `cancelled`.

Per run, the effective agent policy (org default, overridden per project and workflow in **AI agents**) sets the provider, model, tool subset, `max_tool_calls` (default 24), `timeout_s` (300), `budget_usd` (2) and the allowed data classifications. By default, projects classified `restricted` cannot be sent to a model provider.

Every tool call is recorded in `tool_executions` with input, redacted output, status (`ok` / `denied` / `error`) and duration. The workspace shows these receipts. Model reasoning is neither stored nor displayed.

Providers:

- **Claude** (`AI_PROVIDER=anthropic`, `ANTHROPIC_API_KEY`). Uses `@anthropic-ai/sdk` with a manual tool loop on `claude-opus-5-5`. Settings: adaptive thinking (the model default), `output_config.effort` from `AI_EFFORT` (default `medium`), strict tool schemas, a cached system prompt, and server-side refusal fallback (`fallbacks: "default"`, beta `server-side-fallback-2026-07-01`). Thinking blocks are passed back unchanged. Messages are checkpointed after each turn. A refusal, `max_tokens`, budget or timeout ends the run as `partial` with the reason in its limitations. This path is tested against a Messages API test double only; no paid call has been made.
- **Offline deterministic planner** (default when no key is set). A fixed tool sequence per workflow, composed only from tool output. It is not a language model, and every result says so.

## Workflows and tools

| Workflow | Tools |
|---|---|
| evidence_analysis | get_submitted_evidence, match_submitted_components, get_advisory, evaluate_version, search_inventory, record_note |
| discovery | get_project, get_repository_inventory, parse_submitted_manifests, get_knowledge, coverage_report, record_note |
| advisory_research | get_advisory, evaluate_version, record_note |
| impact | get_finding, get_advisory, evaluate_version, search_inventory, get_deployments, get_asset, get_dependency_path, get_knowledge, record_note, propose_finding_update |
| remediation | get_finding, get_advisory, evaluate_version, search_inventory, get_deployments, get_dependency_path, list_findings, record_note |
| verification | get_finding, get_deployments, search_inventory, evaluate_version, get_advisory, record_note |
| portfolio | list_projects, shared_components, list_findings, get_advisory, record_note |
| copilot | list_projects, get_project, search_inventory, get_finding, get_advisory, evaluate_version, get_deployments, list_findings, get_changes_since, coverage_report, shared_components, get_knowledge |

Schemas and descriptions are in `src/ai/tools.mjs` (`TOOL_DEFS`), version `tools-2026-11-21.1`. Every tool is read-only except two. `record_note` writes only to the investigation. `propose_finding_update` creates a proposal that a human with `findings:triage` must approve.

Authorization happens in `executeTool` before any query runs. The tool must be in the workflow's allowed set, the project must be in the frozen scope, and the requester must still have `project:read` on it. Denials are returned to the model as errors and recorded.

Third-party text (advisory summaries and details, knowledge notes, attached manifests) is returned inside `untrusted_content` with a handling note. The synthetic advisory `SYNTH-2026-0003` deliberately contains "IGNORE ALL PREVIOUS INSTRUCTIONS…". Tests confirm that it reaches the model only as wrapped data and that scope stays fixed regardless of tool arguments.

## Output contract

`submit_result` (strict JSON schema in `src/ai/agents.mjs`):

```json
{ "summary": "…", "applicability": "affected|not_affected|under_investigation|unknown|not_applicable",
  "dimensions": { "presence": "…", "reachability": "…", "prerequisites": "…", "compromise": "…" },
  "claims": [{ "statement": "…", "stance": "supporting|counter|neutral", "evidence_refs": [3, 5] }],
  "missing_evidence": ["…"], "limitations": ["…"], "next_actions": ["…"], "plan": ["…"] }
```

`validateResult` then applies four rules:

- Claims whose `evidence_refs` don't point at a successful tool call in the same run move to `unsupported_claims`, and the run becomes `partial`.
- `not_affected` is downgraded to `under_investigation` unless a deterministic `evaluate_version` returned not affected or a cited claim carries counter-evidence.
- Denied tool calls and early stops are appended to `limitations`.
- Secret-shaped strings are redacted.

A rerun keeps the previous run and records what changed in applicability and in each dimension.

## Evaluation

`fixtures/agent-eval.json` holds 5 labeled impact cases on the synthetic portfolio: 2 affected, 1 not affected, 2 with insufficient evidence (one with the injection advisory). `node scripts/eval-agents.mjs` reports per-case pass/fail, applicability accuracy, unsupported claims, missed prerequisites, cost and latency, and writes `docs/eval/latest-<model>.json`.

Current result: the offline planner passes 5/5. That says little, because the planner was written alongside these cases. The dataset is meant for comparing Claude configurations. Run it with `AI_PROVIDER=anthropic` (billed) after any change to model, prompt (`investigator-2026-11-21.1`), tools or policy. Five cases are too few to measure quality. Grow the dataset with real reviewed investigations before relying on the numbers.
