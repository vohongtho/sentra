# Demonstration script

All projects, packages and advisories are synthetic (`SYNTH-*` advisories, `acme`/`demo` packages) and labeled as such in the UI. The automated version of this script is `tests/e2e.test.mjs`. Each step names the test that proves it.

Start with `npm run dev` and open http://localhost:8080. The seed builds 4 artifacts, records 8 deployments and ingests 5 advisories through the real pipeline. Development identity mode lets you switch users. With the Docker realm, sign in through Keycloak as `pat` or `kim` instead.

1. **Two users, different access.** Sign in as *Pat Owner (TTS)*, who sees only the TTS project, then as *Kim Lead (Kiosk)*, who sees only Kiosk. Opening a Kiosk finding URL as Pat returns "Not found or not accessible". Test: `1. two users…`.
2. **Two projects, UAT and Production.** Projects → TTS Telemetry / Kiosk Platform. Onboard a third project from **Onboard project**. Test: `2. onboard a project…`.
3. **SBOM tied to an artifact.** CI/CD setup → create a token → run `scripts/sentra-ci.mjs upload …`, or look at Project → Deployments → ingestion receipts. Test: `3+4. CI SBOM upload…` and `tests/ci-cli.test.mjs`.
4. **Advisory ingestion and affected deployments.** Advisories → *Investigate a CVE* → paste an OSV record for `@acme/xml-parser`. The advisory page lists affected deployments in your scope. Test: `advisory revision re-evaluates…`.
5. **Agent investigation with evidence and unknowns.** As Kim, open the production finding for `SYNTH-2026-0005` → *Investigate impact*. Presence is confirmed and prerequisites are not met, because the asset reports `admin_handler_exposed=false`. Reachability and compromise stay unknown, and the proposal waits for approval. Test: `5. agent impact investigation…`.
6. **Explainable priority, owner notified once.** A finding's *Priority explanation* lists the points per factor. Automation center → Alerts shows one alert per finding and rule, with an occurrence count instead of repeats. Test: `6+7…`.
7. **Remediation ticket.** The production rule created internal tickets automatically. *Create ticket* is idempotent. Test: `6+7…`.
8. **Merged fix stays open.** On the TTS production `SYNTH-2026-0001` finding, *Record pull request* with state merged. Status becomes *fix available*, not closed. Test: `8-10…`.
9. **Deploy the fixed artifact.** `sentra-ci.mjs deploy --environment uat` with the fixed digest closes only the UAT finding. Production stays open until its own deployment.
10. **Verified closure with evidence.** After the production deployment, the finding is *verified fixed*, with the deployed digest, snapshot and timestamp as evidence, and the linked ticket is closed. Rolling back to the old digest reopens it as *contradicted*.
11. **Audit and dashboard.** Audit shows logins, ingestions, deployments, verification and approvals, and the hash chain verifies. Overview numbers link to filtered finding lists. Test: `11…`.
12. **Broken connector.** Integrations → a connector → *Disconnect*. Coverage shows stale observations and a disconnected source, and an `inventory.stale` alert appears. No finding is closed as safe. Test: `12…`.

Also worth showing: Automation → Schedules → *Run now* on "Báo cáo hằng ngày (VI) 08:00". Reports then shows a Vietnamese report, marked incomplete when a feed was unreachable.
