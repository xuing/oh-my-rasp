# Architecture Gap Repair Plan

Source audit: [`architecture-gap-audit.md`](architecture-gap-audit.md)

Status legend:

- `[Open]`: repair not started.
- `[In Progress]`: code or tests are being changed.
- `[Fixed]`: implemented and covered by focused tests.
- `[Deferred By Design]`: explicitly out of the current product boundary, with a compensating documentation or UX change where needed.

## Issue Register

| ID | Audit issue | Explanation | Repair plan | Verification |
|---|---|---|---|---|
| AG-01 | Alert delivery backend is absent. `[Fixed]` | Alert rules create `alert_deliveries`, but queued rows are never sent or failed. The UI can imply notification delivery when no sender exists. | Added an app-level alert delivery worker. It drains queued deliveries, POSTs HTTP/HTTPS webhook targets, and records `delivered` or `failed` with `attempts`, `last_error`, and `delivered_at`. | `go test ./...`; focused worker tests; live acceptance showed one HTTP webhook delivery became `delivered` and one unsupported target became `failed`. |
| AG-02 | Server policy is fetched by the Java agent but not applied. `[Fixed]` | The agent obtains a policy document but detection still comes from built-in rules only. Console rule edits do not affect runtime behavior. | Added an agent policy parser/evaluator, installed pulled policies from `ControlPlaneClient`, and evaluate hook/algorithm/expression/action at detection time. A loaded empty policy suppresses standalone detections. | `docker run --rm -v "$PWD/java-agent":/src -w /src gradle:jdk25 gradle :agent:test`; focused parser, control-plane pull, and hook action tests. |
| AG-03 | Blocking is controlled by a single global JVM flag. `[Fixed]` | The console exposes per-rule `action`, but the agent currently blocks all detections only when a process-wide flag is set. | Policy-controlled detections now use the matched rule action (`log`, `block`, or `ignore`). The legacy `ohmyrasp.block` flag only applies when no policy is loaded, while `ohmyrasp.force_block` remains available as an explicit emergency override. | Java hook tests prove a policy `log` rule does not block even when the legacy flag is set, while a policy `block` rule does block. |
| AG-04 | Agent does not report dependencies. `[Fixed]` | Backend and UI support dependency/SCA data, but the Java agent does not produce it. | Added agent-side dependency inventory reporting for Java runtime, agent code source, and classpath JAR metadata where available. | Java control-plane client tests plus live API evidence from `agt_da418d23e6471bcc`: `GET /dependencies?agent_id=...` returned 2 agent-produced records. |
| AG-05 | Agent does not report baseline/config findings. `[Fixed]` | Backend and UI support baseline findings, but the Java agent does not produce them. | Added JVM runtime baseline checks for debug transport and primary supported Java version. | Java tests plus live API evidence from `agt_da418d23e6471bcc`: `GET /baseline-findings?agent_id=...` returned 2 agent-produced findings. |
| AG-06 | Agent does not report hook/performance telemetry. `[Fixed]` | Observability math is real, but real agents do not feed hook latency or overhead events. | Added hook telemetry and performance samples with latency, rule-evaluation, memory, runtime, policy, and action attributes. | Java tests plus live API evidence from `agt_da418d23e6471bcc`: hook/performance events were ingested and observability returned hook latency plus agent/policy overhead rows. |
| AG-07 | Agent does not report crash/error events. `[Fixed]` | Crash/error pages only populate when tests POST directly to the API. | Added control-plane client error/crash submission, hook failure reporting, control-plane failure reporting when an agent ID exists, and an uncaught-exception crash reporter. | Java tests plus live API evidence from `agt_da418d23e6471bcc`: error and crash event queries each returned agent-produced records with exception attributes. |
| AG-08 | `/addInstance` has no onboarding wizard. | The path renders the broad Agents page, so operators do not get a guided install path. | Add a focused onboarding surface or a route-specific focused view that exposes manual, Docker, Kubernetes, artifact, and daemon-token steps. | Playwright test for `/addInstance` landing on onboarding content. |
| AG-09 | Populated security pages depend on fixtures, not real producers. `[Fixed]` | Dependency, baseline, observability, crash, and error screens can look healthy because acceptance tests feed them manually. | Fixed the producer gaps AG-04 through AG-07 and recorded runtime evidence separately from direct fixture/API tests. | Live acceptance used a real Java `ControlPlaneClient` against the running API; dependency, baseline, hook, performance, error, crash, and observability queries all returned agent-produced data. |
| AG-10 | Memory store uses plaintext password comparison. | Production Postgres uses bcrypt, but the in-memory store stores cleartext in `PasswordHash`, which is misleading and easy to misuse. | Rename the field/path or hash in memory too so test-only behavior cannot be mistaken for production semantics. | Go tests for memory login still pass and no plaintext `PasswordHash` path remains. |
| AG-11 | `pages.tsx` is a monolithic UI module. | A 5k+ line file combines unrelated routes and makes review, testing, and maintenance poor. | Split high-risk route surfaces into dedicated route modules, starting with login/fallback and focused legacy entry pages. | Build/test plus reduced ownership of new route entry points. |
| AG-12 | Frontend is not route-code-split. | The login route downloads the full console bundle and Vite warns about a >500 KB chunk. | Introduce route-level lazy loading and split route modules enough to remove the oversized single app chunk. | `npm run build` without the >500 KB single-chunk warning. |
| AG-13 | Frontend test coverage is too shallow. | Existing tests cover only a small fraction of the route and form behavior. | Add tests for route guards, legacy focus behavior, alert delivery status, onboarding, and route RBAC. | Increased Vitest/Playwright assertions covering each repaired issue. |
| AG-14 | UI advertises data the real agent cannot produce. | Navigation and page copy imply hook/performance/crash/error/dependency pipelines are live even before producers exist. | After AG-04 through AG-07, update copy to distinguish active producer status; before then, show honest empty-state/source text. | UI tests for source/status text and live agent-produced data. |
| AG-15 | Authenticated routes have no route-level RBAC guard. | Client routing only checks for any token; restricted pages rely on API errors after navigation. | Store user roles in session and add route-level role checks for admin/security features. | Playwright test that a viewer reaches `/noaccess` for restricted routes. |
| AG-16 | Legacy entry points do not focus their intended feature. | Legacy URLs render catch-all pages at the top, with no menu highlight, scroll target, or focused section. | Add route-to-focus mapping and section anchors, or split dedicated pages for each legacy capability. | Playwright test for `/maintain/clearData`, `/settings/alarm`, `/platform/user`, `/addInstance`, and other aliases focusing expected content. |
| AG-17 | Coverage documentation overstates endpoint completion as end-to-end completion. | The coverage matrix currently blurs "endpoint exists" and "real agent produces/enforces it." | Update docs to track end-to-end evidence separately from API availability and link this repair plan. | Search confirms the matrix names producer/enforcement status honestly. |
| AG-18 | Application-level alert delivery was dismissed as unnecessary. `[Fixed]` | Email test UI can be deferred, but at least one real delivery channel is necessary. | Reclassified app-level delivery as webhook-backed. Email/provider-specific setup remains future work; the product no longer treats all app-level delivery as unnecessary. | Section 11 docs now describe webhook delivery worker behavior and live webhook acceptance evidence. |

## Execution Order

1. AG-01, AG-18: add honest alert delivery.
2. AG-02, AG-03: wire policy-driven enforcement.
3. AG-04 through AG-07, AG-09, AG-14: add real agent producers and honest UI/source state.
4. AG-08, AG-11 through AG-13, AG-15, AG-16: repair frontend information architecture, route focus, RBAC, tests, and code splitting.
5. AG-10 and AG-17: harden dev semantics and finish documentation honesty.

## Running Evidence

This section is updated as repairs land.

- Initial register created from every issue in `architecture-gap-audit.md`.
- AG-01/AG-18: added `AlertDeliveryWorker`, store methods for queued delivery draining and attempt recording, Compose/env knobs, focused API tests, and live acceptance. Live result: HTTP webhook target -> `delivered` with `attempts=1` and `delivered_at`; unsupported `webhook://` target -> `failed` with `attempts=1` and `last_error`.
- AG-02/AG-03: added `AgentPolicy`, rule expression evaluation, policy installation from authenticated pull, policy action precedence over the legacy block flag, and focused Java tests for parser/evaluator, control-plane pull, `log` versus `block`, empty-policy suppression, and standalone fallback.
- AG-04/AG-05/AG-06/AG-07/AG-09: added real Java agent producers for dependency inventory, baseline findings, hook telemetry, performance samples, error events, and crash events. Focused Java tests passed. Live acceptance against the running API registered `agt_da418d23e6471bcc` and confirmed 2 dependency records, 2 baseline findings, 1 hook event, 2 performance events, 1 error event, 1 crash event, and observability rows for hook latency plus agent/policy overhead.
