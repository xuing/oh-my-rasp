# OhMyRasp — Commercial-Grade Readiness Audit & Refactor Plan (2026-07-12)

> Method: eight parallel read-only auditors (one per layer) each followed by an
> **adversarial verifier** whose job was to *refute* the findings. Of ~60 raw
> findings, verifiers refuted 1 and added 15 the finders missed. Every finding
> below cites `file:line`. The two agent-core criticals were additionally
> re-verified by hand. No builds or Docker were run (disk safety).

---

## 1. Verdict

**Overall grade: C‑ / D+ — "impressive demo, not yet commercial-grade."**

OhMyRasp has *unusually broad* surface for an OSS project — a 9,585-line detector
engine, four JVM-version agents, a full Go control plane with Postgres/ClickHouse/
Valkey, a React console, and a Helm + Prometheus + Grafana stack. But breadth is
hiding four load-bearing failures, any one of which a serious adopter would treat
as disqualifying:

| # | The single most damaging truth | Severity |
|---|--------------------------------|----------|
| 1 | **The agent can crash the app it protects.** ASM is appended to the *bootstrap* classloader **un-relocated**, so it shadows every host library's ASM (Spring CGLIB, Hibernate, Byte Buddy, Groovy, Mockito). Version mismatch → `NoSuchMethodError`/`LinkageError` inside the customer JVM. This is the #1 real-world RASP failure mode and commercial agents universally shade ASM. (`OhMyRaspAgent.java:34`, `agent-jdk25/build.gradle.kts:37`) | CRITICAL |
| 2 | **Turning on blocking breaks all Java deserialization.** `DeserializationGuard.check()` returns `REJECTED` for *every* class when `-Dohmyrasp.block=true`, and silently disables itself if the app already set a serial filter. (`DeserializationGuard.java:18-26`) | CRITICAL |
| 3 | **The console's policy editor is inert on 3 of 4 runtimes.** Only `agent-jdk25` installs cloud policy; `agent-java8/11/17` `RaspRuntime` regex-parse only `"mode"` and have no policy engine at all — exactly the legacy JVMs where the vulnerable middleware lives. (`AgentRuntime.java:177-186` vs `agent-java8/.../RaspRuntime.java:41-45`) | CRITICAL |
| 4 | **The product itself has zero CI.** CI triggers only on `api/**`, `console/**`, `deploy/**`. `java-agent/**` (~100k LOC, the RASP engine) and `daemon/**` are never built or tested. A PR that disables a detector merges green. (`.github/workflows/ohmyrasp-control.yml:3-16`) | CRITICAL |

Per-layer maturity:

| Layer | Grade | One-line |
|-------|-------|----------|
| Java agent core (`agent-jdk25`) | **C** | Broad detection, but host-crash risk, all-or-nothing deser filter, ~10 unwired detector families, regex (not taint) detection. |
| Java backports (`java8/11/17`) | **D** | A 3× copy-paste fork in a *different* architecture than jdk25, already drifted, and missing ~11 detector families jdk25 ships. |
| Rust daemon | **C** | Clean code, but loses events on restart/crash, unbounded spool can fill disk, drops all non-attack telemetry, untested upload path. |
| Go control-plane API | **C** | Solid scaffolding, but no per-application tenant isolation, plaintext agent secrets at rest, an un-drained event outbox, god-file store. |
| React console | **B** | Best-built layer. But every mutation fails silently, no error boundary, no unit tests, no lint, token in localStorage. |
| Tests / CI / release | **D** | Inverted pyramid (30k LOC of un-run bash), no lint/coverage/SBOM/dep-scan, release publishes without testing, agent jar never built or signed. |
| Docs / OSS readiness | **C** | Good structure, but a broken "verified by [AI model]" badge as the top trust signal, and internal audits that contradict the public completeness claims. |
| Cross-cutting contracts | **C** | Event/policy contracts mostly consistent, but a large dead `/api/v1/daemon/*` subsystem, no protocol versioning, no idempotency. |

---

## 2. What is genuinely good (preserve this)

- **Detection breadth.** `DetectorEngine` covers SQLi, command injection, deserialization, JNDI, XXE, SSRF, expression injection, path traversal, and many CVE-specific paths with real context-awareness (benign-path suppression, decoding-variant handling). The *inventory* is a genuine asset.
- **Fail-safe hook discipline.** Hook entrypoints wrap detection in try/catch so a detector bug generally does not propagate into the app (the ASM and deser issues above are the exceptions, not the rule).
- **Two-mode deployment.** The daemon-mediated (spool + control file) and direct-cloud (`ControlPlaneClient`) split is a legitimate, thoughtful design for air-gapped vs connected fleets.
- **Control plane depth.** OpenAPI-first, generated server, 34 ordered Postgres migrations, ClickHouse for analytics, an alert-delivery outbox worker, RBAC matrix, rate limiting, bcrypt (`DefaultCost`) in the production store.
- **Console craft.** TanStack Router/Query, Tailwind v4, a real i18n system (en/zh/ja, 808 keys) with a coverage gate, live Playwright e2e, no `dangerouslySetInnerHTML`, no shipped mock data.
- **Ops maturity.** Helm chart with PDB/HPA/NetworkPolicy/securityContext, Prometheus rules, Grafana dashboards, image attestation + Trivy in release.

---

## 3. Findings by severity

### CRITICAL

| id | layer | title | effort |
|----|-------|-------|--------|
| `unshaded-asm-on-bootstrap` | agent-core | Un-relocated ASM on bootstrap classloader shadows host app's ASM → host crash | M |
| `deserialization-filter-all-or-nothing` | agent-core | Block mode rejects ALL deserialization; self-disables if a filter exists | M |
| `backports-ignore-cloud-policy` | backports | java8/11/17 honor only global `mode`, ignore console policy | L |
| `agent-and-daemon-zero-ci` | tests/ci | ~64% of the codebase (the actual product) has no CI | M |

### HIGH

| id | layer | title | effort |
|----|-------|-------|--------|
| `no-application-tenant-isolation` | go-api | Any authenticated viewer reads any application's events/deps/policies; `application_id` is a filter, not an auth boundary (`store.go:270,738,844`, `strict.go:474`) | XL |
| `plaintext-app-secret-at-rest` | go-api | `applications.agent_secret_value` stored reversibly in plaintext (`migration 026`, `store.go:150,668`) | L |
| `single-global-daemon-token` | go-api | One fleet-wide daemon token; its holder pulls every app's plaintext secret in one call (`store.go:772-814`, `migration 025`) | M |
| `outbox-never-drained` | go-api | `event_ingest_outbox` written but never drained → permanent analytics loss on any ClickHouse blip (`store.go:1801-1853`; index `018` has no consumer) | M |
| `rate-limiter-scoped-to-api-prefix` | go-api | `/metrics` and all `/v1/service/*` daemon-auth paths are unthrottled → brute-force + DoS (`server.go:636`) | M |
| `daemon-drops-all-telemetry` | cross-cutting | Daemon forwards only detections; hook/perf/crash/dependency tables and the Observability & Dependencies dashboards are structurally empty (`daemon/src/main.rs:83-89`) | L |
| `orphaned-daemon-workload-surface` | cross-cutting | Entire `/api/v1/daemon/*` + `/v1/service/*` + websocket + migrations 025-027 are dead (Rust daemon calls only 4 endpoints) (`cloud.rs:68-128`) | L |
| `backport-coverage-divergence` | backports | Backports lack ~11 detector families jdk25 ships (OpenWire/ActiveMQ RCE, RMI, HttpInvoker, XmlRpc, SpringConfig…) — legacy JVMs get weaker protection | XL |
| `fp-suppression-drift-java8-only` | backports | FP-suppression fix landed in java8 only; java11/17/jdk25 still block benign Maven/Nacos/Liferay traffic (`Java8RaspHooks.java:2207,2705,3671`) | M |
| `unjustified-4x-fork` | backports | Backports are a pure copy-paste fork, zero shared source set (`settings.gradle.kts:17-20`) | XL |
| `tailer-no-cursor-persistence` | daemon | Restart seeks to EOF (data loss) or re-reads whole spool (mass duplicates); no persisted offset (`tailer.rs:29,54-59`) | M |
| `outbox-lost-on-crash` | daemon | In-RAM retry buffer (≤10k events) persisted only on graceful shutdown; SIGKILL/OOM/panic drops it (`uploader.rs:116,156,306`) | M |
| `uploader-and-tailer-branches-untested` | daemon | The retry/outbox/rotation paths — the highest-risk code — have zero tests | L |
| `no-ci-builds-or-tests-daemon` | daemon | No CI builds/tests the daemon; README's `cargo test`/`clippy` claims unenforced | S |
| `agent-jar-never-built-signed-published` | tests/ci | Release attests only control-api/web; the agent JAR customers actually load is never built, signed, SBOM'd, or published (`api/Dockerfile:9,22`) | M |
| `unpinned-agent-dependencies` | tests/ci | jdk25 pins `asm:latest.release`; no lockfile, no verification-metadata, no gradle wrapper (`agent-jdk25/build.gradle.kts:6-10`) | S |
| `no-dependency-or-source-scanning` | tests/ci | No Dependabot/Renovate/CodeQL/govulncheck/cargo-audit; Trivy scans only 2 of the shipped components | M |
| `release-runs-no-tests` | tests/ci | Release publishes to GHCR with no `needs:` on the test workflow (`ohmyrasp-release.yml`) | S |
| `mutations-fail-silently` | console | All 30 `useMutation`s have no `onError`; failed security actions show nothing (`access.tsx:69`, `policies.tsx:58,279`) | M |
| `no-error-boundary` | console | No error boundary/`errorComponent`; one malformed record white-screens the whole console (`router.tsx:30`) | M |
| `documented-features-missing-in-ui` | console | Dependency summary/export and system-settings editor are documented "done" but have no UI; the queries are dead code (`api.ts:549,558`) | L |
| `readme-fable-badge` | docs | README's top trust badge is a "verified by [AI model]" self-grade with a **broken anchor** (`README.md:19-20`, `README.zh-CN.md:17-18`) | S |
| `unwired-detector-families` | agent-core | ~10 detector families (XSS-echo, response-data-leak, whole webshell family) are dead code; README advertises "52 detector capabilities" (`OhMyRaspHooks.java:1064-1088`) | L |
| `signature-not-taint-sqli-bypass` | agent-core | Numeric SQLi `id=1 OR 1=1` and concat-obfuscated SpEL bypass the primary detectors (`DetectorEngine.java:29-31,1517-1574,3124-3138`) | XL |

### MEDIUM (summary — full detail in the audit journal)

`no-csp-token-in-localstorage`, `no-pagination`, `a11y-gaps`, `no-unit-tests-no-lint` (console);
`internal-errors-leaked-to-clients`, `static-readiness-healthz`, `no-logout-or-password-change`, `unauthenticated-metrics-info-disclosure`, `memory-store-bcrypt-mincost`, `rate-limiter-fails-open-login-brute-force`, `god-object-store-no-service-layer` (go-api);
`tailer-reads-whole-delta-into-memory`, `spool-never-reclaimed-unbounded-disk`, `unauthenticated-control-disable-surface`, `app-secret-plaintext-http-allowed`, `blocking-fs-in-async`, `insecure-world-readable-tmp-artifacts`, `uploader-head-of-line-blocking`, `daemon-no-metrics-endpoint` (daemon);
`no-protocol-version-negotiation`, `rule-overhead-rollups-dead`, `shared-app-secret-no-agent-identity`, `attack-pipeline-no-idempotency`, `clickhouse-tables-no-ttl` (cross-cutting);
`no-e2e-block-or-perf-tests`, `threadlocal-leak-pooled-thread`, `stackwalker-on-hot-sinks` (agent-core);
`inverted-test-pyramid-acceptance-bash`, `non-hermetic-floating-images`, `no-linter-formatter-coverage`, `false-ci-gate-claims`, `ci-backend-clickhouse-service-latest` (tests/ci);
`java11-java17-fully-redundant`, `split-unnecessary-single-jar-viable`, `no-parity-guard-for-backports` (backports);
`M2-ci-badge-overstates`, `M3-no-code-of-conduct` (docs).

---

## 4. Frontend completeness — is the console finished?

**Verdict: functionally ~85% complete for the *live* API surface, with three real gaps.** Measured empirically: 68 OpenAPI paths, 49 called by the console.

**Has UI (good coverage):** applications, environments, agents, policies (+ versions/rollout/rollback/test/validate/restore-default), events (all types + recycle-bin), analytics (overview + observability), dependencies, baseline-findings, audit-logs, alert-rules, alert-deliveries, users/RBAC, system-settings key path, agent-artifacts, maintenance/cleanup.

**Missing / dead in the UI:**
1. **Dependency summary cards + export**, and a **global system-settings editor** — the `dependencySummary`/`systemSettings`/`updateSystemSetting` API methods and `useSystemSettings` hook exist but have **zero component usages** (`api.ts:549,558`; `queries.ts:125`). Yet `docs/internal/feature-coverage/04` and `/09` mark these "Completed." → build the UI or correct the docs. (`documented-features-missing-in-ui`, HIGH)
2. The Observability & Dependencies pages **render, but are structurally empty** in the recommended daemon deployment because the daemon never forwards telemetry (`daemon-drops-all-telemetry`, HIGH). Not a console bug per se, but the user sees blank dashboards.
3. **Export affordances** (`applications/export`, `dependencies/export`) are never called.

**Not a completeness gap:** the entire `/api/v1/daemon/*` surface has no UI because it is dead server-side (see `orphaned-daemon-workload-surface`).

**Quality gaps that make it feel unfinished even where present:** silent mutation failures, no error boundary, no pagination, keyboard-inaccessible table rows, no unit tests, no lint.

---

## 5. The refactor & repair plan

Legend: **effort** S<½d · M≈1-2d · L≈3-5d · XL≈1-2wk. **∥** = parallelizable (no file overlap with siblings in the same wave). **Verify** = the lightweight gate (never the vulhub matrix).

### Wave 0 — broken / security holes (must fix before any release)

| id | what | files | effort | verify | ∥ |
|----|------|-------|--------|--------|---|
| W0.1 | **Shade ASM** into `io.ohmyrasp.agent.shaded.asm` via the (already-declared) shadow plugin; relocate in `agentJar`. | `java-agent/build.gradle.kts`, `agent-jdk25/build.gradle.kts`, backport `build.gradle.kts` | M | `docker run gradle:jdk25 gradle :agent-jdk25:agentJar` then `unzip -l` shows `io/ohmyrasp/.../shaded/asm`, no `org/objectweb/asm` | A |
| W0.2 | **Selective deser filter**: `check()` rejects only detector-flagged classes; compose with any pre-existing filter instead of overwriting; don't blanket-REJECT in block mode. | `agent-jdk25/.../hook/DeserializationGuard.java`, `OhMyRaspHooks.java`, mirror in backports | M | `gradle :agent-jdk25:test` + new unit test: benign `ArrayList` UNDECIDED, gadget REJECTED | B |
| W0.3 | **Pin `asm` to `9.7.1`** (match backports); add gradle wrapper + dependency lockfile + `verification-metadata.xml`. | `agent-jdk25/build.gradle.kts`, new `gradlew`, `gradle/` | S | `gradle :agent-jdk25:dependencies` reproducible | C |
| W0.4 | **CI for the product**: jobs on `java-agent/**` (`gradle :agent-jdk25:test` + backport tests) and `daemon/**` (`cargo build/test/clippy -D warnings/fmt --check`). Add path triggers. | `.github/workflows/agent.yml`, `daemon.yml` | M | workflows lint clean; run once in CI | D |
| W0.5 | **Backports enforce cloud policy**: add a policy parser + installer to `RaspRuntime` (or the shared core from W2.1) so console policy changes behavior on java8/11/17. | `agent-java{8,11,17}/.../RaspRuntime.java` | L | per-module `gradle test` + a policy-round-trip unit test | E (after W0.4) |
| W0.6 | **Remove plaintext secret at rest**: drop `agent_secret_value`; mint short-lived scoped tokens for any daemon that needs one. Blocks on W0.7 deletion. | `migration 0XX (drop col)`, `store.go`, `types.go` | L | `go test ./...` | ‑ |
| W0.7 | **Delete the dead `/api/v1/daemon/*` + `/v1/service/*` subsystem** (routes, `legacy_daemon_ws.go`, `daemon_artifacts.go`, migrations 025-027) unless a wired roadmap exists. | `server.go:349-354,503-590`, `legacy_daemon_ws.go`, `daemon_artifacts.go` | L | `go test ./...`; OpenAPI regen | F |

### Wave 1 — blocks any serious adopter

| id | what | effort | verify | ∥ |
|----|------|--------|--------|---|
| W1.1 | **Per-application tenant isolation**: add an application-membership model; enforce `WHERE application_id IN (grants)` in the store for every list/read — not an optional filter. | XL | `go test`; new authz test: viewer of app A gets 403/empty for app B | dep→W0.7 |
| W1.2 | **Outbox drainer worker** (mirror `alert_delivery_worker.go`): replay `delivered_to_clickhouse_at IS NULL` into ClickHouse; add an undelivered-age metric. | M | `go test`; kill ClickHouse mid-ingest, confirm backfill | ∥ |
| W1.3 | **Daemon durability**: persist tailer byte-offset+inode to the buffer dir; append to on-disk outbox on enqueue with periodic `sync_all`; reclaim/rotate the consumed spool (bound disk). | L | `cargo test` new integration suite (mock HTTP): restart resumes, crash keeps outbox, spool truncates | ∥ |
| W1.4 | **Daemon forwards telemetry**: classify hook/perf/crash/dependency events and POST to the matching `/events/*` endpoints (schema already exists), or cut those tables + dashboards. Decide, don't leave the third state. | L | `cargo test`; Observability page populates in a daemon deploy | ∥ |
| W1.5 | **Rate-limit all paths + fix fail-open**: scope the limiter to every route incl. `/metrics` and daemon-auth; add per-account login lockout; constant-time daemon-token compare. | M | `go test`; brute-force test throttled | ∥ |
| W1.6 | **Console error surfacing**: a toast/`aria-live` primitive + `QueryClient defaultOptions.mutations.onError`; a route-level error boundary with reload. | M | `npm run build` + Playwright: forced 500 shows toast, bad record shows boundary | ∥ |
| W1.7 | **Console lint + unit tests**: add ESLint (typescript-eslint, jsx-a11y) + Prettier; Vitest + React Testing Library for `lib/` and each route's states; wire into CI. | M | `npm run lint && npm test` in CI | ∥ |
| W1.8 | **FP-suppression parity**: port `isMavenRepositoryArtifactWrite`/`isBenignInternalServicePath`/`isKnownLiferayPortalInclude` to java11/17/jdk25; add a cross-module parity test that fails CI on drift. | M | per-module `gradle test`; parity test green | ∥ (dep W0.4) |
| W1.9 | **Supply chain**: build+SBOM (Syft/CycloneDX)+cosign-attest all four agent jars *and* the daemon in release; publish as Release assets; enable Dependabot/Renovate + CodeQL + govulncheck + cargo-audit; extend Trivy to the daemon; make release `needs:` the test workflow. | M | release dry-run produces signed jars + SBOMs | ∥ |
| W1.10 | **Honest docs**: remove the "verified by [AI model]" badge + broken anchor from both READMEs; scope the CI badge to what it covers; reconcile `feature-coverage/*` with reality; add `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `NOTICE` (ASM/BSD attribution — legally required for the shaded jar). | S | links resolve; `NOTICE` lists ASM | ∥ |

### Wave 2 — architecture

| id | what | effort |
|----|------|--------|
| W2.1 | **Collapse the 4× fork.** The detector logic is reflective/string-name based → version-agnostic. Extract ONE `agent-core` module compiled at Java 8 bytecode; make jdk25 + backports thin adapters (or a multi-release JAR). Migrate the ~11 jdk25-only detector families into core so every runtime gets equal coverage. Delete `Java*RaspHooks` duplication. | XL |
| W2.2 | **Real taint for SQLi/expression**: replace substring "taint" with a SQL tokenizer comparing statement structure pre/post interpolation; evaluate expression payloads at the resolved-call layer. | XL |
| W2.3 | **Split god-files**: `store.go` (3763) → per-aggregate repositories + a service/domain layer; `server.go` (1188) → handler groups; `DetectorEngine.java` (9585) → per-family detector classes behind a registry. | L each |
| W2.4 | **Protocol/schema versioning** across agent↔daemon↔API + an idempotency key on the event contract (ReplacingMergeTree or dedup key) for safe rolling upgrades and no double-counting. | M |
| W2.5 | **Wire or delete unwired detectors** (XSS-echo, response-data-leak, webshell family). Advertised coverage must equal enforced coverage. | L |

### Wave 3 — polish to commercial OSS bar

`clickhouse TTL/retention`; `dependency-check gates + coverage gate (codecov)`; agent **JMH performance benchmark** + a CI overhead budget; console **pagination + full a11y pass** (dialog semantics, keyboard rows) + **httpOnly-cookie session** + **nginx CSP/security headers**; API **logout/password-change/token-revocation** + dependency-checking `/readyz`; daemon **`/metrics` endpoint** + non-root/0600 temp files; **support/compat matrix** (JDKs × app servers × frameworks actually tested); reduce the 141 near-duplicate acceptance bash scripts to a parameterized harness.

---

## 6. Explicitly out of scope / deferred

- **Rewriting detection to full dataflow taint (W2.2)** — correct long-term direction, but XL and orthogonal to shipping; the regex engine works for the CVE corpus today.
- **The god-file splits (W2.3)** — pure refactors; do them behind the behavioral fixes, not before, to keep diffs reviewable.
- **The vulhub acceptance matrix** stays a nightly/manual job, never PR-gating — it pulls 150+ Docker images and cannot run on a contributor laptop or fill a CI runner's disk.
- **Multi-org tenancy** (beyond the single hardcoded org) — the app-level isolation (W1.1) is the prerequisite; true multi-org is a later product decision.
