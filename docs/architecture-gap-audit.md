# OhMyRasp Architecture Gap Audit

> Independent audit of the OhMyRasp refactor/migration against the archived
> original (`.archive/source-drop-1-rasp`), focused on what the migration
> *claims* to deliver versus what actually works end-to-end.
>
> This document deliberately challenges the optimistic accounting in
> [`docs/feature-coverage.md`](feature-coverage.md) and
> [`docs/mock-implementation-audit.md`](mock-implementation-audit.md), both of
> which currently report the system as essentially complete with "no production
> placeholders." That conclusion is **not supported by the code or by live
> testing.**

- **Date:** 2026-06-02
- **Method:** static source review (Go API, React web, Java agent) + a live run of
  the full `docker compose` stack (Postgres + ClickHouse + Valkey + API + web),
  driving the real REST API end-to-end with `curl`, driving the live web console
  with Playwright (login + route comparison), plus `npm run build` / `npm test`
  for the frontend.
- **Evidence convention:** every claim below is backed by either a `file:line`
  reference (**source-verified**) or a reproduced live observation against the
  running API (**live-verified**). Where I could not verify something live, it is
  labeled as such.

---

## 0. TL;DR — the one finding that matters most

**OhMyRasp is currently a convincing control-plane shell with a disconnected
detection agent.** The Go backend, database layer, RBAC, audit, analytics SQL,
and policy CRUD are genuinely implemented and work. But the part that makes a
RASP product a RASP product — *the agent enforcing the policies you configure* —
is not wired up:

1. **The Java agent fetches the policy and throws it away.** The agent *does*
   detect attacks — using hardcoded regexes compiled into the agent JAR — but
   nothing you do in the policy editor (rules, actions, severities, canary %,
   rollback) changes its behavior. It detects; it just ignores everything you
   configure in the console. (§1b.1)
2. **Blocking is a single global JVM flag**, not the per-rule `action` configured
   in the console. (§1b.2)
3. **The agent only reports attack events.** Dependencies, baseline/config
   findings, performance/hook latency, crashes, and error logs are never emitted
   by the agent — those pages are only ever populated by **test fixtures**. (§1b.3, §1c.1)
4. **Alerting has no delivery backend.** "Deliveries" are written to the database
   in state `queued` and nothing ever sends them. Live: **41 of 41 deliveries
   stuck `queued`, zero delivered.** (§1b.4)
5. **The frontend collapsed 27 authenticated routes into 7 page components / 7
   nav entries.** Most legacy URLs render a generic catch-all mega-page with no
   menu entry and no deep-link to the requested feature. (§2)

Each is explained in detail below, with why it is critical and why it must be
finished for the migration to be a true replacement of the original product.

---

## 1. Feature & business implementation status

### Architecture context (what *is* real — credit where due)

To keep this audit fair, the following are genuinely implemented and were
confirmed live, so they should **not** be treated as gaps:

- **Auth/RBAC:** `POST /api/v1/auth/login` with **bcrypt** password verification
  in the production Postgres store (`api/internal/storage/postgres/store.go:206`),
  session tokens, role checks. Verified live.
- **Application / environment / agent / policy CRUD**, secret rotation, audit
  logging — verified live (created an app, environment, registered an agent,
  pulled its assigned policy).
- **Overview analytics are real SQL aggregations** (`store.go:2277-2376`):
  `attack_trend`, `attacks_by_hook`, `attacks_by_algorithm`,
  `attacks_by_user_agent` are computed from the `event_ingest_outbox` table, not
  faked. Verified live (counts and trend reflected the events I ingested).
- **ClickHouse observability genuinely computes p50/p95** quantiles
  (`api/internal/storage/clickhouse/analytics.go:358-383`) — *when fed data*.
- The Java agent's ASM instrumentation and `DetectorEngine` are real, non-trivial
  detection code (SQLi/command/file/SSRF/deserialization/etc. patterns).

The problem is not that the backend is fake. The problem is **integration and
the producer side**: the pieces exist but the data and control flow that connect
them into a working product are missing.

---

### 1a. Business logic that is NOT implemented

| # | Capability | Status | Evidence | Why it matters |
|---|---|---|---|---|
| 1a.1 | **Alert/notification delivery** (email, webhook, any channel) | **Absent.** No sender exists anywhere. | grep of `internal/` for `smtp\|mailer\|webhook\|sendmail\|notify\|sender` → **0 non-test matches**. Deliveries are only `INSERT`ed (`store.go:1774`, `internal/control/store.go:1367`) with `Status:"queued"` (`internal/control/store.go:2580`). | A detection nobody is told about has no operational value. The feature is marked `[Completed]` in coverage but is non-functional. |
| 1a.2 | **Policy → agent enforcement** (apply server rules at runtime) | **Absent.** Policy is fetched and discarded. | `ControlPlaneClient.java:21,121,125` — `cachedPolicy` is written, never read. Detection is hardcoded (`DetectorEngine.java`). | This is the core RASP value proposition. See §1b.1. |
| 1a.3 | **Per-rule / graduated enforcement** | **Absent.** Global on/off only. | `OhMyRaspHooks.java:527,538` — block decided by `Boolean.getBoolean("ohmyrasp.block")`. | See §1b.2. |
| 1a.4 | **Agent-side SCA / dependency reporting** | **Absent in the agent.** Endpoint exists; no producer. | Agent HTTP surface is only `register`, `heartbeat`, `policy`, `POST /events/attack` (`ControlPlaneClient.java:83,111,119,162`). No `/dependencies` call. | "Class-library security" (`/safe/dependency`) can never populate from a real deployment. |
| 1a.5 | **Agent-side baseline/config-audit reporting** | **Absent in the agent.** Endpoint exists; no producer. | Same surface as above; no `POST /baseline-findings` call in the agent. | "Config security check" (`/safe/baseline`) can never populate from a real deployment. |
| 1a.6 | **Agent-side performance/hook telemetry** | **Absent in the agent.** Endpoints exist; no producer. | Agent never calls `/events/performance` or `/events/hook`. Observability data source is `performance_events`/`hook_events`. | Observability page is empty in real deployments. |
| 1a.7 | **Agent-side crash & error reporting** | **Absent in the agent.** Endpoints exist; no producer. | Agent never calls `/events/crash` or `/events/error`; `JsonEventLogger`→`ControlPlaneClient.submit` only routes to `/events/attack`. | Crash/exception log pages are empty in real deployments. |
| 1a.8 | **Add-instance / onboarding wizard** (`/addInstance`) | Not implemented. | `web/src/router.tsx:56-61` routes `/addInstance` to `AgentsPage` (no wizard). Coverage labels it `[Implementation Unnecessary]`. | Operators have no guided path to install the agent (Docker/K8s/manual). Reasonable to defer, but it is *not* "covered." |

### 1b. Implemented but poorly integrated / not connected (the substantive lies)

#### 1b.1 — The policy management subsystem is disconnected from the agent ⚠️ **CRITICAL**

**Source-verified + live-verified.**

The console exposes a full policy lifecycle — create policy, add versions, edit
rules, validate, test, **canary rollout**, **rollback** — all marked
`[Completed]` in `feature-coverage.md` §5. The Go backend genuinely implements
all of these endpoints, and the agent genuinely *fetches* its assigned policy:

```
GET /api/v1/agents/{id}/policy   →  {"rules":[{"action":"block","algorithm":"sql_userinput",
                                     "expression":"' OR '1'='1", ...}], "canary_percent":100, ...}
```
*(live response from my registered agent — the server side works.)*

But the agent **never uses any of it**:

- `java-agent/.../control/ControlPlaneClient.java:21` declares
  `private volatile String cachedPolicy;`
- It is assigned at lines **121** and **125** (`cachedPolicy = response.body();`)
- It is **never read anywhere** — no getter, no parser, no application. grep for
  `cachedPolicy` returns only the declaration and the two writes.

Detection is entirely hardcoded:

- `OhMyRaspHooks.java:26` — `private static final DetectorEngine DETECTORS = new DetectorEngine();`
  (no-arg, no rules injected).
- `DetectorEngine.java:16-122` — rules are `static final Pattern`/`Set` compile-time
  constants baked into the agent JAR.
- `OhMyRaspAgent.java:26,31` — hooks come from `HookRegistry.defaults()`, a fixed set.

The only thing the agent extracts from the control plane is `policy_id` /
`policy_version` (`ControlPlaneClient.java:234-255`), which it **attaches as
metadata to uploaded events** (`policyFields()`, line 245). This is what makes
the deception convincing: events show up tagged with a policy id/version, so the
console *looks* like it is enforcing a policy — but the rules in that policy were
never consulted.

**Why this is critical:** A RASP exists to let security teams *change runtime
protection behavior from a console* — tune rules, raise/lower severity, switch a
rule from monitor to block, roll a change out to 10% of fleet, roll it back if it
breaks. Here, none of those actions affect the agent. The entire §5 ("防护设置和
检测算法") of the coverage document — validation, testing, canary, rollback,
"恢复默认", policy versioning — is operational theater. An operator who blocks an
attack class in the UI, or canaries a new rule, gets a false sense of safety while
the agent does exactly what it did before.

**Why it must be completed:** Without it, the migration has not reproduced the
original product's central function; it has reproduced its *screens*. The agent
must (a) parse the pulled policy, (b) build/adjust its hook+detector set from the
rules, (c) honor `canary_percent` and version pinning, and (d) re-evaluate on
each heartbeat (the pull cadence already exists at `ControlPlaneClient.java:97`).

#### 1b.2 — Enforcement is a global flag, not policy-driven

**Source-verified.** `OhMyRaspHooks.java:527`:
```java
boolean willBlock = blockEnabled() && value.request() != null && value.request().active();
```
and `:538`:
```java
private static boolean blockEnabled() {
  return Boolean.getBoolean("ohmyrasp.block")
      || "true".equalsIgnoreCase(System.getenv("OHMYRASP_BLOCK"));
}
```

Whether the agent blocks is a single JVM-wide boolean set at process start. The
per-rule `action` field (`block`/`log`) that the console lets you edit, validate,
and roll out is **ignored**. There is no way to block SQLi while only monitoring
file access, or to block in one app/env and monitor in another.

**Why critical:** Production RASP rollouts are graduated precisely because
blocking carries outage risk (false positives break legitimate traffic). The
standard safe pattern — monitor a new rule, then promote *that rule* to block —
is impossible. Operators are forced into all-or-nothing, so in practice they will
run monitor-only, which negates the protective value the product advertises.

#### 1b.3 — The agent is a single-signal producer

**Source-verified + live-verified.** The agent's complete outbound API surface:

| Call | Purpose |
|---|---|
| `POST /agents/register` | register |
| `POST /agents/{id}/heartbeat` | liveness |
| `GET /agents/{id}/policy` | pull (then discard) |
| `POST /events/attack` | **the only data it reports** |

(`ControlPlaneClient.java:83,111,119,162`.) Everything else in the data model —
dependencies, baseline findings, performance/hook telemetry, crash, error — has a
backend ingest endpoint and a frontend page, but **no agent code path produces
it**. The `eventPipelines` table in `web/src/domain/control-plane.ts:81-88`
advertises six pipelines (attack/hook/performance/crash/error/dependency) "flowing"
to ClickHouse/Postgres; only the attack pipeline has a real source.

**Why critical & necessary:** SCA/dependency vulnerability tracking and
configuration-baseline auditing are first-class security features the UI presents
as working (`/safe/dependency`, `/safe/baseline`), and observability/overhead
metrics are how an operator justifies running the agent in production at all
("what's the latency cost?"). All of these are dead in any real deployment until
the agent emits them.

#### 1b.4 — Alerting records "deliveries" that are never delivered ⚠️ **CRITICAL**

**Source-verified + live-verified.** On event ingest, both stores match alert
rules and `INSERT` an `alert_deliveries` row
(`postgres/store.go:1760-1784`, `control/store.go:1360-1370`) with
`Status:"queued"`, `Attempts:0`, `DeliveredAt:nil`
(`control/store.go:2572-2584`). **No code anywhere sends these** — no SMTP,
webhook, queue worker, or retry loop exists (grep confirmed). `GET
/api/v1/alert-deliveries` then renders this table in the UI as "Alert Delivery
History," strongly implying notifications went out.

Live proof — after I ingested one critical attack event, a delivery appeared
instantly, and across the whole instance:
```
total: 41
status: Counter({'queued': 41})
any delivered_at: False
attempts: Counter({0: 41})
```
Some of those `queued` rows are 16+ hours old; one even targets
`webhook://section11-live`. None has ever been attempted, let alone delivered.

> **Not the same as Alertmanager.** The compose/Helm stack ships Prometheus
> Alertmanager, but that handles *infrastructure/metric* alerts on the
> control-plane's own `/metrics`. The application's `alert_deliveries` model —
> with targets like `security-operations` and `webhook://section11-live`, created
> per matched security event — is an entirely separate path that **nothing
> drains**. The 41/41 `queued` rows are that app-level path, not Alertmanager.

**Why critical:** This is worse than a missing feature — it is an actively
misleading one. A security console that shows an "alert delivery history" is
telling on-call staff "we notified you." If the SMTP/webhook layer does not
exist, every critical detection silently fails to page anyone, and the UI hides
that fact. The coverage doc disposes of email delivery as
`[Implementation Unnecessary]` ("misleading to add a fake test email"), but the
*entire delivery mechanism* — not just a test button — is missing while the
feature is presented as complete.

**Why necessary:** Detection without notification has no MTTR value. At minimum
the system needs one real channel (webhook is cheapest), a worker that drains the
`queued` rows, and honest status transitions (`queued`→`sent`/`failed` with
`attempts`/`last_error`, which the schema already has).

### 1c. Mock / synthetic data — where the dashboards "lie"

> Note: `docs/mock-implementation-audit.md` claims the cleanup removed all
> production placeholders. The frontend fallback datasets and seeded demo values
> *were* genuinely removed (confirmed — `web/src/lib/api.ts` no longer ships
> fallback records). The remaining deception is subtler and more important: the
> pages that *look* populated are populated by **test fixtures**, not by the
> product.

#### 1c.1 — "Populated" security pages are filled only by test/acceptance fixtures

**Live-verified.** Because the agent emits only attack events (§1b.3), the only
way the dependency / baseline / observability / crash / error surfaces ever get
data is if something *other than the agent* POSTs to their ingest endpoints. In
the running stack, that "something" is the e2e/acceptance test scripts
(`web/e2e/live-control-plane.spec.ts` and the section acceptance flows). The
provenance is unmistakable in the live data:

- **Dependencies:** only `analysis-lib-mpv5hqr9` (`live/mpv5hqr9.jar`) and
  `smoke-lib` (`com/example/smoke-lib/1.0.0/...`) with `CVE-2026-SMOKE`,
  `CVE-2026-mpv5hqr9`.
- **Baseline findings:** titles like `Live baseline mpv5hqr9`.
- **Alert rules / deliveries:** `Section11 Live Alert mpv9zysx`, target
  `webhook://section11-live`.
- **Applications:** descriptions literally read `"Created by the live Playwright
  smoke flow"`.

**Why this is a "lie" to catch:** A reviewer opening the running console sees
populated dependency-vuln tables, baseline findings, observability latency
charts, and alert history, and concludes "these features work." They work only
because a test harness hand-fed them. Disconnect the test scripts and run a real
Java agent against the stack, and every one of those pages is empty. The
`[Completed]` labels in coverage §4, §7, §11 conflate "the endpoint accepts a
POST" with "the product produces this data."

#### 1c.2 — Observability quantiles are real math over fixture inputs

**Live-verified.** `/api/v1/analytics/observability` returned non-empty
`hook_latency` (p50/p95 per hook), `agent_overhead`, and `policy_performance`.
The *computation* is real (ClickHouse quantiles). The *inputs* are entirely
fixture `performance_events`/`hook_events` posted by tests. The
`mock-implementation-audit.md` even concedes the overview "Hook p95 renders `-`
until backend observability exposes a real aggregate" — i.e., the authors know
the real agent does not feed this.

#### 1c.3 — Memory store uses plaintext password comparison (dev-mode only)

**Source-verified, low severity, flagged for honesty.** `MemoryStore.Login`
compares `user.PasswordHash == password` in plaintext
(`internal/control/store.go:220`). This is **only** the in-memory dev/test store;
the production Postgres path uses bcrypt (`postgres/store.go:206`). Not a
production vulnerability, but the field name `PasswordHash` storing a cleartext
value is a footgun and should be renamed/avoided so no one wires it into a real
path.

---

## 2. Frontend issues

### 2a. Flaws & deficiencies

| # | Issue | Evidence | Why it matters |
|---|---|---|---|
| 2a.1 | **The entire app UI is one 5,351-line file.** | `web/src/routes/pages.tsx` (5,351 lines); `AccessPage` alone spans ~lines 3068-5340 (~2,270 lines). | Unmaintainable, un-reviewable, high merge-conflict surface, and impossible to lazy-load. A single page owning login, RBAC, alerts, settings, cleanup, audit, allowlist, and hardening violates separation of concerns. |
| 2a.2 | **No code splitting; 636 KB JS in one chunk.** | `npm run build`: `dist/assets/index-*.js 636.12 kB` + Vite warning "Some chunks are larger than 500 kB." | Every route (including `/login`) downloads the whole console. Poor first paint, especially for an internal security tool that should load instantly. |
| 2a.3 | **Test coverage is token.** | `npm test`: 3 files / 9 tests for ~9,400 LOC of frontend. | The "complete page coverage audit" commit (`86e9981`) does not correspond to meaningful behavioral coverage; regressions in 99% of the UI go uncaught. |
| 2a.4 | **UI advertises data the product can't produce.** | `domain/control-plane.ts:59` Events nav: "Attack, Hook, performance, crash, error, and dependency reports"; `:81-88` six "pipelines." | Sets operator expectations the agent never meets (§1b.3); the empty states will read as "broken" rather than "not yet wired." |
| 2a.5 | **Auth is a client-side token check only; no route-level RBAC.** | `router.tsx:22-26` `requireSession()` only checks `currentSession().token`; every route uses the same guard. | A non-privileged user can navigate to `/access` (user management) UI; protection relies entirely on the API rejecting calls. The archived app had a menu/permission guard (coverage §1 calls this `[Implementation Unnecessary]`). Defensible, but it is a real deficiency, not a non-issue. |

### 2b. Missing / degraded entry points ⚠️ **HIGH**

**Source-verified.** `router.tsx` defines **27 authenticated routes** (plus
`/login` and `/noaccess`) but maps them to only **7 distinct page components**
(`OverviewPage`, `ApplicationsPage`, `AgentsPage`, `PoliciesPage`, `EventsPage`,
`ObservabilityPage`, `AccessPage`). The navigation menu
(`domain/control-plane.ts:27-77`) exposes only **7 sections**. Every legacy route
is aliased to one of these 7 components — and these
are **not redirects** (no `redirect()`), they just render the same component at a
different URL, with **no deep-link, no scroll-to-section, no tab focus**:

| Legacy route(s) | Renders | Intended feature | Reachable from menu? | Focuses the feature? |
|---|---|---|---|---|
| `/maintain/whitelist` | `AccessPage` | Allowlist/whitelist config | No | No — dumps you at top of a 2,270-line page |
| `/maintain/clearData` | `AccessPage` | Data cleanup | No | No |
| `/maintain/general`, `/settings/panel`, `/settings/alarm`, `/settings/systemInfo` | `AccessPage` | System settings, public URL, alert interval, version info | No | No |
| `/algorithm/hardening`, `/algorithm/alarm` | `AccessPage` | Hardening + alarm config | No | No |
| `/platform`, `/platform/user`, `/log/audit` | `AccessPage` | Org/user mgmt, audit | No | No |
| `/maintain/hosts`, `/addInstance`, `/maintain/upgrade`, `/settings/poolVersion`, `/settings/version` | `AgentsPage` | Hosts, onboarding, upgrade, version pool | No | No |
| `/algorithm`, `/algorithm/algorithm` | `PoliciesPage` | Algorithm config | No | No |
| `/log/exceptions`, `/log/crash` | `EventsPage` | Exception/crash logs | No | No |

**Deterministic proof, not inference:** no page component reads the URL to focus
a section. A grep of `pages.tsx` for
`useLocation|useRouterState|location.hash|pathname|scrollIntoView|activeTab|useParams|useSearch`
returns **zero matches**, and there are no tab components. Therefore, *by
construction*, every alias renders its target component identically regardless of
which URL was used.

**Live-verified (Playwright, against the running web container :18091):** logged
in as admin, then compared the canonical page and a legacy alias:

| | `/access` | `/maintain/clearData` |
|---|---|---|
| First heading | `Access & Audit` | `Access & Audit` |
| `main` text length | **44,265** | **44,265** (identical) |
| Scroll position on load | top | top (no jump to cleanup form) |
| Highlighted nav item | `/access` | **none** |

So `/maintain/clearData` renders the byte-identical 44k-character "Access & Audit"
page, scrolled to the top, with no menu item highlighted — the user is given no
indication of where the "clear data" feature is, even though the "Apply Cleanup"
form is somewhere on that page.

The underlying *features* mostly do exist as sections inside `AccessPage`
(confirmed live: "Allowlist Entries/Mode", "Apply Cleanup"/"Cleanup Before",
"Hardening Mode", "Block Process Execution", "Alert Interval Seconds",
"Create User"/"Disable User", "Audit Log", system version fields, etc.). So this
is not "missing functionality" — it is **missing information architecture**:

1. There is **no menu entry** for any of these capabilities; a user who doesn't
   already know to open "Access & Audit" and scroll cannot find allowlist
   management, data cleanup, user management, or system settings.
2. The legacy URLs that *were* preserved "for compatibility" are misleading —
   `/maintain/clearData` does not take you to the cleanup form; it renders the
   whole catch-all page scrolled to the top.
3. Distinct legacy concerns (host inventory vs onboarding vs version pool vs
   upgrade) all collapse onto one undifferentiated page, so the operator cannot
   tell which task a screen is for.

**Why critical & necessary:** The migration's stated goal is to replace the
original console. The original had a structured, discoverable IA (a menu tree for
maintenance, settings, platform, logs). The new console has folded everything
into two giant pages reachable only via 7 menu items. Operators migrating from
the old product will be unable to locate routine tasks (rotate secrets, clear
data, manage users, set the public URL, edit the allowlist) — features that
*exist* but have no front door. At minimum each capability needs a real
navigation entry and the alias routes should deep-link to (and scroll/focus) the
relevant section, or be split into dedicated pages.

---

## 3. On the `[Implementation Unnecessary]` labels (fairness check)

Many `[Implementation Unnecessary]` calls in `feature-coverage.md` are legitimate
scope decisions for a single-org OSS rebuild and should **not** be treated as
defects: multi-tenant/UPMS/Keycloak, PHP/Windows auto-hooks, the runtime plugin
system, and duplicated legacy dialogs. Calling these out as "missing" would be as
misleading as the document this audit critiques.

The objection is narrower: the label is also applied to **core capabilities that
were dismissed rather than built**, most notably:

- **Alert email/delivery** labeled `[Implementation Unnecessary]` — but there is
  *no* delivery channel at all (§1b.4), so "alerting" is incomplete, not merely
  missing a test button.
- **Per-event allowlist, app-config, command settings** dismissed as covered by
  central config — defensible, but combined with §1b.1 (config never reaches the
  agent) the "central config" itself is not enforced, so the dismissal rests on a
  capability that doesn't work yet.

---

## 4. Prioritized remediation

| Priority | Item | What "done" looks like |
|---|---|---|
| **P0** | Wire policy → agent enforcement (§1b.1) | Agent parses pulled policy, builds detector/hook set and per-rule actions from it, honors version + `canary_percent`, refreshes on heartbeat. Add an integration test that changes a rule in the API and asserts the agent's behavior changes. |
| **P0** | Per-rule / scoped enforcement (§1b.2) | Replace the global `ohmyrasp.block` flag with the policy rule's `action`; support monitor-vs-block per rule and per app/env. |
| **P0** | Alert delivery backend (§1b.4) | A worker that drains `queued` deliveries to at least one real channel (webhook), with `sent`/`failed`, `attempts`, `last_error` transitions. Stop presenting "delivery history" until something is delivered. |
| **P1** | Agent producers for SCA / baseline / perf / crash / error (§1b.3, §1c.1) | Agent emits the other five event/data types so the pages populate from reality, not fixtures. |
| **P1** | Frontend IA (§2b) | Real nav entries per capability; alias routes deep-link + scroll/focus, or split `AccessPage`/`AgentsPage` into dedicated pages. |
| **P2** | Frontend hygiene (§2a) | Split `pages.tsx`, add route-level code splitting, expand behavioral tests, add route-level RBAC. |
| **P2** | Documentation honesty | Re-state `feature-coverage.md`/`mock-implementation-audit.md` to distinguish "endpoint exists" from "end-to-end works with a real agent," and mark agent-producer/enforcement items as open. |

---

## 5. Reproduction log (live evidence)

Stack: `docker compose up -d --build` (Postgres store, ClickHouse, Valkey). API on
`:18090`.

```
# health + real bcrypt login
GET  /healthz                         → {"status":"ok"}
POST /api/v1/auth/login               → session token (bcrypt verified)

# core attack loop WORKS end-to-end
POST /api/v1/applications             → app + secret
POST /api/v1/applications/{id}/environments
POST /api/v1/agents/register (app creds) → agent_id + policy assignment
GET  /api/v1/agents/{id}/policy       → real rules (action:block, expression "' OR '1'='1")  [agent discards these]
POST /api/v1/events/attack (app creds)→ accepted; appears in /events/attack and /analytics/overview

# the gaps
GET  /api/v1/analytics/observability  → non-empty, but ONLY fixture performance/hook events
GET  /api/v1/dependencies             → only "smoke-lib" / "mpv5hqr9" test fixtures
GET  /api/v1/baseline-findings        → only "Live baseline ..." test fixtures
GET  /api/v1/alert-deliveries         → 41 items, ALL status="queued", 0 delivered, 0 attempts
```

Frontend (live, Playwright against `:18091`):
```
login as admin@ohmyrasp.local           → lands on / (Overview)
left nav shows exactly 7 entries         (Overview, Applications, Agents, Policies,
                                          Events, Observability, Access & Audit)
GET /access            → heading "Access & Audit", main text 44,265 chars, nav highlights /access
GET /maintain/clearData→ heading "Access & Audit", main text 44,265 chars (identical), nav highlights nothing, scrollY 0
```
Build/test: `npm ci && npm run build` (OK; 636 KB single chunk warning) and
`npm test` (3 files / 9 tests pass). Screenshot of the catch-all page saved to
`web/access-page-catchall.png`.
