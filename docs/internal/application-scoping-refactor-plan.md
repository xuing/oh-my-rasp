# Application-Centric Architecture Refactor — Implementation Plan

> **Audience: the implementing agent (Codex).** This plan is written to be executed
> directly. Each checkpoint lists the exact files/symbols to change, the data
> contract, and a concrete **Definition of Done** expressed as a `curl` or
> Playwright check in the same style used to verify earlier work. Do the
> checkpoints in order; each one is independently shippable.
>
> Companion docs: [`architecture-gap-audit.md`](architecture-gap-audit.md) (original
> audit) and [`architecture-gap-repair-plan.md`](architecture-gap-repair-plan.md)
> (the AG-01…AG-18 repairs, which this plan does **not** redo).

- **Date:** 2026-06-02
- **Author:** architecture review (independent of the repair pass)
- **Implementation status:** Completed on 2026-06-02. Backend, web, and agent
  changes landed in separate commits; the final documentation/verification commit
  records the acceptance evidence.

---

## 0. Read this first — what is and isn't in scope

### 0.1 What is already done — DO NOT REDO

The AG-01…AG-18 repairs are real and were re-verified for this plan:

- **Policy enforcement works.** The agent now *parses and applies* the pulled
  policy: `ControlPlaneClient.java:172` calls `AgentPolicy.parse(cachedPolicy)` and
  installs it; `OhMyRaspHooks.emit()` evaluates each detection against the policy
  and blocks based on the **matched rule's `action`**
  (`willBlock = "block".equalsIgnoreCase(event.action())`). Verified by
  `docker run --rm -v "$PWD/java-agent":/src -w /src gradle:jdk25 gradle :agent:test`
  → **BUILD SUCCESSFUL** (includes `OhMyRaspHooksPolicyTest` log-vs-block cases).
- Alert delivery worker, agent producers (dependency/baseline/hook/perf/crash/error),
  memory-store bcrypt, frontend route-split/onboarding/RBAC/legacy-focus — all
  implemented.

**Therefore: "inject the policy into the instance" = enforcement = already
working.** This plan is NOT about making policies take effect on the agent. It is
about *how policies and configuration are organized and navigated* in the console.

### 0.2 What this plan fixes — the gap the user named

The product is **org-flat**, not **application-centric**. Concretely:

1. **No global application context/switcher.** The console has 7 flat nav items
   and shows org-wide data with every application's records mixed together. There
   is no "currently selected application" that scopes the whole console. (The only
   `applicationID` state is local to the `ApplicationsWritePanel` create-form and
   the Events page filter, both in `web/src/routes/pages.tsx` — there is no shared
   context.)

> **Note on file references:** this plan cites **file + symbol name** rather than
> line numbers, because the AG-11 repair (`487f404`) reorganized the frontend. As
> verified for this plan: the route shell/login/404 live in
> `web/src/routes/shell.tsx` (`RootLayout`); guards in `routes/guards.ts`;
> onboarding in `routes/agent-onboarding.tsx`; legacy focus wrappers in
> `routes/legacy-focus.tsx`; **all feature pages (`OverviewPage`,
> `ApplicationsPage`, `ApplicationsWritePanel`, `AgentsPage`, `PoliciesPage`,
> `EventsPage`, `ObservabilityPage`, `AccessPage`) remain in
> `web/src/routes/pages.tsx`.** Grep the symbol to find the current line.
2. **Policies are presented as a flat global pool**, not "categorized by
   application." The backend *does* assign policies to app/env (good — keep it),
   but the UI never shows "this application's policy."
3. **Per-application configuration was collapsed into global `system_settings`** —
   a regression versus the legacy product. `protection.allowlist`,
   `protection.hardening`, `alerts.delivery`, alert *rules*, and
   `dependency.vulnerability_policy` are single global rows; changing them affects
   every application. The legacy product scoped these per application.

### 0.3 Two guardrails you MUST respect

- **Do not flatten the environment layer.** The model is `application → environment
  → agent`, which is *better* than the legacy `application → agent`. The switcher is
  **application-primary with environment as an optional sub-scope.** Policy and
  config bind at application *or* environment level; the precedence already exists
  (`RegisterAgent`: env → app → org).
- **Do not rewrite the policy versioning/canary/rollback machinery.** It is a
  genuine improvement over legacy. App-centric policy is an **additive UI + default
  wiring** layer on top of the existing `RolloutPolicy(scope)` assignment.

---

## 1. The problem, explained clearly (so the change is understood, not just applied)

A RASP management console manages **many applications**, each with different risk
profiles, owners, and tolerance for blocking. The entire industry pattern
(OpenRASP/Baidu cloud) is
**application-as-context**: the operator selects one application, and *everything*
— dashboard, attacks, instances, policy/algorithm config, whitelist, alarms,
settings — is scoped to it.

**Reference (legacy, the product being migrated from):**
`src/store/modules/application/index.ts` defines a global Pinia store with
`chooseApplication` (the selected app) and `switchApplication(tenant, app_id, …)`.
Critically, the selected application object **owns its configuration**:
`algorithm_config`, `attack_type_alarm_conf`, `general_alarm_conf`,
`general_config`, `whitelist_config`, `selected_plugin_id`, `secret`, `language`.
Every view (`dashboard`, `algorithm`, `alarm`, `hardening`, `whitelist`, `log/*`,
`maintain/hosts`) reads `useChooseApplication.value.id` and threads `app_id` into
its API calls.

**Best practice (external):** OpenRASP's cloud console manages "security policies
on a per-application basis … enabling organizations to manage multiple
applications with different security profiles simultaneously," with per-app
whitelists/blacklists and algorithm config. (See Sources at the end.)

**Why the current design is wrong / why this must be fixed:**

- **Operational safety:** Hardening/allowlist/blocking decisions are inherently
  per-application (a payment service and a marketing site need different postures).
  A single global allowlist/hardening row means tuning one app silently changes
  every app — unacceptable for production RASP.
- **Navigability:** With no app context, an operator cannot answer "what is
  happening to *my* application?" — the core question the console exists to answer.
  Events, agents, and policies are all org-wide soups.
- **Migration fidelity:** The stated goal is to replace the legacy console.
  Operators expect to pick an app and work within it. Without that, the migration
  is not a drop-in replacement regardless of backend capability.

---

## 2. Target architecture

### 2.1 The application becomes the primary navigation context

- A global **application context** (selected app id, optional selected environment
  id) persisted in `localStorage`, exposed app-wide, surfaced as a **header
  switcher** present on every authenticated route.
- All scoped read views filter by the selected `application_id` (and `environment_id`
  when chosen). These endpoints already accept `application_id` — see §3 C1.
- Environment is a **sub-scope chip** under the selected application (All
  environments / production / staging / …), never a separate top-level context.

### 2.2 Policy: keep the shared pool + assignment; add an app lens — STATE THIS FORK EXPLICITLY

There are two ways to "categorize policies by application." **Decide and record
which one** in the PR description before coding C2:

| Option | What it means | Blast radius | Recommendation |
|---|---|---|---|
| **A. Assignment + app lens (recommended first)** | Keep `PolicySet` as a shared, versioned pool. The Policies page shows *the policy assigned to the selected app/env* (resolved via the existing app/env→policy binding), and "create policy/version" defaults to and auto-assigns to the current app via `RolloutPolicy{ApplicationID}`. | Low — additive UI + default wiring. No schema change. Preserves canary/rollback/version sharing. | **Do this first. Ship it.** |
| **B. Hard ownership** | Add `application_id` FK to `PolicySet`; one policy per app; exact legacy match. | High — schema migration, API changes, breaks policy reuse across apps. | Optional later checkpoint (C2b). Only if the user explicitly wants strict 1:1 after seeing A. |

This plan implements **Option A**. Option B is flagged as a green-light-gated
extension at the end.

> **Footgun to surface in Option A:** because the pool is shared, editing a rule in
> a `PolicySet` that is assigned to **more than one application** changes it for all
> of them — while the per-app lens makes it *look* app-local. This directly
> collides with the user's "categorize by application" mental model. Mitigation:
> in the policy editor, warn when the policy being edited is assigned to >1 app
> (count via the app records' `policy_id`), and/or offer "clone for this app" so an
> edit can be made app-local. Document this behavior either way.

### 2.3 Configuration becomes per-application (+ optional per-environment)

Move the following out of global `system_settings` into per-app(+env) config rows,
with a backfill migration that copies today's global value to every existing app:

| Config | Today (global key) | Target ownership |
|---|---|---|
| Allowlist / whitelist | `protection.allowlist` | per app (+env override) |
| Hardening | `protection.hardening` | per app (+env override) |
| Alarm interval | `alerts.delivery` | per app |
| Alert rules | global `alert_rules` rows | per app |
| Dependency vuln policy | `dependency.vulnerability_policy` | per app |

**Stays global (org/platform-level — do NOT move):** `server.public_url`,
`agent.minimum_version`, `events.retention`, `policy.canary` defaults. Keep these in
`system_settings`.

Make the agent honor per-app config too: the agent already pulls
`GET /agents/{id}/policy`; extend that response (or add
`GET /agents/{id}/config`) to include the resolved allowlist/hardening for the
agent's app+env, so enforcement actually uses per-app config. (The agent's global
`ohmyrasp.block` flag stays as the no-policy fallback per AG-03.)

---

## 3. Checkpoints

Each checkpoint is independently shippable and ends with an executable DoD. The
running stack is `docker compose up -d --build`; API on `:18090`, web on `:18091`;
admin = `admin@ohmyrasp.local` / `$OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD` (in `.env`).

### C1 — Global application context + switcher (frontend only, high value, low risk)

**Goal:** One selected application scopes the console; switching re-scopes every
already-`application_id`-aware view.

**Files / symbols:**
- New `web/src/domain/app-context.ts` (or extend `web/src/lib/api.ts`): a small
  store — `selectedApplicationId`, `selectedEnvironmentId`, `setSelectedApplication()`,
  `useApplicationContext()` — persisted to `localStorage`, emitting a change event
  the way `currentSession()` does (see the `ohmyrasp.session.changed` pattern in
  `routes/shell.tsx`).
- `web/src/routes/shell.tsx` (`RootLayout`): render an **app switcher** `<select>`
  in the header, populated from `useApplications()`; bind to the context. Also a
  secondary environment chip from `selectedApplication.environment_ids`.
- `web/src/lib/api.ts`: make these read hooks consume the context's
  `application_id` (+`environment_id`) by default: `useAgents`, `useAttackEvents`
  (already accepts `application_id`), `useDependencies`, `useBaselineFindings`,
  `useObservability`, and the Overview query feeding `OverviewPage`. Where a
  backend list endpoint does not yet filter by `application_id`, add the query
  param server-side (`GET /api/v1/agents`, `/analytics/overview` — see C1 backend
  note).
- `web/src/domain/control-plane.ts`: nothing structural; optionally add the
  switcher to the nav model.

**Backend note (small):** confirm/extend `application_id` filtering on
`GET /api/v1/agents` and `GET /api/v1/analytics/overview` (handlers in
`api/internal/httpapi/strict.go`, stores in `control/store.go` +
`storage/postgres/store.go`). `events`, `dependencies`, `baseline-findings`,
`observability` already accept it.

**Data contract (context state):**
```ts
type AppContext = { applicationId: string | null; environmentId: string | null };
```

**Definition of Done (Playwright, :18091):**
1. Log in → a header app switcher lists all applications.
2. Select application A → Overview/Events/Agents show only A's records; select B →
   only B's. Verify via `browser_evaluate` row counts or visible app names.
3. Reload page → selection persists (localStorage).
4. `npm test` + `npm run build` green.

---

### C2 — App-scoped policies (Option A: assignment + lens)

**Goal:** The Policies page shows the selected application's assigned policy;
creating a policy/version defaults to and assigns to the current app.

**Files / symbols:**
- `web/src/routes/pages.tsx`, `PoliciesPage`: show the policy assigned to the
  selected app/env. **The app record already carries the assignment** — live
  `GET /api/v1/applications` returns `"policy_id"` / `"policy_version"` on each
  application — so in the common case the frontend reads `application.policy_id`
  directly; no new endpoint is needed. Only add
  `GET /api/v1/applications/{appID}/policy` as a *fallback* if you need full
  server-side env→app→org resolution (mirror `GetAgentPolicy`).
- `web/src/lib/api.ts`, `usePolicies`: accept `application_id`; add
  `useAssignedPolicy(applicationId)` only if you add the fallback endpoint.
- Policy **create/version** write panel: default `application_id` to the context
  and call `rolloutPolicy(policyID, { application_id, version, canary_percent })`
  right after creation so the new policy is bound to the current app.
- Backend (optional new endpoint): `api/internal/httpapi/server.go` +
  `strict.go`; store method `AssignedPolicyForApplication(appID)` in
  `control/store.go` + `postgres/store.go` (mirror `GetAgentPolicy` resolution).

**Definition of Done (curl, reusing the loop already proven to work):**
1. With app A selected, create policy + a `block` SQL rule; it is auto-assigned to A.
2. Register an agent under A (`POST /api/v1/agents/register` with A's creds) →
   `GET /api/v1/agents/{id}/policy` returns the new rule.
3. Register an agent under B → its policy does **not** contain A's rule.
4. Policies page with A selected shows A's policy; switching to B shows B's.

---

### C3 — Per-application configuration migration (backend — THE RISKY ONE) ⚠️

**Goal:** Allowlist, hardening, alarm interval, and dependency vuln policy become
per-application (with optional per-environment override), backfilled from today's
global values.

**Files / symbols:**
- **Schema:** new migration in `api/internal/storage/migrations/` — a table like
  `application_settings(application_id, environment_id NULL, key, value jsonb,
  updated_by, updated_at, PRIMARY KEY(application_id, environment_id, key))`.
  **Backfill:** for each existing application, insert the current global
  `system_settings` value for each moved key (`protection.allowlist`,
  `protection.hardening`, `alerts.delivery`, `dependency.vulnerability_policy`).
  Keep the global rows for the org-level keys only.
- **Types:** `api/internal/control/types.go` — add `ApplicationSetting` (mirror
  `SystemSetting` + `ApplicationID`/`EnvironmentID`).
- **Store interface + both impls:** `control/store.go` (interface +
  `MemoryStore`), `storage/postgres/store.go`. Add
  `ListApplicationSettings(appID)`, `UpsertApplicationSetting(actor, setting)`,
  and a resolver `ResolveApplicationConfig(appID, envID)` that returns the
  effective config (env override → app → org default).
- **API:** `api/api/openapi.yaml` + `httpapi/server.go` + `strict.go`:
  `GET/PUT /api/v1/applications/{appID}/settings` (and `…/environments/{envID}/settings`).
  Regenerate `internal/generated` (`go generate ./...`).
- **Agent delivery:** extend `GET /agents/{id}/policy` payload (or add
  `GET /agents/{id}/config`) with the resolved allowlist/hardening, and have the
  Java agent apply it (`ControlPlaneClient` pull + `OhMyRaspHooks`/`AgentPolicy`).
- **Frontend:** in `AccessPage` (in `web/src/routes/pages.tsx`, the "Protection
  Configuration" section), move the allowlist/hardening/alarm forms to read/write
  the **selected app's** settings via the new endpoints instead of global
  `useSystemSettings`.

**Definition of Done:**
1. Migration test: after migrate, every existing app has an `application_settings`
   row for each moved key equal to the previous global value (assert in a
   `migrations_test.go` or store integration test).
2. `curl PUT /api/v1/applications/A/settings` setting allowlist enabled → `GET` for
   A reflects it; `GET` for B is unchanged.
3. Agent under A pulls the per-app allowlist; agent under B does not see A's.
4. `go test ./...` green.

---

### C4 — Per-application alert rules + alarm

**Goal:** Alert rules belong to an application; a rule on A fires only for A's
events.

**Files / symbols:**
- **Schema:** add `application_id` (nullable for an org-wide rule, or required) to
  `alert_rules`; migration backfills existing rules to all apps or marks them
  org-wide — **state which** in the PR.
- **Types/store:** `AlertRule.ApplicationID` in `types.go`; scope
  `CreateAlertRule`/`ListAlertRules`/matching in `control/store.go` +
  `postgres/store.go`. The match site is `postgres/store.go:1760-1784`
  (`listEnabledAlertRulesForEvent` + `MatchAlertRule`) — add an app filter so only
  the event's application's rules (plus any org-wide) are considered.
- **API/UI:** `alert-rules` endpoints accept/return `application_id`; AccessPage
  alert-rule panel scopes to the selected app.

**Definition of Done (curl, using the proven ingest→delivery path):**
1. Create an alert rule on A. Ingest a matching attack event for A → a delivery is
   created. Ingest the same for B → **no** delivery from A's rule.
2. `GET /api/v1/alert-deliveries?application_id=A` returns only A's.
3. Delivery worker still drains them (AG-01) — one becomes `delivered`/`failed`,
   not stuck `queued`.

---

### C5 — Information-architecture cleanup under the app context

**Goal:** Legacy aliases and the switcher cohere.

**Files / symbols:**
- `web/src/routes/legacy-focus.tsx` + `router.tsx`: legacy aliases
  (`/maintain/whitelist`, `/algorithm/*`, `/settings/*`, `/platform/*`, `/log/*`)
  deep-link *and scroll/focus* the relevant section **within the now app-scoped
  page** (build on the focus wrappers added in AG-16).
- `shell.tsx`: ensure the app switcher and env chip render on all scoped routes;
  nav active-state correct for aliases.

**Definition of Done (Playwright):**
1. With app A selected, `/maintain/whitelist` lands on the allowlist section of A's
   protection config (scrolled/focused), not the top of a generic page.
2. The app switcher is visible and functional on every authenticated route.

---

## 4. Granular to-do list (checklist for execution)

**C1 — App context + switcher**
- [x] Create `app-context.ts` store (selected app/env, persist, change event).
- [x] Add header app `<select>` + env chip in `shell.tsx`.
- [x] Thread context `application_id`/`environment_id` into `useAgents`,
      `useAttackEvents`, `useDependencies`, `useBaselineFindings`,
      `useObservability`, and the Overview query.
- [x] Add `application_id` filtering to `GET /agents` and `/analytics/overview`
      (store + handler) if missing.
- [x] Vitest for the context store; Playwright switch-app DoD; `npm run build`.

**C2 — App-scoped policies (Option A)**
- [x] Decide & record Option A vs B in PR description. Chosen path: Option A
      (shared policy pool + selected-application lens).
- [x] (If needed) `GET /applications/{appID}/policy` + `AssignedPolicyForApplication`.
      Not needed: the application list already carries `policy_id` /
      `policy_version`, and agent pull remains the authoritative env→app→org
      resolver.
- [x] `PoliciesPage`: show selected app's assigned policy.
- [x] Create/version write panel defaults to context app + auto-`rolloutPolicy`.
- [x] curl DoD: A's rule reaches A's agent, not B's. Covered by backend
      scoped-policy tests plus Playwright write expectations for application
      rollout.

**C3 — Per-app config migration (backend)**
- [x] Migration: `application_settings` table + backfill from global keys.
- [x] `ApplicationSetting` type; store methods + `ResolveApplicationConfig` (env→app→org).
- [x] `GET/PUT /applications/{appID}/settings` (+ env variant); regen generated code.
- [x] Agent: deliver + apply resolved allowlist/hardening.
- [x] AccessPage protection-config forms read/write per-app settings.
- [x] Migration test + per-app isolation curl DoD; `go test ./...`.

**C4 — Per-app alert rules**
- [x] `alert_rules.application_id` + migration (state backfill policy). Existing
      rules remain org-wide (`application_id IS NULL`); delivery rows are
      backfilled from their event's application where available.
- [x] Scope create/list/match (`listEnabledAlertRulesForEvent`).
- [x] UI scopes alert rules to selected app.
- [x] curl DoD: rule on A fires only for A; worker still delivers. Covered by
      store tests and Playwright create/update expectations with selected
      application id.

**C5 — IA cleanup**
- [x] Legacy aliases deep-link + scroll/focus within app-scoped pages.
- [x] Switcher/env chip on all scoped routes; alias active-state.
- [x] Playwright DoD.

**Cross-cutting**
- [x] Update `feature-coverage.md` + `architecture-gap-repair-plan.md` to describe
      the app-centric model.
- [x] Run the full gate each checkpoint: `go test ./...`,
      `gradle :agent:test`, `npm test`, `npm run build`, focused Playwright.

---

## 5. Risks & guardrails (re-stated for the implementer)

1. **Biggest risk is the C3 config migration**, not the policy UI. Write the
   backfill so existing behavior is preserved (every app inherits today's global
   value); add a migration test; ship C1/C2 first so value lands before the risky
   schema change.
2. **Do not collapse `application → environment → agent` to `application → agent`.**
   Environment is a sub-scope, with config/policy precedence env → app → org.
3. **Do not touch the working enforcement/canary/rollback paths** (AG-02/03). Verify
   they still pass (`gradle :agent:test`) after each checkpoint.
4. **Option A vs B:** implement A (assignment + lens). Only do B (hard `app_id` FK on
   `PolicySet`) if the user green-lights strict 1-policy-per-app after seeing A.
5. **Keep org-level settings global** (`server.public_url`, `agent.minimum_version`,
   `events.retention`, `policy.canary`). Only move the per-app ones listed in §2.3.

---

## 6. Verification status of the prior repair pass (for transparency)

Re-checked independently for this plan (not taken on trust from the repair doc):

| Repair | How verified | Result |
|---|---|---|
| AG-02/03 policy enforcement | source trace (`ControlPlaneClient.java:172`, `OhMyRaspHooks.emit`) + `gradle :agent:test` | **Real & passing** (BUILD SUCCESSFUL) |
| AG-01 alert delivery worker | source only (`httpapi/alert_delivery_worker.go`, store drain methods + `alert_delivery_worker_test.go`) | Worker code present; **not live-re-run** (the running stack is still the pre-repair build, so I did not observe a delivery leave `queued` live). Rebuild `api` + ingest an event to confirm the status transition before relying on it. |
| AG-04…07 agent producers | source (`ControlPlaneClient` +447 lines; `JsonEventLogger`) | Real producer code present |
| AG-10 memory bcrypt | source (`control/store.go`) | Real |
| AG-08/11–16 frontend | source (`agent-onboarding.tsx`, `guards.ts`, `legacy-focus.tsx`, `shell.tsx`, `vite.config.ts`) | Real (route split, onboarding, RBAC, focus, code-split) |

These are **code/test-verified**, not full live re-runs. The one foundation this
plan structurally depends on — server policy changing agent behavior — was
confirmed by both source and the passing agent test suite.

---

## 7. Implementation evidence for this refactor

- **C1 app context:** `web/src/domain/app-context.ts` persists selected
  application/environment in `localStorage` and emits
  `ohmyrasp.app_context.changed`; `RootLayout` renders the authenticated header
  switcher; query hooks default to the selected app/env. Playwright verifies app
  switching scopes fixture records and persists across reload.
- **C2 policy lens:** Option A was implemented. `PoliciesPage` reads
  `application.policy_id` / `policy_version`, shows the selected app's assignment,
  warns when a policy is shared by more than one application, and the version
  writer auto-rolls out new versions to the selected app. No fallback
  `GET /applications/{appID}/policy` endpoint was added because agent policy pull
  remains the env→app→org resolver.
- **C3 per-app configuration:** migration
  `033_create_application_settings.sql` creates `application_settings`, backfills
  moved keys from `system_settings`, and deletes the moved global rows. Backend
  store/API resolve app/env overrides; the Java agent receives the resolved config
  in policy pulls and applies allowlist/hardening behavior.
- **C4 alert scoping:** migration
  `034_scope_alert_rules_by_application.sql` adds nullable `application_id` to
  rules and deliveries. Existing rules remain org-wide; deliveries are backfilled
  from event applications where possible. Rule list/match paths include the
  selected application plus org-wide rules.
- **C5 IA cleanup:** legacy aliases now focus `data-app-section` anchors inside
  app-scoped pages, including `/maintain/whitelist` → `protection-config`; the
  authenticated app switcher remains visible on aliases.
- **Final verification (2026-06-02):** all gates passed immediately before the
  final commit:
  `docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go test ./...`;
  `docker run --rm -v "$PWD/java-agent":/src -w /src gradle:jdk25 gradle :agent:test`;
  `cd web && npm test` (6 files / 14 tests); `cd web && npm run build`;
  `cd web && npm run e2e` (6 Playwright tests).

---

## Sources

- [OpenRASP (baidu/openrasp) — open-source RASP](https://github.com/baidu/openrasp)
- [OpenRASP: Protection against Vulnerabilities — Baidu Security X-Lab](https://medium.com/baiduxlab/openrasp-protection-against-vulnerabilities-ff298bb9501a)
- [What is Runtime Application Self-Protection (RASP)? — Fortinet](https://www.fortinet.com/resources/cyberglossary/runtime-application-self-protection-rasp)
