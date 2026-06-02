# Console Frontend Remediation Ledger

Date: 2026-06-02

This document replaces the earlier acceptance review for the rewritten
`console/` frontend. The original conclusion was correct: the visual rewrite was
not yet a production replacement because critical workflows, deployment wiring,
scoping, and tests were incomplete. This ledger records the remediation plan
derived from those findings and the evidence that the plan has been executed.

## Requirements

| Severity | Requirement | Resolution |
|---|---|---|
| Critical | Docker Compose must build the new console, not the old frontend. | `docker-compose.yml` now builds `./console` for the `web` service. |
| Critical | Core operator workflows must be usable, not read-only. | Added application inventory, app creation, environment creation, secret rotation, app deletion, agent onboarding, artifact catalog, artifact upload, maintenance cleanup, and event recycle-bin actions. |
| Critical | Policy management must support the full lifecycle. | Added policy creation, rule authoring, validation, testing against stored attack events, version creation, scoped rollout, rollback, restore-default, and shared-policy visibility. |
| High | Alert rules and deliveries must honor selected application scope. | `useAlertRules()` and `useAlertDeliveries()` now query with `application_id`; alert rule creation also writes the selected application. |
| High | Protection Config must honor selected environment sub-scope. | App settings queries and writes now use `/applications/{app}/environments/{env}/settings` when an environment is selected. |
| High | Hardening mode must use the agent contract. | The UI now writes `mode: "enforce"` for blocking hardening instead of the non-agent value `block`. |
| High | Non-privileged users must not see mutation actions. | Instance rename, ignore/restore, delete, onboarding, and artifact mutation controls are privileged-only. |
| Medium | Legacy aliases must preserve section intent. | Legacy paths now store a focus target before redirecting; target pages switch/focus the relevant section. |
| Medium | Stored environment selection must be validated. | The global app scope validator now clears stale environment IDs that do not belong to the selected application. |
| Medium | Mobile navigation must be available. | The shell now provides a mobile drawer with the same permission-filtered navigation as desktop. |
| Medium | Automated UI tests must cover acceptance workflows. | Added Playwright tests covering scoping, hardening, app/env management, onboarding, artifact workflows, RBAC, mobile nav, policy lifecycle, alerts, users, cleanup, and recycle-bin actions. |

## Execution Plan

1. Complete the typed API/query surface before route work.
   Add missing endpoint methods for policies, applications, settings,
   artifacts, agent registration, maintenance cleanup, recycle-bin, alert rules,
   users, and scoped reads.

2. Fix cross-cutting scoping and navigation.
   Validate stored app/environment scope, scope alerts and settings by the active
   selection, add mobile navigation, and preserve legacy deep-link intent.

3. Restore operator workflows in focused routes.
   Keep pages split by domain: Applications for inventory, Instances for agent
   lifecycle, Policies for authoring and rollout, Access for users,
   alert routing, audit, system, and cleanup, Threats for event investigation and
   recycle-bin lifecycle, Protection for runtime settings.

4. Wire deployment and documentation to the new console.
   Point Compose at `console/` and update project documentation that still named
   the old frontend as the primary console.

5. Add browser-level acceptance tests.
   Use mocked API responses but the real React routes, context store, router,
   forms, and fetch layer. Assert exact API paths, request bodies, headers, and
   visible RBAC behavior for restored workflows.

## Implemented Tests

The new `console/e2e/console.spec.ts` suite covers:

- Application creation, environment creation, application secret rotation, and
  environment-scoped Protection Config writes.
- Hardening save payload uses `mode: "enforce"`.
- Agent registration sends application credential headers.
- Agent artifact upload through the artifact catalog UI.
- Viewer RBAC hides instance mutation actions.
- Mobile navigation opens and exposes the application route.
- Policy create, validate, test, version, restore-default, and rollout calls.
- Alert rule reads are scoped with `application_id`, and alert rules can be
  created from the selected application.
- User creation and disable lifecycle.
- Maintenance cleanup preview and confirmed apply.
- Event recycle-bin delete, restore, and purge.

## Verification Evidence

Executed from `console/`:

```bash
npm run test
npm run build
```

Result:

```text
i18n coverage OK — 355 used keys, zh=366, ja=366.
tsc -b passed.
5 Playwright tests passed.
Vite production build passed.
```

The suite runs against Vite through Playwright and verifies the actual route
behavior rather than isolated component snapshots. The production build was also
run after the browser suite to cover the packaged console path.

## Daemon Workloads Removed (2026-06-02)

The remediation pass shipped a "Daemon Workloads" panel on the Instances page
(token reveal/rotate plus per-workload bind/unbind) that consumed the
control-plane daemon endpoints. There is **no daemon component in this
repository** that discovers host processes/containers and reports them, so the
panel had no producer — it would always render empty and its token/bind actions
managed a feature nothing emits. Per maintainer direction it has been removed
from the console:

- `console/src/routes/instances.tsx` — dropped `DaemonPanel`/`DaemonRow` and the
  bind/unbind/token mutations; `RegisterAgentPanel` now stands alone.
- `console/src/lib/api.ts` — removed the `DaemonAccessToken`/`DaemonWorkload`
  types and the five `/daemon/*` client methods.
- `console/src/lib/queries.ts` — removed `useDaemonWorkloads`.
- `console/src/i18n/messages.ts` — removed the 14 daemon-only zh/ja keys.
- `console/e2e/console.spec.ts` — removed the daemon fixtures, route mocks, and
  assertions; the instances test was retitled accordingly.

The control-plane **backend** daemon surface is committed and untouched:
`/api/v1/daemon/token`, `/daemon/token/reset`, `/daemon/workloads`,
`/daemon/workloads/{id}/bind`, `/daemon/workloads/{id}/unbind`
(`api/internal/httpapi/server.go`), the ingestion websocket
(`legacy_daemon_ws.go`), artifact handlers (`daemon_artifacts.go`), and the
generated OpenAPI bindings. These are orphaned without a daemon producer but are
tested and code-generation-coupled, so they were left in place pending a
decision on whether to remove the daemon concept end-to-end.
