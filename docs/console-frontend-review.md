# Console Frontend Review

Date: 2026-06-02

This document records the review conclusion for the rewritten frontend under
`console/`. The rewrite builds successfully (`npm run build` passed i18n
coverage, TypeScript, and Vite), but it is not yet a production replacement for
the existing `web/` console.

## Summary

The visual direction is stronger and the source is compact, but several
acceptance-level gaps remain. The biggest blockers are deployment wiring,
missing operator workflows, an incorrect hardening-mode value, and application
scoping regressions for alerts and environment-level settings.

## Findings

| Severity | Problem | Why it is a problem | Importance / necessity |
|---|---|---|---|
| Critical | The new console is not wired into the running stack. `docker-compose.yml` still builds `./web`, not `./console`. | Users running the current Compose service will still see the old frontend. | Must be fixed before acceptance or deployment; otherwise the rewrite is not actually used. |
| Critical | Core operator workflows are missing or read-only. | There is no application management page, app/environment creation, secret rotation, onboarding/register-agent flow, daemon/artifact management, maintenance cleanup, or recycle-bin actions. | Required for replacing the existing control-plane console. |
| Critical | Policy management is mostly absent. | The policies page can display an assigned policy and rollback, but has no create, edit, validate, test, version, rollout, restore-default, or assignment controls. | Policy authoring and rollout are central RASP workflows. Operators cannot tune enforcement without them. |
| High | Alert rules and deliveries ignore the selected application. | `useAlertRules()` and `useAlertDeliveries()` call unscoped endpoints, so Access & Audit can show org-wide alert data while the rest of the console is app-scoped. | Necessary to prevent operators editing or interpreting alerts for the wrong application. |
| High | Environment sub-scope is not honored by Protection Config. | Protection settings read/write only application-level settings, even when an environment is selected. | Important because backend environment overrides exist; the UI context can imply a narrower change than what is saved. |
| High | Hardening mode writes the wrong value. | The console writes `block`, but the Java Agent enforces hardening only when the resolved mode is `enforce`. | Must fix because it creates a false sense that hardening is active. |
| High | Non-privileged users still see instance mutation actions. | Rename and ignore controls render for all roles; only delete is privilege-gated. | Needed for clean RBAC behavior and to avoid predictable server-side permission failures in the UI. |
| Medium | Legacy aliases are shallow redirects, not focused deep links. | `/maintain/whitelist` redirects to `/protection`, losing the legacy route's intended section target. | Important for migration fidelity and existing bookmarked routes. |
| Medium | Stored environment selection is not validated. | The app scope store validates selected application IDs, but not whether the stored environment belongs to that application. | Prevents confusing empty dashboards caused by stale environment filters. |
| Medium | Mobile navigation is missing. | The sidebar is hidden below large breakpoints and no mobile equivalent is provided. | Important for remote/mobile access; users can get stuck on the current route. |
| Medium | No automated UI tests are defined. | `package.json` provides build/typecheck/i18n scripts, but no Playwright or component tests for login, app switching, RBAC, protection saves, or legacy routes. | Necessary before replacing the existing frontend because visual rewrites are regression-prone. |
| Low | Some API client methods are scaffolded but unused. | Methods such as create application, create policy, and rollout policy exist in the API client but are not exposed by routes. | Useful implementation signal: the API layer is partially prepared, but route/UI work is incomplete. |

## Verification Performed

- `cd console && npm run build`
  - i18n coverage passed.
  - TypeScript build passed.
  - Vite production build passed.

## Conclusion

The `console/` rewrite is a promising visual and architectural direction, but it
should be treated as an incomplete replacement. Before switching Compose or
shipping it as the primary console, the implementation needs to restore the core
operator workflows, fix the hardening-mode contract, enforce selected
application/environment scoping consistently, add mobile navigation, and add
acceptance tests.
