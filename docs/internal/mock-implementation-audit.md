# Mock and Placeholder Implementation Audit

This audit lists code paths that still use seeded, generated, simulated, or
otherwise non-production behavior. It also records the mock paths removed during
the current cleanup so future work does not reintroduce them.

> **Historical note (added 2026-06-20).** The `web/src/...` and `web/e2e/...`
> paths in the tables below refer to the **legacy `web/` frontend**, which was
> decommissioned and removed from git (commit `94b5e32`). The current frontend is
> `console/`, whose equivalent tests live under `console/` (unit tests via
> `npm test`, Playwright specs in `console/e2e/`). These rows are kept as the
> historical cleanup record; the cited `web/` files no longer exist.

## Resolved During This Cleanup

| Area | Previous behavior | Current behavior |
| --- | --- | --- |
| Frontend API fallback records | `web/src/lib/api.ts` exported fallback datasets for overview, applications, agents, workloads, policies, events, dependencies, baseline findings, audit logs, artifacts, settings, edition, users, alert rules, alert deliveries, and observability. | The fallback exports were removed. Production pages now render live query data, loading/error notices, or empty states. |
| Frontend overview metrics | The overview rendered seeded application/agent/event counts and a hard-coded hook p95 metric. | Overview counts come from `/api/v1/analytics/overview`. Hook p95 renders `-` until backend observability exposes a real aggregate. |
| Frontend page wiring | Page components used `query.data ?? fallback()` and could look populated while the API was unavailable. | Page components no longer import fallback datasets and show explicit query state notices. |
| Frontend form seed values | Write panels prefilled demo applications, agents, policies, rule tags, alert targets, users, and passwords. | Demo text was removed from write-panel state. |
| Backend memory observability | `(*MemoryStore).Observability` returned hard-coded `pol_demo` and `agt_demo_1` samples. | Memory observability is derived from ingested performance events and returns empty data when no samples exist. |
| Runtime store selection | `buildStore` started with `MemoryStore` whenever `OHMYRASP_POSTGRES_DSN` was missing. | The API now requires `OHMYRASP_POSTGRES_DSN` unless `OHMYRASP_STORE=memory` is explicitly set. |
| Generated Agent bootstrap | The API generated fallback Agent ZIPs whenever no filesystem artifact matched. | The generated ZIP path was removed; Agent downloads now require uploaded or filesystem artifacts. |
| PostgreSQL bootstrap password | The Postgres store defaulted the bootstrap admin password to `change-me`. | Postgres seed data now requires an explicit bootstrap admin password. |
| Rule validation and testing | `ValidateRules` and `TestRule` used shallow string checks and fixed confidence. | Rule validation now parses expressions, checks supported hooks/algorithms/actions/severities, validates regex syntax, and rule tests evaluate structured conditions against event fields and attributes. |
| PostgreSQL default app secret | Postgres seed data and migration `026` used `dev-app-secret`. | Postgres seed data and migration backfill now generate non-hard-coded app secrets. |
| Live Playwright password | Live e2e fell back to `change-me` when no password was configured. | Live e2e now requires `OHMYRASP_E2E_ADMIN_PASSWORD` or `OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD`. |
| Memory-mode default credentials | `NewMemoryStore` hard-coded `admin@ohmyrasp.local / change-me` and `dev-app-secret`. | Memory store seeds now use caller-supplied or generated credentials; API memory mode requires `OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD`. Test-only stores still inject fixed fixtures. |
| Java agent control-plane integration | `OhMyRaspAgent.start` and `JsonEventLogger.log` only started hooks and wrote JSONL/stdout. | The agent can now read real control-plane configuration, register, heartbeat, pull policy metadata, and upload detection events with app credentials. |
| Policy console rule test event | `PolicyWritePanel.handleTestDraft` sent a synthetic policy-console event with generated IDs and message text. | Rule tests now use stored attack events from `/api/v1/events/attack`; the action is unavailable until at least one real event exists. |

## High-Risk Production Placeholders Still Present

| Area | Function or module | Location | Current behavior | Needed real implementation |
| --- | --- | --- | --- | --- |
| None currently identified | - | - | The previous production placeholders have been removed or converted to explicit test fixtures. | Continue replacing test-only mocked Playwright flows with live coverage where environment support permits. |

## Test-Only Mocks

These are acceptable for isolated tests, but they should not be mistaken for
coverage of live integration behavior.

| Test module | Location | Mocked behavior |
| --- | --- | --- |
| Frontend unit tests | `web/src/routes/pages.test.tsx` | Stubs `fetch` responses to verify loading, empty, and API-backed page rendering without relying on a live server. |
| Frontend API tests | `web/src/lib/api.test.ts` | Stubs `fetch` for login/session behavior. |
| Mocked Playwright flow | `web/e2e/control-plane.spec.ts` | Intercepts all `**/api/v1/**` requests, accepts a fixed admin login, stores records in test memory, and returns a mock ZIP. |
| Live Playwright flow | `web/e2e/live-control-plane.spec.ts` | Uses real API requests and requires an explicit admin password from environment or `.env`. |

## Function Inventory That Still Needs Real Code

No production functions are currently listed here. Test-only mocks remain listed above.

## Login and Registration Notes

The browser login and manual agent-registration flows are no longer frontend
mocks: `loginWithPassword` posts to `/api/v1/auth/login`, and `registerAgent`
posts to `/api/v1/agents/register`. The Java agent can now call the
control-plane registration, heartbeat, policy-pull, and event-ingest APIs when
configured with real app credentials.
