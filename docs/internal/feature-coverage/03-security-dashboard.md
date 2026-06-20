# 3. Security Dashboard

Status: Completed

## Evaluation

| Feature | Best-practice alignment | Current need | Necessity | Decision |
|---|---|---|---|---|
| Dashboard metric cards | Aligns. Operators need compact application, Agent, event, attack, crash, and critical-severity totals before drilling into event pages. | Needed. The console already has `/api/v1/analytics/overview`, but the dashboard did not expose enough security signal context. | Necessary. | Implemented through expanded overview fields and frontend metric cards. |
| Attack trend time aggregation | Aligns. A dashboard should show attack volume over time without requiring operators to export raw events. | Needed for quick incident triage. | Necessary. | Implemented as `attack_trend` on `GET /api/v1/analytics/overview`. |
| Attack type aggregation | Aligns when modeled around this product's event taxonomy rather than legacy endpoint names. | Needed. Operators need event type/severity distribution plus RASP hook and algorithm breakdowns. | Necessary. | Implemented with `events_by_type`, `events_by_severity`, `attacks_by_hook`, and `attacks_by_algorithm`. |
| User-Agent aggregation | Aligns. User-Agent clustering helps separate scanner traffic, scripted probes, and browser-originated attacks. | Needed for attack triage and acceptance testing. | Necessary. | Implemented with `attacks_by_user_agent`, including nested request/header attribute extraction. |
| Crash overview component | Aligns. Agent crashes are operational security signals and should be visible on the same dashboard as attacks. | Needed. Crash ingest/query already exists, but the dashboard lacked a visible aggregate. | Necessary. | Implemented with `crash_count` and a dashboard metric card. |
| Standalone vulnerability aggregation endpoint | Does not currently align as a dashboard primitive. Attack events are runtime detections; dependency and application vulnerabilities need their own object model, lifecycle, and remediation workflow. | Not currently needed in Section 3. Risk signal grouping is needed, but a separate vulnerability aggregate would duplicate future Security Analysis and dependency inventory work. | Unnecessary now. | Implementation unnecessary. The dashboard uses hook and algorithm aggregation as runtime risk signals; true vulnerability entities should be handled by later security-analysis/dependency features. |

## Completed Features

- Expanded `GET /api/v1/analytics/overview` with attack trend buckets, attack hook aggregation, attack algorithm aggregation, User-Agent aggregation, and crash count.
- MemoryStore and Postgres implementations for the new dashboard aggregates.
- OpenAPI schema and generated Go bindings for the new overview contract.
- Overview page metric cards for attacks, crashes, and critical events.
- Overview dashboard panels for attack trend, event/severity distribution, attack hooks, risk signals, and User-Agent sources.
- English, Chinese, and Japanese dashboard copy for the new panels.

## New Capabilities

- Operators can see attack trends directly on the overview page without opening raw event search.
- Operators can identify top runtime hooks and algorithms involved in attack detections.
- Operators can group attack detections by User-Agent, including values reported as top-level event attributes or nested request/header attributes.
- Operators can see crash volume in the same security dashboard as attack volume.
- The overview API now provides a single stable analytics contract instead of adding legacy route-name compatibility endpoints.

## Implementation Tasks

Agent side:

- No Agent code changes required for this section. The Agent already reports attack/crash events and can include request metadata in event attributes.

Backend side:

- Extend the `Overview` domain model and OpenAPI schema.
- Regenerate strict OpenAPI bindings.
- Add MemoryStore aggregation for active events only.
- Add Postgres aggregation queries for trend buckets, hook counts, algorithm counts, User-Agent counts, and crash count.
- Preserve existing ClickHouse overview override behavior for total event count/type/severity while keeping the new Postgres-derived dashboard aggregates.
- Extend HTTP API tests for the new overview fields.

Frontend side:

- Extend the typed overview response.
- Add dashboard metric cards and aggregate panels.
- Localize new dashboard labels.
- Extend unit and Playwright fixtures/assertions for the new dashboard fields.

## Verification

- `docker run --rm -v "$PWD":/src -w /src golang:1.26 go generate ./...` from `api/`.
- `docker run --rm -v "$PWD":/src -w /src golang:1.26 go test ./...` from `api/`.
- `cd console && npm run build`
- `cd console && npm test`
- `cd console && npm run test:e2e`
- `docker compose build --no-cache api migrate web && docker compose up -d web`
- Live API acceptance against `http://127.0.0.1:18090` for login, Agent registration, attack ingest, crash ingest, and overview aggregate verification.
- Live UI acceptance against `http://127.0.0.1:18091` for login and dashboard panels with no missing translation markers.
