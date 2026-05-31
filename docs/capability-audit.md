# OhMyRasp Capability Audit

Audit date: 2026-06-01

This audit compares the rewrite under `api` and `web`
against the requested single-organization RASP control-plane scope and the
legacy reference surfaces in this folder. It is a traceability document only;
the legacy source remains reference material and is not reused by the rewrite.

## Sources Reviewed

- Requested rewrite scope: Java Agent management, policy/rule lifecycle,
  event/dependency collection and analysis, observability, RBAC, audit logs,
  settings, Docker Compose, Helm, CI, and thorough tests.
- `AntiyRASP-Daemon/model.md`: daemon token management, legacy command
  websocket frames, process/container workload reporting,
  workload-to-application binding, application credential lookup, and Agent
  artifact retrieval.
- Legacy frontend route tree under `AntiyRASP-WEB/src/views`: application
  onboarding, instance installation, RASP management, security logs,
  dependency/vulnerability/baseline views, maintenance, settings, plugins,
  users, platform/enterprise screens, and license screens.
- Current OpenAPI contract in `api/api/openapi.yaml`.
- Current verification surfaces: backend unit/integration/contract tests,
  frontend Vitest and Playwright, Compose smoke, live Playwright, Helm/render
  validation, and release workflows.

## Core Scope Status

| Capability | Status | Rewrite Evidence |
|---|---|---|
| Single-organization model with multiple applications, environments, Agents, and policy sets | Covered | Application/environment APIs, seeded organization, React Applications page, PostgreSQL migrations and integration tests |
| Java Agent registration, status, heartbeat, version tracking, policy pull, and authenticated reports | Covered | Agent APIs require application credentials; Agents page exercises registration, heartbeat, policy pull; smoke and live Playwright verify the flow |
| Daemon-assisted Agent installation controls | Covered | Daemon token reset/reveal, workload report/list, bind/unbind, command payloads, app credential lookup, injection reports, artifact metadata/download/catalog/upload APIs; Agents page exposes workload binding, artifact upload, catalog visibility, artifact metadata verification, and browser-side Agent ZIP download |
| Rule editing, validation, testing, versioning, canary rollout, scoped rollout, and rollback | Covered | Policy APIs and Policies page cover create/edit/validate/test/version/rollout/rollback; backend and browser tests verify each operation |
| Attack, Hook, performance, crash, dependency, and baseline ingestion | Covered | OpenAPI routes, PostgreSQL/ClickHouse storage adapters, smoke ingest, backend tests, and Events page coverage |
| Querying and aggregated analysis for events, dependencies, and baseline posture | Covered | Filtered event/dependency/baseline query APIs and UI filters, event recycle-bin soft-delete/restore/purge, including dependency vulnerability severity filtering and package/license/vulnerability inventory metadata; overview analytics; smoke and Playwright filter assertions |
| Observability for rule overhead, Hook latency, Agent overhead, and policy-version impact | Covered | ClickHouse rollups, `/analytics/observability`, Prometheus metrics, Grafana dashboard, Observability page filters, live checks |
| Enterprise login, RBAC, user administration, operation audit, and settings | Covered | Session login, role matrix, users/settings/audit APIs, OSS self-hosted edition status, Access page lifecycle flows, protection configuration settings for allowlists, hardening mode, dependency vulnerability thresholds, retention, and audited maintenance cleanup, backend permission tests |
| Alerts and delivery history | Covered | Alert-rule APIs, generated delivery history, Access page lifecycle UI, alert smoke/read-route checks |
| Docker Compose self-hosting | Covered | Compose stack includes API, web, migration job, PostgreSQL, ClickHouse, Valkey, Prometheus, Alertmanager, Grafana; smoke passes against live stack |
| Helm deployment | Covered | Helm chart with migration Job, security contexts, external service settings, HPA/PDB/NetworkPolicy options, production runbook, render validation |
| CI/CD and release hardening | Covered | GitHub Actions for tests, Compose smoke, live browser checks, Helm validation, image/chart release, SBOM/provenance, Trivy gate, pinned actions |

## Legacy Parity Notes

These legacy surfaces are covered by a replacement design rather than exact API
or UI duplication:

- Legacy daemon command websocket compatibility is implemented at
  `/v1/service/command` using the daemon token `X-Auth-Token` header and
  LZ4-framed JSON messages. `UpdateProcess`/`UpdateK8S` frames feed the same
  workload inventory used by the REST daemon API, `InjectProcessGroup` frames
  are generated from bound workloads, and `NotifyInjectError` frames update
  injection status.
- Legacy app/instance onboarding maps to application, environment, Agent
  registration, daemon workload binding, and Agent artifact catalog/download
  APIs, including browser-side Java Agent ZIP upload into the managed
  self-hosted artifact directory.
- Legacy attack, error, crash, policy, dependency, baseline, and audit logs map
  to the typed event/dependency/baseline/audit APIs and the Events/Access pages.
- Legacy attack-event recycle-bin recovery maps to the Events page recycle-bin
  panel and `/api/v1/events/recycle-bin` API family for soft-delete, restore,
  permanent purge, and audit logging.
- Legacy alarm settings map to alert rules, alert delivery history, and system
  settings.
- Legacy maintenance clear-data operations map to audited maintenance cleanup
  with dry-run preview, scoped operational-data selectors, destructive
  confirmation, PostgreSQL/ClickHouse cleanup, and audit logging.
- Legacy enterprise/platform multi-tenant screens are intentionally excluded
  from the default architecture because the requested rewrite is single
  organization by default.
- Legacy license-management screens are intentionally excluded from the
  open-source self-hosted edition. The rewrite exposes `/api/v1/system/edition`
  and the Access page Edition Status panel to make the OSS/no-license-key and
  no-license-enforcement behavior explicit.

## Product Decisions

No open product decisions remain for the requested open-source, self-hosted,
single-organization scope. License-management screens are out of scope for this
edition unless a future commercial distribution is introduced.

## Current Conclusion

The explicit core RASP control-plane rewrite scope is implemented and verified
through automated backend, frontend, Compose, and live browser gates. Legacy
daemon websocket compatibility is present for older helper binaries, and the
OSS license stance is explicit in the API and UI.
