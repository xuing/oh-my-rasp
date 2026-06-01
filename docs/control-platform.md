# OhMyRasp Control Platform Rewrite

This directory contains the new cloud control platform rewrite:

- `api`: Go 1.26 backend, `net/http` + `chi`, OpenAPI 3.1, `slog`.
- `web`: React 19 + TypeScript + Vite 8 frontend.
- `docker-compose.yml`: self-hosted development stack with PostgreSQL,
  ClickHouse, Valkey, Prometheus, API, and web containers.
- `deploy/helm/ohmyrasp-control`: initial Helm chart skeleton.

The legacy projects remain as reference material only. The new
implementation must not import, copy, or directly reuse legacy source code.
Capability parity is tracked by domain and API behavior, not inheritance from
the old codebase.

## Architecture Direction

The platform is single-organization by default. It uses composition:

- applications contain environments
- environments contain Agent instances
- policy sets contain draft-editable policy versions that become immutable when promoted
- policy versions contain rule definitions
- events reference application, environment, Agent, policy, and version
- RBAC grants operations over these resources

## Current Verified Slice

- Backend API tests cover login/permission-matrix RBAC, application and environment creation,
  application secret rotation,
  Agent registration, authenticated Agent heartbeat, authenticated Agent event/dependency/baseline
  reporting, daemon token rotation, daemon workload inventory reporting and
  application bind/unbind, daemon application credential lookup, agent artifact metadata/download/catalog/upload,
  daemon command payloads for bound workloads, legacy daemon command websocket compatibility,
  daemon injection outcome reporting, draft policy rule editing, policy version rollout with optional application/environment scope, authenticated policy pull, event
  ingestion, filtered event queries, event recycle-bin soft-delete/restore/purge,
  filtered dependency inventory queries with vulnerability severity filtering, filtered baseline posture queries, aggregation, observability reports, policy listing, system
  settings, maintenance cleanup preview/apply with destructive confirmation,
  alert-rule management, alert delivery history, OSS edition/license status, user administration, and audit logs.
- Backend migration tests cover sequential PostgreSQL and ClickHouse migration
  artifacts for control-plane state, event analytics and recycle-bin metadata,
  dependency observations with package/license/vulnerability metadata, baseline findings,
  overhead rollups, audit logs, settings, alert rules, alert delivery history,
  daemon workload inventory, daemon injection state, and user administration indexes.
- PostgreSQL integration tests cover migrated durable storage for login,
  hashed sessions, application/environment creation, Agent registration and
  heartbeat, policy listing, draft policy rule editing, policy version rollout and pull, filtered event listing, event recycle-bin lifecycle, dependency
  assignment defaults and pull inheritance, daemon token rotation and workload
  binding persistence, daemon command payloads with application secrets, dependency ingestion and filtered package/license/vulnerability inventory listing, baseline finding ingestion and filtered listing, system settings, alert rules, generated
  alert delivery history, maintenance cleanup over operational data, user
  administration, disabled-user session revocation, audit logs, and the event
  ingest outbox.
- OpenAPI contract tests generate typed `chi` and strict-server bindings with
  `oapi-codegen`, verify the checked-in generated code is current, and exercise
  generated request/response models for auth, users, applications,
  environments, Agents, policies, filtered event queries, event recycle-bin contracts, filtered dependencies, filtered baseline findings, overview analytics,
  daemon token/workload inventory, application lookup, artifact metadata/catalog/upload, command payloads, injection outcome reporting, audit logs, maintenance cleanup, alerts, delivery history, and observability, including required
  application credential headers on Agent operations and report writes.
- The HTTP router now uses generated OpenAPI strict-server handlers for the
  liveness/readiness, login, current-user, application-list, daemon inventory, Agent lifecycle,
  policy lifecycle, event/dependency/baseline collection, filtered event/dependency/baseline listing, event recycle-bin operations, overview/observability
  analytics, system settings, OSS edition status, maintenance cleanup, alert rules, alert delivery
  history, users, and audit-log route slices. All `/api/v1` JSON routes are strict-backed;
  `/metrics` remains the hand-written Prometheus text endpoint. Legacy daemon
  aliases under `/v1/service` include app lookup, Agent artifact download, and
  the LZ4-framed command websocket for older helper binaries.
- The HTTP API enforces named permissions through an explicit role matrix:
  viewers can read control-plane resources, security engineers can manage
  applications, policies, events, settings, and alerts, and admins retain user
  administration.
- Audit logs cover mutating user, application, application secret rotation, environment, daemon token and workload binding, Agent registration
  and heartbeat, policy lifecycle including draft rule updates, system setting, alert rule, event ingest,
  dependency ingest, baseline ingest, Agent artifact upload, event recycle-bin, and maintenance cleanup operations.
- ClickHouse integration tests cover event ingestion and filtered querying, attack/hook/
  performance/crash event detail storage, dependency observation metadata, aggregate
  event counts, rule overhead rollups, hook latency, Agent overhead, and
  policy-version performance reports.
- Valkey integration tests cover cached sessions, Agent policy pull caching,
  policy-cache invalidation, and fixed-window API rate limiting.
- Frontend tests cover capability navigation, policy lifecycle order, event
  pipeline coverage, event, event recycle-bin, dependency, baseline, and observability query filters,
  responsive shell/header navigation, Agent artifact upload, catalog display, and metadata verification, live-query fallback data for the main control pages, page
  rendering, and Playwright browser flows for API-backed login, primary
  control-plane navigation, application/environment creation, Agent
  registration, Agent heartbeat and policy-pull operations, daemon token
  rotation, daemon app/artifact catalog upload/retrieval, workload application binding/unbinding, daemon command retrieval, daemon injection result display, application secret rotation, policy-set
  creation, rule validation, rule testing, draft rule updates, scoped policy version/rollout writes,
  event recycle-bin soft-delete/restore/purge, OSS edition display, system setting updates, maintenance cleanup preview/apply, alert-rule creation and lifecycle updates, user
  creation, and user role/disable lifecycle updates. A separate live Playwright
  config verifies login, application/environment creation, application secret rotation, Agent registration,
  Agent heartbeat, Agent policy pull, daemon app/artifact upload and retrieval, daemon workload reporting, binding, command retrieval, and injection-result reporting,
  policy-set creation, draft policy rule editing, scoped policy rollout, alert-rule creation and disablement, user creation and disablement,
  and primary page reads through the Docker Compose web container and API proxy.
- Docker Compose includes a migration job, persisted Agent artifact storage, and health checks for PostgreSQL,
  ClickHouse, and Valkey. The Helm chart includes a pre-install/pre-upgrade
  migration Job and optional Agent artifact volume/PVC support. CI now includes a Compose smoke job that builds the stack, runs
  the API smoke script, and runs live Playwright checks through the web
  container.
- The API `/metrics` endpoint exports control-plane health, Agent freshness,
  event ingest lag, policy-pull latency, Hook latency, rule evaluation latency,
  and Agent overhead metrics. Prometheus alert rules, Alertmanager routing
  examples, notification templates, and a Grafana dashboard are packaged for
  both Docker Compose and Helm deployments.
- Helm values support production installs with external backing-service Secrets,
  image pull Secrets, resource overrides, PodDisruptionBudgets, non-root
  read-only pod security defaults, service-account token controls, optional
  autoscaling, optional NetworkPolicies, topology controls, and optional
  Ingress/TLS routing through the web proxy. CI validates default,
  production-style, and hardened Helm renders with kubeconform before running
  Compose smoke checks.
- Operational runbooks cover backup/restore and upgrade/downgrade procedures for
  Docker Compose and Helm deployments.
- Release packaging now stamps Helm chart metadata and default image tags,
  publishes versioned API and web images with OCI labels, attaches BuildKit SBOM
  and provenance attestations, signs image and chart provenance through GitHub
  artifact attestations, enforces a mandatory pinned Trivy high/critical CVE
  gate, and pushes the Helm chart as an OCI artifact from GitHub Actions.
  Workflow Actions are pinned to immutable upstream commit SHAs.
- `deploy/scripts/smoke-control-plane.sh` verifies a live self-hosted stack by
  logging in, creating application/environment resources, rotating application
  credentials, creating and editing policy/Agent resources, sending
  authenticated Agent heartbeat/policy requests, ingesting attack, Hook,
  performance, crash, dependency, and baseline telemetry, rotating daemon credentials,
  uploading an Agent artifact, verifying daemon application and agent artifact catalog/retrieval, reporting and binding daemon workloads, verifying bound-workload command payloads and injection outcomes,
  soft-deleting/restoring a security event, previewing/applying audited zero-count maintenance cleanup, and checking
  authenticated read routes.

## Operational Runbooks

- [Backup And Restore](deploy/runbooks/backup-restore.md)
- [Capability Audit](OhMyRasp-Capability-Audit.md)
- [Helm Production Install](deploy/runbooks/helm-production.md)
- [Observability](deploy/runbooks/observability.md)
- [Release Packaging](deploy/runbooks/release.md)
- [Upgrade And Downgrade](deploy/runbooks/upgrade-downgrade.md)

## Next Required Milestones

1. Resolve the open legacy-parity product decisions in
   [OhMyRasp-Capability-Audit.md](OhMyRasp-Capability-Audit.md) before
   declaring the rewrite complete.
