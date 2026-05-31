# api

New Go control-plane backend for the self-hosted OhMyRasp platform. This is a
from-scratch rewrite using `net/http`, `chi`, `slog`, OpenAPI 3.1, and a
storage boundary that can be backed by PostgreSQL, ClickHouse, and Valkey.

When `OHMYRASP_POSTGRES_DSN` is set, the API uses the PostgreSQL-backed
control store and seeds the default organization/admin/demo app. Set
`OHMYRASP_STORE=memory` only for isolated local experiments. The backend also
includes first-class PostgreSQL and ClickHouse migration artifacts plus a
migration command for the self-hosted deployment path.

- admin session login, user administration, and permission-matrix RBAC
- application and environment inventory, including application secret rotation
- daemon access token rotation, authenticated workload inventory reporting,
  workload application bind/unbind operations, daemon application lookup, agent
  artifact metadata/download, operator-visible artifact catalog reads and uploads,
  bound-workload command payloads, legacy command websocket compatibility, and
  injection outcome reporting
- Java Agent registration, authenticated heartbeat, and authenticated policy pull
- policy listing, rule validation, rule testing, draft policy rule editing,
  policy versions, canary rollout, and rollback
- attack/hook/performance/crash/dependency/baseline ingestion contracts and filtered
  attack/hook/performance/crash event reads by application, environment, Agent,
  policy, severity, hook, occurred-at range, and result limit, plus filtered
  deleted-event recycle-bin reads, soft-delete, restore, and permanent purge,
  dependency reads by application, Agent, dependency name, ecosystem,
  vulnerability severity, observed-at range, and result limit, with package
  path, license, and vulnerability metadata, and filtered baseline posture reads
  by application, environment, Agent, severity, status, category, observed-at
  range, and result limit
- system settings including protection allowlists, hardening mode, dependency
  vulnerability policy, retention controls, and audited maintenance cleanup for
  operational event/dependency/baseline/alert-delivery data, alert rules,
  generated alert delivery history, audit log, OSS self-hosted edition/license
  status, overview aggregation, and application/policy-filtered observability reporting
- Prometheus `/metrics`
- embedded PostgreSQL schema migrations for control-plane state, including
  JSONB-backed dependency license and vulnerability inventory
- embedded ClickHouse schema migrations for event and overhead analytics
- PostgreSQL-backed control store for users, sessions, apps, environments,
  agents, daemon settings/workloads/injection state, policies, dependencies, baseline findings, system settings, alert rules, alert delivery
  history, audit logs, and the event ingest outbox
- disabled-user session revocation across PostgreSQL and Valkey cache entries
- audit logging for mutating user, application, application secret rotation, environment, daemon token/workload, Agent, policy,
  Agent artifact upload, settings, maintenance cleanup, alert-rule, event-ingest, event recycle-bin, dependency-ingest, and baseline-ingest operations
- ClickHouse-backed analytics adapter for event queries, event aggregation,
  hook/performance/crash detail tables, dependency observations with package
  path/license/vulnerability payloads, rule overhead,
  hook latency, Agent overhead, and policy-version performance reporting
- Valkey-backed session cache, Agent policy pull cache, policy-cache
  invalidation, and API rate limiting
- `oapi-codegen` generated models, `chi` bindings, and strict-server contracts
  under `internal/generated` for auth, users, applications, environments,
  daemon inventory, app lookup, artifact metadata/catalog/upload, command payloads, and injection reports, Agents, policies, events, dependencies, baseline findings, analytics, audit, settings, and
  alerts
- OpenAPI strict-server routing is enabled for liveness/readiness, login,
  current user, application listing/secret rotation, daemon inventory, Agent artifact catalog/upload, and commands, Agent inventory/registration/heartbeat/
  policy pull, policy lifecycle operations including draft rule updates, event, dependency, and baseline ingestion,
  filtered attack/hook/performance/crash event listing, event recycle-bin operations,
  filtered dependency and baseline listing, overview/observability analytics, system settings,
  OSS edition status,
  maintenance cleanup, alert rules, alert delivery history, users, and audit-log reads

Daemon-side agent artifact endpoints use the daemon token and expose both the
modern `/api/v1/daemon/artifacts/agent` route and legacy-compatible
`/v1/service/dl/agent` aliases. By default the API returns a generated Java
bootstrap ZIP for local validation. The authenticated `/api/v1/agent-artifacts`
route exposes the package catalog to operators and accepts audited Java Agent
ZIP uploads as base64 JSON when `OHMYRASP_AGENT_ARTIFACT_DIR` is configured.
Uploaded packages are stored with canonical names such as
`ohmyrasp-agent-java-linux-17.zip`. Existing filesystem packages named
`agent-java-linux.zip`, `agent-java.zip`, or similarly named ZIPs remain
servable for production agent distribution.

Older helper binaries that use the legacy command websocket can connect to
`/v1/service/command` with `X-Auth-Token`. The endpoint accepts LZ4-framed JSON
`UpdateProcess`, `UpdateK8S`, and `NotifyInjectError` messages, writes them
through the modern daemon workload/injection store, and returns LZ4-framed
`InjectProcessGroup` commands for workloads bound to applications.

The authenticated `POST /api/v1/maintenance/cleanup` route previews or applies
operator-scoped cleanup for operational event, dependency, baseline finding,
alert-delivery, and ClickHouse analytics data before a cutoff time. Destructive
runs require the `CLEAR_OPERATIONAL_DATA` confirmation string and emit a
`maintenance.cleanup` audit entry.

The authenticated `/api/v1/events/recycle-bin` route family supports soft
delete, recycle-bin listing, restore, and permanent purge for security events.
Soft-deleted events are excluded from normal event lists and overview counts,
while restore and purge actions emit dedicated audit entries.

The authenticated `GET /api/v1/system/edition` route returns the fixed
open-source self-hosted edition status. This distribution does not require a
license key and does not enforce license limits; proprietary license-management
screens are out of scope for the OSS deployment model.

## Runtime Store

PostgreSQL mode:

```bash
OHMYRASP_POSTGRES_DSN='postgres://ohmyrasp:ohmyrasp@localhost:15432/ohmyrasp?sslmode=disable' \
OHMYRASP_CLICKHOUSE_DSN='clickhouse://ohmyrasp:ohmyrasp@localhost:19000?database=ohmyrasp' \
OHMYRASP_VALKEY_ADDR='localhost:16379' \
go run ./cmd/ohmyrasp-api
```

Valkey is optional for local experiments, but production-style deployments
should set it. The API uses it for cached session lookups, Agent policy pull
caching, and request rate limiting. The default limit is 600 API requests per
minute per authenticated token, Agent/app identity, or source IP.

Memory mode:

```bash
OHMYRASP_STORE=memory go run ./cmd/ohmyrasp-api
```

## Migrations

Run both database migration sets:

```bash
OHMYRASP_POSTGRES_DSN='postgres://ohmyrasp:ohmyrasp@localhost:15432/ohmyrasp?sslmode=disable' \
OHMYRASP_CLICKHOUSE_DSN='clickhouse://ohmyrasp:ohmyrasp@localhost:19000?database=ohmyrasp' \
go run ./cmd/ohmyrasp-migrate
```

For local development without Go on the host:

```bash
docker run --rm --network host \
  -e OHMYRASP_POSTGRES_DSN='postgres://ohmyrasp:ohmyrasp@localhost:15432/ohmyrasp?sslmode=disable' \
  -v "$PWD":/src -w /src golang:1.26 \
  go run ./cmd/ohmyrasp-migrate -skip-clickhouse
```

## OpenAPI Code Generation

Regenerate typed OpenAPI bindings after editing `api/openapi.yaml`:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.26 go generate ./...
```

The generated code is checked in at `internal/generated/openapi.gen.go`.
`go test ./...` verifies that file is current and exercises representative
generated request/response contracts across the core control-plane workflows.
The HTTP router uses generated strict-server handlers for all `/api/v1` JSON
routes and health/readiness probes. `/metrics` stays hand-written because it is
Prometheus text format, not JSON.

## Local Test

The host may not have Go installed. Use Docker:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.26 go test ./...
```

Run the PostgreSQL integration test:

```bash
docker run -d --rm --name ohmyrasp-postgres-test \
  -e POSTGRES_USER=ohmyrasp \
  -e POSTGRES_PASSWORD=ohmyrasp \
  -e POSTGRES_DB=ohmyrasp \
  -p 55432:5432 postgres:18

docker run --rm --network host \
  -e OHMYRASP_POSTGRES_TEST_DSN='postgres://ohmyrasp:ohmyrasp@localhost:55432/ohmyrasp?sslmode=disable' \
  -v "$PWD":/src -w /src golang:1.26 \
  go test ./internal/storage/postgres -run TestStoreIntegrationPostgresWorkflow -count=1 -v
```

Run the ClickHouse integration test:

```bash
docker run -d --rm --name ohmyrasp-clickhouse-test \
  -e CLICKHOUSE_USER=ohmyrasp \
  -e CLICKHOUSE_PASSWORD=ohmyrasp \
  -e CLICKHOUSE_DB=default \
  -p 59000:9000 clickhouse/clickhouse-server:latest

docker run --rm --network host \
  -e OHMYRASP_CLICKHOUSE_TEST_DSN='clickhouse://ohmyrasp:ohmyrasp@localhost:59000?database=default' \
  -v "$PWD":/src -w /src golang:1.26 \
  go test ./internal/storage/clickhouse -run TestAnalyticsIntegrationClickHouseWorkflow -count=1 -v
```

Run the Valkey integration test:

```bash
docker run -d --rm --name ohmyrasp-valkey-test \
  -p 56379:6379 valkey/valkey:9

docker run --rm --network host \
  -e OHMYRASP_VALKEY_TEST_ADDR='localhost:56379' \
  -v "$PWD":/src -w /src golang:1.26 \
  go test ./internal/storage/valkey -run TestCacheIntegrationValkeyWorkflow -count=1 -v
```

Default local admin:

```text
admin@ohmyrasp.local / change-me
```
