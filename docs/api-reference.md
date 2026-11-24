# Control-Plane API Reference

The OhMyRASP control-plane API (`ohmyrasp-api`, module `github.com/ohmyrasp/control-plane`, Go version pinned in [`api/go.mod`](../api/go.mod)) is an OpenAPI 3.1 HTTP service built with `net/http`, `chi`, `oapi-codegen` strict-server bindings, and `slog`. Source of truth: [openapi.yaml](../api/api/openapi.yaml), [server.go](../api/internal/httpapi/server.go), and [main.go](../api/cmd/ohmyrasp-api/main.go).

## Authentication Models

| Caller | Mechanism | Headers / Env | Scope |
|---|---|---|---|
| Operator / Console | Bearer session token from `POST /api/v1/auth/login` | `Authorization: Bearer <token>` | All `/api/v1/*` operator routes (RBAC-enforced) |
| Java Agent | Application credentials | `X-OhMyRasp-App-ID`, `X-OhMyRasp-App-Secret` | Agent lifecycle, policy pull, event/dependency/baseline ingest |
| Host Daemon | Daemon access token | `X-OhMyRasp-Daemon-Token` (fallback `X-Auth-Token`) | Daemon commands, app lookup, workload/injection reports, artifact download, legacy `/v1/service/*` and `/v2/service/*` |
| Prometheus Scraper | Optional static bearer token | `Authorization: Bearer <OHMYRASP_METRICS_TOKEN>` | `GET /metrics` (unauthenticated if `OHMYRASP_METRICS_TOKEN` is unset) |

Operator RBAC roles defined in [rbac.go](../api/internal/httpapi/rbac.go):
- `admin`: full read/write access including user administration (`users:read`, `users:manage`).
- `security_engineer`: read access across inventory/events/audit plus mutations for applications, agents, daemon, policies, events, settings, and alert rules.
- `viewer`: read-only access to profile, applications, agents, daemon workloads/artifacts, policies, events, analytics, settings, alert rules/deliveries, and audit logs.

## Rate Limiting and Login Protection

- **API rate limit**: Valkey-backed sliding limit configured by `OHMYRASP_RATE_LIMIT` (default `600` requests) and `OHMYRASP_RATE_LIMIT_WINDOW` (default `1m`). Keys resolve in priority order: `user:<sha256-prefix>`, `agent:<agentID>`, `app:<appID>`, or `ip:<clientIP>`. Applies to all routes except `/healthz` and `/readyz`. Fails open on Valkey errors, except `POST /api/v1/auth/login` which fails closed (`503 rate_limiter_unavailable`).
- **Login throttle**: In-process per-IP+email backoff (`loginThrottle`) locks out `POST /api/v1/auth/login` for `15m` after `5` failed (`401`) attempts (`429 login_locked`).

## REST API Endpoints

All paths from [openapi.yaml](../api/api/openapi.yaml) are listed below by domain, alongside legacy daemon compatibility routes implemented in [server.go](../api/internal/httpapi/server.go).

### Health, Version, and Metrics

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/healthz` | None | Process liveness (`{"status":"ok"}`) |
| `GET` | `/readyz` | None | Store/dependency readiness (`200` ready or `503` unavailable) |
| `GET` | `/metrics` | Optional `OHMYRASP_METRICS_TOKEN` | Prometheus text exposition (cached by `OHMYRASP_METRICS_CACHE_TTL`, default `10s`) |
| `GET` | `/v1/version` | None | Public component version metadata |

### Auth and Users

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | None | Exchange email/password for operator session token and user object |
| `GET` | `/api/v1/me` | Bearer | Current authenticated user (`profile:read`) |
| `GET` | `/api/v1/users` | Bearer (`admin`) | List users (`search`, `role`, `status` filters) |
| `POST` | `/api/v1/users` | Bearer (`admin`) | Create user (`201`) |
| `PUT` | `/api/v1/users/{userID}` | Bearer (`admin`) | Update user name, roles, or disabled status (revokes sessions in PostgreSQL and Valkey when disabled) |

### Applications and Environments

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/applications` | Bearer | List applications |
| `POST` | `/api/v1/applications` | Bearer (`admin`, `security_engineer`) | Create application (`201`) |
| `GET` | `/api/v1/applications/export` | Bearer | Export application inventory |
| `DELETE` | `/api/v1/applications/{appID}` | Bearer (`admin`, `security_engineer`) | Remove application (`204`) |
| `POST` | `/api/v1/applications/{appID}/environments` | Bearer (`admin`, `security_engineer`) | Create environment under an application (`201`) |
| `GET` | `/api/v1/applications/{appID}/settings` | Bearer | Read effective application settings |
| `PUT` | `/api/v1/applications/{appID}/settings` | Bearer (`admin`, `security_engineer`) | Upsert application settings |
| `GET` | `/api/v1/applications/{appID}/environments/{envID}/settings` | Bearer | Read effective environment override settings |
| `PUT` | `/api/v1/applications/{appID}/environments/{envID}/settings` | Bearer (`admin`, `security_engineer`) | Upsert environment settings |
| `POST` | `/api/v1/applications/{appID}/secret/rotate` | Bearer (`admin`, `security_engineer`) | Rotate application secret |

### Agents

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/agents` | Bearer | List agents (`application_id`, `environment_id` filters) |
| `POST` | `/api/v1/agents/batch-delete` | Bearer (`admin`, `security_engineer`) | Batch-delete agents from active inventory |
| `DELETE` | `/api/v1/agents/{agentID}` | Bearer (`admin`, `security_engineer`) | Delete single agent |
| `PUT` | `/api/v1/agents/{agentID}/alias` | Bearer (`admin`, `security_engineer`) | Update agent operator alias/remark |
| `POST` | `/api/v1/agents/{agentID}/ignore` | Bearer (`admin`, `security_engineer`) | Toggle agent ignored state |
| `POST` | `/api/v1/agents/register` | App headers | Register Java Agent (`201`) |
| `POST` | `/api/v1/agents/{agentID}/heartbeat` | App headers | Report agent heartbeat |
| `GET` | `/api/v1/agents/{agentID}/policy` | App headers | Fetch active or canary policy for agent (Valkey-cached) |

### Daemon and Agent Artifacts

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/daemon/token` | Bearer (`admin`, `security_engineer`) | Read current daemon access token |
| `POST` | `/api/v1/daemon/token/reset` | Bearer (`admin`, `security_engineer`) | Rotate daemon access token |
| `GET` | `/api/v1/daemon/workloads` | Bearer | List daemon-reported process and container workloads |
| `POST` | `/api/v1/daemon/workloads/{workloadID}/bind` | Bearer (`admin`, `security_engineer`) | Bind workload to an application |
| `POST` | `/api/v1/daemon/workloads/{workloadID}/unbind` | Bearer (`admin`, `security_engineer`) | Unbind workload from its application |
| `GET` | `/api/v1/daemon/commands` | Daemon token | Fetch bound-workload install commands grouped by application |
| `GET` | `/api/v1/daemon/app` | Daemon token | Look up daemon-visible application credentials (`app_id` query param) |
| `GET` | `/api/v1/daemon/artifacts/agent/info` | Daemon token | Agent ZIP metadata (`app_id`, `language`, `system_type`, `language_version`) |
| `GET` | `/api/v1/daemon/artifacts/agent` | Daemon token | Download Java Agent ZIP artifact (`X-OhMyRasp-Agent-MD5` header) |
| `POST` | `/api/v1/daemon/workloads/report` | Daemon token | Submit host/container workload inventory |
| `POST` | `/api/v1/daemon/injection-reports` | Daemon token | Submit workload injection outcome |
| `GET` | `/api/v1/agent-artifacts` | Bearer | List operator-visible Java Agent ZIP catalog (`OHMYRASP_AGENT_ARTIFACT_DIR`) |
| `POST` | `/api/v1/agent-artifacts` | Bearer (`admin`, `security_engineer`) | Upload Java Agent ZIP as base64 JSON (`201`, max 100 MiB) |

The API serves uploaded (`ohmyrasp-agent-<language>-<system_type>-<language_version>.zip`) or pre-staged filesystem ZIP packages (`agent-java-linux.zip`, `agent-java.zip`, etc.) from `OHMYRASP_AGENT_ARTIFACT_DIR`. Generated bootstrap ZIPs are disabled (`GeneratedBootstrapEnabled: false`).

### Policies

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/policies` | Bearer | List policy sets |
| `POST` | `/api/v1/policies` | Bearer (`admin`, `security_engineer`) | Create policy set (`201`) |
| `GET` | `/api/v1/policies/algorithms` | Bearer | List supported hook and detection algorithm catalog |
| `POST` | `/api/v1/policies/{policyID}/restore-default` | Bearer (`admin`, `security_engineer`) | Restore default algorithms as a new draft version |
| `POST` | `/api/v1/policies/{policyID}/versions` | Bearer (`admin`, `security_engineer`) | Create policy version (`201`) |
| `PUT` | `/api/v1/policies/{policyID}/versions/{version}/rules` | Bearer (`admin`, `security_engineer`) | Update draft policy version rules |
| `POST` | `/api/v1/policies/validate` | Bearer (`admin`, `security_engineer`) | Validate rule syntax |
| `POST` | `/api/v1/policies/test` | Bearer (`admin`, `security_engineer`) | Test a rule against a sample security event |
| `POST` | `/api/v1/policies/{policyID}/rollout` | Bearer (`admin`, `security_engineer`) | Apply canary or full rollout (invalidates Valkey policy cache) |
| `POST` | `/api/v1/policies/{policyID}/rollback` | Bearer (`admin`, `security_engineer`) | Roll back active policy version |

### Events and Recycle Bin

All `GET /api/v1/events/{attack,hook,performance,crash,error}` routes accept optional `application_id`, `environment_id`, `agent_id`, `policy_id`, `severity`, `hook`, `occurred_after` (RFC3339), `occurred_before` (RFC3339), and `limit` (`1..1000`) query parameters. All `POST` ingest routes return `202 Accepted`.

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/events/attack` | Bearer | List attack events |
| `POST` | `/api/v1/events/attack` | App headers | Ingest attack event (`202`) |
| `GET` | `/api/v1/events/hook` | Bearer | List hook events |
| `POST` | `/api/v1/events/hook` | App headers | Ingest hook event (`202`) |
| `GET` | `/api/v1/events/performance` | Bearer | List performance telemetry events |
| `POST` | `/api/v1/events/performance` | App headers | Ingest performance event (`202`) |
| `GET` | `/api/v1/events/crash` | Bearer | List crash events |
| `POST` | `/api/v1/events/crash` | App headers | Ingest crash event (`202`) |
| `GET` | `/api/v1/events/error` | Bearer | List error events |
| `POST` | `/api/v1/events/error` | App headers | Ingest error event (`202`) |
| `GET` | `/api/v1/events/recycle-bin` | Bearer | List soft-deleted events (`type` filter + event filters) |
| `POST` | `/api/v1/events/recycle-bin/delete` | Bearer (`admin`, `security_engineer`) | Soft-delete events (excluded from normal lists/overview) |
| `POST` | `/api/v1/events/recycle-bin/restore` | Bearer (`admin`, `security_engineer`) | Restore soft-deleted events |
| `POST` | `/api/v1/events/recycle-bin/purge` | Bearer (`admin`, `security_engineer`) | Permanently purge deleted events |

### Dependencies and Baseline Findings

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/dependencies` | Bearer | List dependencies (`application_id`, `agent_id`, `name`, `ecosystem`, `vulnerability_severity`, `observed_after`, `observed_before`, `limit`) |
| `POST` | `/api/v1/dependencies` | App headers | Ingest dependency observation (`202`) |
| `GET` | `/api/v1/dependencies/export` | Bearer | Export dependency observations |
| `GET` | `/api/v1/dependencies/summary` | Bearer | Aggregate dependency summary (`application_id`, `agent_id`) |
| `GET` | `/api/v1/baseline-findings` | Bearer | List baseline posture findings (`application_id`, `environment_id`, `agent_id`, `severity`, `status`, `category`, `observed_after`, `observed_before`, `limit`) |
| `POST` | `/api/v1/baseline-findings` | App headers | Ingest baseline finding (`202`) |

### Analytics and Observability

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/analytics/overview` | Bearer | Control-plane overview counts (`application_id`, `environment_id`) |
| `GET` | `/api/v1/analytics/observability` | Bearer | Rule overhead, hook latency, agent overhead, and policy performance (`application_id`, `policy_id`) |

### System, Settings, Alerts, and Audit

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/system-settings` | Bearer | List system settings |
| `PUT` | `/api/v1/system-settings/{key}` | Bearer (`admin`, `security_engineer`) | Upsert system setting |
| `GET` | `/api/v1/system/edition` | Bearer | OSS self-hosted edition status (no license key or limits) |
| `GET` | `/api/v1/system/version` | Bearer | Control-plane component version metadata |
| `POST` | `/api/v1/maintenance/cleanup` | Bearer (`admin`, `security_engineer`) | Preview or apply operational data cleanup before a cutoff (`CLEAR_OPERATIONAL_DATA` confirmation required for destructive runs; writes `maintenance.cleanup` audit entry) |
| `GET` | `/api/v1/alert-rules` | Bearer | List alert rules (`application_id` filter) |
| `POST` | `/api/v1/alert-rules` | Bearer (`admin`, `security_engineer`) | Create alert rule (`201`) |
| `PUT` | `/api/v1/alert-rules/{alertRuleID}` | Bearer (`admin`, `security_engineer`) | Update alert rule |
| `GET` | `/api/v1/alert-deliveries` | Bearer | List alert delivery history (`application_id` filter) |
| `GET` | `/api/v1/audit-logs` | Bearer | List operation audit logs |

### Legacy Daemon Compatibility Routes

Implemented directly in [server.go](../api/internal/httpapi/server.go) and [legacy_daemon_ws.go](../api/internal/httpapi/legacy_daemon_ws.go) using the daemon token (`X-OhMyRasp-Daemon-Token` or `X-Auth-Token`):

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/service/app/get` | Legacy application credential lookup (`app_id`) |
| `GET` | `/v1/service/command` | LZ4-framed JSON WebSocket (`UpdateProcess`, `UpdateK8S`, `NotifyInjectError` in; `InjectProcessGroup` out) |
| `POST` | `/v1/service/command/daemon_set/inject` | Legacy DaemonSet injection status report |
| `GET` | `/v1/service/dl/agent/info` | Legacy agent MD5 metadata lookup |
| `GET` | `/v1/service/dl/agent` | Legacy agent ZIP download alias |
| `GET` | `/v2/service/dl/agent` | Legacy v2 agent ZIP download alias |

## Storage Modes

PostgreSQL mode (default; `OHMYRASP_STORE=postgres` or unset with `OHMYRASP_POSTGRES_DSN` set):

```bash
OHMYRASP_POSTGRES_DSN='postgres://ohmyrasp:ohmyrasp@localhost:15432/ohmyrasp?sslmode=disable' \
OHMYRASP_CLICKHOUSE_DSN='clickhouse://ohmyrasp:ohmyrasp@localhost:19000?database=ohmyrasp' \
OHMYRASP_VALKEY_ADDR='localhost:16379' \
OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD='change-me' \
go run ./cmd/ohmyrasp-api
```

- `OHMYRASP_POSTGRES_DSN`: required in PostgreSQL mode for control-plane state, RBAC, policies, settings, audit logs, and event outbox.
- `OHMYRASP_CLICKHOUSE_DSN`: optional; enables ClickHouse event queries, detail tables, and overhead/latency analytics.
- `OHMYRASP_VALKEY_ADDR`: optional for local experiments, recommended in production for session caching, agent policy caching, and API rate limiting.
- `OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD`: required in both PostgreSQL and memory modes.

In-memory mode (`OHMYRASP_STORE=memory`, for isolated local experiments only):

```bash
OHMYRASP_STORE=memory \
OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD='change-me' \
go run ./cmd/ohmyrasp-api
```

## Migrations

Embedded PostgreSQL and ClickHouse schemas are applied via `cmd/ohmyrasp-migrate` (or automatically at API startup when `OHMYRASP_AUTO_MIGRATE=true`):

```bash
OHMYRASP_POSTGRES_DSN='postgres://ohmyrasp:ohmyrasp@localhost:15432/ohmyrasp?sslmode=disable' \
OHMYRASP_CLICKHOUSE_DSN='clickhouse://ohmyrasp:ohmyrasp@localhost:19000?database=ohmyrasp' \
go run ./cmd/ohmyrasp-migrate
```

Flags: `-postgres-dsn`, `-clickhouse-dsn`, `-skip-postgres`, `-skip-clickhouse`, `-timeout` (default `30s`). Without a host Go toolchain (the builder image is resolved from `api/Dockerfile`, as CI does):

```bash
GO_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^golang:/ { print $2; exit }' Dockerfile)"   # run from api/
docker run --rm --network host \
  -e OHMYRASP_POSTGRES_DSN='postgres://ohmyrasp:ohmyrasp@localhost:15432/ohmyrasp?sslmode=disable' \
  -v "$PWD":/src -w /src "$GO_IMAGE" \
  go run ./cmd/ohmyrasp-migrate -skip-clickhouse
```

## OpenAPI Code Generation

After editing `api/api/openapi.yaml`, regenerate `api/internal/generated/openapi.gen.go` from `api/`:

```bash
GO_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^golang:/ { print $2; exit }' Dockerfile)"   # run from api/
docker run --rm -v "$PWD":/src -w /src "$GO_IMAGE" go generate ./...
```

`go test ./...` verifies `internal/generated/openapi.gen.go` stays aligned with `api/openapi.yaml`. `/metrics` and `/v1/service/*` stay hand-written outside strict JSON codegen.

## Local and Integration Tests

Run unit and contract tests from `api/`:

```bash
GO_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^golang:/ { print $2; exit }' Dockerfile)"   # run from api/
docker run --rm -v "$PWD":/src -w /src "$GO_IMAGE" go test ./...
```

The integration tests use the PostgreSQL, ClickHouse, and Valkey service containers from [`.github/docker-compose.ci-services.yml`](../.github/docker-compose.ci-services.yml) (images pinned there; host ports `55432`, `59000`, and `56379`, with the credentials defined in that file). The commands below run from `api/`.

PostgreSQL integration test:

```bash
GO_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^golang:/ { print $2; exit }' Dockerfile)"   # run from api/
docker compose -f ../.github/docker-compose.ci-services.yml up -d --wait postgres

docker run --rm --network host \
  -e OHMYRASP_POSTGRES_TEST_DSN='postgres://ohmyrasp:ohmyrasp@localhost:55432/ohmyrasp?sslmode=disable' \
  -v "$PWD":/src -w /src "$GO_IMAGE" \
  go test ./internal/storage/postgres -run TestStoreIntegrationPostgresWorkflow -count=1 -v
```

ClickHouse integration test:

```bash
GO_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^golang:/ { print $2; exit }' Dockerfile)"   # run from api/
docker compose -f ../.github/docker-compose.ci-services.yml up -d --wait clickhouse

docker run --rm --network host \
  -e OHMYRASP_CLICKHOUSE_TEST_DSN='clickhouse://ohmyrasp:ohmyrasp@localhost:59000?database=default' \
  -v "$PWD":/src -w /src "$GO_IMAGE" \
  go test ./internal/storage/clickhouse -run TestAnalyticsIntegrationClickHouseWorkflow -count=1 -v
```

Valkey integration test:

```bash
GO_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^golang:/ { print $2; exit }' Dockerfile)"   # run from api/
docker compose -f ../.github/docker-compose.ci-services.yml up -d --wait valkey

docker run --rm --network host \
  -e OHMYRASP_VALKEY_TEST_ADDR='localhost:56379' \
  -v "$PWD":/src -w /src "$GO_IMAGE" \
  go test ./internal/storage/valkey -run TestCacheIntegrationValkeyWorkflow -count=1 -v
```

Stop the service containers afterwards with `docker compose -f ../.github/docker-compose.ci-services.yml down`.
