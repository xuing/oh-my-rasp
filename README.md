# OhMyRASP

Self-hosted runtime application self-protection for Java services, with a
control plane, observability stack, daemon-compatible APIs, and a Java agent
proof of concept.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg)](https://go.dev/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docs.docker.com/compose/)

OhMyRASP is built for teams that want an inspectable, self-hosted RASP control
plane instead of a black-box security appliance. It combines application and
agent inventory, policy lifecycle management, runtime telemetry, daemon
workload reporting, auditability, and an OSS Java agent testbed in one
repository.

## Highlights

- **Self-hosted control plane**: Go API, React console, PostgreSQL, ClickHouse,
  Valkey, Prometheus, Alertmanager, and Grafana.
- **Agent lifecycle APIs**: application secrets, agent registration,
  heartbeat, policy pull, artifact catalog, and artifact upload/download.
- **Daemon compatibility**: workload inventory reporting, bind/unbind
  workflows, injection reports, and legacy command websocket support.
- **Policy operations**: draft editing, validation, versioning, canary rollout,
  rollback, and rule testing.
- **Runtime telemetry**: attack, hook, performance, crash, dependency, and
  baseline posture ingestion with filtered reads and analytics.
- **Operations ready**: Helm chart, smoke tests, release workflow, runbooks,
  Prometheus rules, Alertmanager config, and Grafana dashboards.
- **Java agent PoC**: ASM-based Java agent and comparative Tomcat playground
  for validating detector behavior.

## Architecture

```text
                 +-------------------+
                 |   Web Console     |
                 |  React + Vite     |
                 +---------+---------+
                           |
                           v
+-------------------+  +---+----------------+  +--------------------+
| Java Agents       |  | Control API        |  | Daemon / Helper    |
| heartbeat/policy  +->+ Go + OpenAPI       +<-+ workload commands  |
+-------------------+  +---+---+---+---+----+  +--------------------+
                           |   |   |
                +----------+   |   +----------------+
                v              v                    v
          PostgreSQL       ClickHouse             Valkey
        control state      telemetry              cache
                |
                v
   Prometheus + Alertmanager + Grafana
```

## Repository Layout

```text
api/          Go control-plane API, migrations, OpenAPI contract, generated bindings
web/          React 19 + Vite control-plane console
java-agent/   Java agent and comparative Tomcat playground
deploy/       Helm chart, observability assets, smoke and validation scripts
docs/         Architecture notes, audits, and operational runbooks
.github/      CI and release workflows
.archive/     Ignored reference material and upstream source drops
```

## Quick Start

Create a local environment file:

```bash
cp .env.example .env
```

Fill every empty password value in `.env` before starting the stack:

```bash
POSTGRES_PASSWORD=
CLICKHOUSE_PASSWORD=
VALKEY_PASSWORD=
GRAFANA_ADMIN_PASSWORD=
OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD=
```

Start the full self-hosted stack:

```bash
docker compose --env-file .env -f docker-compose.yml up -d --build
docker compose --env-file .env -f docker-compose.yml ps
```

Open the services from the host running Docker:

| Service | URL |
| --- | --- |
| Web console | `http://<host>:18091` |
| API | `http://<host>:18090` |
| Grafana | `http://<host>:13000` |
| Prometheus | `http://<host>:19090` |
| Alertmanager | `http://<host>:19093` |
| ClickHouse HTTP | `http://<host>:18123` |

Default control-plane login:

```text
Email: admin@ohmyrasp.local
Password: value of OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD in .env
```

Grafana login:

```text
User: admin
Password: value of GRAFANA_ADMIN_PASSWORD in .env
```

Stop the stack:

```bash
docker compose --env-file .env -f docker-compose.yml down
```

Remove data volumes for a clean local run:

```bash
docker compose --env-file .env -f docker-compose.yml down -v
```

## Development

Backend checks:

```bash
docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go generate ./...
docker run --rm -v "$PWD/api":/src -w /src golang:1.26 go test ./...
```

Frontend checks:

```bash
cd web
npm ci
npm run build
npm test
npm run e2e
OHMYRASP_E2E_LIVE_URL=http://127.0.0.1:18091 npm run e2e:live
```

Deployment and observability checks:

```bash
./deploy/scripts/smoke-control-plane.sh
./deploy/scripts/validate-helm-manifests.sh
./deploy/scripts/validate-observability-assets.sh
```

Java agent acceptance:

```bash
cd java-agent
bash scripts/acceptance.sh
```

The Java agent acceptance script starts a baseline Tomcat instance on `18080`
and a protected Tomcat instance on `18081`. Those ports are intentionally
separate from the control-plane stack.

## Documentation

- [Control platform overview](docs/control-platform.md)
- [Capability audit](docs/capability-audit.md)
- [API notes](docs/api.md)
- [Web console notes](docs/web.md)
- [Java agent notes](docs/java-agent.md)
- [Runbooks](docs/runbooks/)

Historical upstream and reference material is retained locally under
`.archive/` for traceability, but it is ignored by Git and is not part of the
published repository.

## Security

`.env` is intentionally ignored. Do not commit real service credentials,
private hostnames, private IP addresses, or production agent artifacts.

For security issues, open a private advisory or contact the maintainers before
publishing details.

## License

Apache License 2.0. See [LICENSE](LICENSE).
