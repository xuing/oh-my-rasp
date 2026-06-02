# OhMyRASP

Self-hosted runtime application self-protection for Java services, with a
control plane, observability stack, daemon-compatible APIs, and a Java agent
proof of concept.

**Languages:** English | [简体中文](README.zh-CN.md)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![chi](https://img.shields.io/badge/chi-router-00ADD8?logo=go&logoColor=white)](https://github.com/go-chi/chi)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1-6BA539?logo=openapiinitiative&logoColor=white)](https://www.openapis.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=061A23)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white)](https://vite.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-control_store-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![ClickHouse](https://img.shields.io/badge/ClickHouse-analytics-FFCC01?logo=clickhouse&logoColor=111111)](https://clickhouse.com/)
[![Valkey](https://img.shields.io/badge/Valkey-cache-B71C1C?logo=valkey&logoColor=white)](https://valkey.io/)
[![Prometheus](https://img.shields.io/badge/Prometheus-metrics-E6522C?logo=prometheus&logoColor=white)](https://prometheus.io/)
[![Alertmanager](https://img.shields.io/badge/Alertmanager-routing-E6522C?logo=prometheus&logoColor=white)](https://prometheus.io/docs/alerting/latest/alertmanager/)
[![Grafana](https://img.shields.io/badge/Grafana-dashboards-F46800?logo=grafana&logoColor=white)](https://grafana.com/)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Helm](https://img.shields.io/badge/Helm-chart-0F1689?logo=helm&logoColor=white)](https://helm.sh/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-ready-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Java](https://img.shields.io/badge/Java-agent-ED8B00?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![ASM](https://img.shields.io/badge/ASM-bytecode-5A45FF?logo=apache&logoColor=white)](https://asm.ow2.io/)
[![Nginx](https://img.shields.io/badge/Nginx-web_proxy-009639?logo=nginx&logoColor=white)](https://nginx.org/)
[![Playwright](https://img.shields.io/badge/Playwright-e2e-2EAD33?logo=playwright&logoColor=white)](https://playwright.dev/)
[![Vitest](https://img.shields.io/badge/Vitest-unit_tests-6E9F18?logo=vitest&logoColor=white)](https://vitest.dev/)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-CI-2088FF?logo=githubactions&logoColor=white)](https://github.com/features/actions)

OhMyRASP is built for teams that want an inspectable, self-hosted RASP control
plane instead of a black-box security appliance. It combines application and
agent inventory, policy lifecycle management, runtime telemetry, daemon
workload reporting, auditability, and an OSS Java agent testbed in one
repository.

## Project Status

OhMyRASP is currently under active development. The project is still unstable:
APIs, policy semantics, agent packaging, detector behavior, and deployment
interfaces may change quickly as the architecture matures. It is suitable for
experimentation, evaluation, and contribution, but it should not yet be treated
as a production-ready security boundary.

The near-term roadmap is focused on growing the rule and strategy system:

- Automatically run a large corpus of existing cyber ranges and vulnerable
  application scenarios, then extract reusable RASP detection rules from the
  observed attack paths.
- Use Large Language Models (LLMs) to generate, review, and refine new
  protection strategies from cyber-range behavior, vulnerability patterns, and
  runtime evidence.
- Expand the Java agent line. The current Java agent primarily targets JDK 25;
  future work will produce corresponding agents for each Java Long-Term Support
  (LTS) version so runtime coverage can match real-world deployment baselines.


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

OhMyRASP uses a control-plane architecture. The Go API is the central
coordination point: it owns authentication, RBAC, application inventory,
environment inventory, policies, daemon state, agent artifact metadata, audit
logs, and operational settings through an OpenAPI-defined HTTP surface. The
React console talks to that API and provides the operator workflow for creating
applications, managing policies, reviewing telemetry, rotating credentials, and
monitoring daemon/agent activity.

Runtime data is split by access pattern. PostgreSQL stores authoritative
control-plane state, ClickHouse stores high-volume event and performance
telemetry, and Valkey provides session, policy-pull, and rate-limit caching.
Prometheus scrapes the API and bundled rules, Alertmanager handles alert
routing, and Grafana provides dashboarding.

The Java side demonstrates the protection path. Agents register against the
control plane, heartbeat, pull policies, and report runtime observations. The
daemon-compatible APIs support workload discovery, binding workloads to
applications, command delivery, artifact download, and injection-result
reporting. The Java agent proof of concept uses ASM bytecode transformation to
hook selected runtime call sites inside a comparative Tomcat testbed.

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
console/      React 19 + Vite control-plane console
java-agent/   Java agent and comparative Tomcat playground
deploy/       Helm chart, observability assets, smoke and validation scripts
docs/         Architecture notes, audits, and operational runbooks
.github/      CI and release workflows
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
cd console
npm ci
npm run build
npm test
npm run test:e2e
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

## Acknowledgements

OhMyRASP's Java agent proof of concept uses the
[ASM](https://asm.ow2.io/) bytecode engineering library. We are grateful to the
ASM project and maintainers for the tooling that makes precise JVM
instrumentation practical.

We also want to thank the [OpenRASP](https://github.com/baidu/openrasp)
project. OpenRASP helped define many of the ideas and operational expectations
around open runtime application self-protection, and it remains an important
reference point for the ecosystem.


## License

Apache License 2.0. See [LICENSE](LICENSE).
