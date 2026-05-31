# OhMyRASP

OhMyRASP is a self-hosted RASP control plane with a Go API, React web console,
PostgreSQL control store, ClickHouse analytics store, Valkey cache, Prometheus,
Alertmanager, Grafana, and a Java agent proof of concept.

The repository is organized so the active OhMyRASP project lives at the root.
Reference source drops and unrelated material are kept in `.archive/`, which is
ignored by Git.

## Layout

```text
api/          Go control-plane API, migrations, OpenAPI contract, generated bindings
web/          React 19 + Vite control-plane console
java-agent/   Java agent and comparative Tomcat playground
deploy/       Helm chart, Prometheus/Grafana assets, smoke and validation scripts
docs/         Project docs and runbooks
.github/      CI and release workflows
.archive/     Ignored reference material and unrelated source drops
```

## Configuration

The committed `.env.example` contains the acceptance-environment defaults
without passwords. Copy it to `.env` and fill the empty password values before
starting the stack. All published service ports bind to `0.0.0.0` so they can
be reached remotely at `http://<host>:<port>`.

The local `.env` file is ignored by Git. Generate strong values for
`POSTGRES_PASSWORD`, `CLICKHOUSE_PASSWORD`, `VALKEY_PASSWORD`,
`GRAFANA_ADMIN_PASSWORD`, and `OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD`.

| Service | Remote URL |
| --- | --- |
| Web console | `http://<host>:18091` |
| API | `http://<host>:18090` |
| PostgreSQL | `<host>:15432` |
| ClickHouse HTTP | `http://<host>:18123` |
| ClickHouse native | `<host>:19000` |
| Valkey | `<host>:16379` |
| Prometheus | `http://<host>:19090` |
| Alertmanager | `http://<host>:19093` |
| Grafana | `http://<host>:13000` |

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

## Run The Stack

Start all services from the repository root:

```bash
docker compose --env-file .env -f docker-compose.yml up -d --build
docker compose --env-file .env -f docker-compose.yml ps
```

Stop the stack:

```bash
docker compose --env-file .env -f docker-compose.yml down
```

Remove data volumes for a clean acceptance rerun:

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
and a protected Tomcat instance on `18081`. Those ports are separate from the
control-plane stack.

## Documentation

Primary docs live under `docs/`:

- `docs/api.md`
- `docs/web.md`
- `docs/java-agent.md`
- `docs/control-platform.md`
- `docs/capability-audit.md`
- `docs/runbooks/`

Historical upstream/reference code is retained locally under `.archive/` for
traceability, but it is not part of the root Git repository.
