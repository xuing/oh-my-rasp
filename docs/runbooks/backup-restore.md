# Backup And Restore Runbook

This runbook covers the self-hosted OhMyRasp control plane in this directory.
PostgreSQL is the authoritative control-plane store. ClickHouse stores
analytics and event detail tables. Valkey is a cache for sessions, policy pulls,
and rate limiting; it can be rebuilt from PostgreSQL and Agent traffic.

## Backup Scope

Back up these stores together under one timestamp:

- PostgreSQL: users, sessions, applications, environments, Agents, policies,
  dependency inventory, event ingest outbox, settings, alert rules, alert
  deliveries, and audit logs.
- ClickHouse: security events, hook/performance/crash detail tables, dependency
  observations, and overhead rollups.
- Agent artifacts: uploaded Java Agent ZIP packages in the
  `agent-artifacts` Compose volume or the Helm artifact PVC.
- Valkey: optional. Restore is not required for correctness; missing cache data
  is repopulated by logins, policy pulls, and live traffic.

Use a maintenance window for consistent backups when possible. Stop API writes
before taking a cold ClickHouse volume backup.

## Docker Compose Backup

Run from the repository root:

```bash
export COMPOSE_FILE=docker-compose.yml
export TS="$(date -u +%Y%m%dT%H%M%SZ)"
export BACKUP_DIR="$PWD/backups/$TS"
mkdir -p "$BACKUP_DIR"
```

Create a logical PostgreSQL dump:

```bash
docker compose -f "$COMPOSE_FILE" exec -T postgres \
  pg_dump -U ohmyrasp -d ohmyrasp --format=custom --no-owner \
  > "$BACKUP_DIR/postgres.dump"
```

Create a consistent ClickHouse cold backup:

```bash
docker compose -f "$COMPOSE_FILE" stop api web migrate clickhouse

docker run --rm \
  -v ohmyrasp-control_clickhouse-data:/data:ro \
  -v "$BACKUP_DIR":/backup \
  busybox sh -c 'tar czf /backup/clickhouse-data.tgz -C /data .'

docker compose -f "$COMPOSE_FILE" up -d clickhouse api web
```

Optionally capture Valkey for faster warm restore:

```bash
docker compose -f "$COMPOSE_FILE" exec -T valkey valkey-cli BGSAVE
docker cp "$(docker compose -f "$COMPOSE_FILE" ps -q valkey)":/data/dump.rdb \
  "$BACKUP_DIR/valkey-dump.rdb"
```

Capture uploaded Agent artifacts:

```bash
docker run --rm \
  -v ohmyrasp-control_agent-artifacts:/data:ro \
  -v "$BACKUP_DIR":/backup \
  busybox sh -c 'tar czf /backup/agent-artifacts.tgz -C /data .'
```

Record the running image/source version with the backup:

```bash
docker compose -f "$COMPOSE_FILE" images > "$BACKUP_DIR/images.txt"
git rev-parse HEAD > "$BACKUP_DIR/source-revision.txt" 2>/dev/null || true
```

## Docker Compose Restore

Restore into an isolated environment first when possible. Stop API and web
before replacing database contents:

```bash
export COMPOSE_FILE=docker-compose.yml
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-ohmyrasp-control}"
export BACKUP_DIR="$PWD/backups/<timestamp>"
export CLICKHOUSE_VOLUME="${COMPOSE_PROJECT_NAME}_clickhouse-data"

docker compose -f "$COMPOSE_FILE" stop api web migrate
```

Restore PostgreSQL:

```bash
docker compose -f "$COMPOSE_FILE" exec -T postgres dropdb -U ohmyrasp --if-exists ohmyrasp
docker compose -f "$COMPOSE_FILE" exec -T postgres createdb -U ohmyrasp ohmyrasp
docker compose -f "$COMPOSE_FILE" exec -T postgres \
  pg_restore -U ohmyrasp -d ohmyrasp --no-owner --clean --if-exists \
  < "$BACKUP_DIR/postgres.dump"
```

Restore the ClickHouse volume from the cold backup:

```bash
docker compose -f "$COMPOSE_FILE" stop clickhouse
docker compose -f "$COMPOSE_FILE" rm -sf clickhouse
docker volume rm "$CLICKHOUSE_VOLUME"
docker volume create \
  --label "com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
  --label "com.docker.compose.volume=clickhouse-data" \
  "$CLICKHOUSE_VOLUME"

docker run --rm \
  -v "$CLICKHOUSE_VOLUME":/data \
  -v "$BACKUP_DIR":/backup \
  busybox sh -c 'tar xzf /backup/clickhouse-data.tgz -C /data'
```

Valkey can usually be cleared instead of restored:

```bash
docker compose -f "$COMPOSE_FILE" up -d valkey
docker compose -f "$COMPOSE_FILE" exec -T valkey valkey-cli FLUSHDB
```

Restore uploaded Agent artifacts:

```bash
export ARTIFACT_VOLUME="${COMPOSE_PROJECT_NAME}_agent-artifacts"
docker volume rm "$ARTIFACT_VOLUME" 2>/dev/null || true
docker volume create \
  --label "com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
  --label "com.docker.compose.volume=agent-artifacts" \
  "$ARTIFACT_VOLUME"

docker run --rm \
  -v "$ARTIFACT_VOLUME":/data \
  -v "$BACKUP_DIR":/backup \
  busybox sh -c 'tar xzf /backup/agent-artifacts.tgz -C /data'
```

Start the stack and verify:

```bash
docker compose -f "$COMPOSE_FILE" up -d postgres clickhouse valkey
docker compose -f "$COMPOSE_FILE" run --rm migrate
docker compose -f "$COMPOSE_FILE" up -d api web prometheus alertmanager grafana

curl -fsS http://localhost:18090/healthz
curl -fsS http://localhost:18090/readyz
curl -fsS http://localhost:18091/
curl -fsS http://localhost:19093/-/ready
curl -fsS http://localhost:13000/api/health
deploy/scripts/smoke-control-plane.sh
```

Log in with an admin account and verify applications, Agents, policies, events,
alert deliveries, and audit logs are visible.

## Compose Volume Notes

PostgreSQL 18 containers expect the named volume to be mounted at
`/var/lib/postgresql`, not `/var/lib/postgresql/data`. The included Compose file
uses the PostgreSQL 18-compatible parent directory mount so future major-version
upgrades can use PostgreSQL's versioned data subdirectories.

Prometheus reads `deploy/prometheus/prometheus.yml` from the host. The file and
its parent directories must be readable/traversable by the Prometheus container
user, for example:

```bash
chmod 755 deploy deploy/prometheus
chmod 644 deploy/prometheus/prometheus.yml
```

Prometheus alert rules, Grafana dashboards, and Alertmanager examples are
mounted from the Helm chart asset directory. Keep these readable by container
users:

```bash
chmod 755 deploy/helm deploy/helm/ohmyrasp-control deploy/helm/ohmyrasp-control/files
chmod 755 deploy/helm/ohmyrasp-control/files/prometheus deploy/helm/ohmyrasp-control/files/grafana
chmod 755 deploy/helm/ohmyrasp-control/files/alertmanager deploy/helm/ohmyrasp-control/files/alertmanager/templates
chmod 644 deploy/helm/ohmyrasp-control/files/prometheus/*.yml
chmod 644 deploy/helm/ohmyrasp-control/files/grafana/*.json
chmod 644 deploy/helm/ohmyrasp-control/files/alertmanager/*.yml
chmod 644 deploy/helm/ohmyrasp-control/files/alertmanager/templates/*.tmpl
```

## Helm Backup And Restore

The Helm chart does not deploy PostgreSQL, ClickHouse, or Valkey by itself. Use
the managed-service snapshot mechanism or the operator runbook for those
services. The minimum backup set is:

- PostgreSQL logical dump or managed snapshot.
- ClickHouse snapshot, backup, or volume snapshot.
- Agent artifact PVC snapshot or archive, when `api.artifacts.persistence.enabled=true`.
- Helm release values:

```bash
helm -n ohmyrasp get values ohmyrasp-control --all > "$BACKUP_DIR/helm-values.yaml"
helm -n ohmyrasp get manifest ohmyrasp-control > "$BACKUP_DIR/helm-manifest.yaml"
```

For restore:

1. Scale the API and web deployments to zero.
2. Restore PostgreSQL and ClickHouse using the backing-service procedure.
3. Restore the Agent artifact PVC if managed uploads are enabled.
4. Clear or restore Valkey.
5. Reinstall the same chart/image tags with the saved values.
6. Run health checks and login verification.

```bash
kubectl -n ohmyrasp scale deploy/ohmyrasp-api deploy/ohmyrasp-web --replicas=0

helm upgrade --install ohmyrasp-control deploy/helm/ohmyrasp-control \
  -n ohmyrasp --create-namespace \
  -f "$BACKUP_DIR/helm-values.yaml" \
  --wait

kubectl -n ohmyrasp rollout status deploy/ohmyrasp-api
kubectl -n ohmyrasp rollout status deploy/ohmyrasp-web
```

## Restore Acceptance Checks

Run these before reopening traffic:

- `/healthz` and `/readyz` return HTTP 200.
- Admin login succeeds and creates an audit record.
- Application, Agent, policy, system setting, alert rule, alert delivery, and
  audit-log pages load.
- Recent event counts match the recovery point objective.
- Agents can heartbeat and pull policy.
- Daemon artifact metadata/download succeeds for at least one uploaded or
  generated Java Agent ZIP.
