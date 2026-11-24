# Backup and Restore Runbook

This runbook covers backup and restore for the self-hosted OhMyRASP control plane. PostgreSQL is the authoritative control-plane store, ClickHouse stores analytics and event detail tables, and Valkey caches sessions, agent policies, and rate-limit state (rebuilt automatically from PostgreSQL and live traffic).

## Backup Scope

Back up these components together under one timestamp:

- **PostgreSQL**: users, sessions, applications, environments, Agents, policies, dependency inventory, event ingest outbox, settings, alert rules, alert deliveries, and audit logs.
- **ClickHouse**: security events, hook/performance/crash/error detail tables, dependency observations, and overhead rollups.
- **Agent artifacts**: uploaded Java Agent ZIP packages in the `agent-artifacts` Compose volume or the Helm artifact PVC.
- **Valkey**: optional. Restore is not required for correctness; logins and policy pulls repopulate it.

Use a maintenance window and stop API writes before taking a cold ClickHouse volume backup.

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

Optionally capture Valkey for a faster warm restore:

```bash
docker compose -f "$COMPOSE_FILE" exec -T valkey \
  sh -c 'valkey-cli -a "$VALKEY_PASSWORD" BGSAVE'
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

Record the running image and source revision with the backup:

```bash
docker compose -f "$COMPOSE_FILE" images > "$BACKUP_DIR/images.txt"
git rev-parse HEAD > "$BACKUP_DIR/source-revision.txt" 2>/dev/null || true
```

## Docker Compose Restore

Test restores in an isolated environment first when possible. Stop API and web before replacing database contents:

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

Flush Valkey instead of restoring stale cache entries:

```bash
docker compose -f "$COMPOSE_FILE" up -d valkey
docker compose -f "$COMPOSE_FILE" exec -T valkey \
  sh -c 'valkey-cli -a "$VALKEY_PASSWORD" FLUSHDB'
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

Log in with an admin account and verify applications, Agents, policies, events, alert deliveries, and audit logs are visible.

## Compose Volume Notes

- The `postgres` service mounts `postgres-data` at `/var/lib/postgresql` (not `/var/lib/postgresql/data`) in [docker-compose.yml](../../docker-compose.yml); the image stores its cluster under a per-major subdirectory (`<major>/docker`) inside that volume. For existing PostgreSQL 18 installations, follow the [18 to 19 migration](./upgrade-downgrade.md#postgresql-18-to-19) before starting the new stack.
- Prometheus reads `deploy/prometheus/prometheus.yml`, and alert rules, Grafana dashboards, and Alertmanager configs are mounted from `deploy/helm/ohmyrasp-control/files/`. Keep those host files readable by container users (`0755` directories, `0644` files):

```bash
chmod 755 deploy deploy/prometheus deploy/helm deploy/helm/ohmyrasp-control deploy/helm/ohmyrasp-control/files
chmod 755 deploy/helm/ohmyrasp-control/files/prometheus deploy/helm/ohmyrasp-control/files/grafana
chmod 755 deploy/helm/ohmyrasp-control/files/alertmanager deploy/helm/ohmyrasp-control/files/alertmanager/templates
chmod 644 deploy/prometheus/prometheus.yml deploy/helm/ohmyrasp-control/files/prometheus/*.yml
chmod 644 deploy/helm/ohmyrasp-control/files/grafana/*.json
chmod 644 deploy/helm/ohmyrasp-control/files/alertmanager/*.yml
chmod 644 deploy/helm/ohmyrasp-control/files/alertmanager/templates/*.tmpl
```

## Helm Backup and Restore

The `ohmyrasp-control` Helm chart does not deploy PostgreSQL, ClickHouse, or Valkey. Back up and restore those backing services using your cluster or managed-service procedures. Minimum backup set:

- PostgreSQL logical dump or managed snapshot.
- ClickHouse snapshot or volume backup.
- Agent artifact PVC snapshot or archive when `api.artifacts.persistence.enabled=true`.
- Helm release values and manifest:

```bash
helm -n ohmyrasp get values ohmyrasp-control --all > "$BACKUP_DIR/helm-values.yaml"
helm -n ohmyrasp get manifest ohmyrasp-control > "$BACKUP_DIR/helm-manifest.yaml"
```

Restore order:

1. Scale `deploy/ohmyrasp-api` and `deploy/ohmyrasp-web` to zero.
2. Restore PostgreSQL and ClickHouse.
3. Restore the Agent artifact PVC if persistence is enabled.
4. Flush or restore Valkey.
5. Reinstall the matching chart version and image tags with the saved values.

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

Verify before reopening traffic:

- `/healthz` and `/readyz` return HTTP 200.
- Admin login succeeds and records an audit entry.
- Applications, Agents, Policies, System Settings, Alert Rules, Alert Deliveries, and Audit Logs load in the console.
- Recent event counts match the recovery point objective.
- Agents can heartbeat and pull policy.
- Daemon artifact metadata and download succeed for at least one uploaded or filesystem Java Agent ZIP.
