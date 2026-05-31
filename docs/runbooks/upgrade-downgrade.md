# Upgrade And Downgrade Runbook

This runbook covers control-plane application upgrades for Docker Compose and
Helm deployments. Database migrations are forward-only. If an upgrade applies a
schema change, downgrade is performed by restoring the pre-upgrade PostgreSQL
and ClickHouse backups, then starting the previous API and web versions.

## Pre-Upgrade Checklist

1. Read the release notes and identify whether PostgreSQL or ClickHouse
   migrations changed.
2. Pin the target API and web image tags or source revision. Do not upgrade from
   `latest` without recording the exact image digests.
3. Take a backup using [backup-restore.md](./backup-restore.md).
4. Confirm the current stack is healthy:

```bash
curl -fsS http://localhost:18090/healthz
curl -fsS http://localhost:18090/readyz
curl -fsS http://localhost:18091/
```

5. Pause scheduled maintenance jobs or external automation that might mutate
   policies, users, settings, or alert rules during the upgrade.

## Docker Compose Upgrade

Run from the repository root after checking out the target source revision:

```bash
export COMPOSE_FILE=docker-compose.yml

docker compose -f "$COMPOSE_FILE" build migrate api web
docker compose -f "$COMPOSE_FILE" up --no-deps --build migrate
docker compose -f "$COMPOSE_FILE" up -d --no-deps --build api web
```

Verify the upgrade:

```bash
curl -fsS http://localhost:18090/healthz
curl -fsS http://localhost:18090/readyz
curl -fsS http://localhost:18090/metrics | head
curl -fsS http://localhost:18091/
deploy/scripts/smoke-control-plane.sh
```

Then log in and verify:

- Overview loads current application, Agent, and event counts.
- Applications, Agents, Policies, Events, Observability, and Access & Audit
  pages load.
- An Agent heartbeat and policy pull succeeds.
- A test admin login appears in the audit log.

## Docker Compose Downgrade

If the failed upgrade did not apply database migrations, downgrade only the
application containers:

```bash
export COMPOSE_FILE=docker-compose.yml

git checkout <previous-source-revision>
docker compose -f "$COMPOSE_FILE" build migrate api web
docker compose -f "$COMPOSE_FILE" up -d --no-deps --build api web
```

If the failed upgrade applied migrations, restore the pre-upgrade backup first:

```bash
export COMPOSE_FILE=docker-compose.yml
export BACKUP_DIR="$PWD/backups/<pre-upgrade-timestamp>"

docker compose -f "$COMPOSE_FILE" stop api web migrate
# Follow the PostgreSQL and ClickHouse restore steps in backup-restore.md.
git checkout <previous-source-revision>
docker compose -f "$COMPOSE_FILE" build migrate api web
docker compose -f "$COMPOSE_FILE" run --rm migrate
docker compose -f "$COMPOSE_FILE" up -d api web
```

Do not try to manually delete migration rows or reverse schema changes in
place. Treat the backup as the downgrade boundary.

## Helm Upgrade

Render and review changes before applying:

```bash
helm upgrade --install ohmyrasp-control deploy/helm/ohmyrasp-control \
  -n ohmyrasp --create-namespace \
  --set api.image.tag=<target-api-tag> \
  --set web.image.tag=<target-web-tag> \
  --dry-run
```

Apply the upgrade:

```bash
helm upgrade --install ohmyrasp-control deploy/helm/ohmyrasp-control \
  -n ohmyrasp --create-namespace \
  --set api.image.tag=<target-api-tag> \
  --set web.image.tag=<target-web-tag> \
  --wait
```

The chart runs `ohmyrasp-migrate` as a pre-install/pre-upgrade hook when
`migrations.enabled=true`.

Verify rollout and health:

```bash
kubectl -n ohmyrasp rollout status deploy/ohmyrasp-api
kubectl -n ohmyrasp rollout status deploy/ohmyrasp-web
kubectl -n ohmyrasp get job ohmyrasp-migrate
```

Port-forward or use the ingress/service endpoint to check `/healthz`,
`/readyz`, the web root, login, and the primary navigation pages.

## Helm Downgrade

List release history:

```bash
helm -n ohmyrasp history ohmyrasp-control
```

If no migrations were applied, roll back the release:

```bash
helm -n ohmyrasp rollback ohmyrasp-control <revision> --wait
kubectl -n ohmyrasp rollout status deploy/ohmyrasp-api
kubectl -n ohmyrasp rollout status deploy/ohmyrasp-web
```

If migrations were applied:

1. Scale API and web to zero.
2. Restore the pre-upgrade PostgreSQL and ClickHouse backups.
3. Clear or restore Valkey.
4. Roll back the Helm release or reinstall the previous chart values and image
   tags.
5. Run the same health and login checks as an upgrade.

```bash
kubectl -n ohmyrasp scale deploy/ohmyrasp-api deploy/ohmyrasp-web --replicas=0
# Restore backing stores using backup-restore.md.
helm -n ohmyrasp rollback ohmyrasp-control <revision> --wait
```

## Post-Upgrade Monitoring

For the first 30 minutes after upgrade or downgrade, watch:

- API error rate and `/metrics`.
- PostgreSQL and ClickHouse connection errors.
- Migration job logs.
- Login success and audit-log creation.
- Agent heartbeat freshness and policy-pull latency.
- Event ingest volume and alert delivery queue growth.
