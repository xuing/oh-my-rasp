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

## PostgreSQL 18 to 19

New Compose installations initialize PostgreSQL 19 on first start. For an
existing PostgreSQL 18 deployment, use a maintenance window to restore the
control-plane database onto a fresh volume. These steps assume the single
database and role created by the standard Compose stack. Provision any custom
roles, databases, or extensions on the target as part of your migration.

1. On the deployed 18 revision, keep the same Compose project and `.env`.
   Pause external writers and stop the application. Run the following in one
   Bash session. The backup directory is private to the current user.

   ```bash
   set -euo pipefail
   backup_dir=$(mktemp -d "$HOME/ohmyrasp-pg18-XXXXXXXX")
   old_volume=$(docker inspect "$(docker compose ps -q postgres)" \
     --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql"}}{{.Name}}{{end}}{{end}}')
   test -n "$old_volume"
   git rev-parse HEAD > "$backup_dir/source-revision"
   printf '%s\n' "$old_volume" > "$backup_dir/source-volume"

   docker compose stop web api migrate
   pg() {
     docker compose exec -T postgres sh -ec 'exec "$@" -U "$POSTGRES_USER" -d "$POSTGRES_DB"' sh "$@"
   }
   counts='SELECT (SELECT count(*) FROM schema_migrations), (SELECT count(*) FROM users), (SELECT count(*) FROM applications), (SELECT count(*) FROM policies)'
   pg psql -XAt -v ON_ERROR_STOP=1 -c "$counts" > "$backup_dir/before.counts"
   pg pg_dump --format=custom --no-owner > "$backup_dir/postgres.dump"
   docker compose exec -T postgres pg_restore --list < "$backup_dir/postgres.dump" > /dev/null
   docker compose stop postgres
   ```

2. Check out the target revision containing PostgreSQL 19. Preserve the project
   name and credentials. Start only PostgreSQL and restore the dump. The new
   volume name includes the unique backup directory suffix.

   ```bash
   export POSTGRES_VOLUME_NAME="${old_volume}-19-${backup_dir##*-}"
   docker compose up -d --no-deps --wait postgres
   pg psql -XAt -c 'SHOW server_version'
   pg pg_restore --no-owner --exit-on-error --single-transaction < "$backup_dir/postgres.dump"
   pg psql -XAt -v ON_ERROR_STOP=1 -c "$counts" > "$backup_dir/after.counts"
   diff -u "$backup_dir/before.counts" "$backup_dir/after.counts"
   printf 'POSTGRES_VOLUME_NAME=%s\n' "$POSTGRES_VOLUME_NAME"
   ```

3. Save the printed `POSTGRES_VOLUME_NAME` setting in the deployment's `.env`
   for subsequent Compose invocations. Start the stack with
   `docker compose up -d --build`, check `/readyz`, and verify the expected
   applications and policies before reopening traffic. Keep the 18 volume and
   dump through the rollback window.

If validation fails before writes resume, stop the new services, check out
the revision recorded in `source-revision`, and restore the original volume
setting in `.env` and the shell. Run `docker compose up -d --build` with the
original 18 volume. After 19 accepts writes, reconcile those writes before
rolling back to the 18 snapshot.

## Docker Compose Upgrade

When upgrading from PostgreSQL 18, complete the [database migration](#postgresql-18-to-19) first.
For routine application upgrades, run from the repository root after checking out the target revision:

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
