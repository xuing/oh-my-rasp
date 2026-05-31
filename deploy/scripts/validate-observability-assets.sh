#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
prometheus_image="${PROMETHEUS_IMAGE:-prom/prometheus:latest}"
alertmanager_image="${ALERTMANAGER_IMAGE:-prom/alertmanager:latest}"

docker run --rm --entrypoint promtool \
  -v "$repo_root/deploy/prometheus/prometheus.yml":/etc/prometheus/prometheus.yml:ro \
  -v "$repo_root/deploy/helm/ohmyrasp-control/files/prometheus":/etc/prometheus/rules:ro \
  "$prometheus_image" check config /etc/prometheus/prometheus.yml

docker run --rm --entrypoint promtool \
  -v "$repo_root/deploy/helm/ohmyrasp-control/files/prometheus":/rules:ro \
  "$prometheus_image" check rules /rules/ohmyrasp-control-rules.yml

docker run --rm --entrypoint amtool \
  -v "$repo_root/deploy/helm/ohmyrasp-control/files/alertmanager":/etc/alertmanager:ro \
  "$alertmanager_image" check-config /etc/alertmanager/alertmanager.yml

docker run --rm --entrypoint amtool \
  -v "$repo_root/deploy/helm/ohmyrasp-control/files/alertmanager":/etc/alertmanager:ro \
  "$alertmanager_image" check-config /etc/alertmanager/alertmanager.enterprise.example.yml

python3 - "$repo_root" <<'PY'
import json
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
dashboard = repo_root / "deploy" / "helm" / "ohmyrasp-control" / "files" / "grafana" / "ohmyrasp-control-dashboard.json"
with dashboard.open(encoding="utf-8") as handle:
    parsed = json.load(handle)

if parsed.get("uid") != "ohmyrasp-control":
    raise SystemExit("unexpected Grafana dashboard uid")
if not parsed.get("panels"):
    raise SystemExit("Grafana dashboard has no panels")

for path in [
    repo_root / "deploy" / "grafana" / "provisioning" / "datasources" / "prometheus.yml",
    repo_root / "deploy" / "grafana" / "provisioning" / "dashboards" / "ohmyrasp.yml",
    repo_root / "deploy" / "helm" / "ohmyrasp-control" / "files" / "alertmanager" / "templates" / "ohmyrasp.tmpl",
]:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise SystemExit(f"{path} is empty")

print("observability assets valid")
PY
