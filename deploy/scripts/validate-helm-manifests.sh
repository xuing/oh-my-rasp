#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
chart="deploy/helm/ohmyrasp-control"
tool_image_resolver="${repo_root}/deploy/scripts/resolve-tool-image.sh"
helm_image="${HELM_IMAGE:-$("$tool_image_resolver" helm)}"
kubeconform_image="${KUBECONFORM_IMAGE:-$("$tool_image_resolver" kubeconform)}"
kubernetes_schema_image="$("$tool_image_resolver" kubernetes-schema)"
kubernetes_schema_tag="${kubernetes_schema_image##*:}"
kubernetes_version="${KUBERNETES_VERSION:-${kubernetes_schema_tag#v}}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

render() {
  local output="$1"
  shift
  docker run --rm \
    -v "$repo_root":/src \
    -w /src \
    "$helm_image" template ohmyrasp-control "$chart" "$@" > "$output"
}

validate() {
  local label="$1"
  local manifest="$2"
  echo "Validating ${label} manifests"
  docker run --rm \
    -v "$tmp_dir":/work \
    "$kubeconform_image" \
    -strict \
    -summary \
    -kubernetes-version "$kubernetes_version" \
    "/work/$(basename "$manifest")"
}

render "$tmp_dir/default.yaml"
validate default "$tmp_dir/default.yaml"

render "$tmp_dir/production.yaml" \
  --set secrets.create=true \
  --set secrets.data.postgresDsn='postgres://prod:secret@postgres.example:5432/ohmyrasp?sslmode=require' \
  --set secrets.data.clickhouseDsn='clickhouse://prod:secret@clickhouse.example:9000?database=ohmyrasp' \
  --set secrets.data.valkeyAddr='valkey.example:6379' \
  --set api.artifacts.persistence.enabled=true \
  --set monitoring.alertmanagerExamples.enabled=true \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set ingress.hosts[0].host=rasp.example.com \
  --set ingress.tls[0].secretName=rasp-example-com-tls \
  --set ingress.tls[0].hosts[0]=rasp.example.com
validate production "$tmp_dir/production.yaml"

render "$tmp_dir/hardened.yaml" \
  --set networkPolicy.enabled=true \
  --set networkPolicy.egress.enabled=true \
  --set autoscaling.api.enabled=true \
  --set autoscaling.web.enabled=true \
  --set api.topologySpreadConstraints[0].maxSkew=1 \
  --set api.topologySpreadConstraints[0].topologyKey=kubernetes.io/hostname \
  --set api.topologySpreadConstraints[0].whenUnsatisfiable=ScheduleAnyway \
  --set api.topologySpreadConstraints[0].labelSelector.matchLabels.app\\.kubernetes\\.io/name=ohmyrasp-api \
  --set web.topologySpreadConstraints[0].maxSkew=1 \
  --set web.topologySpreadConstraints[0].topologyKey=kubernetes.io/hostname \
  --set web.topologySpreadConstraints[0].whenUnsatisfiable=ScheduleAnyway \
  --set web.topologySpreadConstraints[0].labelSelector.matchLabels.app\\.kubernetes\\.io/name=ohmyrasp-web
validate hardened "$tmp_dir/hardened.yaml"
