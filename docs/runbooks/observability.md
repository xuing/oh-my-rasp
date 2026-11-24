# Observability Runbook

This runbook covers the OhMyRASP control-plane Prometheus metrics, alert rules, Alertmanager routing templates, and Grafana dashboard.

## Local Compose

Start the stack from the repository root (`prom/prometheus:v3.16.0`, `prom/alertmanager:v0.35.0`, `grafana/grafana:13.3.1`):

```bash
docker compose -f docker-compose.yml up -d --build
```

Default local endpoints (ports configured in `.env` / `.env.example`):

- API metrics: `http://localhost:18090/metrics`
- Prometheus: `http://localhost:19090`
- Alertmanager: `http://localhost:19093`
- Grafana: `http://localhost:13000` (anonymous Viewer enabled; Prometheus datasource provisioned via `deploy/grafana/provisioning/`)

Asset paths:

- Prometheus scrape config: `deploy/prometheus/prometheus.yml` (scrapes `api:8080/metrics` every `15s`; if `OHMYRASP_METRICS_TOKEN` is set, configure bearer authentication in Prometheus)
- Prometheus alert rules: `deploy/helm/ohmyrasp-control/files/prometheus/ohmyrasp-control-rules.yml`
- Grafana dashboard (`uid: ohmyrasp-control`): `deploy/helm/ohmyrasp-control/files/grafana/ohmyrasp-control-dashboard.json`
- Alertmanager config and templates: `deploy/helm/ohmyrasp-control/files/alertmanager/alertmanager.yml`, `deploy/helm/ohmyrasp-control/files/alertmanager/templates/ohmyrasp.tmpl`

Validate all observability assets after edits:

```bash
deploy/scripts/validate-observability-assets.sh
```

## Exported Metrics

`GET /metrics` ([api/internal/httpapi/metrics.go](../../api/internal/httpapi/metrics.go)) exports:

- `ohmyrasp_api_up`: API process liveness gauge.
- `ohmyrasp_applications_total`: registered application count.
- `ohmyrasp_agents_total` and `ohmyrasp_agents_online`: registered and currently online Agent counts.
- `ohmyrasp_agent_last_seen_timestamp_seconds`: latest heartbeat Unix timestamp per Agent.
- `ohmyrasp_events_total`: accepted security events by `type` and `severity`.
- `ohmyrasp_last_event_ingested_timestamp_seconds`: newest accepted event timestamp by `type`.
- `ohmyrasp_event_ingest_lag_seconds`: age in seconds of the newest accepted event by `type`.
- `ohmyrasp_policy_pull_latency_seconds` (`_bucket`, `_sum`, `_count`): Agent policy-pull latency histogram by `status` (`success`, `error`).
- `ohmyrasp_hook_latency_p95_seconds`: hook execution p95 latency by `hook`.
- `ohmyrasp_rule_eval_latency_p95_seconds`: rule evaluation p95 latency by `policy_id` and `policy_version`.
- `ohmyrasp_agent_cpu_overhead_percent`: Agent CPU overhead percentage by `agent_id`.
- `ohmyrasp_event_outbox_undelivered`: PostgreSQL event outbox backlog awaiting ClickHouse delivery (emitted in PostgreSQL mode).
- `ohmyrasp_metrics_scrape_error`: per-source (`agents`, `overview`, `events`, `observability`, `event_outbox`) store query failure indicator.

Responses are cached in-memory for `OHMYRASP_METRICS_CACHE_TTL` (default `10s`) to bound store query load.

## Alerts

`deploy/helm/ohmyrasp-control/files/prometheus/ohmyrasp-control-rules.yml` defines nine alerts under group `ohmyrasp-control`:

- `OhMyRaspAPIDown` (`critical`): `absent(ohmyrasp_api_up) or ohmyrasp_api_up == 0` for `2m`.
- `OhMyRaspMetricsScrapeError` (`warning`): `max(ohmyrasp_metrics_scrape_error) > 0` for `5m`.
- `OhMyRaspNoOnlineAgents` (`critical`): `ohmyrasp_agents_total > 0 and ohmyrasp_agents_online == 0` for `5m`.
- `OhMyRaspAgentHeartbeatStale` (`warning`): latest heartbeat older than `300s` for `10m`.
- `OhMyRaspEventIngestStale` (`warning`): `max by (type) (ohmyrasp_event_ingest_lag_seconds) > 900` for `15m`.
- `OhMyRaspPolicyPullLatencyHigh` (`warning`): successful policy-pull p95 `> 1s` for `10m`.
- `OhMyRaspPolicyPullErrors` (`warning`): error rate on policy pulls `> 0` for `5m`.
- `OhMyRaspHookLatencyHigh` (`warning`): `max by (hook) (ohmyrasp_hook_latency_p95_seconds) > 0.25` for `10m`.
- `OhMyRaspRuleEvalLatencyHigh` (`warning`): `max by (policy_id, policy_version) (ohmyrasp_rule_eval_latency_p95_seconds) > 0.1` for `10m`.

Tune thresholds in `ohmyrasp-control-rules.yml` to match your Agent heartbeat interval, event volume, and latency budget.

## Alertmanager Routing

Prometheus routes alerts to `alertmanager:9093`. The local `alertmanager.yml` targets loopback webhook URLs (`http://127.0.0.1:9/ohmyrasp/{critical,warning}`) so Compose starts safely without external credentials.

For production receiver configuration, adapt:

```text
deploy/helm/ohmyrasp-control/files/alertmanager/alertmanager.enterprise.example.yml
```

The enterprise example routes `critical` alerts to PagerDuty and Slack, `warning` alerts to email, inhibits `warning` when `critical` fires for the same `alertname`, and mirrors all `service="ohmyrasp-control"` alerts to a generic webhook. Replace placeholder URLs, routing keys, SMTP credentials, channels, and addresses with managed Secrets. `ohmyrasp.tmpl` defines `ohmyrasp.title`, `ohmyrasp.text`, and `ohmyrasp.html`.

## Helm

The chart exposes ConfigMaps for the rules, dashboard, and optional Alertmanager examples:

```yaml
monitoring:
  prometheusRules:
    enabled: true
    labels: {}
    annotations: {}
  grafanaDashboard:
    enabled: true
    labels:
      grafana_dashboard: "1"
    annotations: {}
  alertmanagerExamples:
    enabled: false
    labels: {}
    annotations: {}
```

Set labels and annotations to match your Prometheus Operator or Grafana sidecar discovery rules, then validate:

```bash
deploy/scripts/validate-helm-manifests.sh
deploy/scripts/validate-observability-assets.sh
```
