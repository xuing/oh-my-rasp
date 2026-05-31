# Observability Runbook

This runbook covers the self-hosted OhMyRasp control-plane Prometheus alerts
and Grafana dashboard assets.

## Local Compose

Start the stack from the repository root:

```bash
docker compose -f docker-compose.yml up -d --build
```

Endpoints:

- API metrics: `http://localhost:18090/metrics`
- Prometheus: `http://localhost:19090`
- Alertmanager: `http://localhost:19093`
- Grafana: `http://localhost:13000`

Grafana is provisioned with an anonymous viewer and a Prometheus datasource.
The dashboard is loaded from:

```text
deploy/helm/ohmyrasp-control/files/grafana/ohmyrasp-control-dashboard.json
```

Prometheus loads alert rules from:

```text
deploy/helm/ohmyrasp-control/files/prometheus/ohmyrasp-control-rules.yml
```

Alertmanager loads local-safe routing and receiver templates from:

```text
deploy/helm/ohmyrasp-control/files/alertmanager/alertmanager.yml
deploy/helm/ohmyrasp-control/files/alertmanager/templates/ohmyrasp.tmpl
```

Validate the assets before changing them:

```bash
deploy/scripts/validate-observability-assets.sh
```

## Exported Metrics

The API exposes:

- `ohmyrasp_api_up`: API process health.
- `ohmyrasp_agents_total` and `ohmyrasp_agents_online`: Agent inventory.
- `ohmyrasp_agent_last_seen_timestamp_seconds`: latest heartbeat per Agent.
- `ohmyrasp_events_total`: accepted events by type and severity.
- `ohmyrasp_last_event_ingested_timestamp_seconds`: newest accepted event by
  type.
- `ohmyrasp_event_ingest_lag_seconds`: age of the newest accepted event by
  type.
- `ohmyrasp_policy_pull_latency_seconds`: Agent policy-pull latency histogram.
- `ohmyrasp_hook_latency_p95_seconds`: Hook execution latency p95.
- `ohmyrasp_rule_eval_latency_p95_seconds`: rule evaluation latency p95 by
  policy version.
- `ohmyrasp_agent_cpu_overhead_percent`: Agent overhead from performance
  telemetry.
- `ohmyrasp_metrics_scrape_error`: metrics collection failures by store source.

## Alerts

The included Prometheus rules cover:

- API down or missing scrape.
- Metrics scrape errors.
- No online Agents.
- Stale Agent heartbeats.
- Stale event ingest by event type.
- High policy-pull latency.
- Policy-pull errors.
- High Hook latency.
- High rule-evaluation latency.

Tune thresholds in `ohmyrasp-control-rules.yml` for the deployment's Agent
heartbeat interval, expected event volume, and latency budget.

## Alertmanager Routing

The Compose stack runs Alertmanager and Prometheus is configured to send alert
state to `alertmanager:9093`. The default local receivers use loopback webhook
URLs so the config is valid and safe to start without external notification
credentials.

For production receiver patterns, start from:

```text
deploy/helm/ohmyrasp-control/files/alertmanager/alertmanager.enterprise.example.yml
```

The enterprise example separates critical OhMyRasp control-plane alerts from
warnings, sends critical alerts to PagerDuty and Slack, sends warnings to
email, and mirrors all OhMyRasp alerts to a generic webhook. Replace placeholder
URLs, routing keys, SMTP credentials, channels, and email addresses with Secret
or external-secret references in the target Alertmanager deployment.

The bundled `ohmyrasp.tmpl` file defines reusable `ohmyrasp.title`,
`ohmyrasp.text`, and `ohmyrasp.html` templates for email, Slack, PagerDuty, and
webhook integrations.

## Helm

The Helm chart packages the same rules, dashboard, and optional Alertmanager
examples as ConfigMaps:

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

For Prometheus Operator, Grafana sidecar, or Alertmanager config-sync
deployments, set labels/annotations to match the cluster discovery convention.
For example:

```yaml
monitoring:
  prometheusRules:
    labels:
      prometheus: platform
  grafanaDashboard:
    labels:
      grafana_dashboard: "1"
  alertmanagerExamples:
    enabled: true
    labels:
      alertmanager_config: "1"
```

Render and validate:

```bash
deploy/scripts/validate-helm-manifests.sh
deploy/scripts/validate-observability-assets.sh
```
