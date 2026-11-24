# Helm Production Install Runbook

This runbook covers installing the `ohmyrasp-control` Helm chart ([deploy/helm/ohmyrasp-control](../../deploy/helm/ohmyrasp-control)) into a Kubernetes cluster with existing PostgreSQL, ClickHouse, Valkey, ingress, and TLS infrastructure. The chart deploys `ohmyrasp-api`, `ohmyrasp-web`, the `ohmyrasp-migrate` pre-install/pre-upgrade hook Job, Services, optional Secret, optional PVC, and optional Ingress/NetworkPolicy/HPA/monitoring ConfigMaps.

## Backing Service Secret

Keep DSNs and Valkey credentials in a Kubernetes Secret in production. Either let the chart create it:

```yaml
secrets:
  create: true
  name: ohmyrasp-control-env
  data:
    postgresDsn: postgres://ohmyrasp:<password>@postgres.example:5432/ohmyrasp?sslmode=require
    clickhouseDsn: clickhouse://ohmyrasp:<password>@clickhouse.example:9000?database=ohmyrasp
    valkeyAddr: valkey.example:6379
    valkeyUsername: ohmyrasp
    valkeyPassword: <password>
```

Or reference an existing Secret:

```yaml
secrets:
  existingSecret: ohmyrasp-control-env
```

An existing Secret must provide these keys:

```text
OHMYRASP_POSTGRES_DSN
OHMYRASP_CLICKHOUSE_DSN
OHMYRASP_VALKEY_ADDR
OHMYRASP_VALKEY_USERNAME
OHMYRASP_VALKEY_PASSWORD
```

When `secrets.create=false` and `secrets.existingSecret=""`, the chart falls back to plain `api.env` values (for local rendering and non-sensitive development installs only).

## Agent Artifact Storage

The API serves uploaded (`ohmyrasp-agent-<language>-<system_type>-<language_version>.zip`) or pre-staged filesystem Java Agent ZIP packages from `OHMYRASP_AGENT_ARTIFACT_DIR` (`/var/lib/ohmyrasp/artifacts` by default; generated bootstrap ZIPs are not created by the API):

```yaml
api:
  artifacts:
    enabled: true
    mountPath: /var/lib/ohmyrasp/artifacts
```

Enable a PVC (`ohmyrasp-agent-artifacts`) so uploaded ZIPs survive pod replacement:

```yaml
api:
  artifacts:
    persistence:
      enabled: true
      storageClassName: fast-retain
      size: 20Gi
```

Or bind a pre-created claim:

```yaml
api:
  artifacts:
    persistence:
      enabled: true
      existingClaim: ohmyrasp-agent-artifacts
```

## Ingress and TLS

Enable ingress for `ohmyrasp-web`. The web nginx container proxies `/api/` to `ohmyrasp-api`, so one host serves both the console and API:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: rasp.example.com
      paths:
        - path: /
          pathType: Prefix
          serviceName: ohmyrasp-web
          servicePort: 80
  tls:
    - secretName: rasp-example-com-tls
      hosts:
        - rasp.example.com
```

If pulling from a private registry, configure `imagePullSecrets`:

```yaml
imagePullSecrets:
  - name: ghcr-pull
```

## Pod Hardening and Availability

The chart sets `runAsNonRoot: true`, `seccompProfile.type: RuntimeDefault`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, and `automountServiceAccountToken: false` by default. `ohmyrasp-web` listens on container port `8080` while Service `ohmyrasp-web` exposes port `80` (`web.writableRuntimeDirs.enabled=true` mounts `emptyDir` volumes at `/var/cache/nginx`, `/var/run`, and `/tmp`).

Set resource requests and limits before enabling autoscaling:

```yaml
api:
  resources:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: "1"
      memory: 1Gi
web:
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi
```

PodDisruptionBudgets (`minAvailable: 1`) are enabled by default for both `ohmyrasp-api` and `ohmyrasp-web`:

```yaml
podDisruptionBudgets:
  api:
    enabled: true
    minAvailable: 1
  web:
    enabled: true
    minAvailable: 1
```

Enable HPA when `metrics-server` is available:

```yaml
autoscaling:
  api:
    enabled: true
    minReplicas: 2
    maxReplicas: 6
    targetCPUUtilizationPercentage: 70
  web:
    enabled: true
    minReplicas: 2
    maxReplicas: 6
    targetCPUUtilizationPercentage: 70
```

Spread replicas across nodes with `topologySpreadConstraints`:

```yaml
api:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: ScheduleAnyway
      labelSelector:
        matchLabels:
          app.kubernetes.io/name: ohmyrasp-api
web:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: ScheduleAnyway
      labelSelector:
        matchLabels:
          app.kubernetes.io/name: ohmyrasp-web
```

`networkPolicy.enabled` defaults to `false` because ingress-controller and database peers vary by cluster. When enabling `networkPolicy.egress.enabled=true`, `templates/networkpolicy.yaml` always permits `ohmyrasp-web` egress to `ohmyrasp-api:8080` and applies `networkPolicy.egress.api.to` / `networkPolicy.egress.web.to`:

```yaml
networkPolicy:
  enabled: true
  ingress:
    web:
      from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
    api:
      from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: ohmyrasp-web
  egress:
    enabled: true
    api:
      to:
        - ipBlock:
            cidr: 10.0.0.0/8
    web:
      to: []
```

If a service mesh or workload identity controller requires a mounted token, set:

```yaml
serviceAccount:
  automountServiceAccountToken: true
```

## Monitoring Assets

The chart packages Prometheus alert rules (`ohmyrasp-prometheus-rules`), the Grafana dashboard (`ohmyrasp-grafana-dashboard`), and optional Alertmanager examples (`ohmyrasp-alertmanager-examples`) as ConfigMaps:

```yaml
monitoring:
  prometheusRules:
    enabled: true
    labels:
      prometheus: platform
  grafanaDashboard:
    enabled: true
    labels:
      grafana_dashboard: "1"
  alertmanagerExamples:
    enabled: true
    labels:
      alertmanager_config: "1"
```

Do not apply `alertmanager.enterprise.example.yml` directly in production without replacing placeholder webhooks, SMTP credentials, Slack URLs, and PagerDuty routing keys with managed Secrets.

## Render and Install

Render and inspect production manifests:

```bash
helm template ohmyrasp-control deploy/helm/ohmyrasp-control \
  -n ohmyrasp \
  -f values.production.yaml
```

Run the CI kubeconform validation across default, production, and hardened profiles:

```bash
deploy/scripts/validate-helm-manifests.sh
```

Install or upgrade from the local chart (or from `oci://ghcr.io/<namespace>/charts/ohmyrasp-control --version <version>`):

```bash
helm upgrade --install ohmyrasp-control deploy/helm/ohmyrasp-control \
  -n ohmyrasp --create-namespace \
  -f values.production.yaml \
  --wait
```

Verify rollout (`ohmyrasp-migrate` uses `before-hook-creation,hook-succeeded`, so Helm deletes the Job after it succeeds):

```bash
kubectl -n ohmyrasp rollout status deploy/ohmyrasp-api
kubectl -n ohmyrasp rollout status deploy/ohmyrasp-web
kubectl -n ohmyrasp get pods
```

Log in via the ingress hostname and verify Applications, Agents, Policies, Events, Observability, and Access & Audit.
