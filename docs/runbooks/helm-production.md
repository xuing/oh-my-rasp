# Helm Production Install Runbook

This runbook covers installing the OhMyRasp control plane chart into a cluster
that already has PostgreSQL, ClickHouse, Valkey, ingress, and TLS available.
The chart deploys only the API, web console, migration Job, Services, optional
Secret, and optional Ingress.

## Backing Service Secret

For production, keep DSNs and Valkey credentials in a Kubernetes Secret. Either
let the chart create it:

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

An existing Secret must contain these keys:

```text
OHMYRASP_POSTGRES_DSN
OHMYRASP_CLICKHOUSE_DSN
OHMYRASP_VALKEY_ADDR
OHMYRASP_VALKEY_USERNAME
OHMYRASP_VALKEY_PASSWORD
```

When `secrets.create=false` and `secrets.existingSecret=""`, the chart uses the
plain values under `api.env`. That mode is intended for local rendering and
non-sensitive development installs.

## Agent Artifact Storage

The API serves generated bootstrap Agent ZIPs by default and can also store
operator-uploaded Java Agent ZIPs. The chart mounts a writable artifact
directory at `/var/lib/ohmyrasp/artifacts`:

```yaml
api:
  artifacts:
    enabled: true
    mountPath: /var/lib/ohmyrasp/artifacts
```

Use a PVC for production uploads that must survive pod replacement:

```yaml
api:
  artifacts:
    persistence:
      enabled: true
      storageClassName: fast-retain
      size: 20Gi
```

To use a pre-created claim:

```yaml
api:
  artifacts:
    persistence:
      enabled: true
      existingClaim: ohmyrasp-agent-artifacts
```

## Ingress And TLS

Enable ingress for the web service. The web container proxies `/api/` to the API
Service, so a single host can serve both the console and API routes.

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

If the image packages are private, configure pull secrets:

```yaml
imagePullSecrets:
  - name: ghcr-pull
```

## Pod Hardening And Availability

The chart defaults to a non-root pod security context, drops Linux
capabilities, disables service-account token automount, and uses a read-only
root filesystem. The web container listens on port `8080` internally while the
Service keeps the public service port at `80`.

Use resource requests and limits before enabling autoscaling:

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

The chart creates PodDisruptionBudgets for the API and web deployments by
default:

```yaml
podDisruptionBudgets:
  api:
    enabled: true
    minAvailable: 1
  web:
    enabled: true
    minAvailable: 1
```

Enable HPA only when the cluster has metrics-server or an equivalent metrics
pipeline:

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

Use affinity or topology spread constraints to keep replicas apart:

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

NetworkPolicies are available but disabled by default because external
PostgreSQL, ClickHouse, Valkey, DNS, and ingress-controller selectors differ by
cluster. Enable them only after adding the required egress and ingress peers:

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

If an enterprise baseline injects a service mesh sidecar or requires projected
service-account tokens, override:

```yaml
serviceAccount:
  automountServiceAccountToken: true
```

## Monitoring Assets

The chart can package Prometheus rules, the Grafana dashboard, and optional
Alertmanager routing examples as ConfigMaps for clusters that use sidecar or
config-sync discovery:

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

Do not install the enterprise Alertmanager example as-is with real traffic.
Copy it into the platform Alertmanager workflow and replace placeholder
webhooks, SMTP credentials, Slack URLs, and PagerDuty routing keys with managed
Secrets.

## Render And Install

Render production values before applying:

```bash
helm template ohmyrasp-control deploy/helm/ohmyrasp-control \
  -n ohmyrasp \
  -f values.production.yaml
```

Validate the default, production-style, and hardened render paths with the same
kubeconform gate used by CI:

```bash
deploy/scripts/validate-helm-manifests.sh
```

Install or upgrade:

```bash
helm upgrade --install ohmyrasp-control deploy/helm/ohmyrasp-control \
  -n ohmyrasp --create-namespace \
  -f values.production.yaml \
  --wait
```

Verify rollout:

```bash
kubectl -n ohmyrasp rollout status deploy/ohmyrasp-api
kubectl -n ohmyrasp rollout status deploy/ohmyrasp-web
kubectl -n ohmyrasp get job ohmyrasp-migrate
```

Then use the ingress hostname to log in and navigate Applications, Agents,
Policies, Events, Observability, and Access & Audit.
