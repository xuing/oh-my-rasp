# Documentation

## Start here

| Document | Description |
|---|---|
| [Getting Started](getting-started.md) | Prerequisites, local setup with Docker Compose, and first login. |

## Concepts

| Document | Description |
|---|---|
| [Architecture](architecture.md) | System components, data flow, and design decisions. |
| [Detection](detection.md) | How the agent detects and classifies attacks at runtime. |

## Components

| Document | Description |
|---|---|
| [Agent](agent.md) | Java agent internals — hooks, policy evaluation, and the four runtime era builds. |
| [Console](console.md) | React 19 control-plane frontend — screens, dev setup, and build verification. |
| [API Reference](api-reference.md) | REST API endpoints exposed by the Go control plane. |

## Operations

| Document | Description |
|---|---|
| [Backup and Restore](runbooks/backup-restore.md) | Procedures for backing up and restoring platform data. |
| [Helm Production](runbooks/helm-production.md) | Deploying to Kubernetes with the production Helm chart. |
| [Observability](runbooks/observability.md) | Configuring metrics, tracing, and alerting for the platform itself. |
| [Release](runbooks/release.md) | Release checklist and artifact publishing steps. |
| [Upgrade and Downgrade](runbooks/upgrade-downgrade.md) | Upgrading or rolling back the platform in a running environment. |

## Development

| Document | Description |
|---|---|
| [Algorithm Coverage](development/algorithm-coverage.md) | Detector ledger — must be updated whenever detectors are added or changed. |
| [Vulhub Coverage](development/vulhub-coverage.md) | Vulhub replay checklist — tracks CVE-level baseline and protected-side acceptance. |

## Historical

| Document | Description |
|---|---|
| [Internal/](internal/README.md) | Audit and planning artifacts from the initial build phase, preserved for traceability. |
