# Documentation

Current system documentation, operational runbooks, development ledgers, and generated coverage reports live here. Start with the entry relevant to your task and follow links to source files and symbols to verify implementation details.

## Start here

| Document | Description |
|---|---|
| [Getting Started](getting-started.md) | Prerequisites, local Docker Compose setup, toolchain installation, and first login. |

## Subsystem references

| Subsystem | Reference |
|---|---|
| Platform overview & data flow | [Architecture](architecture.md) |
| Runtime detection pipeline & limits | [Detection](detection.md) |
| Java agent (`java-agent/`), hooks & JDK tracks | [Agent](agent.md) |
| React control-plane frontend (`console/`) | [Console](console.md) |
| Go control-plane REST API (`api/`) | [API Reference](api-reference.md) |

## Operations

| Runbook | Description |
|---|---|
| [Backup and Restore](runbooks/backup-restore.md) | Backing up and restoring PostgreSQL and ClickHouse platform state. |
| [Helm Production](runbooks/helm-production.md) | Deploying the control plane to Kubernetes with the Helm chart. |
| [Observability](runbooks/observability.md) | Prometheus, Grafana, Alertmanager, and `/metrics` configuration. |
| [Release](runbooks/release.md) | Versioning, GHCR images, OCI Helm chart, and GitHub Release publishing. |
| [Shirudo Java Upatches](../deploy/shirudo/README.md) | Daemonless, ML-DSA-87-signed Java upatch packaging for shirudo targets. |
| [Upgrade and Downgrade](runbooks/upgrade-downgrade.md) | Upgrading or rolling back a running control-plane deployment. |

## Development ledgers

| Document | Description |
|---|---|
| [Development Guide](development/README.md) | How ledgers and derived agent coverage reports stay in sync. |
| [Algorithm Coverage](development/algorithm-coverage.md) | Durable detector ledger across JDK 25 and backport tracks. |
| [Vulhub Coverage](development/vulhub-coverage.md) | CVE-level baseline exploitation and protected-mode acceptance checklist. |

## Generated docs

Do not edit generated files by hand; regenerate them from source and verify with `--check`:

| Generated file | Generator script |
|---|---|
| [DETECTION-COVERAGE.md](../java-agent/docs/DETECTION-COVERAGE.md) | `python3 java-agent/scripts/gen-detection-coverage.py` |
| [HOOK-TARGETS.md](../java-agent/docs/HOOK-TARGETS.md) | `python3 java-agent/scripts/gen-hook-targets.py` |
| [FALSE-POSITIVE-REPORT.md](../java-agent/docs/FALSE-POSITIVE-REPORT.md) | `bash java-agent/scripts/run-fp-report.sh` |
| [Shirudo top-level README](../deploy/shirudo/README.md) & per-track READMEs (`ohmyrasp/README.md` and `ohmyrasp-{java8,java11,java17,jdk21,jdk25}/README.md`) | `python3 deploy/shirudo/gen-readmes.py` |

## Historical archive

| Document | Description |
|---|---|
| [Internal Archive](internal/README.md) | Initial-build audit and planning artifacts preserved for traceability (frozen; not current behavior). |

## Maintaining documentation

- **Single source of truth:** Keep each volatile fact (CLI flags, version numbers, ports, endpoints, hook counts) in one owning reference and link to it instead of duplicating lists across pages.
- **Link to symbols, not line numbers:** Reference source file paths and named types or functions so links survive routine edits.
- **Update in the same PR:** When a change alters a documented interface, flag, state transition, or operational contract, update the owning page in the same PR.
- **Regenerate derived docs:** Run the generator scripts above and verify `--check` passes rather than hand-editing generated Markdown.
- **Keep `docs/internal/` frozen:** Document current runtime behavior in `docs/` rather than modifying historical planning or audit files.
