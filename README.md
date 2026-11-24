# OhMyRASP

Self-hosted Java RASP built on ASM bytecode instrumentation, call-stack analysis, and request-parameter correlation. Runs inside the JVM across JDK 8, 11, 17, 21, and 25—either paired with a Rust host daemon and Go/React control plane, or standalone as signed [shirudo](https://github.com/shirudo-dev/shirudo) Java upatches.

[![CI](https://github.com/xuing/oh-my-rasp/actions/workflows/ohmyrasp-control.yml/badge.svg)](https://github.com/xuing/oh-my-rasp/actions/workflows/ohmyrasp-control.yml)
[![Release](https://img.shields.io/github/v/release/xuing/oh-my-rasp?include_prereleases)](https://github.com/xuing/oh-my-rasp/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Java agents](https://img.shields.io/badge/Java-8%20%7C%2011%20%7C%2017%20%7C%2025-ED8B00?logo=openjdk&logoColor=white)](java-agent/)
[![Exploit scenarios](https://img.shields.io/badge/exploit_scenarios-136_verified-success)](docs/development/vulhub-coverage.md)

**Languages:** English | [简体中文](README.zh-CN.md)

---

## See it block an attack in 60 seconds

Start Tomcat 11 with the agent in `block` mode and the Rust daemon's local console:

```bash
cd java-agent
docker compose -f docker-compose.daemon.yml up -d --build

# Send a SQL injection payload
curl -L "http://localhost:18090/rasp/sqli?id=1+OR+1=1"
# -> blocked mid-request and redirected to /rasp/blocked

# Live attack events, hook latency, and mode switching (off / monitor / block)
open http://localhost:7070
```

> The demo app uses port `18090`, which is also the control-plane API port. Set `OHMYRASP_DEMO_PORT` if you run both together.

For a side-by-side baseline vs. protected comparison across Tomcat 9, 10, and 11, see [docs/getting-started.md](docs/getting-started.md).

## By the numbers

Every hook, detector, and Vulhub replay script lives in this repository and runs in CI.

| Metric | Value | Source |
|---|---|---|
| Instrumented sink families | 28 ASM hook modules | [DETECTION-COVERAGE.md](java-agent/docs/DETECTION-COVERAGE.md) |
| Detection engine | 54 capabilities, 43 algorithm signatures asserted end-to-end | [docs/detection.md](docs/detection.md) |
| Exploit replay suite | 136 scenarios across 53 [Vulhub](https://github.com/vulhub/vulhub) roots (130 CVEs tracked) | [vulhub-coverage.md](docs/development/vulhub-coverage.md) |
| Benign corpus precision | `0 / 83` false positives across 14 categories | [FALSE-POSITIVE-REPORT.md](java-agent/docs/FALSE-POSITIVE-REPORT.md) |
| Supported JVMs | Builds for JDK 8, 11, 17, and a shared JDK 21/25 build (`javax.servlet` & `jakarta.servlet`) | [docs/agent.md](docs/agent.md) |

**Verified CVEs and exploit classes blocked:**
- **OpenJDK Base64 AVX-512 tail-underflow (Java2Shell / Java4Shell, CVE-2026-114938)** across JDK 8–25
- **JNDI & Deserialization:** Log4Shell (CVE-2021-44228), Fastjson `autoType` and [1.2.83 `getResourceAsStream`](https://github.com/midisec/fastjson-1.2.83-gadget-rce), Shiro `rememberMe` (CVE-2016-4437), ActiveMQ OpenWire (CVE-2023-46604), XStream, WebLogic XMLDecoder
- **Expression & Template RCE:** 19 Struts2 OGNL advisories (S2-001 through S2-067), Spring4Shell (CVE-2022-22965), Spring Cloud Gateway SpEL (CVE-2022-22947), GeoServer (CVE-2024-36401), DataEase (2024–2025)
- **Servlet, File & SQL:** Tomcat Ghostcat (CVE-2020-1938), Shiro/GlassFish/Jetty path confusion, standalone & driver-wide JDBC `Statement` SQLi

## How detection works

Rather than matching regexes on HTTP payloads at a proxy, OhMyRASP intercepts execution inside JDK sinks:

- **Request-parameter correlation:** Process execution and SQL sinks check whether suspect arguments trace back to live HTTP request parameters via `ThreadLocal<RequestContext>`, separating attacker input from scheduled internal jobs.
- **`StackWalker` call-stack classification:** At sinks such as `ProcessBuilder.start`, the agent inspects live stack frames to tell Struts2 OGNL, Spring SpEL, MVEL, Groovy, and XStream gadget chains apart from normal application calls.
- **Six-form path confusion decoding:** Incoming URIs are normalized simultaneously across raw, single-decoded, double-decoded, low-byte Unicode, overlong UTF-8, and lenient percent forms to catch traversal mismatches without per-framework rules.
- **Cryptographic token checks:** Default-secret JWTs are verified by real HMAC execution, and Shiro `rememberMe` cookies are decrypted under known default keys to check for Java serialization magic bytes.
- **Zero-allocation Java2Shell guard (CVE-2026-114938):** Instruments `java.util.Base64$Decoder.decode0` with a pure arithmetic boundary check (`length >= 65`, `1 <= (length & 63) <= 3`, `1 <= padding <= 2`, `padding <= remainder`, strict Base64 alphabet, `!isMIME`) before the native x86-64 AVX-512 stub can write out of bounds. Fires even outside HTTP requests and logs metadata only.
- **Fastjson 1.2.83 class-resource boundary:** Hooks `ClassLoader.getResourceAsStream` inside `ParserConfig.checkAutoType` to block remote (`http(s)://`, `jar:http(s)://`) and `jar:file:/proc/self/fd/` gadgets while keeping normal classpath and Spring Boot `jar:nested:` loads quiet.
- **Non-blocking hot path:** Findings queue asynchronously to a local NDJSON spool (`stderr` in shirudo standalone mode). Runtime mode switches (`off` / `monitor` / `block`) apply without restarting the JVM.

Full specification: [docs/detection.md](docs/detection.md).

## Shirudo Java Upatch Packages

OhMyRASP ships ready-to-sign **[shirudo](https://github.com/shirudo-dev/shirudo) Java upatch packages** in [`deploy/shirudo/`](deploy/shirudo/README.md) for targets managed by shirudo's pull-based, ML-DSA-87 signed, TPM2-measured deployment model.

| Package | Target JVMs | Upatch JAR | Gradle module |
|---|---|---|---|
| `ohmyrasp-java8` | Java 8 (classfile `<= 52`) | `ohmyrasp-java8.jar` | `:agent-java8` |
| `ohmyrasp-java11` | Java 11 (classfile `<= 55`) | `ohmyrasp-java11.jar` | `:agent-java11` |
| `ohmyrasp-java17` | Java 17 & Java 21 (classfile `<= 61`) | `ohmyrasp-java17.jar` | `:agent-java17` |
| `ohmyrasp-jdk25` | Java 21 & Java 25 (classfile `<= 65`) | `ohmyrasp-jdk25.jar` | `:agent-jdk25` |

Each shirudo JAR embeds `META-INF/ohmyrasp-shirudo.properties` (`standalone=true`, `lock_config=true`, `mode=block`, `control=none`, `log=stderr`, `latency_sample=0`):

- Starts **zero background threads** (no control-file poller, no spool writer).
- Ignores `/tmp/ohmyrasp-control.json` and hostile `OHMYRASP_MODE` / `OHMYRASP_CONTROL` overrides (`lock_config=true` is read strictly from the signed JAR).
- Emits structured JSON detections directly to `stderr` without creating `/tmp/ohmyrasp-events.jsonl` or `hook_latency` noise.

Build and sign all four `.bee` packages from source, or grab `ohmyrasp-shirudo-upatches-<version>.tar.gz` from [GitHub Releases](https://github.com/xuing/oh-my-rasp/releases):

```sh
# Build & sign all 4 .bee packages with your operator ML-DSA-87 keys
./deploy/shirudo/build-all.sh 0.2.0 --keys-dir <keys>

# Or build JARs only and run the real-JVM Temurin 8/11/17/21/25 smoke suite
./deploy/shirudo/build-all.sh --jar-only
./deploy/shirudo/verify-shirudo-upatch.sh
./deploy/shirudo/smoke-test.sh
```

See [deploy/shirudo/README.md](deploy/shirudo/README.md) for `shirudo bpm install`, Java 8 `JAVA_TOOL_OPTIONS` limits, container bind-mounts, and security boundaries.

## Quick Start

### Option A: Download pre-built artifacts

Pre-built agent JARs (both standard and shirudo standalone), `ohmyrasp-shirudo-upatches-<version>.tar.gz`, `ohmyrasp-daemon-linux-amd64.tar.gz`, `SHA256SUMS.txt`, and SLSA provenance attestations are published on [GitHub Releases](https://github.com/xuing/oh-my-rasp/releases).

### Option B: Build the agent locally (Docker only)

```bash
cd java-agent
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/tmp/gradle-home \
  -v "$PWD":/workspace -w /workspace gradle:9.9.2-jdk25 \
  gradle --no-daemon :agent-jdk25:agentJar
# -> agent-jdk25/build/libs/ohmyrasp-agent.jar
```

Use `:agent-java8:agentJava8Jar`, `:agent-java11:agentJava11Jar`, or `:agent-java17:agentJava17Jar` for earlier JDKs, or `:agent-*:shirudoUpatchJar` for daemonless shirudo builds.

### Attach to an application

Standalone (no control plane):

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=mode=monitor \
     -Dohmyrasp.log=/var/log/ohmyrasp/events.jsonl \
     -jar your-app.jar
```

With the full self-hosted control plane:

```bash
cp .env.example .env
# Fill empty secrets in .env (e.g. openssl rand -hex 18)
docker compose --env-file .env -f docker-compose.yml up -d --build
```

| Service | Default URL |
|---|---|
| Web console | `http://<host>:18091` |
| Control API | `http://<host>:18090` |
| Grafana / Prometheus / Alertmanager | `:13000` / `:19090` / `:19093` |
| ClickHouse HTTP | `http://<host>:18123` |

Sign in as `admin@ohmyrasp.local` with `OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD`, create an application to obtain `app_id` and `app_secret`, then start your JVM:

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=backend_url=http://<host>:18090,app_id=<app-id>,app_secret=<secret>,environment_id=<env-id>,mode=block \
     -jar your-app.jar
```

Full walkthrough: [docs/getting-started.md](docs/getting-started.md).

## Architecture

```text
                      ┌──────────────────────┐
                      │      Web Console     │
                      │    React 19 + Vite   │
                      └──────────┬───────────┘
                                 │
┌─────────────────┐   ┌──────────▼───────────┐   ┌─────────────────────┐
│   Host Daemon   │──►│      Control API     │◄──│  Prometheus rules   │
│      Rust       │   │     Go + OpenAPI     │   │  Alertmanager       │
└───▲─────────┬───┘   └───┬──────┬───────┬───┘   │  Grafana            │
    │ spool   │ control   │      │       │       └─────────────────────┘
    │ (NDJSON)│ file      ▼      ▼       ▼
┌───┴─────────▼───┐  PostgreSQL ClickHouse Valkey
│   Java Agent    │   control   telemetry  cache
│  ASM sink hooks │    state
└─────────────────┘
```

| Component | Stack | Role |
|---|---|---|
| `java-agent/` | Java 8/11/17/25, ASM 9.11.1 | In-JVM sink hooks, detection engine, NDJSON spool, shirudo standalone JARs |
| `daemon/` | Rust | Tails agent spools, forwards events, serves local live console, injects agents |
| `api/` | Go, OpenAPI 3.1 | RBAC, app/fleet inventory, policy rollout/canary/rollback, telemetry ingestion |
| `console/` | React 19, Vite | Fleet dashboards, threat triage, policy editor, latency & posture views (EN/中文/日本語) |
| `deploy/` | Helm, Compose, shirudo | Kubernetes Helm chart, observability assets, [shirudo Java upatch packages](deploy/shirudo/README.md) |

More detail: [docs/architecture.md](docs/architecture.md).

## Project status

OhMyRASP is pre-release software (`v0.2.0-alpha.1` experimental pre-release on [GitHub Releases](https://github.com/xuing/oh-my-rasp/releases)). APIs, policy schemas, and packaging may change between pre-releases. Do not rely on the JVM agent alone as a boundary against `root`; pair with kernel enforcement (such as shirudo BPF upatches) when host isolation is required.

## Development & Documentation

```bash
# Go control plane
docker run --rm -v "$PWD/api":/src -w /src golang:1.26.5 go test ./...

# Web console
cd console && npm ci && npm run build && npm test

# Java agent unit tests + 136-scenario Docker acceptance suite
cd java-agent && bash scripts/acceptance.sh

# Shirudo upatch Beefile/JAR checks + Temurin 8/11/17/21/25 smoke tests
./deploy/shirudo/build-all.sh --jar-only
./deploy/shirudo/verify-shirudo-upatch.sh
./deploy/shirudo/smoke-test.sh
```

- [Getting started](docs/getting-started.md) · [Architecture](docs/architecture.md) · [Detection engine](docs/detection.md)
- [Java agent](docs/agent.md) · [Shirudo upatch packages](deploy/shirudo/README.md) · [Console](docs/console.md) · [API reference](docs/api-reference.md)
- [Operations runbooks](docs/runbooks/) · [Algorithm coverage](docs/development/algorithm-coverage.md) · [Vulhub coverage](docs/development/vulhub-coverage.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) (detection bypasses are explicitly in scope)

## Acknowledgements

Built on [ASM](https://asm.ow2.io/) for bytecode instrumentation, informed by [OpenRASP](https://github.com/baidu/openrasp), validated against [Vulhub](https://github.com/vulhub/vulhub), and packaged for [shirudo](https://github.com/shirudo-dev/shirudo).

## License

Apache License 2.0. See [LICENSE](LICENSE).
