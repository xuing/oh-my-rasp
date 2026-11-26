# Getting Started

This guide covers two ways to run OhMyRASP: downloading pre-built release artifacts or building and running the control plane and Java agents locally with Docker.

## 1. Prerequisites

### Option A: Pre-built releases

Download immutable release artifacts from [GitHub Releases](https://github.com/xuing/oh-my-rasp/releases). Each release ships the artifacts listed in the [Release Runbook](runbooks/release.md) (the universal and per-line standard Java agent JARs, the universal and per-line standalone shirudo upatch JARs and the bundle, the Rust host daemon tarball, the Helm chart archive, and checksums) plus GHCR container images (`ghcr.io/<namespace>/control-api:<version>`, `ghcr.io/<namespace>/control-web:<version>`) and an OCI Helm chart (`oci://ghcr.io/<namespace>/charts/ohmyrasp-control`).

Start with the universal agent JAR, `ohmyrasp-agent-all.jar`: it runs on Java 8 to 25 and starts the agent line that fits the JVM. To pin one line instead, pick the standard agent JAR that matches your JDK: `ohmyrasp-agent.jar` (JDK 25), `ohmyrasp-agent-jdk21.jar` (JDK 21), `ohmyrasp-agent-java17.jar` (JDK 17), `ohmyrasp-agent-java11.jar` (JDK 11), `ohmyrasp-agent-java8.jar` (JDK 8). For shirudo, install the universal upatch `ohmyrasp` (`ohmyrasp.jar`); the per-line shirudo upatch JARs follow the same pattern (`ohmyrasp-{jdk25,jdk21,java17,java11,java8}.jar`). Releases cut before the JDK 21 builds existed have no `jdk21` JARs; on JDK 21 use their `java17` JARs instead.

Verify checksums and GitHub provenance attestations after downloading:

```bash
VERSION="<version>"   # the release you downloaded, without the leading v
sha256sum -c SHA256SUMS.txt
gh attestation verify ohmyrasp-agent.jar -R xuing/oh-my-rasp
gh attestation verify "ohmyrasp-shirudo-upatches-${VERSION}.tar.gz" -R xuing/oh-my-rasp
gh attestation verify ohmyrasp-daemon-linux-amd64.tar.gz -R xuing/oh-my-rasp
gh attestation verify "ohmyrasp-control-${VERSION}.tgz" -R xuing/oh-my-rasp
```

See the [Release Runbook](runbooks/release.md) and [Helm Production Runbook](runbooks/helm-production.md) to deploy the published chart and images to Kubernetes.

### Option B: Docker-from-source path

Building and running the entire stack locally requires only:

- Docker 24+
- Docker Compose v2

No local JDK, Gradle, Go, Node.js, or Rust installation is required. The control-plane Compose file builds the Go API and the React console, and the agent builds, inside the builder images pinned in each component's `Dockerfile` (`api/`, `console/`, `java-agent/`).

### Local toolchain (development only)

Contributing to individual components directly on the host uses these versions (read them from the pin files):

| Tool | Required version | Source of truth / notes |
|---|---|---|
| Go | version pinned in `api/go.mod` | Builder image pinned in `api/Dockerfile`; set `GOTOOLCHAIN=auto` if the host Go is older |
| Node.js | range in `console/package.json` (`engines.node`) | Builder image pinned in `console/Dockerfile` |
| JDK | `25` | Full JDK with `javac`, not JRE only |
| Gradle | version of the image pinned in `java-agent/Dockerfile` | Gradle on JDK 25; distro packages (for example Ubuntu's) are too old |
| Rust / Cargo | toolchain pinned in `daemon/rust-toolchain.toml` | Edition 2024 (`daemon/Cargo.toml`) |

#### Installing Gradle locally (no sudo required)

Run from the repository root. The version comes from the Gradle image pinned in `java-agent/Dockerfile`, and the checksum is fetched from Gradle's own distribution server:

```bash
GRADLE_VERSION="$(awk '$1 == "FROM" && $2 ~ /^gradle:/ { sub(/^gradle:/, "", $2); sub(/-.*/, "", $2); print $2; exit }' java-agent/Dockerfile)"
GRADLE_URL="https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"
mkdir -p "$HOME/.local/opt" "$HOME/.local/bin"
curl -fsSL "$GRADLE_URL" -o "/tmp/gradle-${GRADLE_VERSION}-bin.zip" &&
  GRADLE_SHA256="$(curl -fsSL "${GRADLE_URL}.sha256")" &&
  printf '%s  %s\n' "$GRADLE_SHA256" "/tmp/gradle-${GRADLE_VERSION}-bin.zip" | sha256sum -c - &&
  unzip -q "/tmp/gradle-${GRADLE_VERSION}-bin.zip" -d "$HOME/.local/opt" &&
  ln -sfn "$HOME/.local/opt/gradle-${GRADLE_VERSION}/bin/gradle" "$HOME/.local/bin/gradle"
```

#### Installing JDK 25 locally (no sudo required)

If the host only has a JRE, Gradle fails with `Toolchain installation ... does not provide the required capabilities: [JAVA_COMPILER]`. Extract the JDK packages locally:

```bash
mkdir -p /tmp/ohmyrasp-jdk
cd /tmp/ohmyrasp-jdk
apt-get download openjdk-25-jdk-headless openjdk-25-jre-headless openjdk-25-jre
rm -rf "$HOME/.local/jdks/openjdk-25"
mkdir -p "$HOME/.local/jdks/openjdk-25"
for deb in *.deb; do
  dpkg-deb -x "$deb" "$HOME/.local/jdks/openjdk-25"
done
export JAVA_HOME="$HOME/.local/jdks/openjdk-25/usr/lib/jvm/java-25-openjdk-amd64"
export PATH="$HOME/.local/bin:$JAVA_HOME/bin:$PATH"
```

## 2. Start the Control Plane

### Configure environment

Create `.env` from the example file and fill every blank password field:

```bash
cp .env.example .env
```

Generate a URL-safe password for each blank field:

```bash
openssl rand -hex 18
```

> **Warning (slash in passwords):** `docker-compose.yml` interpolates passwords directly into `OHMYRASP_POSTGRES_DSN` and `OHMYRASP_CLICKHOUSE_DSN`. A password containing `/` causes the `migrate` container to fail at startup with a DSN parse error. Use hex output from `openssl rand -hex 18`.

Blank password fields required in `.env`:

```text
POSTGRES_PASSWORD=
CLICKHOUSE_PASSWORD=
VALKEY_PASSWORD=
GRAFANA_ADMIN_PASSWORD=
OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD=
```

Optional fields in `.env.example` include `OHMYRASP_BOOTSTRAP_APP_SECRET` and `OHMYRASP_METRICS_TOKEN` (when unset, `/metrics` is served unauthenticated and logs a startup warning).

### Start the stack

Existing Compose installations with PostgreSQL 18 data should complete the
[18 to 19 migration](runbooks/upgrade-downgrade.md#postgresql-18-to-19) before starting this version.

```bash
docker compose --env-file .env -f docker-compose.yml up -d --build
docker compose --env-file .env -f docker-compose.yml ps
```

The first build compiles `api`, `migrate`, and `web` from source and takes several minutes. Verify the API is healthy:

```bash
curl -fsS http://127.0.0.1:18090/healthz
```

### Service URLs

Ports come from `.env.example` and `docker-compose.yml`:

| Service | Default port | URL |
|---|---|---|
| Console (`web`) | `18091` (`WEB_PORT`) | `http://<host>:18091` |
| API (`api`) | `18090` (`API_PORT`) | `http://<host>:18090` |
| Grafana | `13000` (`GRAFANA_PORT`) | `http://<host>:13000` |
| Prometheus | `19090` (`PROMETHEUS_PORT`) | `http://<host>:19090` |
| Alertmanager | `19093` (`ALERTMANAGER_PORT`) | `http://<host>:19093` |
| ClickHouse HTTP | `18123` (`CLICKHOUSE_HTTP_PORT`) | `http://<host>:18123` |
| ClickHouse Native | `19000` (`CLICKHOUSE_NATIVE_PORT`) | `localhost:19000` |
| PostgreSQL | `15432` (`POSTGRES_PORT`) | `localhost:15432` |
| Valkey | `16379` (`VALKEY_PORT`) | `localhost:16379` |

### Default credentials

| Interface | Username | Password |
|---|---|---|
| Console | `admin@ohmyrasp.local` | value of `OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD` |
| Grafana | `admin` | value of `GRAFANA_ADMIN_PASSWORD` |

### Stop or reset the stack

```bash
# Stop and remove containers:
docker compose --env-file .env -f docker-compose.yml down

# Also remove volumes (clean slate):
docker compose --env-file .env -f docker-compose.yml down -v
```

## 3. Protect a Java Application

Skip the build commands below if you downloaded a pre-built JAR from GitHub Releases.

### Build the agent JAR

Run the build inside the Gradle Docker image pinned in `java-agent/Dockerfile`:

```bash
cd java-agent
GRADLE_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^gradle:/ { print $2; exit }' Dockerfile)"
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/tmp/gradle-home \
  -v "$PWD":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon :agent-all:agentAllJar
```

Output: `java-agent/agent-all/build/libs/ohmyrasp-agent-all.jar`, the universal JAR for any supported Java. For a JAR that holds only the Java 21 and later line, build `:agent-jdk25:agentJar` instead (`java-agent/agent-jdk25/build/libs/ohmyrasp-agent.jar`).

> **Note:** Always use the shaded fat JAR produced by `agentAllJar`, `agentJar` or `agentJava{8,11,17}Jar`. The thin JAR (`ohmyrasp-agent-thin.jar`) produced by the plain `jar` task lacks relocated ASM dependencies.

#### Backport agents (Java 8 / 11 / 17) and the JDK 21 JAR

Run these from `java-agent/` with `GRADLE_IMAGE` set as above.

```bash
# Java 8:
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/tmp/gradle-home \
  -v "$PWD":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon :agent-java8:agentJava8Jar
# Output: java-agent/agent-java8/build/libs/ohmyrasp-agent-java8.jar

# Java 11:
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/tmp/gradle-home \
  -v "$PWD":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon :agent-java11:agentJava11Jar
# Output: java-agent/agent-java11/build/libs/ohmyrasp-agent-java11.jar

# Java 17:
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/tmp/gradle-home \
  -v "$PWD":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon :agent-java17:agentJava17Jar
# Output: java-agent/agent-java17/build/libs/ohmyrasp-agent-java17.jar

# Java 21 (copies of the JDK 25 JARs under another name):
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/tmp/gradle-home \
  -v "$PWD":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon :agent-jdk25:jdk21Jars
# Output: java-agent/agent-jdk25/build/jdk21/ohmyrasp-agent-jdk21.jar
```

### Attach the agent: standalone mode

Standalone mode requires no control plane. The agent runs in `monitor` or `block` mode and writes NDJSON events locally:

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent-all.jar=mode=monitor \
     -Dohmyrasp.log=/var/log/ohmyrasp/events.jsonl \
     -jar your-app.jar
```

Switch mode at runtime without restarting the JVM by updating the polled control file (`/tmp/ohmyrasp-control.json` by default):

```bash
echo '{"mode":"block"}' > /tmp/ohmyrasp-control.json
```

### Attach the agent: daemonless shirudo mode

For immutable, daemonless deployments without `/tmp/ohmyrasp-control.json` or `/tmp/ohmyrasp-events.jsonl`, install the universal shirudo upatch `ohmyrasp` (`ohmyrasp.jar`, built by `:agent-all:shirudoUpatchJar`): every JVM on the host gets the line that fits its Java version. Hosts pinned to one Java version can use the per-line upatch JARs (`ohmyrasp-{java8,java11,java17,jdk21,jdk25}.jar`) built via `:agent-*:shirudoUpatchJar` (the `jdk21` copy comes from `:agent-jdk25:jdk21Jars`). They embed signed `META-INF/ohmyrasp-shirudo.properties` (`standalone=true`, `lock_config=true`, `mode=block`, `control=none`, `log=stderr`, `latency_sample=0`), start zero background threads, and install via `shirudo bpm install` or `-javaagent:/run/shirudo-java/<name>.jar`. See [Shirudo Java Upatches](../deploy/shirudo/README.md).

### Attach the agent: connected to the control plane

Create an application in the console (`http://<host>:18091` -> Applications) to obtain an `app_id`, `app_secret`, and `environment_id`. You can attach either through the [Rust Host Daemon](../daemon/README.md) (recommended for decoupling control-plane network I/O and offline buffering from the JVM) or pass credentials directly to the agent:

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=backend_url=http://127.0.0.1:18090,app_id=<app-id>,app_secret=<secret>,environment_id=<env-id>,mode=block \
     -jar your-app.jar
```

| `-javaagent` argument | Environment variable | System property |
|---|---|---|
| `backend_url` | `OHMYRASP_BACKEND_URL` | `-Dohmyrasp.backend_url` |
| `app_id` | `OHMYRASP_APP_ID` | `-Dohmyrasp.app_id` |
| `app_secret` | `OHMYRASP_APP_SECRET` | `-Dohmyrasp.app_secret` |
| `environment_id` | `OHMYRASP_ENVIRONMENT_ID` | `-Dohmyrasp.environment_id` |
| `mode` | `OHMYRASP_MODE` | `-Dohmyrasp.mode` |

## 4. See It Block an Attack

### Option A: Daemon demo

> **Port collision warning:** `java-agent/docker-compose.daemon.yml` binds the protected Tomcat app to port `18090` by default, which collides with the control-plane `api` port. If the control plane is running, set `OHMYRASP_DEMO_PORT` first:
>
> ```bash
> export OHMYRASP_DEMO_PORT=18095
> ```

Start the daemon demo (building the Rust daemon and Tomcat 11 playground images from source typically takes 1–2 minutes on first run):

```bash
cd java-agent
docker compose -f docker-compose.daemon.yml up -d --build --wait
```

`--wait` waits for Tomcat's `/rasp/health` healthcheck to pass before returning, and the demo starts `ohmyrasp-daemon` with `--default-mode=block` so a fresh volume enters blocking mode immediately (if you previously switched modes in the console, `down -v` resets the persisted `control.json`). This starts one agent-protected Tomcat 11 container and `ohmyrasp-daemon` sharing a volume for `events.jsonl` and `control.json`, with no control plane required.

| Endpoint | URL |
|---|---|
| Protected application | `http://localhost:${OHMYRASP_DEMO_PORT:-18090}` |
| Daemon console | `http://localhost:${OHMYRASP_DAEMON_CONSOLE_PORT:-7070}` |

Trigger a SQL injection attempt against `/rasp/sql`:

```bash
curl -i -G --data-urlencode "value=' OR '1'='1" \
  "http://localhost:${OHMYRASP_DEMO_PORT:-18090}/rasp/sql"
```

Expected result: `HTTP/1.1 302` with `Location: /rasp/blocked?hook=sql&algorithm=sql_userinput&...`. Inspect the logged `sql_userinput` block event from the daemon API or view it in a browser at `http://localhost:7070`:

```bash
curl -s "http://localhost:${OHMYRASP_DAEMON_CONSOLE_PORT:-7070}/api/events?limit=5"
```

### Option B: Full comparative playground

`java-agent/docker-compose.yml` starts three Tomcat version pairs (baseline without agent, and protected with the agent in `block` mode):

```bash
cd java-agent
docker compose up -d --build
```

| Tomcat version | Baseline | Protected |
|---|---|---|
| 9 | `http://localhost:18080/rasp/ui` | `http://localhost:18081/rasp/ui` |
| 10 | `http://localhost:18082/rasp/ui` | `http://localhost:18083/rasp/ui` |
| 11 | `http://localhost:18084/rasp/ui` | `http://localhost:18085/rasp/ui` |

`/rasp/ui` fires test cases across SQL injection, command injection, JNDI/Log4Shell, deserialization, XXE, file read/write, SSRF, Base64 AVX-512 tail-underflow, and expression injection (OGNL/SpEL/FreeMarker) covering the algorithm signatures asserted in the acceptance scripts listed in [DETECTION-COVERAGE.md](../java-agent/docs/DETECTION-COVERAGE.md).

### Option C: Automated acceptance script

```bash
cd java-agent
bash acceptance/runtime/jdk25.sh
```

This builds the agent and playground WARs (`playground` and `playground-javax`), starts all three Tomcat baseline/protected pairs, runs the attack suite, and verifies that protected ports redirect to `/rasp/blocked` and emit the expected NDJSON records while baselines do not.

## 5. Local Development Setup

Install console dependencies (Node.js range in `console/package.json` `engines.node`):

```bash
cd console
npm ci
```

Download Go module dependencies:

```bash
cd api
go mod download
```

If your host Go is older than the version in `api/go.mod`, add `GOTOOLCHAIN=auto` before running `go` commands so Go downloads the required toolchain automatically.

### Run tests

Backend (`api/`):

```bash
cd api
go generate ./...
go test ./...
```

Console (`console/`):

```bash
cd console
npm run build   # runs i18n:check, tsc -b, and vite build
npm test        # runs i18n:check, lint, typecheck, and test:e2e
```

Playwright end-to-end tests require Chromium (`npx playwright install chromium` on first run):

```bash
cd console
npx playwright install chromium
npm run test:e2e       # mocked API tests on http://127.0.0.1:5273
npm run test:e2e:live  # live Compose tests against http://127.0.0.1:18091
```

`test:e2e:live` reads admin credentials from `OHMYRASP_E2E_ADMIN_PASSWORD` / `OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD` (or the root `.env` file).

Java agent (`java-agent/`, requires `JAVA_HOME` pointing to JDK 25 and the Gradle version from Prerequisites):

```bash
cd java-agent
export JAVA_HOME="$HOME/.local/jdks/openjdk-25/usr/lib/jvm/java-25-openjdk-amd64"
export PATH="$HOME/.local/bin:$JAVA_HOME/bin:$PATH"
gradle test
```

Rust daemon (`daemon/`, uses the Rust toolchain pinned in `rust-toolchain.toml`):

```bash
cd daemon
cargo test
cargo clippy --all-targets
```

### Troubleshooting

- **PostgreSQL or ClickHouse migration fails at startup**: check that none of the `.env` passwords contain `/`. Regenerate with `openssl rand -hex 18`.
- **`gradle test` fails with `[JAVA_COMPILER]`**: the host has a JRE instead of a JDK. Set `JAVA_HOME` to a JDK 25 installation as shown in Prerequisites.
- **`gradle` not found or wrong version**: Ubuntu's packaged `gradle` is too old to build this project. Install the Gradle version from Prerequisites under `$HOME/.local` or use the Gradle image pinned in `java-agent/Dockerfile` via Docker.
- **`npm ci` fails after pulling changes**: ensure the active Node.js satisfies `engines.node` in `console/package.json` and re-run `npm ci` inside `console/`.
- **`oapi-codegen` warns about OpenAPI 3.1**: expected upstream warning during `go generate ./...`; it does not affect the generated bindings or build.
