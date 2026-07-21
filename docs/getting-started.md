# Getting Started

This guide takes you from zero to a protected Java application in four
steps: start the control plane, build the agent, attach it, and watch
an attack get blocked.

---

## 1. Prerequisites

### Docker-only path (recommended)

Running everything — including building the agent jars — requires only:

- Docker 24+
- Docker Compose v2

There is no need for a local JDK or Gradle installation. The agent build
uses the `gradle:9.6.1-jdk25` Docker image, and the entire control plane builds
locally from source via `docker compose`.

### Local toolchain (development only)

Contributing to the project requires the following verified toolchain:

| Tool | Required version | Notes |
|------|-----------------|-------|
| Go | 1.26 | Go 1.25 + `GOTOOLCHAIN=auto` also works |
| Node.js | 26 | Use the npm bundled with the current Node.js 26 release |
| JDK | 25 | JDK, not just JRE — `javac` must be present |
| Gradle | 9.6.1+ | Ubuntu's packaged `gradle` (4.4.1) is too old |
| Rust / Cargo | 1.97.1 | Pinned by `daemon/rust-toolchain.toml` |

#### Installing Gradle locally (no sudo required)

```bash
mkdir -p "$HOME/.local/opt" "$HOME/.local/bin"
curl -fsSL https://services.gradle.org/distributions/gradle-9.6.1-bin.zip \
  -o /tmp/gradle-9.6.1-bin.zip
printf '%s  %s\n' \
  '9c0f7faeeb306cb14e4279a3e084ca6b596894089a0638e68a07c945a32c9e14' \
  '/tmp/gradle-9.6.1-bin.zip' | sha256sum -c -
unzip -q /tmp/gradle-9.6.1-bin.zip -d "$HOME/.local/opt"
ln -sfn "$HOME/.local/opt/gradle-9.6.1/bin/gradle" "$HOME/.local/bin/gradle"
```

#### Installing JDK 25 locally (no sudo required)

If the host only has a Java 25 JRE, Gradle will fail with
`Toolchain installation ... does not provide the required capabilities:
[JAVA_COMPILER]`. Extract the JDK packages locally:

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

#### Known toolchain issues

- Host Go `1.25.x` — add `GOTOOLCHAIN=auto` to your shell; `go mod
  download` will fetch a compatible Go 1.26 toolchain automatically.
- A generated password containing `/` breaks the PostgreSQL DSN during the
  compose migration step. Always use URL-safe passwords (see the next
  section).
- `go generate ./...` completes successfully; `oapi-codegen` warns that
  OpenAPI 3.1 is not fully supported — this is a known upstream limitation
  and does not affect the build.
- `npm ci` is required (not `npm install`) after dependency changes; the
  lockfile must stay in sync.
- Playwright 1.61.1 does not support the native `ubuntu26.04-x64` download
  target. The `e2e:install`, `e2e`, and `e2e:live` scripts set
  `PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64` automatically,
  matching the upstream workaround for Microsoft Playwright issue #40117.

---

## 2. Start the Control Plane

### Configure environment

Create `.env` from the example and fill every empty password field:

```bash
cp .env.example .env
```

Generate a URL-safe password for each blank field:

```bash
openssl rand -hex 18
```

> **Warning — slash in passwords:** The compose file interpolates
> passwords directly into PostgreSQL DSNs. A password containing `/`
> will cause the migration container to fail at startup with a DSN parse
> error. Use hex output from `openssl rand -hex 18`, which is always
> slash-free.

Required fields in `.env`:

```text
POSTGRES_PASSWORD=
CLICKHOUSE_PASSWORD=
VALKEY_PASSWORD=
GRAFANA_ADMIN_PASSWORD=
OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD=
```

### Start the stack

```bash
docker compose --env-file .env -f docker-compose.yml up -d --build
docker compose --env-file .env -f docker-compose.yml ps
```

All services are built from source; there are no pre-built images. The
first build takes several minutes.

Verify the API is up:

```bash
curl -fsS http://127.0.0.1:18090/healthz
```

### Service URLs

| Service | Default port | URL |
|---------|-------------|-----|
| Console | 18091 | `http://<host>:18091` |
| API | 18090 | `http://<host>:18090` |
| Grafana | 13000 | `http://<host>:13000` |
| Prometheus | 19090 | `http://<host>:19090` |
| Alertmanager | 19093 | `http://<host>:19093` |
| ClickHouse HTTP | 18123 | `http://<host>:18123` |

### Default credentials

| Interface | Username | Password |
|-----------|----------|----------|
| Console | `admin@ohmyrasp.local` | value of `OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD` |
| Grafana | `admin` | value of `GRAFANA_ADMIN_PASSWORD` |

### Stop or reset the stack

```bash
# Stop and remove containers:
docker compose --env-file .env -f docker-compose.yml down

# Also remove volumes (clean slate):
docker compose --env-file .env -f docker-compose.yml down -v
```

---

## 3. Protect a Java Application

### Build the agent jar

No local JDK or Gradle is required. The build runs entirely inside the
`gradle:9.6.1-jdk25` Docker image:

```bash
cd java-agent
docker run --rm -v "$PWD":/workspace -w /workspace gradle:9.6.1-jdk25 \
  gradle --no-daemon :agent-jdk25:agentJar
```

Output: `java-agent/agent-jdk25/build/libs/ohmyrasp-agent.jar`

> **Note:** The Gradle task is named `agentJar`. The thin jar
> (`ohmyrasp-agent-thin.jar`) produced by the plain `jar` task is not
> the usable agent — always use the fat jar produced by `agentJar`.

#### Backport agents (Java 8 / 11 / 17)

For applications running on older JVMs, build the corresponding backport
jar. The task names differ from the primary agent:

```bash
# Java 8 backport:
docker run --rm -v "$PWD":/workspace -w /workspace gradle:9.6.1-jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar
# Output: java-agent/agent-java8/build/libs/ohmyrasp-agent-java8.jar

# Java 11 backport:
docker run --rm -v "$PWD":/workspace -w /workspace gradle:9.6.1-jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar
# Output: java-agent/agent-java11/build/libs/ohmyrasp-agent-java11.jar

# Java 17 backport:
docker run --rm -v "$PWD":/workspace -w /workspace gradle:9.6.1-jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar
# Output: java-agent/agent-java17/build/libs/ohmyrasp-agent-java17.jar
```

### Attach the agent — standalone mode

Standalone mode requires no control plane. The agent runs in `monitor`
or `block` mode and writes events to a local NDJSON log file:

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=mode=monitor \
     -Dohmyrasp.log=/var/log/ohmyrasp/events.jsonl \
     -jar your-app.jar
```

Switch mode at runtime without restarting the application:

```bash
echo '{"mode":"block"}' > /tmp/ohmyrasp-control.json
```

### Attach the agent — connected to the control plane

Before attaching, create an application in the console
(`http://<host>:18091` → Applications → New Application) to obtain an
`app_id` and `app_secret`.

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=backend_url=http://127.0.0.1:18090,app_id=<app-id>,app_secret=<secret>,environment_id=<env-id>,mode=block \
     -jar your-app.jar
```

Configuration can also be supplied via environment variables or system
properties:

| `javaagent` argument | Environment variable | System property |
|----------------------|---------------------|-----------------|
| `backend_url` | `OHMYRASP_BACKEND_URL` | `-Dohmyrasp.backend_url` |
| `app_id` | `OHMYRASP_APP_ID` | `-Dohmyrasp.app_id` |
| `app_secret` | `OHMYRASP_APP_SECRET` | `-Dohmyrasp.app_secret` |
| `environment_id` | `OHMYRASP_ENVIRONMENT_ID` | `-Dohmyrasp.environment_id` |
| `mode` | `OHMYRASP_MODE` | `-Dohmyrasp.mode` |

---

## 4. See It Block an Attack

### Option A — Daemon demo (quickest, single command)

> **Port collision warning:** The daemon demo binds to port `18090` by
> default, which is the same port as the control-plane API. If you have
> the control plane running, set `OHMYRASP_DEMO_PORT` before starting
> the demo:
>
> ```bash
> export OHMYRASP_DEMO_PORT=18095
> ```

Start the demo:

```bash
cd java-agent
docker compose -f docker-compose.daemon.yml up -d --build
```

This starts one agent-protected Tomcat 11 and the Rust host daemon. They
share a volume for the event spool and control file. No control plane is
required.

| Endpoint | URL |
|----------|-----|
| Protected application | `http://localhost:${OHMYRASP_DEMO_PORT:-18090}` |
| Daemon console | `http://localhost:7070` |

Trigger a SQL injection attempt:

```bash
curl -s "http://localhost:${OHMYRASP_DEMO_PORT:-18090}/rasp/sqli?id=1+OR+1=1" -L
```

Expected result: the agent blocks the request and redirects to
`/rasp/blocked`. The daemon console at `http://localhost:7070` shows the
event in the live attack log along with hook latency percentiles.

### Option B — Full comparative playground

The full playground starts three Tomcat version pairs (each version run
once unprotected as a baseline and once with the agent):

```bash
cd java-agent
docker compose up -d --build
```

| Tomcat version | Baseline | Protected |
|----------------|----------|-----------|
| 9 | `http://localhost:18080/rasp/ui` | `http://localhost:18081/rasp/ui` |
| 10 | `http://localhost:18082/rasp/ui` | `http://localhost:18083/rasp/ui` |
| 11 | `http://localhost:18084/rasp/ui` | `http://localhost:18085/rasp/ui` |

The `/rasp/ui` page is an interactive comparative runner. It fires the
full test case set against any baseline/protected pair. Attack categories
covered include SQL injection, command injection, JNDI/Log4Shell,
deserialization, XXE, file read/write, SSRF, and expression injection
(OGNL/SpEL/FreeMarker) — 42 verified algorithm signatures in total.

### Option C — Automated acceptance script

```bash
cd java-agent
bash scripts/acceptance.sh
```

This builds the agent and playground, starts all three Tomcat
baseline/protected pairs, exercises attack endpoints, and verifies that
protected ports redirect to `/rasp/blocked` while baselines do not.

---

## 5. Local Development Setup

Install the console dependencies:

```bash
cd console
npm ci
```

Download Go module dependencies:

```bash
cd api
go mod download
```

If Go 1.25 is the host toolchain, add `GOTOOLCHAIN=auto` before running
any `go` commands; the correct toolchain is downloaded automatically.

### Run tests

Backend:

```bash
cd api
go generate ./...
go test ./...
```

Console:

```bash
cd console
npm run build
npm test
```

Java agent (requires `JAVA_HOME` pointing to a JDK 25):

```bash
cd java-agent
export JAVA_HOME="$HOME/.local/jdks/openjdk-25/usr/lib/jvm/java-25-openjdk-amd64"
export PATH="$HOME/.local/bin:$JAVA_HOME/bin:$PATH"
gradle test
```

End-to-end tests require a Playwright-supported browser installation:

```bash
cd console
npm run e2e:install
npm run e2e
```

### Troubleshooting

- **PostgreSQL migration fails at startup** — check that none of the
  `.env` passwords contain a `/`. Regenerate with `openssl rand -hex 18`.
- **`gradle test` fails with `[JAVA_COMPILER]` error** — the host has a
  JRE but not a JDK. Set `JAVA_HOME` to a JDK installation or extract the
  JDK packages locally as described in the Prerequisites section above.
- **`gradle` not found or wrong version** — Ubuntu's package manager
  provides Gradle 4.4.1, which cannot build this project. Install Gradle
  9.5.1+ under `$HOME/.local` as described above.
- **`npm ci` fails after pulling changes** — run `npm ci` again from the
  `console/` directory to synchronize the lockfile after dependency
  updates.
- **Playwright `e2e:install` fails on Ubuntu 26.04** — the scripts set
  `PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64` automatically.
  If you are running the install command manually, export that variable
  first.
- **`oapi-codegen` warns about OpenAPI 3.1** — this is expected and does
  not affect the build.
