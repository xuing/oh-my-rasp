# Installation Guide

This guide documents the local installation path verified on Ubuntu 26.04 with
Docker available.

## Prerequisites

- Docker and Docker Compose
- Node.js 24 and npm 11
- Go 1.26, or Go 1.25+ with `GOTOOLCHAIN=auto`
- Java 25 JDK
- Gradle 9.5.1 or newer

## Install Local Dependencies

Install the web dependencies:

```bash
cd web
npm ci
```

Download Go module dependencies. On a host with Go 1.25 and
`GOTOOLCHAIN=auto`, this downloads and uses the Go 1.26 toolchain requested by
`api/go.mod`.

```bash
cd ../api
go mod download
```

If Gradle is not installed, install a current Gradle distribution in a
user-local location:

```bash
mkdir -p "$HOME/.local/opt" "$HOME/.local/bin"
curl -fsSL https://services.gradle.org/distributions/gradle-9.5.1-bin.zip \
  -o /tmp/gradle-9.5.1-bin.zip
printf '%s  %s\n' \
  'bafc141b619ad6350fd975fc903156dd5c151998cc8b058e8c1044ab5f7b031f' \
  '/tmp/gradle-9.5.1-bin.zip' | sha256sum -c -
unzip -q /tmp/gradle-9.5.1-bin.zip -d "$HOME/.local/opt"
ln -sfn "$HOME/.local/opt/gradle-9.5.1/bin/gradle" "$HOME/.local/bin/gradle"
```

If the host only has a Java 25 runtime, install or expose a Java 25 JDK so
`javac` is available. In restricted environments without sudo, the Ubuntu
packages can be downloaded and extracted locally:

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

## Configure the Compose Stack

Create `.env` from the example:

```bash
cp .env.example .env
```

Fill every empty password value. Use URL-safe values, such as hex strings,
because the compose file interpolates the database password into DSNs.

```bash
openssl rand -hex 18
```

Required fields:

```text
POSTGRES_PASSWORD=
CLICKHOUSE_PASSWORD=
VALKEY_PASSWORD=
GRAFANA_ADMIN_PASSWORD=
OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD=
```

For local API-only experiments without PostgreSQL, set
`OHMYRASP_STORE=memory` explicitly and provide
`OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD`. Memory mode generates an application secret
unless `OHMYRASP_BOOTSTRAP_APP_SECRET` is supplied. Agent downloads require a
real uploaded or filesystem Agent ZIP in `OHMYRASP_AGENT_ARTIFACT_DIR`.

## Start the Project

Build and start the full stack:

```bash
docker compose --env-file .env -f docker-compose.yml up -d --build
docker compose --env-file .env -f docker-compose.yml ps
```

Verify the web console and API:

```bash
curl -fsS http://127.0.0.1:18091/ >/tmp/ohmyrasp-web.html
curl -fsS http://127.0.0.1:18090/healthz
```

Useful local URLs:

| Service | URL |
| --- | --- |
| Web console | `http://127.0.0.1:18091` |
| API | `http://127.0.0.1:18090` |
| Grafana | `http://127.0.0.1:13000` |
| Prometheus | `http://127.0.0.1:19090` |
| Alertmanager | `http://127.0.0.1:19093` |
| ClickHouse HTTP | `http://127.0.0.1:18123` |

Stop the stack:

```bash
docker compose --env-file .env -f docker-compose.yml down
```

Remove development volumes for a clean run:

```bash
docker compose --env-file .env -f docker-compose.yml down -v
```

## Verification Commands

Backend:

```bash
cd api
go generate ./...
go test ./...
```

Frontend:

```bash
cd web
npm run build
npm test
```

Java agent:

```bash
cd java-agent
export JAVA_HOME="$HOME/.local/jdks/openjdk-25/usr/lib/jvm/java-25-openjdk-amd64"
export PATH="$HOME/.local/bin:$JAVA_HOME/bin:$PATH"
gradle test
```

End-to-end tests require a Playwright-supported browser installation:

```bash
cd web
npm run e2e:install
npm run e2e
```

## Issues Encountered During Installation

- Host Go was `1.25.3` while `api/go.mod` requires Go `1.26`. With
  `GOTOOLCHAIN=auto`, `go mod download` downloaded `go1.26.0` automatically
  and `go test ./...` passed.
- Ubuntu's available `gradle` package was `4.4.1`, which is too old for this
  Kotlin DSL/Java 25 build. Gradle `9.5.1` was installed under
  `$HOME/.local/opt` instead.
- The host initially had Java 25 JRE only. Gradle failed with
  `Toolchain installation ... does not provide the required capabilities:
  [JAVA_COMPILER]`. Extracting the Java 25 JDK packages locally and setting
  `JAVA_HOME` fixed `gradle test`.
- `sudo apt-get install openjdk-25-jdk-headless` could not be used in this
  environment because sudo required terminal authentication.
- A generated password containing `/` broke the PostgreSQL DSN during compose
  migration startup. Use URL-safe passwords, such as `openssl rand -hex 18`.
- `go generate ./...` completed, but `oapi-codegen` warned that OpenAPI 3.1 is
  not fully supported.
- `npm ci` was required after dependency changes introduced `i18next` and
  `react-i18next`; after installing, `npm test` passed.
- Playwright 1.60 does not yet support the native `ubuntu26.04-x64` browser
  download target. The web `e2e:install`, `e2e`, and `e2e:live` scripts set
  `PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64`, matching the upstream
  workaround for Microsoft Playwright issue #40117.
