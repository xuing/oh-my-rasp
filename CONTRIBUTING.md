# Contributing to OhMyRASP

This guide covers the repository layout, supported toolchains, component test suites, generated documentation checks, and pull request expectations.

## Table of Contents

- [Project layout](#project-layout)
- [Dev environment](#dev-environment)
  - [Docker-only path (recommended)](#docker-only-path-recommended)
  - [Local toolchain](#local-toolchain)
- [Running the tests](#running-the-tests)
  - [Go control-plane API](#go-control-plane-api)
  - [React console](#react-console)
  - [Java agent](#java-agent)
  - [Daemon (Rust)](#daemon-rust)
  - [Deployment, shirudo, and observability checks](#deployment-shirudo-and-observability-checks)
- [Regenerating generated docs](#regenerating-generated-docs)
- [Adding a new hook family or detector](#adding-a-new-hook-family-or-detector)
- [Console i18n expectations](#console-i18n-expectations)
- [Detection-rule contributions](#detection-rule-contributions)
- [Pull request expectations](#pull-request-expectations)
- [License](#license)

## Project layout

```text
api/              Go control-plane API, migrations, OpenAPI contract, generated bindings
console/          React + Vite control-plane console (TypeScript, Tailwind CSS)
java-agent/       Java agent (agent-jdk25 primary + agent-java8/11/17 backports) and Tomcat playgrounds
daemon/           Rust host daemon (ohmyrasp-daemon)
deploy/           Helm chart, observability assets, release/smoke scripts, and shirudo upatches (deploy/shirudo/)
docs/             Architecture, detection, API, and console references, development ledgers, and runbooks
```

## Dev environment

### Docker-only path (recommended)

All components can be built and tested in containers matching CI without installing local toolchains. See [docs/getting-started.md](docs/getting-started.md) for full stack bring-up.

### Local toolchain

| Component | Tool | Version | Source of truth |
|---|---|---|---|
| API | Go | version pinned in `api/go.mod` (set `GOTOOLCHAIN=auto` if the host Go is older); container image pinned in `api/Dockerfile` | `api/go.mod`, `api/Dockerfile` |
| Console | Node.js & npm | range in `console/package.json` (`engines.node`) | `console/package.json`, `console/Dockerfile` |
| Java agent | JDK | `25` (primary); `8`, `11`, `17` for backports | `java-agent/Dockerfile*` |
| Java agent | Gradle | Gradle on JDK 25 (builder image pinned in `java-agent/Dockerfile`) | `java-agent/Dockerfile` |
| Daemon | Rust / Cargo | toolchain pinned in `daemon/rust-toolchain.toml` (edition 2024 in `daemon/Cargo.toml`) | `daemon/rust-toolchain.toml`, `daemon/Cargo.toml` |

`docs/getting-started.md` documents verified local installation steps on Ubuntu.

## Running the tests

### Go control-plane API

```bash
# Via Docker (no local Go required):
GO_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^golang:/ { print $2; exit }' api/Dockerfile)"
docker run --rm -v "$PWD/api":/src -w /src "$GO_IMAGE" go generate ./...
docker run --rm -v "$PWD/api":/src -w /src "$GO_IMAGE" go test ./...

# Or with a local Go matching api/go.mod:
cd api
go generate ./...
go test ./...
```

### React console

```bash
cd console
npm ci
npm run build       # i18n:check + tsc -b + vite build
npm test            # i18n:check + lint + typecheck + test:e2e
```

Individual checks in `console/package.json`:

```bash
npm run i18n:check  # en/zh/ja key parity (console/scripts/i18n-coverage.ts)
npm run lint        # eslint .
npm run typecheck   # tsc -b --noEmit
npm run test:e2e    # playwright test
```

### Java agent

Run unit tests and `verifyShirudoUpatchJar` via Docker (matching `.github/workflows/agent.yml`):

```bash
GRADLE_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^gradle:/ { print $2; exit }' java-agent/Dockerfile)"
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/tmp/gradle-home \
  -v "$PWD/java-agent":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon clean check :agent-jdk25:agentJar \
  :agent-java8:shirudoUpatchJar :agent-java11:shirudoUpatchJar \
  :agent-java17:shirudoUpatchJar :agent-jdk25:shirudoUpatchJar
```

Run parity, Vulhub ledger, and Docker acceptance checks from `java-agent/`:

```bash
cd java-agent
bash scripts/check-detector-parity.sh
python3 scripts/check-vulhub-java-coverage.py
bash scripts/acceptance.sh
```

Per-runtime Vulhub scripts are named `scripts/acceptance-vulhub-<component>-<jdk>.sh`. The Java 21 runtime compatibility matrix lives in `scripts/acceptance-java21.sh`.

### Daemon (Rust)

```bash
cd daemon
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
```

### Deployment, shirudo, and observability checks

```bash
./deploy/scripts/smoke-control-plane.sh
./deploy/scripts/validate-helm-manifests.sh
./deploy/scripts/validate-observability-assets.sh

# Shirudo Java upatch Beefile, JAR, and real-JVM smoke tests:
./deploy/shirudo/build-all.sh --jar-only
./deploy/shirudo/verify-shirudo-upatch.sh
./deploy/shirudo/smoke-test.sh
```

## Regenerating generated docs

These Markdown files (and the README "By the numbers" regions) are derived from source. Do not edit them by hand. `python3 scripts/check-docs.py` runs the `--check` mode of the detection-coverage and Shirudo README generators in CI and fails when they are stale; the false-positive report is regenerated with its script.

Hand-written docs must not restate release versions, pinned toolchain or image versions, or code-base counts; link to the fact's home instead. The rules and the full list of checks are in [AGENTS.md](AGENTS.md#documentation).

Run them in this order: the coverage generator and the Shirudo README generator both read the false-positive report.

**1. False-positive report** (runs `scripts/fp-harness/FpReport.java` against `DetectorEngine`):

```bash
cd java-agent
bash scripts/run-fp-report.sh                      # writes java-agent/docs/FALSE-POSITIVE-REPORT.md
```

**2. Detection coverage doc** (derived from `HookRegistry.java`, `DetectorEngine.java`, and `acceptance-vulhub-*.sh`):

```bash
cd java-agent
python3 scripts/gen-detection-coverage.py          # writes java-agent/docs/DETECTION-COVERAGE.md and the README "By the numbers" regions
python3 scripts/gen-detection-coverage.py --check  # fails if stale
```

**3. Shirudo upatch READMEs** (derived from `java-agent/` sources, `Beefile`s, and `FALSE-POSITIVE-REPORT.md`):

```bash
python3 deploy/shirudo/gen-readmes.py              # writes deploy/shirudo/README.md and the per-package READMEs
python3 deploy/shirudo/gen-readmes.py --check      # fails if stale (also run by verify-shirudo-upatch.sh)
```

Commit regenerated docs in the same PR as the code change that triggered them.

## Adding a new hook family or detector

1. Implement the hook module under `java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/asm/` and register it in `HookRegistry.defaults()`.
2. Add the corresponding detector method(s) to `DetectorEngine`.
3. Write unit tests covering the new detection path in `agent-jdk25/src/test/`.
4. Add or extend an acceptance scenario under `java-agent/scripts/`.
5. Update `docs/development/algorithm-coverage.md` and, if mapped to a Vulhub scenario, `docs/development/vulhub-coverage.md` in the same patch.
6. Regenerate `java-agent/docs/DETECTION-COVERAGE.md`, `java-agent/docs/FALSE-POSITIVE-REPORT.md`, and `deploy/shirudo/` READMEs, and verify `bash java-agent/scripts/check-detector-parity.sh`.

Update backport builds (`agent-java8`, `agent-java11`, `agent-java17`) when the hook applies to earlier JDKs. See `docs/development/algorithm-coverage.md` for per-era capabilities.

## Console i18n expectations

The console ships English (`en`), Simplified Chinese (`zh`), and Japanese (`ja`) in `console/src/i18n/messages.ts`. `console/scripts/i18n-coverage.ts` enforces:

1. Identical key sets between `zh` and `ja`.
2. Every `t("key")` call in TypeScript source files has entries in both `zh` and `ja`.

Run `npm run i18n:check` (included in `npm run build` and `npm test`) before opening a PR.

## Detection-rule contributions

Contributions that add detection rules or hook families should include runnable verification via either:

- A **Vulhub acceptance scenario** (`java-agent/scripts/acceptance-vulhub-*.sh`) proving baseline exploitation and protected-mode blocking.
- A **playground reproduction** using the comparative Tomcat testbeds under `java-agent/playground*/`.

## Pull request expectations

- **Small and focused:** One logical change per PR. Avoid unrelated formatting or refactoring outside the PR scope.
- **Tests pass:** Run the test suite for every component you touch (`go test ./...`, `npm test`, `gradle :agent-jdk25:check`, `cargo test --locked`, `verify-shirudo-upatch.sh`).
- **Single source of truth & doc sync:** Keep each fact in one owning reference under `docs/` and link to source files and symbols rather than duplicating volatile lists. Update the owning doc in the same PR whenever behavior, flags, endpoints, or contracts change. Keep `docs/internal/` frozen as historical archive.
- **Generated files committed:** Commit fresh outputs from `gen-detection-coverage.py`, `run-fp-report.sh`, and `deploy/shirudo/gen-readmes.py` whenever affected.

## License

By contributing to OhMyRASP you agree that your contribution will be licensed under the [Apache License 2.0](LICENSE).
