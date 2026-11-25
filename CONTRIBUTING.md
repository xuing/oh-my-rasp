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

For detector development on Linux, start with the JDK 25 agent. Run the primary
unit tests, the complete benign corpus and the packaged probe for the rule you
changed. These commands exercise file reads and file deletion respectively.

```bash
java-agent/scripts/check-jdk25.sh file-read
java-agent/scripts/check-jdk25.sh --tests '*DetectorEngineTest' file-delete
```

The script reuses build outputs and Gradle dependencies in a per-checkout cache.
It prints the cache path and prefers the user's runtime directory. Set
`RASP_JDK25_CACHE` to choose a different cache parent. Run with `--help` for the
available probes. To focus the unit-test step, put a Gradle filter before the
probe name (for example `--tests '*HostReadPathTest' file-read`). Each run still checks
the full benign corpus. Extra probe options use container paths under `/workspace`
(the read-only Java project) or `/state` (the cache for this checkout).

The file, process and multipart probes run each scenario once by default,
including concurrent access. If successive rule changes trade false positives
for missed detections, retain examples of both and use `--rounds N` for focused
comparisons with varied inputs.

Once the change passes on JDK 25, verify the same behavior on JDK 21 with the
primary JAR, apply any required backport changes, and run the affected Java 8,
11 and 17 probes together. Shared detector code is compiled into each agent;
each applicable runtime still needs its packaged check. Use the full build and
compatibility matrix for integration.

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

For an offline coverage review, use the same local Vulhub checkout and the
retained event logs. From `java-agent/`, run:

```bash
python3 scripts/check-vulhub-java-coverage.py --vulhub-root "$VULHUB_ROOT" \
  --evidence-report /tmp/vulhub-inventory.json
python3 scripts/check-vulhub-event-decisions.py --report /tmp/vulhub-decisions.json
```

The inventory reads Vulhub's catalogue, Compose manifests and README paths.
It records literal script references and ledger rows sharing a vulnerability
identifier separately. Either relationship can be ambiguous. Event files with
probe names may include exploratory or startup detections. The decision check
needs a JDK 17+ with `javac` and the built Java 8/11/17 agent jars. It passes
retained arguments to detector callbacks, compares the hook label, rule, block decision and any recorded decision basis, and checks a benign input for each tested hook and track. Exit 1
indicates a difference from history, which can include a corrected false
positive. To check for changes between agent builds, pass a prior report
with `--compare-report` and write the candidate to a new file. Comparison
requires matching input digests and still fails on any candidate benign alert.
Historical file reads that require the original filesystem, working directory or request
source have an explicit unavailable status. Their paths are excluded from the probe batch.
For processes, a message naming an interpreter or initialization context cannot
supply the original caller. A display string from an array API does not preserve
argument boundaries. These records also receive an unavailable status.
Backport class-descriptor and proxy-interface callbacks historically logged the same
hook label. For records retaining a name, the offline probe checks the name
predicate without loading the named class. These results stay in the unresolved
total because the probe did not observe the resolved class or proxy interfaces.
The comparison distinguishes changes in evidence availability from changes in tested
detector outcomes and reports both.
An archive filename cannot establish deployment authorization. To require every retained
block to be replayed and matched, pass `--require-complete`; this still applies when
comparing two reports. An end-to-end result requires separate evidence of the application outcome.

The runtime matrix runs [the HTTP transport check](java-agent/scripts/fp-harness/check-http-transport.py)
against the built agent. Its local responder verifies cache hits, redirect receipts and
request attribution under block and monitor modes.

The Linux matrix checks open modes and provider namespaces against the packaged agent.
The fixtures read ordinary ZIP entries, check locally opened channels and consume concurrent
directory walks in block and monitor modes. [File-read check](java-agent/scripts/fp-harness/check-file-read.py)

The Linux matrix also runs `java-agent/scripts/fp-harness/check-process-launch.py`.
It verifies argument boundaries, application list accesses, per-stage redirection
and explicit dispatch policy with locally executed report commands. The primary
agent check uses curl and an in-process loopback responder to verify callback
destination decisions and receipt of allowed transfers.

The [stream resolution check](java-agent/scripts/fp-harness/check-stream-resolution.py)
uses inert records, an application resolver and a BeanShell scalar. It checks
the type actually read, resolver exceptions, and decisions on independent streams.
Use `--beanshell-jar` to run the probe using a local copy of the fixture library.

The primary [serial filter check](java-agent/scripts/fp-harness/check-serial-filter.py)
verifies application filter registration, JDK rejection and ordinary data reads
in separate JVMs. Run it locally with `java-agent/scripts/check-jdk25.sh serial-filter`.

The [Spark submit check](java-agent/scripts/fp-harness/check-spark-submit.py)
uses Javax and Jakarta servlet requests with a recording handler. It checks
role decisions for a fixed report job. Pass `--api-dir` to use local servlet jars.
With a Spark 2.3.1 distribution and a compatible JDK, add
`--spark-classpath '/path/to/spark/jars/*'` to exercise Spark's original parser
and validator against a handler that only counts submissions.

The [YARN admission check](java-agent/scripts/fp-harness/check-yarn-submit.py)
uses the Hadoop release REST resource and a recording client service.
Run `java-agent/scripts/check-jdk25.sh yarn-submit` for the primary agent.
The compatibility matrix shares the fixture dependencies staged by the root
`stageYarnProbe` Gradle task. For another agent, pass its jar and
`--jar-dir java-agent/build/yarn-probe` to the probe.

The [JWT filter check](java-agent/scripts/fp-harness/check-jwt-verification.py)
runs a local filter fixture with java-jwt and a deny-only downstream receiver.
Use `java-agent/scripts/check-jdk25.sh jwt-verification` for the primary agent.
Pass `--jar-dir` to the probe to use local copies of the pinned fixture jars.

The multipart check covers both the Javax and Jakarta Servlet APIs.
Pass `--api-dir` to `java-agent/scripts/fp-harness/check-multipart-archive.py` to
use local copies of its pinned API jars. CI stages those jars once with
`:stageServletProbe` and shares them across the runtime matrix.

The packaged-agent job exercises MyBatis rendering and a recording JDBC receiver
in block and monitor modes. For a local run, pass the agent JAR to
[`check-mybatis-mapping.py`](java-agent/scripts/fp-harness/check-mybatis-mapping.py).
Its `--mybatis-jar` option accepts an existing library for offline checks.

For the MySQL-family lexer, `java-agent/scripts/fp-harness/check-mysql-comments.py`
accepts the agent JAR, a private MariaDB Unix socket (`--socket`), and the
MariaDB Connector/J classpath including its Unix socket libraries
(`--driver-classpath`). The fixture connects as the local test user `reports`
and issues read-only constant queries. It checks both returned rows and events.

The runtime compatibility job also runs `scripts/fp-harness/check-xml-resolution.py`
against the packaged agent. To exercise a separate Apache Xerces installation,
pass its JARs with `--xerces-classpath`. The fixture uses an in-memory URL
handler and temporary catalogue archives and checks both block and monitor modes.

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

Prioritize zero observed false positives on normal application workloads. Check
the business result and the detection log against an uninstrumented run, including
alerts that did not block the request. If repeated refinements expose a persistent ambiguity, recommend opt-in monitoring and
document which legitimate actions produce alerts.

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
