# Contributing to OhMyRASP

Thank you for your interest in contributing. OhMyRASP is under active
development and welcomes bug reports, feature ideas, documentation improvements,
and code contributions of all sizes.

This document covers the repository layout, local development paths, how to run
each component's test suite, how to keep generated artefacts fresh, and what we
look for in a pull request.

---

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
  - [Deployment and observability checks](#deployment-and-observability-checks)
- [Regenerating generated docs](#regenerating-generated-docs)
- [Adding a new hook family or detector](#adding-a-new-hook-family-or-detector)
- [Console i18n expectations](#console-i18n-expectations)
- [Detection-rule contributions](#detection-rule-contributions)
- [Pull request expectations](#pull-request-expectations)
- [License](#license)

---

## Project layout

```text
api/          Go control-plane API, migrations, OpenAPI contract, generated bindings
console/      React 19 + Vite control-plane console (app-centric rewrite)
java-agent/   Java agent (agent-jdk25 primary + agent-java8/11/17 backports)
              and comparative Tomcat playgrounds
daemon/       Rust host daemon (ohmyrasp-daemon)
deploy/       Helm chart, observability assets, smoke and validation scripts
docs/         Architecture notes, development ledgers, and operational runbooks
web/          Legacy console (superseded by console/, retained for reference)
```

---

## Dev environment

### Docker-only path (recommended)

All components can be built and tested through Docker images with no local
toolchain beyond Docker itself. This is how CI runs and the safest way to get
started. See [docs/getting-started.md](docs/getting-started.md) for the full
stack bring-up procedure.

### Local toolchain

If you prefer a local install, the minimum versions required are:

| Component | Tool | Version |
|-----------|------|---------|
| API | Go | 1.26 (or 1.25+ with `GOTOOLCHAIN=auto`) |
| Console | Node.js | 26+ |
| Console | npm | Bundled with Node.js 26+ |
| Java agent | JDK | 25 (primary); 8, 11, 17 for backport modules |
| Java agent | Gradle | 9.6.1+ |
| Daemon | Rust / Cargo | 1.97.1 (matches `daemon/rust-toolchain.toml`) |

`docs/getting-started.md` documents verified installation steps for each
toolchain on Ubuntu, including workarounds for restricted environments.

---

## Running the tests

### Go control-plane API

```bash
# Via Docker (no local Go required):
docker run --rm -v "$PWD/api":/src -w /src golang:1.26.5 go generate ./...
docker run --rm -v "$PWD/api":/src -w /src golang:1.26.5 go test ./...

# Or with a local Go 1.26 toolchain:
cd api
go generate ./...
go test ./...
```

### React console

```bash
cd console
npm ci
npm run build       # i18n:check + tsc + vite build
npm test            # i18n:check + typecheck + playwright e2e
```

The individual steps that `npm test` composes are:

```bash
npm run i18n:check  # enforces en/zh/ja key parity (scripts/i18n-coverage.ts)
npm run typecheck   # tsc --noEmit
npm run test:e2e    # Playwright end-to-end suite
```

### Java agent

Unit tests run against the primary JDK 25 module:

```bash
# Via Docker (no local JDK required):
docker run --rm -v "$PWD/java-agent":/workspace -w /workspace gradle:9.6.1-jdk25 \
  gradle --no-daemon :agent-jdk25:test
```

The acceptance suite boots real vulnerable applications under the agent (Tomcat
pairs on 18080/18081) and asserts detection and blocking:

```bash
cd java-agent
bash scripts/acceptance.sh
```

Per-runtime acceptance scripts cover JDK 7/8/11/17/21 Vulhub scenarios and are
named `scripts/acceptance-vulhub-<component>-<jdk>.sh`. The Java 21 runtime
compatibility matrix lives in `scripts/acceptance-java21.sh`.

### Daemon (Rust)

```bash
cd daemon
cargo build
cargo test
```

A release binary with link-time optimisation and stripping:

```bash
cargo build --release
```

### Deployment and observability checks

```bash
./deploy/scripts/smoke-control-plane.sh
./deploy/scripts/validate-helm-manifests.sh
./deploy/scripts/validate-observability-assets.sh
```

---

## Regenerating generated docs

Two Markdown files under `java-agent/docs/` are derived, not hand-written. They
must be regenerated after any change to hook modules, detector capabilities, or
acceptance scenarios, and CI fails the build when they are stale.

**Detection coverage doc** — derived from `HookRegistry.java`,
`DetectorEngine.java`, and the `acceptance-vulhub-*.sh` scenario scripts:

```bash
cd java-agent
python3 scripts/gen-detection-coverage.py          # writes docs/DETECTION-COVERAGE.md
python3 scripts/gen-detection-coverage.py --check  # fails if the committed file is stale
```

**False-positive report** — runs the FP harness against the real
`DetectorEngine` inside the JDK 25 build image and counts benign-corpus
detections:

```bash
cd java-agent
bash scripts/run-fp-report.sh                      # writes docs/FALSE-POSITIVE-REPORT.md
```

Commit both files together with the code change that caused them to change.

---

## Adding a new hook family or detector

1. Implement the hook module under
   `java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/asm/` and register
   it in `HookRegistry.defaults()`.
2. Add the corresponding detector method(s) to `DetectorEngine`.
3. Write a unit test covering the new detection path in `agent-jdk25/src/test/`.
4. Add or extend an acceptance scenario under `java-agent/scripts/`.
5. Update `docs/development/algorithm-coverage.md` — this is the durable ledger
   of every algorithm family and must be updated in the same patch as the new
   hook. If the new coverage maps to a Vulhub scenario, also update
   `docs/development/vulhub-coverage.md` in the same patch.
6. Regenerate `java-agent/docs/DETECTION-COVERAGE.md` (see above) and commit it
   with the rest of the change.

Backport builds (`agent-java8`, `agent-java11`, `agent-java17`) should be
updated when the new hook can be implemented against the older ASM / JDK
surface. See the per-module notes in `docs/development/algorithm-coverage.md`
for which constructs are available on each era track.

---

## Console i18n expectations

The console ships three locales: English (`en`), Simplified Chinese (`zh`), and
Japanese (`ja`). The enforced rules are:

1. The `zh` and `ja` translation tables in `console/src/i18n/messages.ts` must
   have identical key sets (parity check).
2. Every `t("key")` call found in TypeScript source files must have a
   corresponding entry in both `zh` and `ja`.

The check runs automatically as part of `npm run build` and `npm test`:

```bash
npm run i18n:check
```

The script is `console/scripts/i18n-coverage.ts`. When adding a new string,
add translations for all three locales in `messages.ts` before opening a PR.

---

## Detection-rule contributions

A new detection rule or hook family is most useful when there is observable
evidence that it works. Contributions that add detection rules should include at
least one of the following:

- A **Vulhub acceptance scenario** (`java-agent/scripts/acceptance-vulhub-*.sh`)
  that boots the vulnerable application, confirms exploitation in baseline mode,
  and confirms blocking or detection in protected mode.
- A **playground reproduction** using the comparative Tomcat testbed under
  `java-agent/playground*/` that demonstrates the before/after behaviour.

Both forms provide durable, runnable evidence that CI can replay.

---

## Pull request expectations

- **Small and focused.** One logical change per PR. A PR that adds a detector,
  its unit test, its acceptance scenario, the updated algorithm-coverage ledger,
  and the regenerated `DETECTION-COVERAGE.md` is an ideal shape.
- **Tests pass.** Run the full test matrix for any component you touch before
  opening a PR: `go test ./...` for API changes, `npm test` for console changes,
  `gradle :agent-jdk25:test` plus the relevant acceptance script(s) for Java
  agent changes, `cargo test` for daemon changes.
- **Docs updated.** If your change affects how operators configure, deploy, or
  use OhMyRASP, update the relevant file under `docs/`. If you changed
  hook/detector definitions, regenerate the derived docs (see above).
- **Generated files committed.** `java-agent/docs/DETECTION-COVERAGE.md` and
  `java-agent/docs/FALSE-POSITIVE-REPORT.md` are CI-checked; commit fresh
  copies whenever they would be affected by your change.
- **No accidental scope.** Avoid reformatting or refactoring code outside the
  area your PR is focused on — it makes review harder.

---

## License

By contributing to OhMyRASP you agree that your contribution will be licensed
under the [Apache License 2.0](LICENSE).
