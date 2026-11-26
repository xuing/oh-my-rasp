# Changelog

All notable changes to OhMyRASP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `deploy/shirudo/gen-readmes.py`: auto-generates `deploy/shirudo/README.md`
  and per-track `ohmyrasp-{java8,java11,java17,jdk25}/README.md` with
  source-derived hook, transformer, algorithm, and Vulhub coverage tables;
  `deploy/shirudo/verify-shirudo-upatch.sh` enforces `--check`.
- `docs/images/architecture.svg`: architectural overview diagram in root READMEs.

### Changed
- The default Compose database is PostgreSQL 19. Existing PostgreSQL 18 deployments can follow the [volume migration and rollback procedure](docs/runbooks/upgrade-downgrade.md#postgresql-18-to-19).
- The primary Java agent and standalone `ohmyrasp-jdk25.jar` run on both JDK 21 and 25. JDK 21 downloads are named `ohmyrasp-agent-jdk21.jar` and `ohmyrasp-jdk21.jar`. The `ohmyrasp-jdk21` Shirudo package uses the same standalone binary as `ohmyrasp-jdk25`.
- Documentation overhaul across root guides, navigation (`docs/README.md`),
  `CONTRIBUTING.md`, `SECURITY.md`, and `.github/PULL_REQUEST_TEMPLATE.md` to
  align toolchains, commands, and generated-doc checks with the current tree.

### Fixed
- **Java agent (all 4 tracks):** a `lock_config=true` profile without a baked
  `control` path no longer polls `/tmp/ohmyrasp-control.json`.
- **Java agent (all 4 tracks):** the control file is read on every poll and
  applied when its content changes, not its modification time, so a document
  read half-written is applied once complete. When the file is removed, the
  mode (and on `agent-jdk25` the per-algorithm switches, the revision and a
  policy the file installed) return to their start-up values together, so an
  `ignore` rule from a removed control file stops suppressing detections; a
  policy installed by the direct-cloud client stays. An unreadable file keeps
  the last good state.
- **Java agent (`agent-jdk25`):** a control file rewritten without `policy`
  (how the daemon withdraws one) drops the policy the file installed, so its
  `ignore` rules stop suppressing detections. Policy text that does not parse is
  no longer recorded as applied, so it cannot later reinstall the file's
  unchanged policy over a direct-cloud one.
- **Java agent (all 4 tracks):** only well-formed control-file content changes
  anything: at most 1 MiB (the reader stops one byte past that bound), strict
  UTF-8, and exactly one JSON object, with `mode` read from its top level. A
  truncated document, a nested `mode`, a number such as `01`, non-ASCII escape
  digits or malformed UTF-8 no longer switch detection. Nothing thrown while the
  file is read leaves the poll step, an `Error` from a file system provider
  included, so the first read at agent start cannot abort the application's
  start-up, and no error stops the poller.
- **Java agent (`java8`/`java11`/`java17`):** standalone mode never polls a
  control file, as on `agent-jdk25`; before, an explicitly set control path was
  polled in standalone mode.
- **Java agent (all 4 tracks):** an invalid control path, poll interval or
  `ohmyrasp.log.sync` value no longer hides a valid lower-priority value; on the
  backports the same holds for `ohmyrasp.java{8,11,17}.block`, and on
  `agent-jdk25` for `ohmyrasp.latency_sample` and `ohmyrasp.log.queue`.
- **Java agent (all 4 tracks):** the shutdown hook waits up to 2 seconds for the
  event writer, then writes what is still queued waiting up to 1 second for the
  write lock, and an event submitted after that is written inline. These are
  bounded waits; events accepted while the JVM is shutting down may be lost. On
  the backports a queued event is written to the log target it was accepted for.
- **Java agent (all 4 tracks):** a detection decided as a block is blocked even
  when recording its event fails (for example a replaced `System.out` that
  throws while events go to the console); before, the operation went ahead.
- **Java agent (`agent-jdk25`):** the event logger and the hooks' static state
  are initialised before the first transformer is added, so no hook starts the
  event writer or registers its shutdown hook, and the logger's standalone
  defaults follow the `standalone` value the runtime resolved.
- **Java agent (all 4 tracks):** the agent's own event and control-file I/O is
  no longer reported or blocked by its file hooks, so a spool path such as
  `webapps/ROOT/events.jsp` no longer aborts or hangs the JVM in block mode,
  and it no longer uses up a pending archive entry the application's next
  write is checked against.

## [0.2.0-alpha.1] - 2026-11-25

### Security
- **Java agent (`agent-jdk25`):** relocate (shade) bundled ASM under
  `io.ohmyrasp.agent.shaded.asm` so the bootstrap classloader no longer shadows
  the instrumented application's own ASM, matching the `java8`/`java11`/`java17`
  backports. Make `ObjectInputStream` deserialization filtering selective.
- **Java agent (all 4 tracks):** add zero-allocation arithmetic guard on
  `java.util.Base64$Decoder.decode0` for OpenJDK AVX-512 tail-underflow
  (CVE-2026-114938), block Fastjson 1.2.83 `ClassLoader.getResourceAsStream`
  remote/`/proc/self/fd/` gadgets inside `ParserConfig.checkAutoType`, and add
  standalone JDBC `Statement` SQLi protection.
- **Console (`console/`):** add strict security headers
  (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`) to `console/nginx.conf`.
- **Daemon (`daemon/`):** create telemetry temp files (spool, control, outbox)
  with owner-only (`0600`) permissions.

### Added
- **Shirudo standalone Java upatch packages (`deploy/shirudo/`):** daemonless
  JARs (`ohmyrasp-java8.jar`, `ohmyrasp-java11.jar`, `ohmyrasp-java17.jar`,
  `ohmyrasp-jdk25.jar`) built via `shirudoUpatchJar` / `verifyShirudoUpatchJar`
  with signed `META-INF/ohmyrasp-shirudo.properties` (`standalone=true`,
  `lock_config=true`, `mode=block`, `control=none`, `log=stderr`,
  `latency_sample=0`), `Beefile` packaging, and Temurin 8/11/17/21/25 Docker
  smoke tests (`deploy/shirudo/smoke-test.sh`).
- **Release pipeline (`.github/workflows/ohmyrasp-release.yml`):** automated
  GitHub Release publishing via `deploy/scripts/publish-github-release.sh` with
  12 release assets (4 standard JARs, 4 shirudo JARs,
  `ohmyrasp-shirudo-upatches-<version>.tar.gz`, `ohmyrasp-daemon-linux-amd64.tar.gz`,
  `ohmyrasp-control-<version>.tgz`, `SHA256SUMS.txt`), GHCR images, OCI Helm
  chart, Trivy scan gate, and GitHub artifact attestations.
- **CI & supply-chain checks:** automated CI workflows for `java-agent/` and
  `daemon/`, `scripts/check-detector-parity.sh`, Dependabot, CodeQL,
  `govulncheck`, and `cargo audit`.
- **API & daemon observability:** `/metrics` endpoints and event outbox drainer
  configuration (`api/`, `daemon/`).
- `NOTICE` and `CODE_OF_CONDUCT.md`.

### Changed
- **Console:** removed legacy `web/` frontend; `console/` (React 19, Vite 8,
  TypeScript 6, Tailwind CSS 4) is the sole frontend.
- **Toolchains:** aligned Go (`1.26.7` / `golang:1.27.4`), JDK 25 + Gradle
  `9.9.2`, Rust `1.100.0` (edition 2024), and Node `>=26` / Playwright `1.65.1`.
- **READMEs:** clarified that detection is signature-based with
  `ThreadLocal<RequestContext>` substring correlation and call-stack analysis
  (not bytecode dataflow taint tracking).

### Fixed
- **Console:** surface failed mutations (policy rollout/rollback, user disable,
  secret rotation, cleanup) to operators and add a route-level error boundary.
- **API:** drain event outbox, enforce rate-limiting across paths, stop leaking
  internal errors, and fix policy cache invalidation across updates.
- **Java agent:** port false-positive suppressions across `agent-java11`,
  `agent-java17`, and `agent-jdk25` with parity enforcement.

<!--
Release process: when cutting a version, move the Unreleased section to a new
`## [X.Y.Z] - YYYY-MM-DD` heading and start a fresh Unreleased block. See
docs/runbooks/release.md.
-->

## [0.1.0] - 2026-06-01

Initial public preview: Java RASP agent (JDK 8/11/17/25), Rust host daemon,
Go control-plane API (Postgres + ClickHouse + Valkey), React console, and a
Helm chart with Prometheus/Grafana/Alertmanager observability.
