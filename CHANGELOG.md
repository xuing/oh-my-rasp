# Changelog

All notable changes to OhMyRASP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- The primary Java agent redacts the values of sensitive parameters inside the `request.query` string of an event line, with the marker it already used for `parameters`. The query is split on `&` and `;`, and a piece is redacted when it, or what it decodes to (percent escapes and `+`, up to three rounds), holds a sensitive parameter name as a token: `id=1&amp;password=x`, `%2570assword=x`, `user[password]=x`, `cfg={"password":"x"}` and `next=/cb?token=x` are all redacted, and `passwordless=1` is not. A query longer than 8192 characters is not scanned and is replaced by the marker as a whole. Before, `password=...` in a query string was written to the spool, shown in the local console and uploaded by the daemon (and by the direct-cloud client) as written.

### Fixed
- The primary Java agent reads the text a hook asks of an object whose class is not public, through a public type of the object's hierarchy instead of its own class: the request URI and method of a Spark, YARN or DataEase request (Tomcat's package-private `ApplicationHttpRequest` overrides `getRequestURI`), the text of an expression object, the system id of an XML source and the target, method and arguments of a `java.beans.Statement` subclass. Before, the call failed silently and the event carried no request or the text was not inspected. The Java 8, 11 and 17 agents read the source of javac's own file objects (`com.sun.tools.javac.file.PathFileObject`, the unit for a file on disk) through `javax.tools.FileObject`; on Java 17 and later `setAccessible` on that class fails (`module jdk.compiler does not "exports com.sun.tools.javac.file"`), so such a source was never inspected.
- The per-line `deploy/shirudo/*/build.sh` scripts ran Gradle in `gradle:9.8.1-jdk25`, a copy of the pin that had moved on. They resolve the image from `java-agent/Dockerfile` like CI, as the caller's UID.
- The primary Java agent reads the source of a `javax.tools.JavaFileObject` that is not a public class. Compiling from a string with an anonymous `SimpleJavaFileObject` subclass, the usual way to do it, made the `getCharContent` lookup fail, so the source was never inspected and `java_compile_runtime` did not fire; the method is now resolved on a public type of the unit's hierarchy (`SimpleJavaFileObject`, `FileObject`). The backport agents already read such a unit.
- All four agent lines give Jetty 12 uploads the same filename inspection as Jetty 9.4 to 11. In Jetty 12 the servlet layer left jetty-server (`MultiPartFormInputStream` and `MultiParts` are gone there); its part classes are `ee10.servlet.ServletMultiPartFormData$ServletPart`, `ee9.nested` and `ee8.nested` `MultiPartFormInputStream$MultiPart` and `MultiPartInputStreamLegacyParser$MultiPart`, and `ee11` in 12.1. They were hooked only for denied archive uploads; they now go through the full upload check. The hook-target map records the ee8, ee9, ee10 and ee11 artifacts (12.0.41, and 12.1.15 for ee10 and ee11).
- The backport agents check the table name SkyWalking 9 writes into its log query. 9.x replaced `H2LogQueryDAO.queryLogs(String metricName, ...)` with `jdbc.common.dao.JDBCLogQueryDAO`, so the SQL-identifier hook matched nothing in storage-jdbc-hikaricp-plugin 9.7.0. It now covers `JDBCLogQueryDAO.buildSQL(..., String table)`, and the event names that source and the `table` parameter. The primary agent has no hook on this DAO; its request-field check for SQL identifiers is unchanged.
- All four agent lines hook janino's `Cookable` under its real name, `org.codehaus.commons.compiler.Cookable` (commons-compiler 2.7.8, 3.0.16 and 3.1.12 checked): `cook(String source)` and `cook(String fileName, String source)` hand the source to the compilation detector. The old name, `org.codehaus.janino.Cookable`, exists only in janino 2.5 and earlier.
- All four agent lines trace the SQL that PageHelper 4.2.x dialects compose: `getPageSql(String, Page, RowBounds, CacheKey)` is hooked next to the 5.x `(String, Page, CacheKey)` and `(String, RowBounds, CacheKey)` forms. With pagehelper 4.2.1 no dialect method matched (hooked methods 0 to 12 per agent family).
- The primary Java agent hooks Struts 7's `org.apache.struts2.ognl.OgnlUtil` (`getValue` and `setValue` with an expression string), as it does the `com.opensymphony.xwork2.ognl` one of Struts 2.3 to 6.x. With struts2-core 7.0.3 the hook matched nothing, and OGNL expressions that Struts evaluates were no longer handed to the expression detector there (hooked methods 1 to 4).
- The backport agents no longer name `org/apache/commons/jexl2/ScriptImpl`. JEXL 2.0, 2.0.1, 2.1 and 2.1.1 have no such class (scripts run in `ExpressionImpl`, which stays hooked); `ScriptImpl` exists only in JEXL 1.x, in the `org/apache/commons/jexl` package.
- All four agent lines no longer name `com/alibaba/com/caucho/hessian/io/UnsafeDeserializer`. Hessian Lite has no such class in any release (2.6.2 and 3.2.2 to 3.2.13 checked), so the name matched nothing; Caucho Hessian's own `UnsafeDeserializer` is still hooked.
- The primary Java agent no longer names `org/snakeyaml/engine/v2/constructor/*` as a hook target. SnakeYAML Engine (2.0, 2.10 and 3.2 checked) never resolves a tag to a Java class, so the `getClassForName` hook it wanted matched nothing; the snakeyaml 1.x `Constructor.getClassForName` hook is unchanged.
- The daemon no longer reinitialises a control file whose `mode` an operator edited to a spelling the agents accept (`record`, `observe`, `log`, `disabled`, `none`, `blocking`, `protect`, or another letter case). It keeps the document and writes the canonical `off`, `monitor` or `block` the next time it writes the file. Both agent engines accept the same set of spellings.
- The daemon refuses to write a control document larger than the agents read (a large cloud policy used to be written, and the agents then ignored the whole file, mode changes included). It keeps the previous document, logs an error that names the size and the limit, and reports the refusal in `/api/stats`, `/metrics` and the local console. The limit is one value in `java-agent/contracts/agent-daemon/control/limits.properties`, which the daemon and both agent engines test their own constant against. The size is measured on the file as found at start-up: a hand-edited file padded past the limit, which the agents were ignoring, is written again when its document fits (the log and `control_status.oversized_file_replaced` say the agents apply it from then on), and when it does not fit the refusal says the agents are not applying the daemon's in-memory state (`control_status.write_refused.agents_apply_state` is false). A refused cloud policy is logged once per assignment (its id and version, else a hash of its text) and no longer once per document size; the policy version the daemon reports upstream is the installed one, not the refused assignment; and the refusal indicator clears when the cloud's policy becomes the installed one again.
- The daemon no longer reads the backport agents' start line as a detection: it is not counted in the attack log and not uploaded (it was shown as a low-severity "agent event"). It fills the `agent` entry of `/api/stats` instead. A line with a `kind` the daemon does not know is not a detection either; it is counted under `ignored_kinds`, as is a line whose `kind` is present but not a string (under `(non-string)`), which is never read as a detection from its other members. At most 32 distinct kinds are kept (a label is cut to 64 characters, and later kinds are counted under `(other)`), so a spool producer cannot grow the map.
- `/api/stats` reads the control state and the status of its last write in one snapshot.
- The daemon reads the backport agents' numeric epoch-millisecond `timestamp`, so an uploaded detection carries the time it happened and not the time the daemon read it.

### Added
- Shirudo package `ohmyrasp` (`deploy/shirudo/ohmyrasp/`): the universal `ohmyrasp.jar` as one upatch for
  every JVM on a host, Java 8 to 25. It is the default a shirudo operator installs; the per-line packages stay
  for hosts pinned to one Java version, and a second OhMyRASP package on the same host is harmless. Its
  `[upatches.tree]` lists in `fixes` the advisories whose tested exploit path the agent blocks, read from
  `deploy/shirudo/fixes.toml`. `gen-readmes.py --check` fails when an ID has no tracked Vulhub script, is not on
  a checked row of the Vulhub ledger that names the script, or the script lacks a baseline-exploited, a
  protected-not-exploited and a block-event assertion (legacy and setup-boundary scripts are refused).
  `smoke-test.sh` runs the universal JAR on every JDK and on a mixed host that loads every package;
  `verify-shirudo-upatch.sh` checks the launcher entry, all four lines and the baked properties. `ohmyrasp.jar`
  and `ohmyrasp-agent-all.jar` are release assets, and the Beefile bundle carries the new package.
- `deploy/shirudo/gen-readmes.py`: auto-generates `deploy/shirudo/README.md`
  and per-track `ohmyrasp-{java8,java11,java17,jdk25}/README.md` with
  source-derived hook, transformer, algorithm, and Vulhub coverage tables;
  `deploy/shirudo/verify-shirudo-upatch.sh` enforces `--check`.
- `docs/images/architecture.svg`: architectural overview diagram in root READMEs.
- `hook-targets` probe: each packaged agent runs over every class of real versions of the libraries it
  hooks (`java-agent/probes/hook-targets/libraries.toml`, staged by `:stageHookTargets`) and the methods that
  come out calling the agent are compared with a recorded map. A hook that stops matching after a library
  rename now fails the probe. `java-agent/docs/HOOK-TARGETS.md` summarises the map, generated by
  `java-agent/scripts/gen-hook-targets.py`. `check-agent.sh` copies a probe's `--update` output back into
  `java-agent/`.
- Universal Java agent JARs, `ohmyrasp-agent-all.jar` and the Shirudo
  standalone `ohmyrasp.jar` (module `java-agent/agent-all`), holding every
  agent line. Attached to any supported Java, they start the line that fits
  it ([which JAR to attach](docs/agent.md#which-jar-to-attach)). The new
  `launcher` probe checks them on every JDK of the runtime matrix, and
  `probes/run.py --artifact all` (also `check-agent.sh --artifact all`, the
  slow `agent-probes` gate and a second CI pass on each runtime row) runs every
  probe against the universal JAR.
- Rule cases: `java-agent/rules/cases/<rule id>.toml` records inputs per rule id and what the primary and backport engines do with each today; the `rule-cases` probe runs them on every agent line, `java-agent/rules/cases/uncovered.toml` lists the ids without cases and why, and `java-agent/docs/RULE-CASES.md` summarises them and the cases where the engines differ.

### Changed
- The Java 8, 11 and 17 agents decide from one copy of their rules. `Java{8,11,17}RaspHooks` and the three identical `RaspRuntime` copies moved to the `:shared` module (`java-agent/shared/src/main/java/io/ohmyrasp/agent/backport/`: `BackportHooks`, `RaspRuntime`, and `BackportLine`, the line descriptor), compiled for Java 8. Each line keeps its entry class, transformers and block exception, a `Java<N>RaspLine` that names its rule-id prefix, properties, environment variables, threads and log prefix, and a `Java<N>RaspHooks` whose public methods (same names and descriptors) each call the shared method. No behaviour change is intended: rule ids, messages, property and environment names, thread names and the event and control formats are unchanged, and the contract examples compare equal. The entry class now starts the line explicitly before it registers any transformer, and the shared runtime refuses to run before that; the start also loads the shared hook classes and `RaspRuntime.Mode`, which a hook used to load the first time it ran when no mode was configured. The backport JARs have no invokedynamic call site left in the decisions (`check-dynamic-calls.py`: 10 lambda sites per backport line, from 12).
- The default Compose database is PostgreSQL 19. Existing PostgreSQL 18 deployments can follow the [volume migration and rollback procedure](docs/runbooks/upgrade-downgrade.md#postgresql-18-to-19).
- The primary Java agent and standalone `ohmyrasp-jdk25.jar` run on both JDK 21 and 25. JDK 21 downloads are named `ohmyrasp-agent-jdk21.jar` and `ohmyrasp-jdk21.jar`. The `ohmyrasp-jdk21` Shirudo package uses the same standalone binary as `ohmyrasp-jdk25`.
- Documentation overhaul across root guides, navigation (`docs/README.md`),
  `CONTRIBUTING.md`, `SECURITY.md`, and `.github/PULL_REQUEST_TEMPLATE.md` to
  align toolchains, commands, and generated-doc checks with the current tree.

- Java agent development layout. Packaged-agent probes moved from
  `java-agent/scripts/fp-harness/` to one directory each under
  `java-agent/probes/`, with a registry that `java-agent/scripts/check-agent.sh`
  (replaces `check-jdk25.sh`; takes `--line`) and the CI runtime matrix both
  read. Acceptance scripts moved from `java-agent/scripts/acceptance*.sh` to
  `java-agent/acceptance/{runtime,vulhub/<component>}/`. The Java 8, 11 and 17
  agents share one unit-test tree, `java-agent/backport-tests/`. Detection rules
  of `agent-jdk25` moved from `DetectorEngine` to per-family detector classes.
  `scripts/gates.py` lists the checks a change needs.
- CI runs the `sqlite-identifiers` probe on every agent line, not only JDK 25.
- **Java agent (all 4 tracks):** an agent JAR attached to a JVM it does not
  fit is skipped with a `{"event":"ohmyrasp-agent-skipped","reason":"unsupported-java",...}`
  line on `stderr` instead of aborting the JVM. Before, the Java 11, 17 and
  primary JARs stopped an older JVM with `UnsupportedClassVersionError`, and
  the Java 8 JAR stopped Java 11 and later with `NoClassDefFoundError:
  java/sql/DriverManager` (exit code 134). This matters wherever one agent JAR
  reaches JVMs of several versions, such as Shirudo's host-wide
  `JAVA_TOOL_OPTIONS`.
- **Java agent (all 4 tracks):** a failure while an agent line starts no longer
  stops the JVM; it is reported as `"event":"ohmyrasp-agent-start-failed"` on
  `stderr`, and no later JAR or attach starts another line over it. A second
  OhMyRASP JAR or attach in the same JVM starts nothing and reports
  `"reason":"already-active"`; before, two lines could both instrument one JVM.
  Each kind of agent JAR now names its own entry class in
  `io.ohmyrasp.agent.launch` as `Premain-Class` and `Agent-Class`.
- **Java agent (all JARs):** on Java 6 and 7 an agent JAR no longer aborts the
  JVM with `Unsupported major.minor version 52.0`. Its entry class, now
  class-file version 49, prints the `unsupported-java` skip line and the JVM
  starts unprotected.
- The Java agent's shared classes are the `:shared` Gradle module, compiled
  once with `--release 8` instead of once per line.
- The detection counts no longer include primary rule ids that no hook can report. Eighteen ids are marked `not_wired` in `java-agent/rules/general.json`: sixteen have a `OhMyRaspHooks` entry method that no hook module injects (only the playground servlet and one probe's stub servlet call it), `expression_runtime` is the fallback for an engine name no module passes, and `ognl_runtime` is emitted by no code. The README "By the numbers" table, `DETECTION-COVERAGE.md` and the Shirudo READMEs now count 45 detector capabilities (were 60) and 176 algorithm signatures asserted in acceptance scripts (were 190), and `DETECTION-COVERAGE.md` lists the 18 ids in a "Defined, not wired" section with the reason. `docs/detection.md` and `docs/development/algorithm-coverage.md` say so, `uncovered.toml` takes their reason from the catalogue, and `scripts/test_rule_cases.py` fails when the marking and the sources disagree.

### Fixed
- **Java agent (all 4 tracks):** the baked `META-INF/ohmyrasp-shirudo.properties`
  is read only from the agent's own JAR. Before, a same-named file in a JAR on
  the application class path was read in its place and could switch a locked
  `mode=block` agent to `off`. A baked file that is malformed part-way keeps the
  keys read before the malformed line.
- **Java agent (all 4 tracks):** an unrecognised `mode` or `standalone` value in
  one source is skipped and the next source applies, so a mistyped value no
  longer hides a valid `block` and leaves the agent not blocking.
- **Java agent (`java8`/`java11`/`java17`):** the three lines share one runtime.
  On `java11` and `java17`, `lock_config=true` now ignores system properties and
  environment for `standalone`, `mode` and `control` even when a baked key is
  missing, and standalone with no mode configured resolves to `block`. On
  `java8`, the event writer thread starts when the agent loads (only when the
  log target is a file), not inside a hook.
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
