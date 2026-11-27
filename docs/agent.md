# OhMyRASP Java Agent

OhMyRASP instruments running JVMs (JDK 8, 11, 17, 21, and 25) via a `-javaagent` using ASM bytecode transformation, evaluates detections in-process with JVM request and stack context, enforces synchronous block/allow decisions, and reports events asynchronously to a local NDJSON spool or directly to `stderr` in standalone locked mode.

## Runtime tracks and artifacts

Each Gradle subproject below builds a self-contained fat JAR with ASM (`asm` and `asm-commons`, version in each `agent-*/build.gradle.kts`) relocated under `io.ohmyrasp.agent.shaded.asm` via ShadowJar so the agent does not collide with ASM copies bundled by instrumented applications (such as Spring CGLIB, Hibernate, or Struts2).

| Track | Target JVMs | Standard agent task & JAR | Shirudo standalone task & JAR |
|---|---|---|---|
| `agent-all` (universal) | Every supported Java; the launcher starts the line that fits | `:agent-all:agentAllJar`<br>`java-agent/agent-all/build/libs/ohmyrasp-agent-all.jar` | `:agent-all:shirudoUpatchJar`<br>`java-agent/agent-all/build/libs/ohmyrasp.jar` |
| `agent-jdk25` (primary) | Java 21 and 25 (`<= 65`) | `:agent-jdk25:agentJar`<br>`java-agent/agent-jdk25/build/libs/ohmyrasp-agent.jar` | `:agent-jdk25:shirudoUpatchJar`<br>`java-agent/agent-jdk25/build/libs/ohmyrasp-jdk25.jar` |
| `agent-java17` | Java 17 and 21 (`<= 61`) | `:agent-java17:agentJava17Jar`<br>`java-agent/agent-java17/build/libs/ohmyrasp-agent-java17.jar` | `:agent-java17:shirudoUpatchJar`<br>`java-agent/agent-java17/build/libs/ohmyrasp-java17.jar` |
| `agent-java11` | Java 11 (`<= 55`) | `:agent-java11:agentJava11Jar`<br>`java-agent/agent-java11/build/libs/ohmyrasp-agent-java11.jar` | `:agent-java11:shirudoUpatchJar`<br>`java-agent/agent-java11/build/libs/ohmyrasp-java11.jar` |
| `agent-java8` | Java 8 (`<= 52`) | `:agent-java8:agentJava8Jar`<br>`java-agent/agent-java8/build/libs/ohmyrasp-agent-java8.jar` | `:agent-java8:shirudoUpatchJar`<br>`java-agent/agent-java8/build/libs/ohmyrasp-java8.jar` |

All tracks compile with `JavaLanguageVersion.of(25)` using `options.release` set to `21` (`agent-jdk25`, which serves JDK 21 and 25), `17`, `11`, or `8` respectively. The classes every track carries, and the launcher, are the `:shared` module (`java-agent/shared/`), compiled once with `--release 8`, so each JAR holds the same Java 8 bytecode for them. `agent-all` compiles nothing: it packs the four tracks with one copy of the shared classes and of the relocated ASM. No agent JAR names `Boot-Class-Path`: every line's entry class appends the JAR it was started from to the bootstrap search, so OpenJDK 8 bootstrap search also works directly with the sealed `/run/shirudo-java/ohmyrasp-java8.jar` path under the 1024-byte `JAVA_TOOL_OPTIONS` limit. Each backport JAR also carries `META-INF/ohmyrasp/preload/<module>.txt`, written by [`gradle/preload-index.gradle.kts`](../java-agent/gradle/preload-index.gradle.kts): the classes of the module and of `:shared`, and the ASM classes they use, which the line loads before it installs a hook (the universal JAR carries the three lists).

Gradle and the JDK 25 build image (pinned in [`java-agent/Dockerfile`](../java-agent/Dockerfile)) are pinned for reproducible builds. Resolve the image from the Dockerfile the same way CI does:

```bash
GRADLE_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^gradle:/ { print $2; exit }' java-agent/Dockerfile)"

# Build standard primary agent + run unit tests and checks
docker run --rm -v "$PWD/java-agent":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon clean check :agent-jdk25:agentJar

# Build and verify every Shirudo standalone upatch JAR
docker run --rm -v "$PWD/java-agent":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon \
  :agent-java8:verifyShirudoUpatchJar \
  :agent-java11:verifyShirudoUpatchJar \
  :agent-java17:verifyShirudoUpatchJar \
  :agent-jdk25:verifyShirudoUpatchJar \
  :agent-all:verifyAgentAllJars
```

`shirudoUpatchJar` accepts optional Gradle properties `-PshirudoMode=block|monitor` (default `block`) and `-PshirudoLockConfig=true|false` (default `true`); the universal `:agent-all:shirudoUpatchJar` also takes `-PshirudoOutsideRequest=block|log` (default `block`), baked as `outside_request` ([Outside an HTTP request](detection.md#outside-an-http-request)). The `verifyShirudoUpatchJar` task checks the `< 16 MiB` size limit, `Premain-Class` and `OhMyRasp-Shirudo-Upatch: true` manifest headers, baked `META-INF/ohmyrasp-shirudo.properties`, classfile major version bounds, absence of `module-info.class` and `META-INF/versions/`, and absence of `Boot-Class-Path` on `ohmyrasp-java8.jar`. Backport tracks also expose `verifyJava{8,11,17}AgentBytecode`. For the universal pair, `verifyAgentAllJars` checks each class against the class-file version of the module it comes from (the launcher, the shared classes and ASM must load on Java 8), the 16 MiB limit and a single properties file in `ohmyrasp.jar`, and `verifyAgentAllInputs` fails when two modules hold the same class name with different contents. `check` runs all of them.

### Which JAR to attach

Attach the universal JAR, `ohmyrasp-agent-all.jar` (or `ohmyrasp.jar`, the `ohmyrasp` package of [`deploy/shirudo/`](../deploy/shirudo/README.md), for a Shirudo standalone install), on any supported Java. Each kind of agent JAR has an entry class of its own, its `Premain-Class` and `Agent-Class`, that no other kind of JAR holds (generated at build time as Java 5 bytecode by `java-agent/shared/src/entryGenerator`): `io.ohmyrasp.agent.launch.UniversalEntry` in the universal pair, and `PrimaryEntry`, `Java17Entry`, `Java11Entry` and `Java8Entry` in the same package for the per-track pairs. The JVM loads a `Premain-Class` by name, so a name shared by two JARs would make the second JAR run the first one's class. The entry hands itself to the launcher, which opens the JAR that class came from, reads `java.specification.version`, and starts the first line, in this order, that this JAR holds and whose range contains the running version:

| Line | Line entry class | Runs on |
|---|---|---|
| primary (`agent-jdk25`) | `io.ohmyrasp.agent.OhMyRaspAgent` | Java 21 and later |
| `agent-java17` | `io.ohmyrasp.agent.java17.OhMyRaspJava17Agent` | Java 17 and later |
| `agent-java11` | `io.ohmyrasp.agent.java11.OhMyRaspJava11Agent` | Java 11 and later |
| `agent-java8` | `io.ohmyrasp.agent.java8.OhMyRaspJava8Agent` | Java 8 only |

So the universal JAR runs the primary line on Java 21 and 25, the Java 17 line on 17, the Java 11 line on 11 and the Java 8 line on 8. On a version between or after these (for example 18 or 26) it starts the line the table selects and says nothing extra; the probes cover only 8, 11, 17, 21 and 25. No line runs below Java 8 or on Java 9 or 10. A per-track JAR still starts its own line within that line's range: the Java 17 JAR also starts on Java 21 and 25.

One line starts per JVM, whether through `premain` or a later `agentmain` attach. The launcher keeps the state in a static field of `io.ohmyrasp.agent.launch.AgentLauncher`: unset, `starting`, then `installed:<line>` or `failed:<line>`. A JVM can define that class more than once (a line appends its JAR to the bootstrap search, and a bootstrap-defined entry then resolves its own copy), so before it starts a line the launcher reads the state of every loaded definition, through `Instrumentation.getAllLoadedClasses()`, while holding one lock all definitions share. It publishes the state as the system property `ohmyrasp.agent.state` and, once a line has started, the line as `ohmyrasp.agent.line`, for operators and probes to read. It never reads them back, so setting them on the command line changes nothing.

The launcher never stops the JVM. In each of these cases it writes one JSON line to standard error and the application starts:

- **The JAR holds no line that fits the running Java** (a per-track JAR on an older or a newer JVM than it supports, or any JAR on Java 9 or 10). The state stays unset, so a later JAR that fits still starts. Before, the JVM aborted with exit code 134 (`UnsupportedClassVersionError`, or `NoClassDefFoundError: java/sql/DriverManager` from the Java 8 track on Java 11 and later).
  `{"event":"ohmyrasp-agent-skipped","reason":"unsupported-java","java_version":"25.0.1","lines":"java8","jar":"ohmyrasp-agent-java8.jar"}`
- **Java 6 or 7.** The entry classes are class-file version 49 (Java 5) and load there, but the launcher is Java 8 bytecode. The entry catches the error and prints the skip line itself, with the Java specification version, its own class name and the error's class, and the JVM starts unprotected. Before, the JVM aborted with `Unsupported major.minor version 52.0`.
  `{"event":"ohmyrasp-agent-skipped","reason":"unsupported-java","java_version":"1.6","entry":"io.ohmyrasp.agent.launch.Java8Entry","exception":"java.lang.UnsupportedClassVersionError"}`
- **A line already started or is starting**, for example when Shirudo and the command line each add one of our JARs, or an attach follows `-javaagent`. Before, two lines could both instrument one JVM.
  `{"event":"ohmyrasp-agent-skipped","reason":"already-active","java_version":"25.0.1","state":"installed:primary"}`
- **The line throws while starting**, including a `LinkageError`. Protection is then inactive or incomplete: the line may have installed some of its hooks. No later JAR or attach starts another line over it, and each says `"reason":"earlier-start-failed"`. Before, the exception aborted the JVM.
  `{"event":"ohmyrasp-agent-start-failed","line":"java8","protection":"inactive or incomplete","java_version":"1.8.0_472","exception":"java.lang.NoClassDefFoundError","message":"..."}`

With two JARs that hold the same line, the line's classes, and the baked `META-INF/ohmyrasp-shirudo.properties` they read, come from the first of them on the class path: the line entry class is loaded by name through the system class loader, and both properties readers locate the file through that class's code source. Attach `ohmyrasp.jar` first when it should govern. A same-named properties file on the application class path is never read. A JAR on the application class path that holds an entry class or a line class of ours wins over the attached agent JAR, which the JVM appends to the end of the class path, so whoever sets the JVM's class path or options can replace or disable the agent, a locked `ohmyrasp.jar` included ([known limitations](detection.md#known-limitations)). The `launcher` probe under `java-agent/probes/` checks each of these cases on every JDK of the runtime matrix.

## Architecture and module layout

### Primary module (`agent-jdk25`)

Under `java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/`:

- **`OhMyRaspAgent`:** `premain` / `agentmain` entry point. Appends the agent JAR to the bootstrap classloader search (`Instrumentation.appendToBootstrapClassLoaderSearch`) and reflectively invokes `BootstrapAgent.start` on the bootstrap loader (`ClassLoader == null`) so JDK classes like `ProcessBuilder` and `Base64$Decoder` can resolve hook classes directly.
- **`BootstrapAgent`:** Starts `AgentRuntime`, optionally starts `ControlPlaneClient` when `cloud_direct=true` is enabled and not suppressed by `standalone`/`lock_config`, initialises `JsonEventLogger` and the hooks' static state, then registers `OhMyRaspTransformer` and retransforms already-loaded target classes. No hook starts the event writer or registers its shutdown hook.
- **`asm/` (`HookRegistry`, `OhMyRaspTransformer`, `HookClassVisitor`, `SqlCallsiteClassVisitor`, `*HookModule`):** `HookRegistry.defaults()` registers every `HookModule` implementation (see [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md) for the generated module table). `OhMyRaspTransformer` skips agent/ASM/reflection internals and non-target JDK classes (`isJdkClass(name) && !registry.isDirectTarget(name)`), expanding frames with `ClassReader.EXPAND_FRAMES` and rewriting call sites with `COMPUTE_MAXS`.
- **`detect/`:** One detector class per rule family, each exposing the `detect*` methods that its hooks call. Together they implement signature classification, request-parameter substring correlation (`RequestContext.hasParameterIn`), `StackWalker` frame inspection, six-form path-confusion decoding, SQL syntax analysis, and CVE-2026-114938 Base64 tail-underflow checks. `DetectorEngine` runs the HTTP request chain in a fixed first-match order. [`detection.md`](detection.md#primary-agent-detector-layout) maps each kind of evidence to its class. See also [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md).
- **`hook/` (`OhMyRaspHooks`, `DeserializationGuard`, `OhMyRaspBlockException`):** Static hook entry points invoked by instrumented bytecode. Manages `ThreadLocal<RequestContext>`, evaluates `AgentPolicy`, applies `AgentRuntime` mode, `outside_request` and per-algorithm switches, logs detections, sends HTTP redirects to `/rasp/blocked` when a servlet response is active, and throws `OhMyRaspBlockException` when blocking. Once a detection is decided as a block, the exception is thrown even when recording the event or the redirect fails; only the event, or the redirect, is lost.
- **`runtime/` (`AgentRuntime`, `DetectionMode`, `ShirudoDefaults`, `AgentOwnIo`):** Holds the control state, the control-file poller (`ohmyrasp-control-poller` daemon thread), and the baked `META-INF/ohmyrasp-shirudo.properties` loader. The control state is the active `DetectionMode` (`off`, `monitor`, `block`), whether a finding outside an HTTP request blocks (`outside_request`), the per-algorithm overrides, the revision and the installed policy with the source that installed it, published together atomically as one immutable `ControlState`, so a reader of one snapshot never sees a restored mode next to a stale switch or policy. The final decision in a hook reads one snapshot, but some hooks also read the mode or a switch earlier on their own path (the JAAS hook checks its switch before that decision), so a control change between the two reads can reach only the second. `AgentOwnIo` marks the agent's own event writes (spool file and console) and control-file reads on the current thread. While it is set the hooks neither report nor block, and the file hooks that this I/O reaches check the mark before they inspect it, so a log or control path that matches a file rule cannot re-enter the hooks or use up state the application's next file operation needs. Not marked: the start-up line and the agent's error messages on `stdout`/`stderr`, and the direct-cloud client's network traffic. File I/O that application code performs from a replaced `System.out` or `System.err` while the agent prints an event runs on the marked thread and is hidden as well.
- **`log/JsonEventLogger`:** Emits NDJSON detection events and periodic `hook_latency` telemetry (`latency_us`) while redacting sensitive headers, sensitive parameters, and executable-source parameters. The `request.query` string is redacted as well: it is split once on `&` only (a `;` stays inside its piece, as Tomcat reads it), and a piece that, or whose decoding (percent escapes and `+`, up to 8 rounds; a piece still changing after that counts as sensitive), holds one of those parameter names as a token (a run of ASCII letters, digits and underscores, so `user[password]` and `{"password":"x"}` match and `passwordless` does not) keeps its name and gets the marker as its value, or is replaced as a whole when it has no plain `name=` in front. Separators and order stay. A query longer than 8192 characters is not scanned and becomes the marker. The direct-cloud client uploads the same redacted query. For file targets, a bounded `ArrayBlockingQueue` (capacity `max(256, ohmyrasp.log.queue)`, default `8192`) feeds a background daemon writer thread (`ohmyrasp-event-writer`). At JVM shutdown a hook stops the writer, waits up to 2 seconds for it to finish the batch it holds, then writes what is still queued, waiting up to 1 second for the write lock; an event submitted after that is written on the submitting thread. These are bounded waits, and events accepted while the JVM is shutting down may be lost: for example the batch of a writer stalled in an output call (a blocked `stdout` pipe), and the queued events that cannot get the write lock it holds. No event is written twice. Console output is written while the logger holds its write lock, so an application that replaces `System.out` or `System.err` with a stream that takes its own lock can deadlock with a thread that logs while holding that lock. Events dropped under sustained saturation are counted in `droppedCount()`. Setting `ohmyrasp.log.sync=true` (`OHMYRASP_LOG_SYNC=true`) forces inline file writes and disables periodic latency sampling for deterministic CI and acceptance runs.
- **`policy/` (`AgentPolicy`, `PolicyEvaluation`, `PolicyRule`, `SimpleJson`):** Evaluates distributed JSON policy rules locally without external JSON parser dependencies.
- **`control/` (`ControlPlaneClient`, `ControlPlaneConfig`):** Legacy direct-cloud HTTP client (registration, heartbeats, policy sync, crash and event upload). Off by default.

### Backport modules (`agent-java8`, `agent-java11`, `agent-java17`)

Each backport track lives under `java-agent/agent-java{8,11,17}/src/main/java/io/ohmyrasp/agent/java{8,11,17}/` and depends only on ASM and the `:shared` module. Its decisions and runtime are one copy for the three tracks, in the `:shared` module's `io.ohmyrasp.agent.backport` package, compiled for Java 8:

- `OhMyRaspJava{8,11,17}Agent`: entry point (`premain`/`agentmain`) and transformer registration.
- `Java{8,11,17}*Transformer` classes covering the algorithm signatures listed in [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md).
- `Java{8,11,17}RaspHooks`: the class the transformers inject calls to. Each public method is a one-line call to the method of the same name in `BackportHooks`.
- `Java{8,11,17}RaspLine` and `Java{8,11,17}RaspBlockException`: the line descriptor (a `BackportLine`: the line's rule-id prefix, property, environment and thread names, log prefix, and how to make and recognise its block exception) and the exception a block throws.
- `BackportHooks` (shared): the hook and detection logic, the per-thread request state and the event text.
- `RaspRuntime` (shared): mirrors `AgentRuntime` + `JsonEventLogger` using only Java 8 APIs, including `META-INF/ohmyrasp-shirudo.properties` support, async file spooling, and `control.json` polling.

Detector false-positive-suppression parity between `BackportHooks` and `agent-jdk25`'s `detect/` package is enforced by [`check-detector-parity.sh`](../java-agent/scripts/check-detector-parity.sh).

## Runtime modes and configuration

### Operating modes

1. **Host-daemon mode (default):** The agent makes no outbound network connections. It appends NDJSON events to `/tmp/ohmyrasp-events.jsonl` and polls `/tmp/ohmyrasp-control.json` every `2000` ms (`control_poll_ms`, floor `200` ms) for live updates written by the companion host daemon ([`../daemon/README.md`](../daemon/README.md)):
   ```json
   { "mode": "monitor", "outside_request": "block", "algorithms": { "sql_userinput": false }, "revision": 3 }
   ```
   On `agent-jdk25` a `"policy"` string field in `control.json` is also parsed with `AgentPolicy.parse` and installed whenever its contents change. A document whose `policy` is absent, null or blank drops a policy the control file installed (the daemon withdraws a policy that way); a policy the direct-cloud client installed stays. Policy text that does not parse changes nothing and is not recorded as applied, so it cannot make the file's unchanged policy look new and reinstall it over a later direct-cloud policy.

   Every line reads the control file on each poll and applies it when its content differs from the content last applied; the modification time is not consulted. Only well-formed content counts: at most 1 MiB (the reader reads at most one byte past that bound, which tells a larger file apart; the daemon keeps to the same limit when it writes the file, see [`limits.properties`](../java-agent/contracts/agent-daemon/control/limits.properties)), strict UTF-8 with no byte-order mark, and exactly one JSON object in the RFC 8259 grammar with containers nested at most 64 deep. That means JSON whitespace only, no raw control characters in strings, backslash-u escapes of four ASCII hex digits, and no numbers such as `01`, `.5` or `1.`. On `agent-jdk25` the object must also be readable by its `SimpleJson` parser, which rejects integers outside the 64-bit range. `mode` is read from the top level only: truncated text, a `mode` inside a nested object or string, or an unrecognised `mode` value changes nothing, and content that fails these checks is not recorded, so a document read half-written is applied once it is complete. Every line also reads the top-level `outside_request` (`block` or `log`, any letter case, padding ignored): whether a finding outside an HTTP request blocks ([Outside an HTTP request](detection.md#outside-an-http-request)). A document without it, or with null, sets the start-up value; a value nobody accepts changes nothing. The control file overrides the start-up settings only while it exists. When it is removed, everything it set returns to its start-up value at once: the mode and `outside_request` on every line, and on `agent-jdk25` also the per-algorithm switches (all enabled), the revision and a policy the control file installed (start-up has none), so an `ignore` rule from a removed file stops suppressing detections. A policy the direct-cloud client (`cloud_direct=true`) installed is not the control file's and stays: the last source to install a policy owns it, and a control file that comes back installs its policy again. When the file exists but cannot be read or parsed, the last good settings stay: the daemon replaces it atomically (temp file and rename), so such a read is transient. Nothing thrown while the file is read or applied leaves the poll step, an `Error` from a file system provider included, so the first read, made while the agent starts, cannot stop the application's start-up. The read itself is a blocking call: a control file on a file system that stalls (a hung network or FUSE mount) holds up that first read, and with it the agent's start-up, until the file system answers.
2. **Standalone mode (`standalone=true`):** Disables legacy direct-cloud reporting and control-file polling on every line, whatever control path is set. When `mode` is unset, standalone defaults to `block`; `log` defaults to `stderr`; and `latency_sample` defaults to `0`.
3. **Shirudo daemonless locked mode (`META-INF/ohmyrasp-shirudo.properties`):** Used by `shirudoUpatchJar` packages (`ohmyrasp-{java8,java11,java17,jdk25}.jar`) for target-side attachment via `/run/shirudo-java/<name>.jar`. Baked properties are:
   ```properties
   standalone=true
   lock_config=true
   mode=block
   control=none
   log=stderr
   latency_sample=0
   ```
   The universal `ohmyrasp.jar` also bakes `outside_request` (`block` unless built with `-PshirudoOutsideRequest=log`); the per-line JARs bake none, which means `block`. When `lock_config=true`, `standalone`, `mode`, `outside_request` and `control` come only from the baked `META-INF/ohmyrasp-shirudo.properties`. A missing `standalone`, `mode` or `outside_request` there takes its default. A missing or invalid `control` disables control polling on every line. A baked control path is polled, the default `/tmp/ohmyrasp-control.json` included when that is the path baked, unless `standalone=true`, which never polls. `ohmyrasp.mode`/`OHMYRASP_MODE`, `ohmyrasp.outside_request`/`OHMYRASP_OUTSIDE_REQUEST`, `ohmyrasp.control`/`OHMYRASP_CONTROL` and `ohmyrasp.standalone`/`OHMYRASP_STANDALONE` are ignored, and `lock_config` itself cannot be set from outside the JAR. It does not hold against whoever controls the JVM's class path: see [known limitations](detection.md#known-limitations). `log` and `latency_sample` stay overridable through the usual sources below. The baked `control=none` starts no control-poller thread. A file-writer thread is started only when the log target resolved at agent start is a file, so the baked `log=stderr` starts none. `cloud_direct` is unconditionally suppressed. Every line reads the baked resource only from the agent's own JAR: a same-named file in a JAR on the application class path is ignored. If the resource is malformed part-way, the keys before the malformed line still apply. An invalid value in one source is skipped and the next source applies, so a mistyped higher-priority value does not hide a valid `block`; [Configuration keys](#configuration-keys) lists the settings this covers. See [`../deploy/shirudo/README.md`](../deploy/shirudo/README.md).
4. **Legacy direct-cloud mode (`cloud_direct=true`):** Enables `ControlPlaneClient` inside the JVM to register, heartbeat, pull policies, and upload events directly to the Go control plane. Ignored when `standalone=true` or `lock_config=true`.

### Detection modes

| Mode | Tokens accepted by `DetectionMode.parse` | Behavior |
|---|---|---|
| `off` | `off`, `disabled`, `none` | Short-circuits hook entry points before detectors run; no logging or blocking |
| `monitor` | `monitor`, `record`, `observe`, `log` | Evaluates detectors and records events (rewriting `block` action to `monitor`), never blocks |
| `block` | `block`, `blocking`, `protect` | Evaluates detectors, records events, redirects active HTTP responses to `/rasp/blocked`, and throws block exception |
| *(unset)* | *(no mode set)* | Legacy mode: permits blocking when policy or legacy block flags request it (or defaults to `block` when `standalone=true`) |

### Configuration keys

In `agent-jdk25`, `AgentRuntime` and `ControlPlaneConfig` resolve settings in order: `-javaagent` argument (`key=value`, `.` and `-` normalized to `_`, `,` or `;` separated) -> Java system property (`-D...`) -> environment variable -> `META-INF/ohmyrasp-shirudo.properties` -> default. `JsonEventLogger` resolves `ohmyrasp.log` from agent arg `log`, then `-Dohmyrasp.log`, then `OHMYRASP_LOG`, then baked defaults; `ohmyrasp.log.sync` and `ohmyrasp.log.queue` use system properties or env vars. The logger's standalone defaults (`stderr`, `latency_sample=0`) follow the `standalone` value `AgentRuntime` resolved. For `mode`, `outside_request`, `standalone`, the control path, `control_poll_ms`, `latency_sample`, `ohmyrasp.log.sync` and `ohmyrasp.log.queue`, each source is parsed on its own and the first valid value wins: an unrecognised mode or boolean, a poll interval, sample rate or queue size that is not a number, or a control value that is not a valid path is skipped. The legacy block flag `ohmyrasp.block`/`OHMYRASP_BLOCK` is on when either source is `true`.

| Setting | `-javaagent` arg (`agent-jdk25`) | System property | Environment variable | Default |
|---|---|---|---|---|
| Detection mode | `mode` | `ohmyrasp.mode` | `OHMYRASP_MODE` | unset (`block` if `standalone=true`) |
| Outside an HTTP request: `block` or `log` | `outside_request` | `ohmyrasp.outside_request` | `OHMYRASP_OUTSIDE_REQUEST` | `block` |
| Standalone mode | `standalone` | `ohmyrasp.standalone` | `OHMYRASP_STANDALONE` | `false` |
| Control file path | `control` | `ohmyrasp.control` | `OHMYRASP_CONTROL` | `/tmp/ohmyrasp-control.json` (no polling if `standalone=true`) |
| Control poll interval (ms) | `control_poll_ms` | `ohmyrasp.control.poll_ms` | `OHMYRASP_CONTROL_POLL_MS` | `2000` (min `200`) |
| Event log target | `log` | `ohmyrasp.log` | `OHMYRASP_LOG` | `/tmp/ohmyrasp-events.jsonl` (`stderr` if `standalone=true`) |
| Synchronous file logging | - | `ohmyrasp.log.sync` | `OHMYRASP_LOG_SYNC` | `false` |
| Async log queue size | - | `ohmyrasp.log.queue` | `OHMYRASP_LOG_QUEUE` | `8192` (min `256`) |
| Latency telemetry sample (1-in-N) | `latency_sample` | `ohmyrasp.latency_sample` | `OHMYRASP_LATENCY_SAMPLE` | `10` (`0` if `standalone=true` or `log.sync=true`) |
| Direct cloud upload (legacy) | `cloud_direct` | `ohmyrasp.cloud.direct` | `OHMYRASP_CLOUD_DIRECT` | `false` |
| Control plane URL (legacy) | `backend_url` | `ohmyrasp.backend_url` | `OHMYRASP_BACKEND_URL` | `""` |
| App ID (legacy) | `app_id` | `ohmyrasp.app_id` | `OHMYRASP_APP_ID` | `""` |
| App secret (legacy) | `app_secret` | `ohmyrasp.app_secret` | `OHMYRASP_APP_SECRET` | `""` |
| Environment ID (legacy) | `environment_id` | `ohmyrasp.environment_id` | `OHMYRASP_ENVIRONMENT_ID` | `""` |
| Hostname (legacy) | `hostname` | `ohmyrasp.hostname` | `OHMYRASP_HOSTNAME` | `InetAddress.getLocalHost()` |
| Runtime label (legacy) | `runtime` | `ohmyrasp.runtime` | `OHMYRASP_RUNTIME` | `java` |
| Version label (legacy) | `version` | `ohmyrasp.version` | `OHMYRASP_VERSION` | JAR implementation version |
| Legacy block flag | - | `ohmyrasp.block` | `OHMYRASP_BLOCK` | `false` |
| Force block flag | - | `ohmyrasp.force_block` | `OHMYRASP_FORCE_BLOCK` | `false` |
| Debug stderr logging | - | `ohmyrasp.debug` | - | `false` |

Backport modules (`agent-java8`, `agent-java11`, `agent-java17`) read system properties, environment variables, and `META-INF/ohmyrasp-shirudo.properties` via `RaspRuntime` (not `-javaagent` arguments). They also accept track-specific overrides `ohmyrasp.java{8,11,17}.log` and `ohmyrasp.java{8,11,17}.block` / `OHMYRASP_JAVA{8,11,17}_BLOCK`. On these lines:

- An invalid value in one source is ignored and the next source applies, so a malformed `-Dohmyrasp.mode` does not mask `OHMYRASP_MODE=block`. This holds for mode, `outside_request`, standalone, latency sample, the control path (a value that is not a valid path), the poll interval, `ohmyrasp.log.sync`, and the legacy flag `ohmyrasp.java{8,11,17}.block` / `OHMYRASP_JAVA{8,11,17}_BLOCK`, which takes the same boolean tokens as the other flags (`true`/`1`/`yes`/`on`, `false`/`0`/`no`/`off`).
- Control polling runs when `standalone` is off and the resolved control path is not `none`, `off` or `disabled`. As on the primary agent, standalone mode never polls, so `-Dohmyrasp.control=<path>` or a baked `control` does not start a poller there. With `lock_config` on, only a baked control path is polled.
- A queued event is written to the log target it was accepted for, even when the target changes before the writer drains it.
- `META-INF/ohmyrasp-shirudo.properties` is read only from the agent's own JAR; a same-named resource elsewhere on the class path is ignored. A malformed one does not stop the agent: the keys before the malformed line apply and the rest are ignored.
- With no log setting and `standalone` off, events go to `stderr`, not to `/tmp/ohmyrasp-events.jsonl`.
- Before it installs any hook, on the thread that runs `premain` or `agentmain`, the agent entry point appends its JAR to the bootstrap search and checks that the classes the start is about to use (the line descriptor, `BackportLine`, `RaspRuntime`, `BackportHooks`, the line's hooks class and `Preload`) are the ones the bootstrap loader defined, which the injected calls reach. If the append fails, or one of them was already defined by another loader (the agent JAR is also on the application class path and the application used the line's classes there before an attach), the start fails before anything is started or registered, naming the class and its loader; the launcher reports `ohmyrasp-agent-start-failed` and the JVM runs unprotected. It then resolves the JDK types the transformers need outside `java.base` and loads and initialises every class of ours that a hook or a transformer can use, from the JAR's preload list, so no hook loads one inside an instrumented JDK call; the `rule-cases` probe fails a case on a backport line when a class of the agent loads during its operation. Last, it starts the line (`Java{8,11,17}RaspLine.start()`: it installs the line descriptor and starts `RaspRuntime`) and registers its transformers. A failure after the start (registering a transformer, setting up the retransformation) removes the transformers registered so far and stops the runtime (its threads stopped, its shutdown hook removed, the hooks inactive) before the launcher reports the failure. A hook reached before the start, or after such a stop, returns without doing anything.
- The start is all or nothing. The first control-file read and the shutdown-hook registration come before the poller thread (`ohmyrasp-java{8,11,17}-control`, only if polling is on) and the event-writer thread (`ohmyrasp-java{8,11,17}-writer`, only if the log target at that moment is a file) start, and the runtime counts as started only once both have. If starting one fails, the threads already started are stopped, the shutdown hook is removed, and a later start begins again. The shutdown hook takes the start's lock: a hook that runs during a start waits for it and then closes a fully started runtime, and no start succeeds once it has run. A target that becomes a file later is written inline on the request thread. At JVM shutdown a hook stops the writer, waits up to 2 seconds for the batch it holds, then writes what is still queued, waiting up to 1 second for the write lock; an event offered after that is written on the hook's thread. As on `agent-jdk25` these are bounded waits, and events accepted while the JVM is shutting down may be lost or written out of order: an event written inline once shutdown has begun can reach the file before queued events the hook is still writing. A failure while an event is recorded never replaces a block. Known limits of these bounded waits: a thread is waited for 2 seconds when the runtime stops it, so a poller stuck in an uninterruptible file-system call (a hung network mount) can outlive the stop; a writer blocked on a full pipe (`stdout` read by nobody) holds the write lock until shutdown gives up on it and drops what is queued, and the shutdown hook's own write to that pipe can block as well, since the timeout bounds only taking the lock.
- In monitor mode a hook logs a finding once until it logs a different value for the same kind of finding on the same thread, so an immediate repeat inside a request is one event. The memory is cleared when the outermost request on the thread enters and when it exits: the same attack in the next request served by that thread is logged again. Outside a request (a background worker, which never enters one), an identical consecutive finding is suppressed only within one second of the thread's last logged finding. The same logical request can be reported more than once when it is redispatched (asynchronous or error dispatch after the outer frame has exited): that over-reporting is accepted. Blocked findings are always written.
- `RaspRuntime` marks its own event writes and control-file reads on the current thread, as `AgentOwnIo` does on `agent-jdk25`, with the same exceptions: the hooks neither report nor block them, and the file hooks this I/O reaches check the mark before they inspect it. Two things still run under the mark: the `.plot` output-stream tracker records and scans an agent-written stream before its check (without reporting or blocking it), and file I/O that an installed `SecurityManager` performs from its `checkWrite` callback during an agent write is hidden as well. [`own-writes`](../java-agent/probes/own-writes/check.py) checks this on every packaged line with a `.jsp` spool in a web root.

[`Java8ShirudoStandaloneTest`](../java-agent/backport-tests/src/test/java/io/ohmyrasp/agent/backport/Java8ShirudoStandaloneTest.java), [`Java8RuntimeControlTest`](../java-agent/backport-tests/src/test/java/io/ohmyrasp/agent/backport/Java8RuntimeControlTest.java) and [`Java8EventSpoolTest`](../java-agent/backport-tests/src/test/java/io/ohmyrasp/agent/backport/Java8EventSpoolTest.java) pin these rules on all three lines.

### Hooks that read application objects

A few hooks ask an application object for text through reflection: the source of a Java compilation unit (`getCharContent(true)`), the text of an expression object, the system id of an XML source, the request URI of a wrapped servlet request. The call is made on the hook's thread, on a public type of the object's hierarchy, so it runs application code. For a compilation unit the consequence is that the agent reads the source once before javac does: a file object that fetches its source lazily blocks the hook until it has it, and a one-shot supplier is consumed before the compiler reads it. Neither the primary agent nor the backports guard against this, and none is planned: reading the text is how the rule sees the source.

## Comparative playground and acceptance verification

From `java-agent/`, [`docker-compose.yml`](../java-agent/docker-compose.yml) runs baseline/protected Tomcat pairs on JDK 25 with the comparative playground WAR (`playground` for Jakarta on Tomcat 10/11, `playground-javax` for Javax on Tomcat 9):

- Tomcat 9: `http://localhost:18080/rasp/ui` (baseline), `http://localhost:18081/rasp/ui` (protected)
- Tomcat 10: `http://localhost:18082/rasp/ui` (baseline), `http://localhost:18083/rasp/ui` (protected)
- Tomcat 11: `http://localhost:18084/rasp/ui` (baseline), `http://localhost:18085/rasp/ui` (protected)

The `/rasp/labs` view loads archived Java range scenarios from [`archived-java-ranges.json`](../java-agent/playground/src/main/resources/ohmyrasp/labs/archived-java-ranges.json). Protected containers write events to `logs/tomcat{9,10,11}-protected/events.jsonl`. [`docker-compose.daemon.yml`](../java-agent/docker-compose.daemon.yml) pairs Tomcat 11 (`18090`) with the host daemon console (`7070`) over a shared spool/control volume.

End-to-end verification scripts in `java-agent/acceptance/`:

```bash
# Tomcat 11 -> 10 -> 9 baseline/protected suite (JDK 25)
bash java-agent/acceptance/runtime/jdk25.sh

# Backport Tomcat compatibility matrices (baseline + protected)
bash java-agent/acceptance/runtime/java8.sh     # Tomcat 10.0, 9, 8.5
bash java-agent/acceptance/runtime/java11.sh    # Tomcat 10.1, 9
bash java-agent/acceptance/runtime/java17.sh    # Tomcat 11, 10.1, 9
bash java-agent/acceptance/runtime/java21.sh    # agent-java17 on Temurin 21 (Tomcat 11, 10, 9)

# Vulhub CVE replay scripts (individual per-CVE scripts)
ls java-agent/acceptance/vulhub/*/*.sh

# Regenerate coverage and false-positive reports
python3 java-agent/scripts/gen-detection-coverage.py --check
bash java-agent/scripts/run-fp-report.sh
```
