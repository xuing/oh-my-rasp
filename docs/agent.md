# OhMyRASP Java Agent

OhMyRASP instruments running JVMs (JDK 8, 11, 17, 21, and 25) via a `-javaagent` using ASM bytecode transformation, evaluates detections in-process with JVM request and stack context, enforces synchronous block/allow decisions, and reports events asynchronously to a local NDJSON spool or directly to `stderr` in standalone locked mode.

## Runtime tracks and artifacts

Each Gradle subproject below builds a self-contained fat JAR with ASM (`asm` and `asm-commons`, version in each `agent-*/build.gradle.kts`) relocated under `io.ohmyrasp.agent.shaded.asm` via ShadowJar so the agent does not collide with ASM copies bundled by instrumented applications (such as Spring CGLIB, Hibernate, or Struts2).

| Track | Target JVMs | Standard agent task & JAR | Shirudo standalone task & JAR |
|---|---|---|---|
| `agent-jdk25` (primary) | Java 21 and 25 (`<= 65`) | `:agent-jdk25:agentJar`<br>`java-agent/agent-jdk25/build/libs/ohmyrasp-agent.jar` | `:agent-jdk25:shirudoUpatchJar`<br>`java-agent/agent-jdk25/build/libs/ohmyrasp-jdk25.jar` |
| `agent-java17` | Java 17 and 21 (`<= 61`) | `:agent-java17:agentJava17Jar`<br>`java-agent/agent-java17/build/libs/ohmyrasp-agent-java17.jar` | `:agent-java17:shirudoUpatchJar`<br>`java-agent/agent-java17/build/libs/ohmyrasp-java17.jar` |
| `agent-java11` | Java 11 (`<= 55`) | `:agent-java11:agentJava11Jar`<br>`java-agent/agent-java11/build/libs/ohmyrasp-agent-java11.jar` | `:agent-java11:shirudoUpatchJar`<br>`java-agent/agent-java11/build/libs/ohmyrasp-java11.jar` |
| `agent-java8` | Java 8 (`<= 52`) | `:agent-java8:agentJava8Jar`<br>`java-agent/agent-java8/build/libs/ohmyrasp-agent-java8.jar` | `:agent-java8:shirudoUpatchJar`<br>`java-agent/agent-java8/build/libs/ohmyrasp-java8.jar` |

All tracks compile with `JavaLanguageVersion.of(25)` using `options.release` set to `21` (`agent-jdk25`, which serves JDK 21 and 25), `17`, `11`, or `8` respectively. In [`agent-java8/build.gradle.kts`](../java-agent/agent-java8/build.gradle.kts), `agentJava8Jar` sets `Boot-Class-Path: ohmyrasp-agent-java8.jar`, while `shirudoUpatchJar` omits `Boot-Class-Path` so OpenJDK 8 bootstrap search works directly with the sealed `/run/shirudo-java/ohmyrasp-java8.jar` path under the 1024-byte `JAVA_TOOL_OPTIONS` limit.

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
  :agent-jdk25:verifyShirudoUpatchJar
```

`shirudoUpatchJar` accepts optional Gradle properties `-PshirudoMode=block|monitor` (default `block`) and `-PshirudoLockConfig=true|false` (default `true`). The `verifyShirudoUpatchJar` task checks the `< 16 MiB` size limit, `Premain-Class` and `OhMyRasp-Shirudo-Upatch: true` manifest headers, baked `META-INF/ohmyrasp-shirudo.properties`, classfile major version bounds, absence of `module-info.class` and `META-INF/versions/`, and absence of `Boot-Class-Path` on `ohmyrasp-java8.jar`. Backport tracks also expose `verifyJava{8,11,17}AgentBytecode`.

## Architecture and module layout

### Primary module (`agent-jdk25`)

Under `java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/`:

- **`OhMyRaspAgent`:** `premain` / `agentmain` entry point. Appends the agent JAR to the bootstrap classloader search (`Instrumentation.appendToBootstrapClassLoaderSearch`) and reflectively invokes `BootstrapAgent.start` on the bootstrap loader (`ClassLoader == null`) so JDK classes like `ProcessBuilder` and `Base64$Decoder` can resolve hook classes directly.
- **`BootstrapAgent`:** Wires `AgentRuntime`'s policy installer callback (`AgentPolicy.parse`), starts `AgentRuntime`, optionally starts `ControlPlaneClient` when `cloud_direct=true` is enabled and not suppressed by `standalone`/`lock_config`, registers `OhMyRaspTransformer`, and retransforms already-loaded target classes.
- **`asm/` (`HookRegistry`, `OhMyRaspTransformer`, `HookClassVisitor`, `SqlCallsiteClassVisitor`, `*HookModule`):** `HookRegistry.defaults()` registers every `HookModule` implementation (see [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md) for the generated module table). `OhMyRaspTransformer` skips agent/ASM/reflection internals and non-target JDK classes (`isJdkClass(name) && !registry.isDirectTarget(name)`), expanding frames with `ClassReader.EXPAND_FRAMES` and rewriting call sites with `COMPUTE_MAXS`.
- **`detect/DetectorEngine`:** Exposes the `detect*` methods implementing signature classification, request-parameter substring correlation (`RequestContext.hasParameterIn`), `StackWalker` frame inspection, six-form path-confusion decoding, SQL syntax analysis, and CVE-2026-114938 Base64 tail-underflow checks. See [`detection.md`](detection.md) and [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md).
- **`hook/` (`OhMyRaspHooks`, `DeserializationGuard`, `OhMyRaspBlockException`):** Static hook entry points invoked by instrumented bytecode. Manages `ThreadLocal<RequestContext>`, evaluates `AgentPolicy`, applies `AgentRuntime` mode and per-algorithm switches, logs detections, sends HTTP redirects to `/rasp/blocked` when a servlet response is active, and throws `OhMyRaspBlockException` when blocking.
- **`runtime/` (`AgentRuntime`, `DetectionMode`, `ShirudoDefaults`):** Holds the active `DetectionMode` (`off`, `monitor`, `block`), per-algorithm overrides, control-file poller (`ohmyrasp-control-poller` daemon thread), and baked `META-INF/ohmyrasp-shirudo.properties` loader.
- **`log/JsonEventLogger`:** Emits NDJSON detection events and periodic `hook_latency` telemetry (`latency_us`) while redacting sensitive headers, sensitive parameters, and executable-source parameters. For file targets, a bounded `ArrayBlockingQueue` (capacity `max(256, ohmyrasp.log.queue)`, default `8192`) feeds a background daemon writer thread (`ohmyrasp-event-writer`) with a JVM shutdown drain hook. Events dropped under sustained saturation are counted in `droppedCount()`. Setting `ohmyrasp.log.sync=true` (`OHMYRASP_LOG_SYNC=true`) forces inline file writes and disables periodic latency sampling for deterministic CI and acceptance runs.
- **`policy/` (`AgentPolicy`, `PolicyEvaluation`, `PolicyRule`, `SimpleJson`):** Evaluates distributed JSON policy rules locally without external JSON parser dependencies.
- **`control/` (`ControlPlaneClient`, `ControlPlaneConfig`):** Legacy direct-cloud HTTP client (registration, heartbeats, policy sync, crash and event upload). Off by default.

### Backport modules (`agent-java8`, `agent-java11`, `agent-java17`)

Each backport track is self-contained under `java-agent/agent-java{8,11,17}/src/main/java/io/ohmyrasp/agent/java{8,11,17}/` with no shared runtime library dependency:

- `OhMyRaspJava{8,11,17}Agent`: entry point (`premain`/`agentmain`) and transformer registration.
- `Java{8,11,17}*Transformer` classes covering the algorithm signatures listed in [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md).
- `Java{8,11,17}RaspHooks` and `Java{8,11,17}RaspBlockException`: self-contained hook and detection logic.
- `RaspRuntime`: mirrors `AgentRuntime` + `JsonEventLogger` using only the target JDK's APIs, including `META-INF/ohmyrasp-shirudo.properties` support, async file spooling, and `control.json` polling.

Detector false-positive-suppression parity between the backport `Java{8,11,17}RaspHooks` files and `agent-jdk25`'s `DetectorEngine` is enforced by [`check-detector-parity.sh`](../java-agent/scripts/check-detector-parity.sh).

## Runtime modes and configuration

### Operating modes

1. **Host-daemon mode (default):** The agent makes no outbound network connections. It appends NDJSON events to `/tmp/ohmyrasp-events.jsonl` and polls `/tmp/ohmyrasp-control.json` every `2000` ms (`control_poll_ms`, floor `200` ms) for live updates written by the companion host daemon ([`../daemon/README.md`](../daemon/README.md)):
   ```json
   { "mode": "monitor", "algorithms": { "sql_userinput": false }, "revision": 3 }
   ```
   A `"policy"` string field in `control.json` is also forwarded to `AgentPolicy.parse` whenever its contents change.
2. **Standalone mode (`standalone=true`):** Disables control-file polling and legacy direct-cloud reporting. When `mode` is unset, standalone defaults to `block`; `log` defaults to `stderr`; and `latency_sample` defaults to `0`.
3. **Shirudo daemonless locked mode (`META-INF/ohmyrasp-shirudo.properties`):** Used by `shirudoUpatchJar` packages (`ohmyrasp-{java8,java11,java17,jdk25}.jar`) for target-side attachment via `/run/shirudo-java/<name>.jar`. Baked properties are:
   ```properties
   standalone=true
   lock_config=true
   mode=block
   control=none
   log=stderr
   latency_sample=0
   ```
   When `lock_config=true`, `standalone`, `mode`, and `control` are locked to the signed JAR resource, ignoring `ohmyrasp.mode`/`OHMYRASP_MODE`, `ohmyrasp.control`/`OHMYRASP_CONTROL`, `ohmyrasp.standalone`/`OHMYRASP_STANDALONE`, and `/tmp/ohmyrasp-control.json`. Zero control-poller threads and zero file-writer threads are started, and `cloud_direct` is unconditionally suppressed. See [`../deploy/shirudo/README.md`](../deploy/shirudo/README.md).
4. **Legacy direct-cloud mode (`cloud_direct=true`):** Enables `ControlPlaneClient` inside the JVM to register, heartbeat, pull policies, and upload events directly to the Go control plane. Ignored when `standalone=true` or `lock_config=true`.

### Detection modes

| Mode | Tokens accepted by `DetectionMode.parse` | Behavior |
|---|---|---|
| `off` | `off`, `disabled`, `none` | Short-circuits hook entry points before detectors run; no logging or blocking |
| `monitor` | `monitor`, `record`, `observe`, `log` | Evaluates detectors and records events (rewriting `block` action to `monitor`), never blocks |
| `block` | `block`, `blocking`, `protect` | Evaluates detectors, records events, redirects active HTTP responses to `/rasp/blocked`, and throws block exception |
| *(unset)* | *(no mode set)* | Legacy mode: permits blocking when policy or legacy block flags request it (or defaults to `block` when `standalone=true`) |

### Configuration keys

In `agent-jdk25`, `AgentRuntime` and `ControlPlaneConfig` resolve settings in order: `-javaagent` argument (`key=value`, `.` and `-` normalized to `_`, `,` or `;` separated) -> Java system property (`-D...`) -> environment variable -> `META-INF/ohmyrasp-shirudo.properties` -> default. `JsonEventLogger` resolves `ohmyrasp.log` from agent arg `log`, then `-Dohmyrasp.log`, then `OHMYRASP_LOG`, then baked defaults; `ohmyrasp.log.sync` and `ohmyrasp.log.queue` use system properties or env vars.

| Setting | `-javaagent` arg (`agent-jdk25`) | System property | Environment variable | Default |
|---|---|---|---|---|
| Detection mode | `mode` | `ohmyrasp.mode` | `OHMYRASP_MODE` | unset (`block` if `standalone=true`) |
| Standalone mode | `standalone` | `ohmyrasp.standalone` | `OHMYRASP_STANDALONE` | `false` |
| Control file path | `control` | `ohmyrasp.control` | `OHMYRASP_CONTROL` | `/tmp/ohmyrasp-control.json` (`none` if `standalone=true`) |
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

Backport modules (`agent-java8`, `agent-java11`, `agent-java17`) read system properties, environment variables, and `META-INF/ohmyrasp-shirudo.properties` via `RaspRuntime` (not `-javaagent` arguments). They also accept track-specific overrides `ohmyrasp.java{8,11,17}.log` and `ohmyrasp.java{8,11,17}.block` / `OHMYRASP_JAVA{8,11,17}_BLOCK`.

## Comparative playground and acceptance verification

From `java-agent/`, [`docker-compose.yml`](../java-agent/docker-compose.yml) runs baseline/protected Tomcat pairs on JDK 25 with the comparative playground WAR (`playground` for Jakarta on Tomcat 10/11, `playground-javax` for Javax on Tomcat 9):

- Tomcat 9: `http://localhost:18080/rasp/ui` (baseline), `http://localhost:18081/rasp/ui` (protected)
- Tomcat 10: `http://localhost:18082/rasp/ui` (baseline), `http://localhost:18083/rasp/ui` (protected)
- Tomcat 11: `http://localhost:18084/rasp/ui` (baseline), `http://localhost:18085/rasp/ui` (protected)

The `/rasp/labs` view loads archived Java range scenarios from [`archived-java-ranges.json`](../java-agent/playground/src/main/resources/ohmyrasp/labs/archived-java-ranges.json). Protected containers write events to `logs/tomcat{9,10,11}-protected/events.jsonl`. [`docker-compose.daemon.yml`](../java-agent/docker-compose.daemon.yml) pairs Tomcat 11 (`18090`) with the host daemon console (`7070`) over a shared spool/control volume.

End-to-end verification scripts in `java-agent/scripts/`:

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
