# OhMyRASP Java Agent (JDK 25)

A Java-native Runtime Application Self-Protection agent. It uses ASM class
transformation in a `-javaagent` to intercept risky runtime behavior, evaluates
detections in-process, writes local security events, and can block active-request
attacks. Detection is the core capability and stays in Java to exploit JVM-native
context (stack walking, request thread-locals, reflective inspection).

The agent is built for **JDK 25** (`agent` module). Dedicated backport builds
target older runtimes: `agent-java8` (release 8), `agent-java11`, `agent-java17`.

## Architecture: agent + daemon

The agent does one job — **detect and (optionally) block** — and offloads
everything else to a companion [host daemon](../daemon/README.md):

```
 Java agent (this module)                 Host daemon (../daemon)             Cloud
 ────────────────────────                 ───────────────────────             ─────
 hook → detect → block? ─┐ events.jsonl  ┌─ tail → console :7070
  (synchronous decision)  ├──(append)────▶┤        (raw log, switches, latency)
 control poll ◀───────────┘ control.json └─ enrich → upload (retry/offline) ─▶ control plane
        ▲                        ▲
        └──── writes ────────────┘  (mode + algorithm toggles)
```

- The agent talks to **nothing on the network by default** — it appends events to
  a local NDJSON spool and reads a local control file. The daemon tails the spool,
  forwards to the cloud, heartbeats, and serves the console.
- The agent runs **standalone** without the daemon: it still writes its own
  interception/suspicious-activity log and honors the control file (or env vars).
- Direct cloud mode (legacy single-process) remains available via
  `cloud_direct=true`.

## Performance: never delay the business response

The protected request path must not block on reporting. The agent enforces this:

- The block/allow **decision** is synchronous in the hook (it has to be).
- **All reporting is asynchronous.** Event serialization, the file write, the
  `stdout` echo, and any legacy cloud upload run on a dedicated background daemon
  thread fed by a bounded queue. Under a sustained event storm, events are dropped
  and counted rather than stalling application logic.
- Each event carries the measured in-hook `latency_us`, surfaced by the daemon
  console as a p50/p95/p99/max/avg "business latency impact" panel.

## What it detects

Coverage is **generated from source** so it can't drift — see
[`docs/DETECTION-COVERAGE.md`](docs/DETECTION-COVERAGE.md). At a glance:

- **27** hook families (instrumentation points): SQL, Process, File, Network/URL,
  JNDI, deserialization (ObjectInputStream / polymorphic / Hessian / OpenWire /
  HTTP-invoker / RMI), XXE, expression/EL, class loading, Spring config, JMX,
  JAAS, JWT, servlet, archive extraction, multipart upload, and more.
- **52** detector capabilities (engine entry points).
- **42** algorithm signatures **verified** by the acceptance suite.
- **127** end-to-end vulnerability acceptance scenarios across JDK 7/8/11/17/21.

Regenerate after changing hooks/detectors/tests:

```bash
python3 scripts/gen-detection-coverage.py          # writes docs/DETECTION-COVERAGE.md
python3 scripts/gen-detection-coverage.py --check   # CI: fail if stale
```

## Standalone operation & control

The agent is fully usable on a single host with no control plane.

**Detection mode** (master switch) and **per-algorithm switches** are read from a
control file (default `/tmp/ohmyrasp-control.json`), hot-reloaded on a background
poller — no restart needed:

```json
{ "mode": "monitor", "algorithms": { "sql_userinput": false }, "revision": 3 }
```

| Mode | Behavior |
|------|----------|
| `off` | Detection suppressed (no logging, no blocking) |
| `monitor` | Detect and record, never block (record mode) |
| `block` | Detect, record, and block active-request attacks |

The mode can also be seeded at startup and never requires the daemon:

| Setting | Agent arg | System property | Env var |
|---------|-----------|-----------------|---------|
| Detection mode | `mode=block` | `-Dohmyrasp.mode=block` | `OHMYRASP_MODE=block` |
| Event log path | `log=/var/log/…` | `-Dohmyrasp.log=…` | `OHMYRASP_LOG=…` |
| Control file | `control=/etc/…` | `-Dohmyrasp.control=…` | `OHMYRASP_CONTROL=…` |
| Direct cloud (legacy) | `cloud_direct=true` | `-Dohmyrasp.cloud.direct=true` | `OHMYRASP_CLOUD_DIRECT=true` |

When no control file and no `mode` are set, the agent uses legacy behavior
(blocking permitted, driven by policy/flags) — a freshly installed agent behaves
exactly as before.

Attach it:

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=mode=monitor \
     -Dohmyrasp.log=/var/log/ohmyrasp/events.jsonl \
     -jar your-app.jar
# switch to blocking at runtime, no restart:
echo '{"mode":"block"}' > /tmp/ohmyrasp-control.json
```

## Build

Built with Gradle in the JDK 25 image (no local toolchain required):

```bash
# self-contained agent jar -> agent/build/libs/ohmyrasp-agent.jar
docker run --rm -v "$PWD":/workspace -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent:agentJar

# unit tests
docker run --rm -v "$PWD":/workspace -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent:test
```

## Testing, compatibility & false positives

- **Unit tests** — hook registry, SQL call-site rewriting, policy evaluation,
  the detector engine, and the runtime mode/algorithm controls
  (`agent/src/test`).
- **Acceptance suite** — `scripts/acceptance*.sh` boots real vulnerable
  applications under the agent (Tomcat 9/10/11 pairs and 127 vulhub scenarios
  across JDK 7/8/11/17/21) and asserts the expected detection/block. The verified
  algorithm signatures and the full scenario matrix are listed in
  [`docs/DETECTION-COVERAGE.md`](docs/DETECTION-COVERAGE.md).
- **False-positive rate** — measured, not asserted. `scripts/fp-harness` runs a
  curated benign corpus through the real `DetectorEngine` and counts detections;
  results in [`docs/FALSE-POSITIVE-REPORT.md`](docs/FALSE-POSITIVE-REPORT.md).
  Regenerate with `scripts/run-fp-report.sh`.

## Module layout

```
java-agent/
├── agent/              JDK 25 agent (primary)
│   └── src/main/java/io/ohmyrasp/agent/
│       ├── OhMyRaspAgent / BootstrapAgent   premain/agentmain entry + wiring
│       ├── asm/         hook modules + ASM transformer (the only "hook" logic)
│       ├── detect/      DetectorEngine — detection algorithms (stays in Java)
│       ├── hook/        OhMyRaspHooks — hook callbacks → detect → block/record
│       ├── runtime/     AgentRuntime + DetectionMode — standalone control
│       ├── log/         JsonEventLogger — async event spool
│       ├── policy/      remote policy evaluation
│       └── control/     legacy direct-cloud client (off by default)
├── agent-java8 / -java11 / -java17   backport builds for older runtimes
├── playground*/        comparative test apps (servlet labs)
├── scripts/            acceptance suite + doc/FP generators
└── docs/               generated coverage + FP reports
```
