# OhMyRASP Java Agent

OhMyRASP is a Java-native Runtime Application Self-Protection agent. It uses ASM class transformation in a `-javaagent` to intercept risky runtime behavior, evaluates detections in-process with JVM request and stack context, blocks active attacks synchronously, and writes local NDJSON events asynchronously (or directly to `stderr` in standalone locked mode).

The runtime tracks below ship from this directory with ASM relocated to `io.ohmyrasp.agent.shaded.asm`:

- `agent-jdk25`: primary JDK 21 and 25 track, compiled with `--release 21` (`ohmyrasp-agent.jar`, `ohmyrasp-jdk25.jar`; `:agent-jdk25:jdk21Jars` copies them to `build/jdk21/ohmyrasp-agent-jdk21.jar` and `build/jdk21/ohmyrasp-jdk21.jar`)
- `agent-java17`: Java 17 track (`ohmyrasp-agent-java17.jar`, `ohmyrasp-java17.jar`)
- `agent-java11`: Java 11 track (`ohmyrasp-agent-java11.jar`, `ohmyrasp-java11.jar`)
- `agent-java8`: Java 8 track (`ohmyrasp-agent-java8.jar`, `ohmyrasp-java8.jar`)

See [`../docs/agent.md`](../docs/agent.md) for full architecture, runtime modes, and configuration keys, [`../docs/detection.md`](../docs/detection.md) for the detection pipeline, [`../daemon/README.md`](../daemon/README.md) for the companion host daemon, and [`../deploy/shirudo/README.md`](../deploy/shirudo/README.md) for daemonless Shirudo Java upatch packaging.

## What it detects

Coverage is generated from source into [`docs/DETECTION-COVERAGE.md`](docs/DETECTION-COVERAGE.md), which holds the current counts and tables:

- hook families (`HookRegistry` modules in `agent-jdk25`; ASM transformers per backport track)
- `DetectorEngine` capabilities (`detect*` entry points), including the Fastjson 1.2.83 class-resource boundary, standalone JDBC `Statement` SQLi, and the CVE-2026-114938 `Base64$Decoder.decode0` AVX-512 tail-underflow guard
- algorithm signatures verified end-to-end by acceptance tests
- vulnerability acceptance scenarios, grouped by JDK line
- false-positive results over the curated benign corpus, in [`docs/FALSE-POSITIVE-REPORT.md`](docs/FALSE-POSITIVE-REPORT.md)

Regenerate or check ledgers after changing hooks, detectors, or acceptance scripts:

```bash
python3 scripts/gen-detection-coverage.py          # writes docs/DETECTION-COVERAGE.md
python3 scripts/gen-detection-coverage.py --check  # fails if stale
bash scripts/check-detector-parity.sh              # checks backport/jdk25 FP carve-out parity
```

## Build and test

Built with Gradle in the JDK 25 builder image pinned in [`Dockerfile`](Dockerfile):

```bash
GRADLE_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^gradle:/ { print $2; exit }' Dockerfile)"

# Primary agent jar -> agent-jdk25/build/libs/ohmyrasp-agent.jar
docker run --rm -v "$PWD":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon :agent-jdk25:agentJar

# Standalone Shirudo upatch jars -> agent-<track>/build/libs/ohmyrasp-<track>.jar
docker run --rm -v "$PWD":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon \
  :agent-java8:shirudoUpatchJar :agent-java8:verifyShirudoUpatchJar \
  :agent-java11:shirudoUpatchJar :agent-java11:verifyShirudoUpatchJar \
  :agent-java17:shirudoUpatchJar :agent-java17:verifyShirudoUpatchJar \
  :agent-jdk25:shirudoUpatchJar :agent-jdk25:verifyShirudoUpatchJar

# Unit tests (agent-jdk25/src/test and backport suites)
docker run --rm -v "$PWD":/workspace -w /workspace "$GRADLE_IMAGE" \
  gradle --no-daemon check
```

## Quick attach

Daemon-managed or local control-file mode (polls `/tmp/ohmyrasp-control.json`, writes NDJSON spool asynchronously):

```bash
java -javaagent:/opt/ohmyrasp/ohmyrasp-agent.jar=mode=monitor \
     -Dohmyrasp.log=/var/log/ohmyrasp/events.jsonl \
     -jar your-app.jar
echo '{"mode":"block"}' > /tmp/ohmyrasp-control.json
```

For Shirudo locked daemonless JARs (`ohmyrasp-{java8,java11,java17,jdk25}.jar`), `META-INF/ohmyrasp-shirudo.properties` bakes in `standalone=true`, `lock_config=true`, `mode=block`, `control=none`, `log=stderr`, and `latency_sample=0`.

## Acceptance and false-positive suites

- **Unit tests:** `agent-jdk25/src/test` covers the hook registry, SQL callsite rewriting, Fastjson/Base64 hooks, policy evaluation, `DetectorEngine`, `AgentRuntime`, and Shirudo standalone defaults.
- **Acceptance suite:** `acceptance/runtime/jdk25.sh` (Tomcat 11/10/9 on JDK 25), `acceptance/runtime/java{8,11,17,21}.sh`, and the `acceptance/vulhub/*/*.sh` scenarios boot real applications and assert detection and blocking.
- **False-positive report:** `scripts/run-fp-report.sh` runs `scripts/fp-harness/FpReport.java` against `DetectorEngine` and writes `docs/FALSE-POSITIVE-REPORT.md`.

## Module layout

```text
java-agent/
├── agent-jdk25/                      primary JDK 21/25 agent
│   ├── src/main/java/io/ohmyrasp/agent/
│   │   ├── OhMyRaspAgent.java        premain/agentmain -> bootstrap loader
│   │   ├── BootstrapAgent.java       runtime/transformer/guard wiring
│   │   ├── asm/                      HookRegistry + HookModule classes
│   │   ├── detect/DetectorEngine.java
│   │   ├── hook/                     OhMyRaspHooks, DeserializationGuard, OhMyRaspBlockException
│   │   ├── runtime/                  AgentRuntime, DetectionMode, ShirudoDefaults
│   │   ├── log/JsonEventLogger.java  async NDJSON spool + redaction + telemetry
│   │   ├── policy/                   local AgentPolicy evaluation
│   │   └── control/                  legacy direct-cloud client (off by default)
│   └── src/test/                     JUnit 6 unit tests
├── agent-java8 / -java11 / -java17   self-contained backport builds
├── playground* /                     comparative servlet test apps (Jakarta & Javax)
├── acceptance/                       runtime/ JDK suites, vulhub/<component>/ scenarios, lib/
├── scripts/                          coverage/FP generators and ledger checks
└── docs/                             generated DETECTION-COVERAGE.md + FALSE-POSITIVE-REPORT.md
```
