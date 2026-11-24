# OhMyRASP Shirudo Java Upatch Packages

This directory packages OhMyRASP's standalone, daemonless Java runtime
self-protection agents as [shirudo](https://github.com/shirudo-dev/shirudo) Java
upatches (`.bee` packages and signed `.upatch` artifacts).

Pre-built staged JARs and the full `deploy/shirudo/` bundle
(`ohmyrasp-shirudo-upatches-<version>.tar.gz`) are also published on
[GitHub Releases](https://github.com/xuing/oh-my-rasp/releases), ready to sign
directly with `shirudo bpm build`.

## Packages

| Package | Target JVMs | Upatch / JAR name | Gradle module |
|---|---|---|---|
| `ohmyrasp-java8` | Java 8 (classfile `<= 52`) | `ohmyrasp-java8.jar` | `:agent-java8` |
| `ohmyrasp-java11` | Java 11 (classfile `<= 55`) | `ohmyrasp-java11.jar` | `:agent-java11` |
| `ohmyrasp-java17` | Java 17 and Java 21 (classfile `<= 61`) | `ohmyrasp-java17.jar` | `:agent-java17` |
| `ohmyrasp-jdk25` | Java 25 (classfile `<= 69`) | `ohmyrasp-jdk25.jar` | `:agent-jdk25` |

Each package sets `type = "java"` in its `Beefile`, builds a single
self-contained agent JAR with `Premain-Class` in `META-INF/MANIFEST.MF` and
baked-in `META-INF/ohmyrasp-shirudo.properties`:

- `standalone=true`
- `lock_config=true`
- `control=none`
- `log=stderr`
- `latency_sample=0`

In this profile the agent starts zero background control-poller or
event-writer threads, ignores `/tmp/ohmyrasp-control.json`, never writes
`/tmp/ohmyrasp-events.jsonl`, suppresses `hook_latency` telemetry, and logs
structured JSON detection events directly to `stderr`.

## Build

Build all four `.bee` packages into the current working directory:

```sh
./deploy/shirudo/build-all.sh 0.1.0 --keys-dir <keys>
```

Build a single package (for example `ohmyrasp-java17`):

```sh
./deploy/shirudo/ohmyrasp-java17/build.sh 0.1.0 --keys-dir <keys>
```

Stage only the `.jar` artifacts without invoking `shirudo bpm build` (for
example before running verification or smoke tests without operator keys):

```sh
./deploy/shirudo/build-all.sh --jar-only
```

Both `build.sh` and `build-all.sh` also accept `--mode block|monitor`
(default: `block`) and honor `SHIRUDO_BIN` when `shirudo` is not on `PATH`.
If `gradle` is not installed locally, the build scripts invoke the
`gradle:9.8.1-jdk25` Docker image as the current UID/GID with an isolated
Gradle home and project cache under `/tmp`.

## Load, Unload, and How `shirudo` Attaches the Agent

Install a built `.bee` package (or load a signed `.upatch` directly) on a
shirudo target:

```sh
sudo shirudo bpm install <repository>/ohmyrasp-java17
# or load a standalone signed artifact:
sudo shirudo upatch load ohmyrasp-java17.upatch
```

Unload on the target:

```sh
sudo shirudo bpm uninstall ohmyrasp-java17
# or unload a standalone signed artifact:
sudo shirudo upatch unload ohmyrasp-java17.unload.upatch
```

When a Java upatch `<name>` is loaded, `shirudo`:

1. Verifies the ML-DSA-87 signature against the target's sealed `.bpf`
   keyring, extends the TPM2 measurement register with a `java_load` event,
   and seals the signed JAR at `/run/shirudo-java/<name>.jar` (mode `0644`).
2. Writes `/run/environment.d/shirudo.conf` with
   `-javaagent:/run/shirudo-java/<name>.jar` for each loaded Java upatch
   in name order, appended to `JAVA_TOOL_OPTIONS`.

On `unload`, `shirudo` measures a `java_unload` event, replaces
`/run/shirudo-java/<name>.jar` with a no-op stub JAR (so JVMs started from
an already-running systemd user manager do not abort on a missing `-javaagent`
path), and updates `/run/environment.d/shirudo.conf`.

## Java 8 `JAVA_TOOL_OPTIONS` Limit

OpenJDK 8 truncates `JAVA_TOOL_OPTIONS` at **1024 bytes** and **64 options**
without reporting an error (JDK-8288483), silently dropping any trailing
options. Package and upatch names are deliberately kept short
(`ohmyrasp-java8`, producing `-javaagent:/run/shirudo-java/ohmyrasp-java8.jar`,
47 bytes) so the option fits comfortably alongside existing environment
settings. Keep loaded Java agents few and other `environment.d` JVM flags
concise on Java 8 hosts.

## Containers and System Services

`systemd` user managers read `/run/environment.d/shirudo.conf` when they
start and pass `JAVA_TOOL_OPTIONS` to JVMs they launch afterwards.

- **Containers, system services, and direct logins** do not inherit
  user-manager `environment.d` files. Pass the sealed agent explicitly on
  the service unit or container runtime:
  `-javaagent:/run/shirudo-java/<name>.jar` (for example via
  `JAVA_TOOL_OPTIONS` with `/run/shirudo-java/<name>.jar` bind-mounted
  read-only into the container).
- **Already-running JVMs** only read `JAVA_TOOL_OPTIONS` at process start
  and must be restarted to pick up a newly loaded or unloaded upatch.

## Security Boundary

A Java upatch is **an application-level mitigation inside the JVM**, not a
kernel security boundary:

- `shirudo`'s seal protects `/run/shirudo-java/<name>.jar` from tampering
  by unprivileged tasks, while `/run/environment.d/shirudo.conf` is not
  sealed.
- `root` or the user launching a JVM can override `JAVA_TOOL_OPTIONS` or
  start a JVM without `-javaagent`. Use BPF upatches for policies that
  `root` must not bypass.
- A Java agent cannot query or call BPF upatches because shirudo's BPF LSM
  denies `BPF_OBJ_GET` and `BPF_PROG_TEST_RUN` to all tasks except `shirudo`.

## Verification and Smoke Tests

Validate Beefile syntax/limits and staged JAR manifests/properties:

```sh
./deploy/shirudo/verify-shirudo-upatch.sh --beefile-only
./deploy/shirudo/verify-shirudo-upatch.sh
```

Run the real-JVM Docker integration suite across Temurin 8, 11, 17, 21, and 25:

```sh
./deploy/shirudo/smoke-test.sh
```
