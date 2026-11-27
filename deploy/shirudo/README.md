# OhMyRASP Shirudo Java Upatch Packages

> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources and test suites.
> Re-run after changing hooks, transformers, or detectors; `--check` fails CI when stale.

Packages OhMyRASP's standalone, daemonless Java runtime self-protection agent as
[shirudo](https://github.com/shirudo-dev/shirudo) Java upatches (`.bee` packages and
signed `.upatch` artifacts).

Pre-built staged JARs and the full `deploy/shirudo/` bundle
(`ohmyrasp-shirudo-upatches-<version>.tar.gz`) are published on
[GitHub Releases](https://github.com/xuing/oh-my-rasp/releases), ready to sign
with `shirudo bpm build`.

## Quick start

Install one package, `ohmyrasp`. Every JVM on the host, from Java 8 to Java 25, gets the agent line that fits its Java version:

```sh
sudo shirudo bpm install <repository>/ohmyrasp
```

`ohmyrasp.jar` holds every line and a launcher. When a JVM loads it through `JAVA_TOOL_OPTIONS`, the launcher reads the JVM's Java version and starts the first line, in the order primary (Java 21 and later), Java 17, Java 11, Java 8, whose range contains it. The launcher never stops the JVM: a JVM that fits no line (Java 9 and 10 have none) writes one `ohmyrasp-agent-skipped` JSON line to stderr and the application starts without protection. A host with Java 8, 11, 17 and 21 applications needs no per-version setup, and installing the package stops none of them from starting.

A second OhMyRASP package on the same host is harmless. One line starts per JVM, the first JAR in `JAVA_TOOL_OPTIONS` wins (shirudo lists the agents in name order, so `ohmyrasp` comes before `ohmyrasp-java8`), and each later JAR writes `"reason":"already-active"` and does nothing more.

## Packages

| Package | Starts on | Upatch / JAR | Instrumentation | Detection Scope | Vulhub Replay |
|---|---|---|---|---|---|
| `ohmyrasp` | Java 8 to 25, the line that fits | `ohmyrasp.jar` | every line below | every line below | 120 Vulhub scripts on supported JVMs |
| `ohmyrasp-java8` | Java 8 only (classfile `<= 52`) | `ohmyrasp-java8.jar` | 24 ASM transformers | 45 algorithms | 95 (java8) |
| `ohmyrasp-java11` | Java 11 and later (classfile `<= 55`) | `ohmyrasp-java11.jar` | 24 ASM transformers | 45 algorithms | 10 (java11) |
| `ohmyrasp-java17` | Java 17 and later (classfile `<= 61`) | `ohmyrasp-java17.jar` | 24 ASM transformers | 45 algorithms | 12 (java17) + 3 (java21) |
| `ohmyrasp-jdk21` | Java 21 and later (classfile `<= 65`) | `ohmyrasp-jdk21.jar` | 30 ASM hook modules | 42 `detect*` capabilities | 120 Vulhub scripts on supported JVMs |
| `ohmyrasp-jdk25` | Java 21 and later (classfile `<= 65`) | `ohmyrasp-jdk25.jar` | 30 ASM hook modules | 42 `detect*` capabilities | 120 Vulhub scripts on supported JVMs |

## Which package to install

- **`ohmyrasp`** is the default for any host, and the only choice for a host with more than one Java version. A JVM gets the line that fits it, so a Java 21 JVM gets the primary line and a Java 17 JVM the Java 17 line.
- **A per-line package** is for a host pinned to one Java version, or for an operator who wants only one line's JAR to sign. It holds that line only and starts it on every Java the line supports: `ohmyrasp-java11` starts the Java 11 line on a Java 17 or 21 JVM too, where `ohmyrasp` would start the Java 17 or the primary line. On a Java the line does not support it writes the `ohmyrasp-agent-skipped` line and the JVM starts unprotected. The names `ohmyrasp-jdk21` and `ohmyrasp-jdk25` hold the same agent bytecode.
- **Mixed installs** are safe. Each JVM starts one line, whichever JAR comes first and fits.

For JDK 21, extract `ohmyrasp-jdk21-shirudo.tar.gz` to sign the staged package with your operator keys.

Benign-traffic precision across the curated engine corpus: **0 / 194** false positives across **26** categories (0.0%; see [FALSE-POSITIVE-REPORT.md](../../java-agent/docs/FALSE-POSITIVE-REPORT.md)).

## Check that it is active

A protected JVM writes one line to its standard error when it starts, before the application runs. The line names the Java line that started. The Java 21 and later line also shows the baked mode, `block` here and `monitor` in a monitor build:

| JVM | First line on stderr |
|---|---|
| Java 8 | `{"event":"ohmyrasp-java8-agent-start","mode":"premain", ...}` |
| Java 11 | `{"event":"ohmyrasp-java11-agent-start","mode":"premain", ...}` |
| Java 17 | `{"event":"ohmyrasp-java17-agent-start","mode":"premain", ...}` |
| Java 21 and 25 | `[OHMYRASP] agent started with ASM transformer, standalone=true, mode=block, args=` |

JVMs that start a Java agent with an appended bootstrap path may also print `OpenJDK 64-Bit Server VM warning: Sharing is only supported for boot loader classes because bootstrap classpath has been appended`. It is the JVM's notice that class-data sharing is limited, not an error.

A JVM that was already running when the package was loaded shows none of this: it has to restart. A JVM that a systemd user manager starts also needs a manager that has read the change. The manager reads `/run/environment.d/shirudo.conf` when it starts and when it reloads, so a manager that started before the upatch was loaded (or unloaded) still passes the old options, and a restarted JVM starts without the agent. Run `systemctl --user daemon-reload` as the JVM's user, check with `systemctl --user show-environment | grep JAVA_TOOL_OPTIONS` that the manager now names the agent, then restart the JVM.

To see whether a running JVM has the agent, look for the start line in its log, or ask the JVM: `jcmd <pid> VM.system_properties | grep ohmyrasp.agent.line` prints `ohmyrasp.agent.line=<line>`, one of `primary`, `java17`, `java11` and `java8`, when a line started, and prints nothing when none did.

A JVM whose line is not started says why in one JSON line instead:

- `{"event":"ohmyrasp-agent-skipped","reason":"unsupported-java", ...}`: this JAR holds no line that fits the JVM's Java version (a per-line JAR on a Java it does not cover, or any JAR on Java 9 or 10). This JAR protects nothing; the JVM and the application start.
- `{"event":"ohmyrasp-agent-skipped","reason":"already-active", ...}`: another OhMyRASP JAR started a line first. The JVM is protected.
- `{"event":"ohmyrasp-agent-start-failed", ...}`: the line threw while starting. Protection is inactive or incomplete, and the JVM still starts.

Detections are JSON objects, one per line, on the JVM's standard error (`"event":"ohmyrasp-detection"`, with the hook, the rule in `algorithm`, and `action`: `block` or `monitor`). Nothing is written to a file. Read them where the JVM's stderr goes: `journalctl -u <unit>` for a systemd unit, `docker logs <container>` for a container.

## Advisories the universal package lists

`ohmyrasp/Beefile` sets `fixes` in its `[upatches.tree]` entry, which shirudo's backend reads to show which loaded upatch covers an advisory a node is exposed to. The list means that the agent blocks the tested exploit path of that advisory inside the JVM; it does not patch the vulnerable library. It describes the block build: a monitor build only observes, so `build.sh --mode monitor` packages it from a Beefile without `fixes`, and `verify-shirudo-upatch.sh` checks that the baked mode and the Beefile agree. It is written from [fixes.toml](fixes.toml), which names for each advisory the Vulhub acceptance script that shows it, and `gen-readmes.py --check` fails when the list, the script or the evidence ledger disagree. `replay-fixes.sh` runs those scripts against the universal JAR; `fixes.toml` records the date of the last replay of each entry. The per-line packages list none. See [ohmyrasp/README.md](ohmyrasp/README.md) for the list.

## Security Protections Included

Each package injects ASM bytecode hooks at JVM class-load / retransform time across the following attack surfaces:

| Security Category | What It Inspects & Blocks | Java 8 / 11 / 17 Transformers | JDK 21/25 Hook Modules |
|---|---|---|---|
| **Command Execution & RCE** | Blocks exploit-grade `ProcessBuilder.start` / `Runtime.exec` calls (including OGNL, SpEL, MVEL, Groovy, JEXL, XStream, deserialization, and scheduler stacks) and Spark/YARN REST job submissions. | `Java*SparkRestTransformer`, `Java*YarnRestTransformer`, `Java*ProcessTransformer` | `ArgumentParserHookModule`, `ProcessHookModule` |
| **Elasticsearch LZ4 Transport (CVE-2026-82303)** | In block mode, isolates the declared compressed transport block and checks the decoder consumed its exact length. | `Java*ElasticLz4Transformer` | `ElasticLz4HookModule` |
| **OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)** | Zero-allocation arithmetic boundary check on `java.util.Base64$Decoder.decode0` blocking x86-64 AVX-512 tail-underflow inputs (Java2Shell / Java4Shell) before the native intrinsic runs. | `Java*Base64Transformer` | `Base64HookModule` |
| **SQL Injection & JDBC** | Detects and blocks structural SQL injection across JDBC `Statement` drivers, MyBatis `BoundSql` order-by identifiers, GeoServer OGC CQL filters, H2 `INIT` code execution, Derby SQLJ loading, and MySQL `autoDeserialize` URLs. | `Java*JdbcTransformer` | `SqlHookModule` |
| **JNDI, Deserialization & XML/XXE** | Checks remote naming routes, including JDK JAAS directory lookups, and blocks dangerous `ObjectInputStream` / RMI / OpenWire / Hessian / Fastjson `autoType` / `1.2.83` class-resource gadgets, XMLDecoder graphs, and external XML entities (XXE). | `Java*JndiTransformer`, `Java*DeserializationTransformer`, `Java*FastjsonTransformer`, `Java*HessianTransformer`, `Java*JavaBeansTransformer`, `Java*XxeTransformer` | `HessianHookModule`, `HttpInvokerHookModule`, `JavaBeansHookModule`, `JndiHookModule`, `ObjectInputStreamHookModule`, `OpenWireHookModule`, `PolymorphicDeserializationHookModule`, `RmiRegistryHookModule`, `SessionHookModule`, `XmlAttachmentHookModule`, `XmlRpcHookModule`, `XxeHookModule` |
| **HTTP Request, Path Confusion, Auth & SSRF** | Six-form URI path-confusion decoding (Shiro, GlassFish, Jetty, Spring), weak/default JWT HMAC secret checks, Shiro default `rememberMe` AES detection, forged internal identities, and cloud-metadata / loopback-admin / obfuscated-IP SSRF guards. | `Java*ServletTransformer`, `Java*UrlTransformer`, `Java*JwtTransformer` | `JwtHookModule`, `NetworkHookModule`, `ServletHookModule` |
| **File I/O, Uploads & Archive Traversal** | Guards sensitive reads (`/etc/passwd`, `/proc/self/environ`, SSH keys), webroot script writes, ZipSlip archive traversal (`ZipEntry` / 7z), multipart upload path traversal, and `.gnuplot` command injection. | `Java*FileTransformer`, `Java*MultipartUploadTransformer`, `Java*ArchiveTransformer` | `ArchiveHookModule`, `FileHookModule`, `MultipartUploadHookModule` |
| **Expression Engines, Scripting, ClassLoading & JMX** | Inspects Nashorn/Rhino `ScriptEngine`, JEXL, Jakarta/JSP EL, `JavacTool`/Janino compilation, remote `URLClassLoader`/`RMIClassLoader` codebases, and mutating JMX MBean invocations. | `Java*ClassLoaderTransformer`, `Java*ScriptEngineTransformer`, `Java*JexlTransformer`, `Java*ElTransformer`, `Java*JavaCompilationTransformer`, `Java*JmxTransformer` | `ClassLoaderHookModule`, `ExpressionHookModule`, `JavaCompilationHookModule`, `JmxHookModule`, `SpringConfigHookModule` |
| **Other / Newly Added** | Additional ASM instrumentation hooks detected in agent sources. | - | `SparkSubmitHookModule`, `YarnSubmitHookModule` |

### Blocking Semantics Across Tracks

- **`ohmyrasp`** blocks as the line it starts does: the Java 8, 11 and 17 lines on those JVMs, the primary line on Java 21 and later.
- **`ohmyrasp-java8`, `ohmyrasp-java11`, `ohmyrasp-java17`**: With baked-in `mode=block`, exploit-grade sink detections (command execution, sensitive file reads/script writes, remote JNDI, deserialization gadgets, SQLi/JDBC, XXE, SSRF, Base64 CVE-2026-114938, and servlet path/JWT/cookie checks) throw `Java*RaspBlockException` both inside HTTP requests and in standalone JVMs.
- **`ohmyrasp-jdk21`, `ohmyrasp-jdk25`** use the evidence available at the hook and the active policy to decide whether to block.
- **Every track** blocks a finding outside an HTTP request (a scheduled job, a consumer, start-up code) as inside one; a few rules too broad to block without request input block only inside one. `ohmyrasp` bakes `outside_request` (`--outside-request log` at build time records those findings and lets the operation run). [Outside an HTTP request](../../docs/detection.md#outside-an-http-request)

## Standalone Profile (`META-INF/ohmyrasp-shirudo.properties`)

Each shirudo upatch JAR, the universal one included, embeds `META-INF/ohmyrasp-shirudo.properties` so it runs without a host daemon, control file, or spool rotation:

- `standalone=true`: turns cloud upload off (`cloud_direct` forced off) and control-file polling off, whatever control path is set.
- `lock_config=true`: `standalone`, `mode` and `control` come only from this baked file; `OHMYRASP_MODE=off` and `OHMYRASP_CONTROL` are ignored, and a baked file without `control` polls no control file, not even the default `/tmp/ohmyrasp-control.json`. A locked JAR that is not standalone polls a baked control path, the default one included. `log` and `latency_sample` stay overridable. Every package reads the file only from its own JAR; a same-named file on the application class path is ignored. When two OhMyRASP JARs hold the same line, that line's classes and the baked file it reads come from the first of them on the class path.
- `mode=block`: enables blocking immediately at JVM startup (use `--mode monitor` when building for observe-only rollout).
- `control=none`: starts zero background control-poller threads.
- `log=stderr`: writes structured JSON detection events directly to `stderr` with zero file-writer threads and no `/tmp/ohmyrasp-events.jsonl`, unless a log override names a file at start-up.
- `latency_sample=0`: suppresses benign `hook_latency` telemetry lines.

## Build

Build and sign all `.bee` packages into the current working directory:

```sh
./deploy/shirudo/build-all.sh "<version>" --keys-dir "<keys>"
```

Build a single package (for example `ohmyrasp`):

```sh
./deploy/shirudo/ohmyrasp/build.sh "<version>" --keys-dir "<keys>"
```

Stage only the `.jar` artifacts without invoking `shirudo bpm build` (for example before verification or smoke tests without operator keys):

```sh
./deploy/shirudo/build-all.sh --jar-only
```

Both `build.sh` and `build-all.sh` accept `--mode block|monitor` (default: `block`) and honor `SHIRUDO_BIN` when `shirudo` is not on `PATH`. If `gradle` is not installed locally, the build scripts run the Gradle Docker image that `java-agent/Dockerfile` pins, under the caller's UID/GID.

## Load, Unload, and How `shirudo` Attaches the Agent

Install a built `.bee` package (or load a signed `.upatch` directly) on a shirudo target:

```sh
sudo shirudo bpm install <repository>/ohmyrasp
# or load a standalone signed artifact:
sudo shirudo upatch load ohmyrasp.upatch
```

Unload on the target:

```sh
sudo shirudo bpm uninstall ohmyrasp
# or unload a standalone signed artifact:
sudo shirudo upatch unload ohmyrasp.unload.upatch
```

When a Java upatch `<name>` is loaded, `shirudo`:

1. Verifies the ML-DSA-87 signature against the target's sealed `.bpf` keyring, extends the TPM2 measurement register with a `java_load` event, and seals the signed JAR at `/run/shirudo-java/<name>.jar` (mode `0644`).
2. Writes `/run/environment.d/shirudo.conf` with `-javaagent:/run/shirudo-java/<name>.jar` for each loaded Java upatch in name order, appended to `JAVA_TOOL_OPTIONS`.

On `unload`, `shirudo` measures a `java_unload` event, replaces `/run/shirudo-java/<name>.jar` with a no-op stub JAR (so JVMs started from an already-running systemd user manager do not abort on a missing `-javaagent` path), and updates `/run/environment.d/shirudo.conf`.

## Java 8 `JAVA_TOOL_OPTIONS` Limit

OpenJDK 8 does not honor a `JAVA_TOOL_OPTIONS` of **1024 bytes** or more, or more than **64 options**, and reports no error (JDK-8288483). shirudo's documentation says the trailing options are dropped; the control run in `smoke-test.sh` saw Temurin 8 ignore the whole variable at 1024 bytes, so every agent was lost. Package and upatch names are deliberately kept short (`ohmyrasp`, producing `-javaagent:/run/shirudo-java/ohmyrasp.jar`, 41 bytes). With every OhMyRASP package loaded the `-javaagent` options take 283 bytes of the 1024, which leaves the rest for what other `environment.d` files set. `ohmyrasp-java8.jar` omits `Boot-Class-Path` so `appendToBootstrapClassLoaderSearch` loads the sealed `/run/shirudo-java/ohmyrasp-java8.jar` path directly. `ohmyrasp.jar` omits it for the same reason, and each line appends the JAR it was started from.

## Containers and System Services

`systemd` user managers read `/run/environment.d/shirudo.conf` at startup and pass `JAVA_TOOL_OPTIONS` to JVMs they launch afterwards.

- **Containers, system services, and direct logins** do not inherit user-manager `environment.d` files. Pass `-javaagent:/run/shirudo-java/<name>.jar` explicitly on the unit or container (for example via `JAVA_TOOL_OPTIONS` with the sealed JAR bind-mounted read-only).
- **Already-running JVMs** only read `JAVA_TOOL_OPTIONS` at process start and must be restarted to pick up a newly loaded or unloaded upatch.
- **A user manager that started before a load or unload** still passes the old options. Run `systemctl --user daemon-reload` as the JVM's user (or restart the manager) before restarting the JVM.

## Security Boundary

A Java upatch is **an application-level mitigation inside the JVM**, not a kernel security boundary:

- `shirudo`'s seal protects `/run/shirudo-java/<name>.jar` from tampering by unprivileged tasks, while `/run/environment.d/shirudo.conf` is not sealed.
- `root` or the user launching a JVM can override `JAVA_TOOL_OPTIONS` or start a JVM without `-javaagent`. Use BPF upatches for policies that `root` must not bypass.
- A Java agent cannot query or call BPF upatches because shirudo's BPF LSM denies `BPF_OBJ_GET` and `BPF_PROG_TEST_RUN` to all tasks except `shirudo`.

## Verification and Smoke Tests

Validate Beefile syntax/limits, staged JAR manifests/properties, the `fixes` list and README freshness:

```sh
python3 deploy/shirudo/gen-readmes.py --check
./deploy/shirudo/verify-shirudo-upatch.sh --beefile-only
./deploy/shirudo/verify-shirudo-upatch.sh
```

Run the real-JVM Docker integration suite across Temurin 8, 11, 17, 21, and 25, including a host that loads every package at once:

```sh
./deploy/shirudo/smoke-test.sh
```
