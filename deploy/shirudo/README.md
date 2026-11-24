# OhMyRASP Shirudo Java Upatch Packages

> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources and test suites.
> Re-run after changing hooks, transformers, or detectors; `--check` fails CI when stale.

This directory packages OhMyRASP's standalone, daemonless Java runtime
self-protection agents as [shirudo](https://github.com/shirudo-dev/shirudo) Java
upatches (`.bee` packages and signed `.upatch` artifacts).

Pre-built staged JARs and the full `deploy/shirudo/` bundle
(`ohmyrasp-shirudo-upatches-<version>.tar.gz`) are also published on
[GitHub Releases](https://github.com/xuing/oh-my-rasp/releases), ready to sign
with `shirudo bpm build`.

## Packages

| Package | Target JVMs | Upatch / JAR | Instrumentation | Detection Scope | Vulhub Replay |
|---|---|---|---|---|---|
| `ohmyrasp-java8` | Java 8 (classfile `<= 52`) | `ohmyrasp-java8.jar` | 24 ASM transformers | 43 algorithms | 96 (java8) |
| `ohmyrasp-java11` | Java 11 (classfile `<= 55`) | `ohmyrasp-java11.jar` | 24 ASM transformers | 43 algorithms | 10 (java11) |
| `ohmyrasp-java17` | Java 17 and Java 21 (classfile `<= 61`) | `ohmyrasp-java17.jar` | 24 ASM transformers | 43 algorithms | 12 (java17) + 3 (java21) |
| `ohmyrasp-jdk25` | Java 21 and Java 25 (classfile `<= 65`) | `ohmyrasp-jdk25.jar` | 28 ASM hook modules | 54 `detect*` capabilities | 136 total scenarios across 6 JDK lines |

Benign-traffic precision across the curated engine corpus: **0 / 83** false positives across **14** categories (0.0%; see [FALSE-POSITIVE-REPORT.md](../../java-agent/docs/FALSE-POSITIVE-REPORT.md)).

## Security Protections Included

Each package injects ASM bytecode hooks at JVM class-load / retransform time across the following attack surfaces:

| Security Category | What It Inspects & Blocks | Java 8 / 11 / 17 Transformers | JDK 21/25 Hook Modules |
|---|---|---|---|
| **Command Execution & RCE** | Blocks exploit-grade `ProcessBuilder.start` / `Runtime.exec` calls (including OGNL, SpEL, MVEL, Groovy, JEXL, XStream, deserialization, and scheduler stacks) and Spark/YARN REST job submissions. | `Java*SparkRestTransformer`, `Java*YarnRestTransformer`, `Java*ProcessTransformer` | `ArgumentParserHookModule`, `ProcessHookModule` |
| **OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)** | Zero-allocation arithmetic boundary check on `java.util.Base64$Decoder.decode0` blocking x86-64 AVX-512 tail-underflow inputs (Java2Shell / Java4Shell) before the native intrinsic runs. | `Java*Base64Transformer` | `Base64HookModule` |
| **SQL Injection & JDBC** | Detects and blocks structural SQL injection across JDBC `Statement` drivers, MyBatis `BoundSql` order-by identifiers, GeoServer OGC CQL filters, H2 `INIT` code execution, Derby SQLJ loading, and MySQL `autoDeserialize` URLs. | `Java*JdbcTransformer` | `SqlHookModule` |
| **JNDI, Deserialization & XML/XXE** | Blocks remote `InitialContext.lookup` (`ldap`/`rmi`/`iiop`/`corba`), dangerous `ObjectInputStream` / RMI / OpenWire / Hessian / Fastjson `autoType` / `1.2.83` class-resource gadgets, XMLDecoder graphs, and external XML entities (XXE). | `Java*JndiTransformer`, `Java*DeserializationTransformer`, `Java*FastjsonTransformer`, `Java*HessianTransformer`, `Java*JavaBeansTransformer`, `Java*XxeTransformer` | `HessianHookModule`, `HttpInvokerHookModule`, `JavaBeansHookModule`, `JndiHookModule`, `ObjectInputStreamHookModule`, `OpenWireHookModule`, `PolymorphicDeserializationHookModule`, `RmiRegistryHookModule`, `SessionHookModule`, `XmlAttachmentHookModule`, `XmlRpcHookModule`, `XxeHookModule` |
| **HTTP Request, Path Confusion, Auth & SSRF** | Six-form URI path-confusion decoding (Shiro, GlassFish, Jetty, Spring), weak/default JWT HMAC secret checks, Shiro default `rememberMe` AES detection, forged internal identities, and cloud-metadata / loopback-admin / obfuscated-IP SSRF guards. | `Java*ServletTransformer`, `Java*UrlTransformer`, `Java*JwtTransformer` | `JwtHookModule`, `NetworkHookModule`, `ServletHookModule` |
| **File I/O, Uploads & Archive Traversal** | Guards sensitive reads (`/etc/passwd`, `/proc/self/environ`, SSH keys), webroot script writes, ZipSlip archive traversal (`ZipEntry` / 7z), multipart upload path traversal, and `.gnuplot` command injection. | `Java*FileTransformer`, `Java*MultipartUploadTransformer`, `Java*ArchiveTransformer` | `ArchiveHookModule`, `FileHookModule`, `MultipartUploadHookModule` |
| **Expression Engines, Scripting, ClassLoading & JMX/JAAS** | Inspects Nashorn/Rhino `ScriptEngine`, JEXL, Jakarta/JSP EL, `JavacTool`/Janino compilation, remote `URLClassLoader`/`RMIClassLoader` codebases, JAAS remote JNDI providers, and mutating JMX MBean invocations. | `Java*ClassLoaderTransformer`, `Java*ScriptEngineTransformer`, `Java*JexlTransformer`, `Java*ElTransformer`, `Java*JavaCompilationTransformer`, `Java*JaasTransformer`, `Java*JmxTransformer` | `ClassLoaderHookModule`, `ExpressionHookModule`, `JaasHookModule`, `JavaCompilationHookModule`, `JmxHookModule`, `SpringConfigHookModule` |

### Blocking Semantics Across Tracks

- **`ohmyrasp-java8`, `ohmyrasp-java11`, `ohmyrasp-java17`**: With baked-in `mode=block`, exploit-grade sink detections (command execution, sensitive file reads/script writes, remote JNDI, deserialization gadgets, SQLi/JDBC, XXE, SSRF, Base64 CVE-2026-114938, and servlet path/JWT/cookie checks) throw `Java*RaspBlockException` both inside HTTP requests and in standalone JVMs.
- **`ohmyrasp-jdk25`**: Enforces blocking (`OhMyRaspBlockException`) on all HTTP-request-correlated detections (`ThreadLocal<RequestContext>`) and explicitly marks `detectBase64Decode`, `detectHessianType`, `detectProtocolClassInstantiation`, `detectSql` for request-less blocking; non-request sink calls without HTTP context emit structured JSON detection alerts to `stderr`.

## Standalone Profile (`META-INF/ohmyrasp-shirudo.properties`)

Each shirudo upatch JAR embeds `META-INF/ohmyrasp-shirudo.properties` so it runs without a host daemon, control file, or spool rotation:

- `standalone=true` — disables daemon polling and cloud upload (`cloud_direct` forced off).
- `lock_config=true` — read strictly from the signed JAR; ignores `/tmp/ohmyrasp-control.json`, `OHMYRASP_MODE=off`, and `OHMYRASP_CONTROL`.
- `mode=block` — enables blocking immediately at JVM startup (use `--mode monitor` when building for observe-only rollout).
- `control=none` — starts zero background control-poller threads.
- `log=stderr` — writes structured JSON detection events directly to `stderr` with zero file-writer threads and no `/tmp/ohmyrasp-events.jsonl`.
- `latency_sample=0` — suppresses benign `hook_latency` telemetry lines.

## Build

Build and sign all four `.bee` packages into the current working directory:

```sh
./deploy/shirudo/build-all.sh 0.2.0 --keys-dir <keys>
```

Build a single package (for example `ohmyrasp-java17`):

```sh
./deploy/shirudo/ohmyrasp-java17/build.sh 0.2.0 --keys-dir <keys>
```

Stage only the `.jar` artifacts without invoking `shirudo bpm build` (for example before verification or smoke tests without operator keys):

```sh
./deploy/shirudo/build-all.sh --jar-only
```

Both `build.sh` and `build-all.sh` accept `--mode block|monitor` (default: `block`) and honor `SHIRUDO_BIN` when `shirudo` is not on `PATH`. If `gradle` is not installed locally, the build scripts invoke `gradle:9.8.1-jdk25` via Docker under the caller's UID/GID.

## Load, Unload, and How `shirudo` Attaches the Agent

Install a built `.bee` package (or load a signed `.upatch` directly) on a shirudo target:

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

1. Verifies the ML-DSA-87 signature against the target's sealed `.bpf` keyring, extends the TPM2 measurement register with a `java_load` event, and seals the signed JAR at `/run/shirudo-java/<name>.jar` (mode `0644`).
2. Writes `/run/environment.d/shirudo.conf` with `-javaagent:/run/shirudo-java/<name>.jar` for each loaded Java upatch in name order, appended to `JAVA_TOOL_OPTIONS`.

On `unload`, `shirudo` measures a `java_unload` event, replaces `/run/shirudo-java/<name>.jar` with a no-op stub JAR (so JVMs started from an already-running systemd user manager do not abort on a missing `-javaagent` path), and updates `/run/environment.d/shirudo.conf`.

## Java 8 `JAVA_TOOL_OPTIONS` Limit

OpenJDK 8 truncates `JAVA_TOOL_OPTIONS` at **1024 bytes** and **64 options** without reporting an error (JDK-8288483), silently dropping trailing options. Package and upatch names are deliberately kept short (`ohmyrasp-java8`, producing `-javaagent:/run/shirudo-java/ohmyrasp-java8.jar`, 47 bytes), and `ohmyrasp-java8.jar` omits `Boot-Class-Path` so `appendToBootstrapClassLoaderSearch` loads the sealed `/run/shirudo-java/ohmyrasp-java8.jar` path directly.

## Containers and System Services

`systemd` user managers read `/run/environment.d/shirudo.conf` at startup and pass `JAVA_TOOL_OPTIONS` to JVMs they launch afterwards.

- **Containers, system services, and direct logins** do not inherit user-manager `environment.d` files. Pass `-javaagent:/run/shirudo-java/<name>.jar` explicitly on the unit or container (for example via `JAVA_TOOL_OPTIONS` with the sealed JAR bind-mounted read-only).
- **Already-running JVMs** only read `JAVA_TOOL_OPTIONS` at process start and must be restarted to pick up a newly loaded or unloaded upatch.

## Security Boundary

A Java upatch is **an application-level mitigation inside the JVM**, not a kernel security boundary:

- `shirudo`'s seal protects `/run/shirudo-java/<name>.jar` from tampering by unprivileged tasks, while `/run/environment.d/shirudo.conf` is not sealed.
- `root` or the user launching a JVM can override `JAVA_TOOL_OPTIONS` or start a JVM without `-javaagent`. Use BPF upatches for policies that `root` must not bypass.
- A Java agent cannot query or call BPF upatches because shirudo's BPF LSM denies `BPF_OBJ_GET` and `BPF_PROG_TEST_RUN` to all tasks except `shirudo`.

## Verification and Smoke Tests

Validate Beefile syntax/limits, staged JAR manifests/properties, and README freshness:

```sh
python3 deploy/shirudo/gen-readmes.py --check
./deploy/shirudo/verify-shirudo-upatch.sh --beefile-only
./deploy/shirudo/verify-shirudo-upatch.sh
```

Run the real-JVM Docker integration suite across Temurin 8, 11, 17, 21, and 25:

```sh
./deploy/shirudo/smoke-test.sh
```
