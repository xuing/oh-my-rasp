# ohmyrasp-jdk25

> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources.

The `ohmyrasp-jdk25` package installs the `ohmyrasp-jdk25` Java upatch: a standalone, daemonless OhMyRASP runtime self-protection agent targeting **Java 21 and Java 25** JVMs (classfile version `<= 65`). It registers **31 ASM hook modules** and **42 detector capabilities**, backed by **120** end-to-end Vulhub acceptance scripts that run the exploit on a supported JVM.

This package is for hosts pinned to one Java version; the universal package [`ohmyrasp`](../ohmyrasp/README.md) starts the line that fits each JVM of a mixed host. It starts its line on **Java 21 and later**; on any other Java it writes one `ohmyrasp-agent-skipped` JSON line to stderr and the JVM starts without this agent.

## Security Coverage

| Category | Protection Scope | ASM Hook Modules |
|---|---|---|
| **Command Execution & RCE** | Blocks exploit-grade `ProcessBuilder.start` / `Runtime.exec` calls (including OGNL, SpEL, MVEL, Groovy, JEXL, XStream, deserialization, and scheduler stacks) and Spark/YARN REST job submissions. | `ArgumentParserHookModule`, `ProcessHookModule` |
| **Elasticsearch LZ4 Transport (CVE-2026-82303)** | In block mode, isolates the declared compressed transport block and checks the decoder consumed its exact length. | `ElasticLz4HookModule` |
| **OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)** | Zero-allocation arithmetic boundary check on `java.util.Base64$Decoder.decode0` blocking x86-64 AVX-512 tail-underflow inputs (Java2Shell / Java4Shell) before the native intrinsic runs. | `Base64HookModule` |
| **SQL Injection & JDBC** | Detects and blocks structural SQL injection across JDBC `Statement` drivers, MyBatis `BoundSql` order-by identifiers, GeoServer OGC CQL filters, H2 `INIT` code execution, Derby SQLJ loading, and MySQL `autoDeserialize` URLs. | `SqlHookModule` |
| **JNDI, Deserialization & XML/XXE** | Checks remote naming routes, including JDK JAAS directory lookups, and blocks dangerous `ObjectInputStream` / RMI / OpenWire / Hessian / Fastjson `autoType` / `1.2.83` class-resource gadgets, XMLDecoder graphs, and external XML entities (XXE). | `HessianHookModule`, `HttpInvokerHookModule`, `JavaBeansHookModule`, `JndiHookModule`, `ObjectInputStreamHookModule`, `OpenWireHookModule`, `PolymorphicDeserializationHookModule`, `RmiRegistryHookModule`, `SessionHookModule`, `XmlAttachmentHookModule`, `XmlRpcHookModule`, `XxeHookModule` |
| **HTTP Request, Path Confusion, Auth & SSRF** | Six-form URI path-confusion decoding (Shiro, GlassFish, Jetty, Spring), weak/default JWT HMAC secret checks, Shiro default `rememberMe` AES detection, forged internal identities, and cloud-metadata / loopback-admin / obfuscated-IP SSRF guards. | `JwtHookModule`, `NetworkHookModule`, `ServletHookModule` |
| **File I/O, Uploads & Archive Traversal** | Guards sensitive reads (`/etc/passwd`, `/proc/self/environ`, SSH keys), webroot script writes, ZipSlip archive traversal (`ZipEntry` / 7z), multipart upload path traversal, and `.gnuplot` command injection. | `ArchiveHookModule`, `FileHookModule`, `MultipartUploadHookModule` |
| **Expression Engines, Scripting, ClassLoading & JMX** | Inspects Nashorn/Rhino `ScriptEngine`, JEXL, Jakarta/JSP EL, `JavacTool`/Janino compilation, remote `URLClassLoader`/`RMIClassLoader` codebases, and mutating JMX MBean invocations. | `ClassLoaderHookModule`, `ExpressionHookModule`, `JavaCompilationHookModule`, `JmxHookModule`, `SpringConfigHookModule` |
| **Other / Newly Added** | Additional ASM instrumentation hooks detected in agent sources. | `RequestBodyHookModule`, `SparkSubmitHookModule`, `YarnSubmitHookModule` |

<details><summary>All detector capabilities (42)</summary>

- `detectArchiveExtraction`
- `detectArgumentFileExpansion`
- `detectBase64Decode`
- `detectClassLoaderUrl`
- `detectCommand`
- `detectDeserialization`
- `detectDirectoryList`
- `detectDns`
- `detectExpression`
- `detectFastjsonClassResource`
- `detectFileDelete`
- `detectFileRead`
- `detectFileUpload`
- `detectFileWrite`
- `detectGeneratedScriptFileWrite`
- `detectHessianAllocation`
- `detectHttpInvokerDeserialization`
- `detectHttpObjectStreamDeserialization`
- `detectJavaCompilation`
- `detectJdbcUrl`
- `detectJmxFileWrite`
- `detectJmxMBeanInvoke`
- `detectJndi`
- `detectJwtVerificationFailure`
- `detectMarkupParameter`
- `detectOgnl`
- `detectOpenWireThrowable`
- `detectPolymorphicType`
- `detectRemoteJob`
- `detectRequest`
- `detectRmiRegistryBind`
- `detectScannerUserAgent`
- `detectServletIncludeAttributes`
- `detectSessionDeserialization`
- `detectSpringConfigLocation`
- `detectSql`
- `detectUrl`
- `detectWindowsStreamWrite`
- `detectXmlAttachmentReference`
- `detectXmlDecoderExpression`
- `detectXmlRpcSerializableValue`
- `detectXxeEntity`

</details>

## Runtime Behavior

- **Standalone and daemonless**: Built with `standalone=true`, `lock_config=true`, `control=none` and `log=stderr`. No control-file poller is started, `cloud_direct` is forced off, and `/tmp/ohmyrasp-control.json` or `OHMYRASP_MODE=off` is ignored. No background event-writer thread is started unless a log override names a file at start-up.
- **Blocking enforcement** uses `mode=block`. Enforcement outside an HTTP request depends on the hook evidence and the active rule. Monitor decisions emit structured events to `stderr`. [Detection policies](../../../docs/detection.md#deserialization-defenses)
- **Logging**: Emits structured JSON detection events directly to `stderr` (`log=stderr`, `latency_sample=0`) with no `/tmp/ohmyrasp-events.jsonl` file output and no `hook_latency` telemetry.

## Deployment and Limits

- `shirudo` seals the signed JAR at `/run/shirudo-java/ohmyrasp-jdk25.jar` and appends `-javaagent:/run/shirudo-java/ohmyrasp-jdk25.jar` to `JAVA_TOOL_OPTIONS` in `/run/environment.d/shirudo.conf`.
- Only JVMs started by a systemd user manager after load inherit `/run/environment.d/shirudo.conf`; system services and containers must pass `-javaagent:/run/shirudo-java/ohmyrasp-jdk25.jar` explicitly.
- A Java agent is an application-level mitigation inside the JVM, not a kernel security boundary against `root` or the JVM-launching user.
- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.
