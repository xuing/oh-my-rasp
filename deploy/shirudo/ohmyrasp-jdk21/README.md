# ohmyrasp-jdk21

> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources.

The `ohmyrasp-jdk21` package installs the `ohmyrasp-jdk21` Java upatch: a standalone, daemonless OhMyRASP runtime self-protection agent targeting **Java 21 and Java 25** JVMs (classfile version `<= 65`). It registers **28 ASM hook modules** and **56 `DetectorEngine` capabilities**, backed by **136** end-to-end Vulhub acceptance scenarios.

## Security Coverage

| Category | Protection Scope | ASM Hook Modules |
|---|---|---|
| **Command Execution & RCE** | Blocks exploit-grade `ProcessBuilder.start` / `Runtime.exec` calls (including OGNL, SpEL, MVEL, Groovy, JEXL, XStream, deserialization, and scheduler stacks) and Spark/YARN REST job submissions. | `ArgumentParserHookModule`, `ProcessHookModule` |
| **OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)** | Zero-allocation arithmetic boundary check on `java.util.Base64$Decoder.decode0` blocking x86-64 AVX-512 tail-underflow inputs (Java2Shell / Java4Shell) before the native intrinsic runs. | `Base64HookModule` |
| **SQL Injection & JDBC** | Detects and blocks structural SQL injection across JDBC `Statement` drivers, MyBatis `BoundSql` order-by identifiers, GeoServer OGC CQL filters, H2 `INIT` code execution, Derby SQLJ loading, and MySQL `autoDeserialize` URLs. | `SqlHookModule` |
| **JNDI, Deserialization & XML/XXE** | Blocks remote `InitialContext.lookup` (`ldap`/`rmi`/`iiop`/`corba`), dangerous `ObjectInputStream` / RMI / OpenWire / Hessian / Fastjson `autoType` / `1.2.83` class-resource gadgets, XMLDecoder graphs, and external XML entities (XXE). | `HessianHookModule`, `HttpInvokerHookModule`, `JavaBeansHookModule`, `JndiHookModule`, `ObjectInputStreamHookModule`, `OpenWireHookModule`, `PolymorphicDeserializationHookModule`, `RmiRegistryHookModule`, `SessionHookModule`, `XmlAttachmentHookModule`, `XmlRpcHookModule`, `XxeHookModule` |
| **HTTP Request, Path Confusion, Auth & SSRF** | Six-form URI path-confusion decoding (Shiro, GlassFish, Jetty, Spring), weak/default JWT HMAC secret checks, Shiro default `rememberMe` AES detection, forged internal identities, and cloud-metadata / loopback-admin / obfuscated-IP SSRF guards. | `JwtHookModule`, `NetworkHookModule`, `ServletHookModule` |
| **File I/O, Uploads & Archive Traversal** | Guards sensitive reads (`/etc/passwd`, `/proc/self/environ`, SSH keys), webroot script writes, ZipSlip archive traversal (`ZipEntry` / 7z), multipart upload path traversal, and `.gnuplot` command injection. | `ArchiveHookModule`, `FileHookModule`, `MultipartUploadHookModule` |
| **Expression Engines, Scripting, ClassLoading & JMX/JAAS** | Inspects Nashorn/Rhino `ScriptEngine`, JEXL, Jakarta/JSP EL, `JavacTool`/Janino compilation, remote `URLClassLoader`/`RMIClassLoader` codebases, JAAS remote JNDI providers, and mutating JMX MBean invocations. | `ClassLoaderHookModule`, `ExpressionHookModule`, `JaasHookModule`, `JavaCompilationHookModule`, `JmxHookModule`, `SpringConfigHookModule` |

<details><summary>All DetectorEngine capabilities (56)</summary>

- `detectArchiveExtraction`
- `detectArgumentFileExpansion`
- `detectBase64Decode`
- `detectClassLoaderUrl`
- `detectCommand`
- `detectDeserialization`
- `detectDirectoryList`
- `detectDns`
- `detectEval`
- `detectExpression`
- `detectFastjsonClassResource`
- `detectFileDelete`
- `detectFileRead`
- `detectFileUpload`
- `detectFileWrite`
- `detectGeneratedScriptFileWrite`
- `detectHessianType`
- `detectHttpInvokerDeserialization`
- `detectHttpObjectStreamDeserialization`
- `detectInclude`
- `detectJaasConfig`
- `detectJavaCompilation`
- `detectJdbcUrl`
- `detectJmxFileWrite`
- `detectJmxMBeanInvoke`
- `detectJndi`
- `detectJwtVerificationFailure`
- `detectLink`
- `detectLoadLibrary`
- `detectOgnl`
- `detectPolymorphicType`
- `detectProtocolClassInstantiation`
- `detectRemoteJobSubmission`
- `detectRename`
- `detectRequest`
- `detectResponseDataLeak`
- `detectRmiRegistryBind`
- `detectServletIncludeAttributes`
- `detectSessionDeserialization`
- `detectSpringConfigLocation`
- `detectSql`
- `detectSqlException`
- `detectSqlRegex`
- `detectUrl`
- `detectWebdavUpload`
- `detectWebshellCallable`
- `detectWebshellCommand`
- `detectWebshellEval`
- `detectWebshellFileWrite`
- `detectWebshellLdPreload`
- `detectWindowsStreamWrite`
- `detectXmlAttachmentReference`
- `detectXmlDecoderExpression`
- `detectXmlRpcSerializableValue`
- `detectXssEcho`
- `detectXxeEntity`

</details>

## Runtime Behavior

- **Standalone and daemonless**: Built with `standalone=true`, `lock_config=true`, and `control=none`. No control-file poller or background event-writer threads are started, `cloud_direct` is forced off, and `/tmp/ohmyrasp-control.json` or `OHMYRASP_MODE=off` is ignored.
- **Blocking enforcement**: Built with `mode=block`; throws `OhMyRaspBlockException` on HTTP-request-correlated exploit detections and on request-less blocking sinks (`detectBase64Decode`, `detectHessianType`, `detectProtocolClassInstantiation`); request-less sink probes without an active HTTP request log structured JSON detections to `stderr`.
- **Logging**: Emits structured JSON detection events directly to `stderr` (`log=stderr`, `latency_sample=0`) with no `/tmp/ohmyrasp-events.jsonl` file output and no `hook_latency` telemetry.

## Deployment and Limits

- `shirudo` seals the signed JAR at `/run/shirudo-java/ohmyrasp-jdk21.jar` and appends `-javaagent:/run/shirudo-java/ohmyrasp-jdk21.jar` to `JAVA_TOOL_OPTIONS` in `/run/environment.d/shirudo.conf`.
- Only JVMs started by a systemd user manager after load inherit `/run/environment.d/shirudo.conf`; system services and containers must pass `-javaagent:/run/shirudo-java/ohmyrasp-jdk21.jar` explicitly.
- A Java agent is an application-level mitigation inside the JVM, not a kernel security boundary against `root` or the JVM-launching user.
- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.
