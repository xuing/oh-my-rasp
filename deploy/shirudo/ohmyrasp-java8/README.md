# ohmyrasp-java8

> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources.

The `ohmyrasp-java8` package installs the `ohmyrasp-java8` Java upatch: a standalone, daemonless OhMyRASP runtime self-protection agent targeting **Java 8** JVMs (classfile version `<= 52`). It covers **25 ASM transformer families** and **44 detection algorithms**, validated against **96** real Vulhub scenarios on `java8`.

## Security Coverage

| Category | Protection Scope | ASM Transformers |
|---|---|---|
| **Command Execution & RCE** | Blocks exploit-grade `ProcessBuilder.start` / `Runtime.exec` calls (including OGNL, SpEL, MVEL, Groovy, JEXL, XStream, deserialization, and scheduler stacks) and Spark/YARN REST job submissions. | `Java8SparkRestTransformer`, `Java8YarnRestTransformer`, `Java8ProcessTransformer` |
| **Elasticsearch LZ4 Transport (CVE-2026-82303)** | In block mode, isolates the declared compressed transport block and checks the decoder consumed its exact length. | `Java8ElasticLz4Transformer` |
| **OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)** | Zero-allocation arithmetic boundary check on `java.util.Base64$Decoder.decode0` blocking x86-64 AVX-512 tail-underflow inputs (Java2Shell / Java4Shell) before the native intrinsic runs. | `Java8Base64Transformer` |
| **SQL Injection & JDBC** | Detects and blocks structural SQL injection across JDBC `Statement` drivers, MyBatis `BoundSql` order-by identifiers, GeoServer OGC CQL filters, H2 `INIT` code execution, Derby SQLJ loading, and MySQL `autoDeserialize` URLs. | `Java8JdbcTransformer` |
| **JNDI, Deserialization & XML/XXE** | Blocks remote `InitialContext.lookup` (`ldap`/`rmi`/`iiop`/`corba`), dangerous `ObjectInputStream` / RMI / OpenWire / Hessian / Fastjson `autoType` / `1.2.83` class-resource gadgets, XMLDecoder graphs, and external XML entities (XXE). | `Java8JndiTransformer`, `Java8DeserializationTransformer`, `Java8FastjsonTransformer`, `Java8HessianTransformer`, `Java8JavaBeansTransformer`, `Java8XxeTransformer` |
| **HTTP Request, Path Confusion, Auth & SSRF** | Six-form URI path-confusion decoding (Shiro, GlassFish, Jetty, Spring), weak/default JWT HMAC secret checks, Shiro default `rememberMe` AES detection, forged internal identities, and cloud-metadata / loopback-admin / obfuscated-IP SSRF guards. | `Java8ServletTransformer`, `Java8UrlTransformer`, `Java8JwtTransformer` |
| **File I/O, Uploads & Archive Traversal** | Guards sensitive reads (`/etc/passwd`, `/proc/self/environ`, SSH keys), webroot script writes, ZipSlip archive traversal (`ZipEntry` / 7z), multipart upload path traversal, and `.gnuplot` command injection. | `Java8FileTransformer`, `Java8MultipartUploadTransformer`, `Java8ArchiveTransformer` |
| **Expression Engines, Scripting, ClassLoading & JMX/JAAS** | Inspects Nashorn/Rhino `ScriptEngine`, JEXL, Jakarta/JSP EL, `JavacTool`/Janino compilation, remote `URLClassLoader`/`RMIClassLoader` codebases, JAAS remote JNDI providers, and mutating JMX MBean invocations. | `Java8ClassLoaderTransformer`, `Java8ScriptEngineTransformer`, `Java8JexlTransformer`, `Java8ElTransformer`, `Java8JavaCompilationTransformer`, `Java8JaasTransformer`, `Java8JmxTransformer` |

<details><summary>All detection algorithm IDs (44)</summary>

- `java8_archive_entry_traversal_write`
- `java8_base64_avx512_tail_underflow`
- `java8_classloader_remote_codebase`
- `java8_command_execution_exploit_primitive`
- `java8_command_execution_shell_meta`
- `java8_deserialization_fastjson_resource_url`
- `java8_deserialization_gadget_class`
- `java8_deserialization_hessian_type`
- `java8_directory_userinput`
- `java8_el_runtime_execution`
- `java8_file_generated_plot_script_command`
- `java8_file_script_write`
- `java8_file_sensitive_read`
- `java8_jaas_jndi_remote_provider`
- `java8_java_compile_runtime_execution`
- `java8_jdbc_derby_code_loading`
- `java8_jdbc_h2_code_execution`
- `java8_jdbc_mysql_deserialization`
- `java8_jexl_runtime_execution`
- `java8_jmx_remote_config_source`
- `java8_jmx_script_file_write`
- `java8_jndi_remote_lookup`
- `java8_request_debug_process_launch`
- `java8_request_default_crypto_cookie`
- `java8_request_default_jwt_secret`
- `java8_request_forged_include_attribute`
- `java8_request_internal_forward`
- `java8_request_internal_identity`
- `java8_request_jwt_verification_failure`
- `java8_request_ogc_filter_sql_injection`
- `java8_request_path_confusion`
- `java8_request_remote_job_submission`
- `java8_request_session_file_deserialization`
- `java8_request_template_source`
- `java8_request_typed_payload_deserialization`
- `java8_script_engine_runtime_execution`
- `java8_sql_identifier_injection`
- `java8_sql_statement_injection`
- `java8_ssrf_cloud_metadata`
- `java8_ssrf_loopback_admin`
- `java8_ssrf_request_parameter_url`
- `java8_xml_decoder_runtime_execution`
- `java8_xml_decoder_script_file_write`
- `java8_xxe_external_entity_protocol`

</details>

## Runtime Behavior

- **Standalone and daemonless**: Built with `standalone=true`, `lock_config=true`, and `control=none`. No control-file poller or background event-writer threads are started, and `/tmp/ohmyrasp-control.json` or `OHMYRASP_MODE=off` is ignored.
- **Blocking enforcement**: Built with `mode=block`; exploit detections throw `Java8RaspBlockException` immediately at the sink (including standalone non-HTTP calls such as malicious `InitialContext.lookup`, `/etc/passwd` reads, `Statement` SQLi, deserialization gadgets, and CVE-2026-114938 Base64 tail-underflow).
- **Logging**: Emits structured JSON detection events directly to `stderr` (`log=stderr`, `latency_sample=0`) with no `/tmp/ohmyrasp-events.jsonl` file output and no `hook_latency` telemetry.

## Deployment and Limits

- `shirudo` seals the signed JAR at `/run/shirudo-java/ohmyrasp-java8.jar` and appends `-javaagent:/run/shirudo-java/ohmyrasp-java8.jar` to `JAVA_TOOL_OPTIONS` in `/run/environment.d/shirudo.conf`.
- **Java 8 `JAVA_TOOL_OPTIONS` limit**: OpenJDK 8 truncates `JAVA_TOOL_OPTIONS` at 1024 bytes and 64 options (JDK-8288483); keep agents few and options short. This JAR also omits `Boot-Class-Path` so `appendToBootstrapClassLoaderSearch` loads the sealed `/run/shirudo-java/` path cleanly.
- Only JVMs started by a systemd user manager after load inherit `/run/environment.d/shirudo.conf`; system services and containers must pass `-javaagent:/run/shirudo-java/ohmyrasp-java8.jar` explicitly.
- A Java agent is an application-level mitigation inside the JVM, not a kernel security boundary against `root` or the JVM-launching user.
- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.
