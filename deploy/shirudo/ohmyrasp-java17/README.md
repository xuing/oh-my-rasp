# ohmyrasp-java17

> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources.

The `ohmyrasp-java17` package installs the `ohmyrasp-java17` Java upatch: a standalone, daemonless OhMyRASP runtime self-protection agent targeting **Java 17 and Java 21** JVMs (classfile version `<= 61`). It covers **24 ASM transformer families** and **44 detection algorithms**, validated against **12** real Vulhub scenarios on `java17` plus **3** on `java21`.

## Security Coverage

| Category | Protection Scope | ASM Transformers |
|---|---|---|
| **Command Execution & RCE** | Blocks exploit-grade `ProcessBuilder.start` / `Runtime.exec` calls (including OGNL, SpEL, MVEL, Groovy, JEXL, XStream, deserialization, and scheduler stacks) and Spark/YARN REST job submissions. | `Java17SparkRestTransformer`, `Java17YarnRestTransformer`, `Java17ProcessTransformer` |
| **OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)** | Zero-allocation arithmetic boundary check on `java.util.Base64$Decoder.decode0` blocking x86-64 AVX-512 tail-underflow inputs (Java2Shell / Java4Shell) before the native intrinsic runs. | `Java17Base64Transformer` |
| **SQL Injection & JDBC** | Detects and blocks structural SQL injection across JDBC `Statement` drivers, MyBatis `BoundSql` order-by identifiers, GeoServer OGC CQL filters, H2 `INIT` code execution, Derby SQLJ loading, and MySQL `autoDeserialize` URLs. | `Java17JdbcTransformer` |
| **JNDI, Deserialization & XML/XXE** | Blocks remote `InitialContext.lookup` (`ldap`/`rmi`/`iiop`/`corba`), dangerous `ObjectInputStream` / RMI / OpenWire / Hessian / Fastjson `autoType` / `1.2.83` class-resource gadgets, XMLDecoder graphs, and external XML entities (XXE). | `Java17JndiTransformer`, `Java17DeserializationTransformer`, `Java17FastjsonTransformer`, `Java17HessianTransformer`, `Java17JavaBeansTransformer`, `Java17XxeTransformer` |
| **HTTP Request, Path Confusion, Auth & SSRF** | Six-form URI path-confusion decoding (Shiro, GlassFish, Jetty, Spring), weak/default JWT HMAC secret checks, Shiro default `rememberMe` AES detection, forged internal identities, and cloud-metadata / loopback-admin / obfuscated-IP SSRF guards. | `Java17ServletTransformer`, `Java17UrlTransformer`, `Java17JwtTransformer` |
| **File I/O, Uploads & Archive Traversal** | Guards sensitive reads (`/etc/passwd`, `/proc/self/environ`, SSH keys), webroot script writes, ZipSlip archive traversal (`ZipEntry` / 7z), multipart upload path traversal, and `.gnuplot` command injection. | `Java17FileTransformer`, `Java17MultipartUploadTransformer`, `Java17ArchiveTransformer` |
| **Expression Engines, Scripting, ClassLoading & JMX/JAAS** | Inspects Nashorn/Rhino `ScriptEngine`, JEXL, Jakarta/JSP EL, `JavacTool`/Janino compilation, remote `URLClassLoader`/`RMIClassLoader` codebases, JAAS remote JNDI providers, and mutating JMX MBean invocations. | `Java17ClassLoaderTransformer`, `Java17ScriptEngineTransformer`, `Java17JexlTransformer`, `Java17ElTransformer`, `Java17JavaCompilationTransformer`, `Java17JaasTransformer`, `Java17JmxTransformer` |

<details><summary>All detection algorithm IDs (44)</summary>

- `java17_archive_entry_traversal_write`
- `java17_base64_avx512_tail_underflow`
- `java17_classloader_remote_codebase`
- `java17_command_execution_exploit_primitive`
- `java17_command_execution_shell_meta`
- `java17_deserialization_fastjson_resource_url`
- `java17_deserialization_gadget_class`
- `java17_deserialization_hessian_type`
- `java17_directory_userinput`
- `java17_el_runtime_execution`
- `java17_file_generated_plot_script_command`
- `java17_file_script_write`
- `java17_file_sensitive_read`
- `java17_jaas_jndi_remote_provider`
- `java17_java_compile_runtime_execution`
- `java17_jdbc_derby_code_loading`
- `java17_jdbc_h2_code_execution`
- `java17_jdbc_mysql_deserialization`
- `java17_jexl_runtime_execution`
- `java17_jmx_remote_config_source`
- `java17_jmx_script_file_write`
- `java17_jndi_remote_lookup`
- `java17_request_debug_process_launch`
- `java17_request_default_crypto_cookie`
- `java17_request_default_jwt_secret`
- `java17_request_forged_include_attribute`
- `java17_request_internal_forward`
- `java17_request_internal_identity`
- `java17_request_jwt_verification_failure`
- `java17_request_ogc_filter_sql_injection`
- `java17_request_path_confusion`
- `java17_request_remote_job_submission`
- `java17_request_session_file_deserialization`
- `java17_request_template_source`
- `java17_request_typed_payload_deserialization`
- `java17_script_engine_runtime_execution`
- `java17_sql_identifier_injection`
- `java17_sql_statement_injection`
- `java17_ssrf_cloud_metadata`
- `java17_ssrf_loopback_admin`
- `java17_ssrf_request_parameter_url`
- `java17_xml_decoder_runtime_execution`
- `java17_xml_decoder_script_file_write`
- `java17_xxe_external_entity_protocol`

</details>

## Runtime Behavior

- **Standalone and daemonless**: Built with `standalone=true`, `lock_config=true`, and `control=none`. No control-file poller or background event-writer threads are started, and `/tmp/ohmyrasp-control.json` or `OHMYRASP_MODE=off` is ignored.
- **Blocking enforcement**: Built with `mode=block`; exploit detections throw `Java17RaspBlockException` immediately at the sink (including standalone non-HTTP calls such as malicious `InitialContext.lookup`, `/etc/passwd` reads, `Statement` SQLi, deserialization gadgets, and CVE-2026-114938 Base64 tail-underflow).
- **Logging**: Emits structured JSON detection events directly to `stderr` (`log=stderr`, `latency_sample=0`) with no `/tmp/ohmyrasp-events.jsonl` file output and no `hook_latency` telemetry.

## Deployment and Limits

- `shirudo` seals the signed JAR at `/run/shirudo-java/ohmyrasp-java17.jar` and appends `-javaagent:/run/shirudo-java/ohmyrasp-java17.jar` to `JAVA_TOOL_OPTIONS` in `/run/environment.d/shirudo.conf`.
- Only JVMs started by a systemd user manager after load inherit `/run/environment.d/shirudo.conf`; system services and containers must pass `-javaagent:/run/shirudo-java/ohmyrasp-java17.jar` explicitly.
- A Java agent is an application-level mitigation inside the JVM, not a kernel security boundary against `root` or the JVM-launching user.
- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.
