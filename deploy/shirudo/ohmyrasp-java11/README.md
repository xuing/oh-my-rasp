# ohmyrasp-java11

> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources.

The `ohmyrasp-java11` package installs the `ohmyrasp-java11` Java upatch: a standalone, daemonless OhMyRASP runtime self-protection agent targeting **Java 11** JVMs (classfile version `<= 55`). It covers **25 ASM transformer families** and **45 detection algorithms**, validated against **10** Vulhub scripts that run the exploit on `java11`.

This package is for hosts pinned to one Java version; the universal package [`ohmyrasp`](../ohmyrasp/README.md) starts the line that fits each JVM of a mixed host. It starts its line on **Java 11 and later**; on any other Java it writes one `ohmyrasp-agent-skipped` JSON line to stderr and the JVM starts without this agent.

## Security Coverage

| Category | Protection Scope | ASM Transformers |
|---|---|---|
| **Command Execution & RCE** | Blocks exploit-grade `ProcessBuilder.start` / `Runtime.exec` calls (including OGNL, SpEL, MVEL, Groovy, JEXL, XStream, deserialization, and scheduler stacks) and Spark/YARN REST job submissions. | `Java11SparkRestTransformer`, `Java11YarnRestTransformer`, `Java11ProcessTransformer` |
| **Elasticsearch LZ4 Transport (CVE-2026-82303)** | In block mode, isolates the declared compressed transport block and checks the decoder consumed its exact length. | `Java11ElasticLz4Transformer` |
| **OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)** | Zero-allocation arithmetic boundary check on `java.util.Base64$Decoder.decode0` blocking x86-64 AVX-512 tail-underflow inputs (Java2Shell / Java4Shell) before the native intrinsic runs. | `Java11Base64Transformer` |
| **SQL Injection & JDBC** | Detects and blocks structural SQL injection across JDBC `Statement` drivers, MyBatis `BoundSql` order-by identifiers, GeoServer OGC CQL filters, H2 `INIT` code execution, Derby SQLJ loading, and MySQL `autoDeserialize` URLs. | `Java11JdbcTransformer` |
| **JNDI, Deserialization & XML/XXE** | Checks remote naming routes, including JDK JAAS directory lookups, and blocks dangerous `ObjectInputStream` / RMI / OpenWire / Hessian / Fastjson `autoType` / `1.2.83` class-resource gadgets, XMLDecoder graphs, and external XML entities (XXE). | `Java11JndiTransformer`, `Java11DeserializationTransformer`, `Java11FastjsonTransformer`, `Java11HessianTransformer`, `Java11JavaBeansTransformer`, `Java11XxeTransformer` |
| **HTTP Request, Path Confusion, Auth & SSRF** | Six-form URI path-confusion decoding (Shiro, GlassFish, Jetty, Spring), weak/default JWT HMAC secret checks, Shiro default `rememberMe` AES detection, forged internal identities, and cloud-metadata / loopback-admin / obfuscated-IP SSRF guards. | `Java11ServletTransformer`, `Java11UrlTransformer`, `Java11JwtTransformer` |
| **File I/O, Uploads & Archive Traversal** | Guards sensitive reads (`/etc/passwd`, `/proc/self/environ`, SSH keys), webroot script writes, ZipSlip archive traversal (`ZipEntry` / 7z), multipart upload path traversal, and `.gnuplot` command injection. | `Java11FileTransformer`, `Java11MultipartUploadTransformer`, `Java11ArchiveTransformer` |
| **Expression Engines, Scripting, ClassLoading & JMX** | Inspects Nashorn/Rhino `ScriptEngine`, JEXL, Jakarta/JSP EL, `JavacTool`/Janino compilation, remote `URLClassLoader`/`RMIClassLoader` codebases, and mutating JMX MBean invocations. | `Java11ClassLoaderTransformer`, `Java11ScriptEngineTransformer`, `Java11JexlTransformer`, `Java11ElTransformer`, `Java11JavaCompilationTransformer`, `Java11JmxTransformer` |
| **Other / Newly Added** | Additional ASM instrumentation hooks detected in agent sources. | `Java11RequestBodyTransformer` |

<details><summary>All detection algorithm IDs (45)</summary>

- `java11_archive_entry_traversal_write`
- `java11_base64_avx512_tail_underflow`
- `java11_classloader_remote_codebase`
- `java11_command_execution_exploit_primitive`
- `java11_command_execution_shell_meta`
- `java11_deserialization_fastjson_resource_url`
- `java11_deserialization_gadget_class`
- `java11_deserialization_hessian_type`
- `java11_deserialization_protocol_class`
- `java11_directory_userinput`
- `java11_el_runtime_execution`
- `java11_file_generated_plot_script_command`
- `java11_file_script_write`
- `java11_file_sensitive_read`
- `java11_jaas_jndi_remote_provider`
- `java11_java_compile_runtime_execution`
- `java11_jdbc_derby_code_loading`
- `java11_jdbc_h2_code_execution`
- `java11_jdbc_mysql_deserialization`
- `java11_jexl_runtime_execution`
- `java11_jmx_remote_config_source`
- `java11_jmx_script_file_write`
- `java11_jndi_remote_lookup`
- `java11_request_debug_process_launch`
- `java11_request_default_crypto_cookie`
- `java11_request_default_jwt_secret`
- `java11_request_forged_include_attribute`
- `java11_request_internal_forward`
- `java11_request_internal_identity`
- `java11_request_jwt_verification_failure`
- `java11_request_ogc_filter_sql_injection`
- `java11_request_path_confusion`
- `java11_request_remote_job_submission`
- `java11_request_session_file_deserialization`
- `java11_request_template_source`
- `java11_request_typed_payload_deserialization`
- `java11_script_engine_runtime_execution`
- `java11_sql_identifier_injection`
- `java11_sql_statement_injection`
- `java11_ssrf_cloud_metadata`
- `java11_ssrf_loopback_admin`
- `java11_ssrf_request_parameter_url`
- `java11_xml_decoder_runtime_execution`
- `java11_xml_decoder_script_file_write`
- `java11_xxe_external_entity_protocol`

</details>

## Runtime Behavior

- **Standalone and daemonless**: Built with `standalone=true`, `lock_config=true`, `control=none` and `log=stderr`. No control-file poller is started, and `/tmp/ohmyrasp-control.json` or `OHMYRASP_MODE=off` is ignored. The baked settings are read only from this JAR: a same-named `META-INF/ohmyrasp-shirudo.properties` elsewhere on the class path is ignored. The runtime starts while the agent loads, before any hook is installed, and no background event-writer thread is started unless a log override names a file at start-up.
- **Blocking enforcement**: Built with `mode=block`; exploit detections throw `Java11RaspBlockException` immediately at the sink (including standalone non-HTTP calls such as malicious `InitialContext.lookup`, `/etc/passwd` reads, `Statement` SQLi, deserialization gadgets, and CVE-2026-114938 Base64 tail-underflow).
- **Logging**: Emits structured JSON detection events directly to `stderr` (`log=stderr`, `latency_sample=0`) with no `/tmp/ohmyrasp-events.jsonl` file output and no `hook_latency` telemetry.

## Deployment and Limits

- `shirudo` seals the signed JAR at `/run/shirudo-java/ohmyrasp-java11.jar` and appends `-javaagent:/run/shirudo-java/ohmyrasp-java11.jar` to `JAVA_TOOL_OPTIONS` in `/run/environment.d/shirudo.conf`.
- Only JVMs started by a systemd user manager after load inherit `/run/environment.d/shirudo.conf`; system services and containers must pass `-javaagent:/run/shirudo-java/ohmyrasp-java11.jar` explicitly.
- A Java agent is an application-level mitigation inside the JVM, not a kernel security boundary against `root` or the JVM-launching user.
- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.
