# OhMyRASP Detection Coverage

> **Generated** by `scripts/gen-detection-coverage.py` — derived from the agent
> sources and acceptance suite, not written by hand. Re-run after changing hooks,
> detectors, or acceptance scripts. `--check` fails CI when this file is stale.

## Summary

| Metric | Count |
|--------|------:|
| Hook families (instrumentation points) | 31 |
| Detector capabilities (engine entry points) | 56 |
| Verified algorithm signatures (asserted by tests) | 43 |
| End-to-end vulnerability acceptance scenarios | 136 |
| JDK lines exercised | 6 |

## Hook families

Instrumentation points registered by `HookRegistry.defaults()`. Each module
rewrites a family of risky call sites and routes them to the detector engine.

| Family | Hook module |
|--------|-------------|
| Archive | `ArchiveHookModule` |
| ArgumentParser | `ArgumentParserHookModule` |
| Base64 | `Base64HookModule` |
| ClassLoader | `ClassLoaderHookModule` |
| ElasticLz4 | `ElasticLz4HookModule` |
| Expression | `ExpressionHookModule` |
| File | `FileHookModule` |
| Hessian | `HessianHookModule` |
| HttpInvoker | `HttpInvokerHookModule` |
| Jaas | `JaasHookModule` |
| JavaBeans | `JavaBeansHookModule` |
| JavaCompilation | `JavaCompilationHookModule` |
| Jmx | `JmxHookModule` |
| Jndi | `JndiHookModule` |
| Jwt | `JwtHookModule` |
| MultipartUpload | `MultipartUploadHookModule` |
| Network | `NetworkHookModule` |
| ObjectInputStream | `ObjectInputStreamHookModule` |
| OpenWire | `OpenWireHookModule` |
| PolymorphicDeserialization | `PolymorphicDeserializationHookModule` |
| Process | `ProcessHookModule` |
| RmiRegistry | `RmiRegistryHookModule` |
| Servlet | `ServletHookModule` |
| Session | `SessionHookModule` |
| SparkSubmit | `SparkSubmitHookModule` |
| SpringConfig | `SpringConfigHookModule` |
| Sql | `SqlHookModule` |
| XmlAttachment | `XmlAttachmentHookModule` |
| XmlRpc | `XmlRpcHookModule` |
| Xxe | `XxeHookModule` |
| YarnSubmit | `YarnSubmitHookModule` |

## Detector capabilities

The engine exposes **56** detection entry points:

- `detectArchiveExtraction` · `detectArgumentFileExpansion` · `detectBase64Decode`
- `detectClassLoaderUrl` · `detectCommand` · `detectDeserialization`
- `detectDirectoryList` · `detectDns` · `detectEval`
- `detectExpression` · `detectFastjsonClassResource` · `detectFileDelete`
- `detectFileRead` · `detectFileUpload` · `detectFileWrite`
- `detectGeneratedScriptFileWrite` · `detectHessianType` · `detectHttpInvokerDeserialization`
- `detectHttpObjectStreamDeserialization` · `detectInclude` · `detectJaasConfig`
- `detectJavaCompilation` · `detectJdbcUrl` · `detectJmxFileWrite`
- `detectJmxMBeanInvoke` · `detectJndi` · `detectJwtVerificationFailure`
- `detectLink` · `detectLoadLibrary` · `detectOgnl`
- `detectPolymorphicType` · `detectProtocolClassInstantiation` · `detectRemoteJobSubmission`
- `detectRename` · `detectRequest` · `detectResponseDataLeak`
- `detectRmiRegistryBind` · `detectServletIncludeAttributes` · `detectSessionDeserialization`
- `detectSpringConfigLocation` · `detectSql` · `detectSqlException`
- `detectSqlRegex` · `detectUrl` · `detectWebdavUpload`
- `detectWebshellCallable` · `detectWebshellCommand` · `detectWebshellEval`
- `detectWebshellFileWrite` · `detectWebshellLdPreload` · `detectWindowsStreamWrite`
- `detectXmlAttachmentReference` · `detectXmlDecoderExpression` · `detectXmlRpcSerializableValue`
- `detectXssEcho` · `detectXxeEntity`

## Rule scope

The index covers literal detection IDs in the primary engine and hooks, reviewed computed IDs, and named findings in the Java backports. A row with both columns populated has distinct branches or a product-specific exclusion. General request indicators still need runtime evidence to establish an effect.

The descriptions live in the [general catalog](../rules/general.json) and [product-specific catalog](../rules/product.json). Scope describes applicability. Policy selection continues to use the exact event ID.

### Primary agent

| Algorithm identifier | Cross-product evidence | Product or component dependency |
|---|---|---|
| `archive_traversal` | An archive entry and its destination cross the extraction boundary. | — |
| `base64_avx512_tail_underflow` | — | The candidate input shape targets a particular JDK Base64 decoder implementation. |
| `classloader_remote` | A class loader is given a remote code source. | — |
| `command_common` | Recognized direct or literal shell file-reader operands select a listed path. Other shell programs are checked for command indicators. | — |
| `command_config_injection` | — | RocketMQ filter-server ownership of a process launch supplies the configuration context. |
| `command_config_listener` | — | The Apache Solr executable-listener implementation appears on the process stack. |
| `command_dnslog` | A directly launched network tool names a listed callback host in a recognized destination argument. | — |
| `command_error` | Command text matches a configured or built-in suspicious-command, shell-syntax or callback-domain indicator. | — |
| `command_reflect` | Explicit policy selects reflective dispatch at the process API. | — |
| `command_userinput` | Request-controlled syntax reaches the launched shell program. The POSIX branch preserves the argument boundaries. | — |
| `deleteFile_userinput` | A request-selected host entry escapes the configured deletion root. Exact absolute-path matches can also be selected explicitly by policy. | — |
| `deserialization_blacklist` | — | Known class families, type-resolution behavior or unmarshaller implementations affect the judgment. |
| `deserialization_cluster_message` | — | Known cluster, logging or remoting implementation frames supply transport provenance. |
| `deserialization_fastjson_resource_url` | — | Fastjson autoType resolves a URL-shaped class resource. |
| `deserialization_gadget` | — | Known class families, type-resolution behavior or unmarshaller implementations affect the judgment. |
| `deserialization_hessian_type` | — | Known class families, type-resolution behavior or unmarshaller implementations affect the judgment. |
| `deserialization_http_invoker` | — | The HTTP remoting invocation mechanism determines where object-stream input is expected. |
| `deserialization_http_object_stream` | A Java object stream is read from an HTTP request body. | — |
| `deserialization_jms_object_message` | Object deserialization is correlated with a particular messaging or RPC transport. | — |
| `deserialization_logging_message` | — | Known cluster, logging or remoting implementation frames supply transport provenance. |
| `deserialization_polymorphic_type` | — | Known class families, type-resolution behavior or unmarshaller implementations affect the judgment. |
| `deserialization_protocol_class` | — | Known class families, type-resolution behavior or unmarshaller implementations affect the judgment. |
| `deserialization_remoting_transport` | — | Known cluster, logging or remoting implementation frames supply transport provenance. |
| `deserialization_rmi_registry_bind` | The registry bind is observed in an RMI transport context with a proxy or reference type. | — |
| `deserialization_rmi_transport` | Object deserialization is correlated with a particular messaging or RPC transport. | — |
| `deserialization_session_file` | — | The judgment assumes file-backed session persistence and suspicious session-ID semantics. |
| `deserialization_signed_object` | — | Known cluster, logging or remoting implementation frames supply transport provenance. |
| `deserialization_webflow_state` | — | Spring Web Flow state restoration supplies the deserialization context. |
| `deserialization_xmlrpc_serialized` | Object deserialization is correlated with a particular messaging or RPC transport. | — |
| `directory_reflect` | Explicit directory policy selects a dispatch mechanism or a filesystem location. | — |
| `directory_unwanted` | Explicit directory policy selects a dispatch mechanism or a filesystem location. | — |
| `directory_userinput` | A request-selected directory is listed. The evidence distinguishes the protected target, a selected walk and a path-only policy. | — |
| `dns_blacklist` | A DNS name matches a configured or built-in domain indicator. | — |
| `el_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `eval_regex` | The operator supplies a pattern to match against evaluation input or SQL. | — |
| `expression_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `fileUpload_java_archive` | The application declares deployment authorization and the request supplies an archive. Deployment-context metadata alone requires explicit policy. | — |
| `fileUpload_multipart_exe` | A submitted filename suggests executable, script or active web content. Its suffix alone does not establish execution. | — |
| `fileUpload_multipart_expression` | An upload filename contains expression-language indicators. | — |
| `fileUpload_multipart_html` | A submitted filename suggests executable, script or active web content. Its suffix alone does not establish execution. | — |
| `fileUpload_multipart_script` | A submitted filename suggests executable, script or active web content. Its suffix alone does not establish execution. | — |
| `fileUpload_path_traversal` | The submitted filename contains path-escape indicators. | — |
| `fileUpload_webdav` | A WebDAV-style operation targets a script or an unsafe filesystem destination. | — |
| `include_protocol` | An include target is checked for an external protocol or request-derived path. | — |
| `include_userinput` | An include target is checked for an external protocol or request-derived path. | — |
| `java_compile_runtime` | Java source presented to the compiler contains runtime execution primitives. | — |
| `javascript_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `jdbc_h2_init` | — | H2 connection initialization is interpreted using that driver’s URL semantics. |
| `jdbc_mysql_deserialization` | — | Execution or deserialization depends on the selected database driver's options or SQL extensions. |
| `jexl_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `jiffle_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `jmx_file_write` | A synchronous MBean argument names the same script destination that the JDK opens for writing. The event records a write-open attempt. | — |
| `jmx_remote_config` | A resolved JMX invocation carries a location expression with configuration indicators. | Compound broker configuration sources include XBean or Spring location expressions. |
| `jndi_disable_all` | A lookup uses a URL scheme listed by the naming policy. Runtime events identify scheme selection or direct URL-provider lookup. | — |
| `jndi_jaas_config` | A naming operation or a JAAS naming-provider configuration is checked against the JNDI policy. | — |
| `link_webshell` | A link or rename selects a script-like destination. | — |
| `loadLibrary_unc` | A native library load selects a network share. | — |
| `ognl_blacklist` | — | The OGNL policy uses engine-specific syntax or a configured expression-length limit. |
| `ognl_length_limit` | — | The OGNL policy uses engine-specific syntax or a configured expression-length limit. |
| `ognl_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `readFile_argument_expansion` | — | The argument parser's file-expansion convention determines whether a request selected a file. |
| `readFile_outsideWebroot` | File-read policies use location, remote address or request selection as evidence. | — |
| `readFile_unwanted` | File-read policies use location, remote address or request selection as evidence. | — |
| `readFile_userinput` | Request input selects a host-file read. Path-only matches require explicit policy. | — |
| `readFile_userinput_http` | File-read policies use location, remote address or request selection as evidence. | — |
| `readFile_userinput_unwanted` | File-read policies use location, remote address or request selection as evidence. | — |
| `rename_webshell` | A link or rename selects a script-like destination. | — |
| `request_debug_process_launch` | Request route, method and fields suggest a debug process-launch operation. No process receipt is required. | — |
| `request_default_credential` | — | Known administrative credentials, encryption keys or signing secrets depend on the product and credential format. |
| `request_default_crypto_cookie` | — | Known administrative credentials, encryption keys or signing secrets depend on the product and credential format. |
| `request_default_jwt_secret` | — | Known administrative credentials, encryption keys or signing secrets depend on the product and credential format. |
| `request_dynamic_script_config` | — | Application configuration fields select executable scripts or enable a template loader. |
| `request_empty_credential_bypass` | — | The meaning of a bypass flag or setup-state field depends on the application's access-control contract. |
| `request_expression_header` | An HTTP field or path contains expression or template syntax. These are input indicators. | — |
| `request_expression_parameter` | An HTTP field or path contains expression or template syntax. These are input indicators. | — |
| `request_expression_parameter_name` | An HTTP field or path contains expression or template syntax. These are input indicators. | — |
| `request_expression_path` | An HTTP field or path contains expression or template syntax. These are input indicators. | — |
| `request_forged_include_attribute` | The decision uses servlet include attributes and the request context. | A Liferay portal dispatch is a product-specific normal-include exclusion. |
| `request_internal_forward` | Route and parameter conventions suggest an internal forward or an external template source. | — |
| `request_internal_identity` | — | The request presents a Nacos internal-service identity. Maintenance routes and control-path conventions affect the decision. |
| `request_internal_resource` | Alternative interpretations of the request target expose protected web resources or ambiguous path structure. | — |
| `request_java_bean_pollution` | A request binding name refers to Java class-loader metadata. | — |
| `request_jndi_lookup` | Request text contains naming-lookup or XML entity syntax. Transport opening is unconfirmed. | — |
| `request_json_patch_expression` | A JSON Patch path contains an expression indicator. | — |
| `request_jwt_verification_failure` | — | The DataEase authentication filter hands the same request to its chain after its selected credential fails verification. |
| `request_message_selector_expression` | A message-selector field contains runtime expression syntax. | — |
| `request_ogc_filter_sql_injection` | An OGC filter argument contains SQL-control indicators. JDBC execution is unconfirmed. | — |
| `request_path_confusion` | Alternative interpretations of the request target expose protected web resources or ambiguous path structure. | — |
| `request_plot_command_injection` | A plotting parameter contains a plot-interpreter command directive. | — |
| `request_remote_content_stream` | — | The meaning of stream, import or repository configuration fields depends on the application contract. |
| `request_remote_import_script_write` | — | The meaning of stream, import or repository configuration fields depends on the application contract. |
| `request_remote_job_submission` | — | Spark and YARN check their deployment-specific submit roles. Descriptor-only remote artifacts and YARN command indicators require explicit policy selection. |
| `request_repository_webroot_write` | — | The meaning of stream, import or repository configuration fields depends on the application contract. |
| `request_scanner` | The user-agent resembles a scanner. This is client-supplied metadata. | — |
| `request_scheduler_shell_job` | — | Scheduler request fields select a shell-backed job type and supply its source. |
| `request_serialized_client_state` | Client state in a request contains a Java object stream. | — |
| `request_server_side_script_put` | An HTTP PUT selects a script-like destination. | — |
| `request_setup_state_reset` | — | The meaning of a bypass flag or setup-state field depends on the application's access-control contract. |
| `request_sql_identifier_injection` | An explicitly selected policy inspects SQL-related request fields before any JDBC handoff. | — |
| `request_sql_sort_injection` | An explicitly selected policy inspects SQL-related request fields before any JDBC handoff. | — |
| `request_template_loader_enable` | — | Application configuration fields select executable scripts or enable a template loader. |
| `request_template_parameter` | An HTTP field or path contains expression or template syntax. These are input indicators. | — |
| `request_template_source` | Route and parameter conventions suggest an internal forward or an external template source. | — |
| `request_typed_parameter_deserialization` | — | Typed binding syntax and known classes or gadget families determine the match. |
| `request_typed_payload_deserialization` | — | Typed binding syntax and known classes or gadget families determine the match. |
| `request_upload_filename_override` | — | Upload-binding field conventions determine whether a filename can be overridden. |
| `request_xml_polymorphic_gadget` | — | Typed binding syntax and known classes or gadget families determine the match. |
| `request_xxe_payload` | Request text contains naming-lookup or XML entity syntax. Transport opening is unconfirmed. | — |
| `response_dataLeak` | Response text matches a sensitive-data pattern. | — |
| `script_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `spel_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `spring_remote_config` | — | A Spring configuration-loading mechanism receives a remote location. |
| `sql_derby_code_execution` | — | Execution or deserialization depends on the selected database driver's options or SQL extensions. |
| `sql_exception` | JDBC evidence includes an error, a configured SQL policy or request-correlated query structure, depending on the identifier. | — |
| `sql_h2_code_execution` | — | Execution or deserialization depends on the selected database driver's options or SQL extensions. |
| `sql_identifier_injection` | SQL control syntax is correlated with an identifier or mapper substitution. | The MyBatis branch requires substitution provenance at statement handoff. |
| `sql_policy` | JDBC evidence includes an error, a configured SQL policy or request-correlated query structure, depending on the identifier. | — |
| `sql_regex` | The operator supplies a pattern to match against evaluation input or SQL. | — |
| `sql_userinput` | JDBC evidence includes an error, a configured SQL policy or request-correlated query structure, depending on the identifier. | — |
| `ssrf_aws` | — | Cloud metadata endpoints have provider-specific address and path semantics. |
| `ssrf_common` | Outbound connection evidence includes target, protocol, representation or request correlation. Some destination-only findings require explicit policy. | — |
| `ssrf_obfuscate` | Outbound connection evidence includes target, protocol, representation or request correlation. Some destination-only findings require explicit policy. | — |
| `ssrf_protocol` | Outbound connection evidence includes target, protocol, representation or request correlation. Some destination-only findings require explicit policy. | — |
| `ssrf_userinput` | Outbound connection evidence includes target, protocol, representation or request correlation. Some destination-only findings require explicit policy. | — |
| `template_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `webshell_callable` | The monitored operation involves a callable, command, evaluated text, file write or loader environment setting. The individual rule determines the required evidence. | — |
| `webshell_command` | The monitored operation involves a callable, command, evaluated text, file write or loader environment setting. The individual rule determines the required evidence. | — |
| `webshell_eval` | The monitored operation involves a callable, command, evaluated text, file write or loader environment setting. The individual rule determines the required evidence. | — |
| `webshell_file_put_contents` | The monitored operation involves a callable, command, evaluated text, file write or loader environment setting. The individual rule determines the required evidence. | — |
| `webshell_ld_preload` | The monitored operation involves a callable, command, evaluated text, file write or loader environment setting. The individual rule determines the required evidence. | — |
| `writeFile_NTFS` | Explicit policy selects a writable Windows open of a named data stream. The unnamed default stream uses ordinary base-file policy. | — |
| `writeFile_config_path` | — | RocketMQ configuration-persistence frames identify the file write. |
| `writeFile_generated_script` | A file-write decision uses a stream name, dispatch stack, script suffix or generated interpreter content. | — |
| `writeFile_reflect` | A file-write decision uses a stream name, dispatch stack, script suffix or generated interpreter content. | — |
| `writeFile_script` | A file-write decision uses a stream name, dispatch stack, script suffix or generated interpreter content. | — |
| `xml_decoder_runtime` | JavaBeans XML decoding is correlated with runtime invocation or a script-file operation. | — |
| `xml_decoder_webshell` | JavaBeans XML decoding is correlated with runtime invocation or a script-file operation. | — |
| `xpath_runtime` | Runtime execution primitives occur in an expression or execution is observed under an evaluator. A library hook identifies the evaluation context. | — |
| `xss_echo` | Reflected output or an input pattern supplies an XSS indicator. | — |
| `xss_userinput` | Reflected output or an input pattern supplies an XSS indicator. | — |
| `xxe_file` | An XML external entity refers to a file. | — |
| `xxe_protocol` | The XML parser selects an external protocol. At the instrumented transport boundary the agent can check local catalog provenance. | — |

### Backport agents

| Algorithm identifier | Cross-product evidence | Product or component dependency |
|---|---|---|
| `java8_archive_entry_traversal_write`, `java11_archive_entry_traversal_write`, `java17_archive_entry_traversal_write` | An observed archive member selects an absolute or escaping relative host-write operand at a file API or Unix channel open. | — |
| `java8_base64_avx512_tail_underflow`, `java11_base64_avx512_tail_underflow`, `java17_base64_avx512_tail_underflow` | — | The input shape corresponds to a JDK decoder implementation defect. |
| `java8_classloader_remote_codebase`, `java11_classloader_remote_codebase`, `java17_classloader_remote_codebase` | A remote codebase is supplied to a Java class-loading API. | — |
| `java8_command_execution_exploit_primitive`, `java11_command_execution_exploit_primitive`, `java17_command_execution_exploit_primitive` | Process arguments or a deserialization context supply the evidence. Other branches use a product-specific caller. | decision_basis=configured_listener identifies the Solr executable listener. Other component-specific callers share this ID with general process branches. |
| `java8_command_execution_shell_meta`, `java11_command_execution_shell_meta`, `java17_command_execution_shell_meta` | With decision_basis=request_shell_syntax, request input contributes shell control syntax at process launch. The Windows branch uses a command-text heuristic. | decision_basis=configuration_launcher identifies the RocketMQ filter-server branch. The scheduler job branch records decision_basis=scheduled_script. |
| `deleteFile_userinput` | A request-selected deletion escapes a configured filesystem root. | — |
| `java8_deserialization_fastjson_resource_url`, `java11_deserialization_fastjson_resource_url`, `java17_deserialization_fastjson_resource_url` | — | Fastjson autoType reaches a URL-shaped resource lookup. |
| `java8_deserialization_gadget_class`, `java11_deserialization_gadget_class`, `java17_deserialization_gadget_class` | — | The stream resolver selected a listed class or a proxy implementing a listed interface. The event identifies the resolution operation. |
| `java8_deserialization_hessian_type`, `java11_deserialization_hessian_type`, `java17_deserialization_hessian_type` | — | Hessian type resolution is checked against known dangerous types. |
| `java8_directory_userinput`, `java11_directory_userinput`, `java17_directory_userinput` | A request-selected protected directory or walk reaches a listing operation. | — |
| `java8_el_runtime_execution`, `java11_el_runtime_execution`, `java17_el_runtime_execution` | An expression at the Unified EL evaluation boundary contains runtime execution syntax. | — |
| `fileUpload_java_archive` | The application declares deployment authorization and the request supplies an archive. Deployment-context metadata alone requires explicit policy. | — |
| `fileUpload_multipart_exe` | A submitted filename suggests executable, script or active web content. Its suffix alone does not establish execution. | — |
| `fileUpload_multipart_expression` | An upload filename contains expression-language indicators. | — |
| `fileUpload_multipart_html` | A submitted filename suggests executable, script or active web content. Its suffix alone does not establish execution. | — |
| `fileUpload_multipart_script` | A submitted filename suggests executable, script or active web content. Its suffix alone does not establish execution. | — |
| `fileUpload_path_traversal` | The submitted filename contains path-escape indicators. | — |
| `java8_file_generated_plot_script_command`, `java11_file_generated_plot_script_command`, `java17_file_generated_plot_script_command` | A directive in plot syntax reaches the output stream opened for that plot file. The event records a write attempt. | — |
| `java8_file_script_write`, `java11_file_script_write`, `java17_file_script_write` | A file write selects a target with a script or executable suffix. This is a file-type indicator. | Maven repository layout and TeamCity plugin startup provide product-specific exclusions to the general file rule. |
| `java8_file_sensitive_read`, `java11_file_sensitive_read`, `java17_file_sensitive_read` | A host file open selects a protected location. Request and resolved-path evidence depend on the branch. | — |
| `java8_jaas_jndi_remote_provider`, `java11_jaas_jndi_remote_provider`, `java17_jaas_jndi_remote_provider` | A JAAS JNDI login module receives remote naming-provider options. | — |
| `java8_java_compile_runtime_execution`, `java11_java_compile_runtime_execution`, `java17_java_compile_runtime_execution` | Source at Java compilation contains runtime execution primitives. | — |
| `java8_jdbc_derby_code_loading`, `java11_jdbc_derby_code_loading`, `java17_jdbc_derby_code_loading` | — | The Derby connection URL enables driver-specific Java code loading. |
| `java8_jdbc_h2_code_execution`, `java11_jdbc_h2_code_execution`, `java17_jdbc_h2_code_execution` | — | H2 connection options have driver-specific execution semantics. |
| `java8_jdbc_mysql_deserialization`, `java11_jdbc_mysql_deserialization`, `java17_jdbc_mysql_deserialization` | — | MySQL driver properties determine the meaning of the JDBC options. |
| `java8_jexl_runtime_execution`, `java11_jexl_runtime_execution`, `java17_jexl_runtime_execution` | Runtime execution syntax is observed at expression evaluation. The Commons JEXL hook supplies this signal across applications using the library. | — |
| `java8_jmx_remote_config_source`, `java11_jmx_remote_config_source`, `java17_jmx_remote_config_source` | A resolved JMX operation receives a complete location expression with configuration indicators. The argument alone does not establish a fetch. | The classifier also recognizes broker configuration and XBean or Spring location syntax in the dispatched argument. |
| `java8_jmx_script_file_write`, `java11_jmx_script_file_write`, `java17_jmx_script_file_write` | A synchronous MBean argument names the same script destination that the JDK opens for writing. The event records a write-open attempt. | — |
| `java8_jndi_remote_lookup`, `java11_jndi_remote_lookup`, `java17_jndi_remote_lookup` | A lookup uses a URL scheme listed by the naming policy. Runtime events identify scheme selection or direct URL-provider lookup. | — |
| `java8_request_debug_process_launch`, `java11_request_debug_process_launch`, `java17_request_debug_process_launch` | Debug-route and executable-parameter conventions are request indicators. Process launch is unconfirmed. | — |
| `java8_request_default_crypto_cookie`, `java11_request_default_crypto_cookie`, `java17_request_default_crypto_cookie` | — | Shiro's rememberMe representation and a known encryption key are required. |
| `java8_request_default_jwt_secret`, `java11_request_default_jwt_secret`, `java17_request_default_jwt_secret` | — | The submitted JWT is checked against the known HugeGraph default signing secret. |
| `java8_request_forged_include_attribute`, `java11_request_forged_include_attribute`, `java17_request_forged_include_attribute` | Servlet include attributes and the request path indicate an internal include. | Liferay portal dispatch supplies a product-specific normal-include exclusion. |
| `java8_request_internal_forward`, `java11_request_internal_forward`, `java17_request_internal_forward` | A forwarding parameter names a sensitive route. Dispatch is inferred from request conventions. | — |
| `java8_request_internal_identity`, `java11_request_internal_identity`, `java17_request_internal_identity` | — | Nacos's internal user-agent convention and maintenance routes determine the judgment. |
| `java8_request_jwt_verification_failure`, `java11_request_jwt_verification_failure`, `java17_request_jwt_verification_failure` | — | The DataEase filter continues after catching a signature or algorithm rejection for its selected credential. |
| `java8_request_ogc_filter_sql_injection`, `java11_request_ogc_filter_sql_injection`, `java17_request_ogc_filter_sql_injection` | An OGC service or route and a filter parameter contain SQL-control indicators. JDBC execution is unconfirmed. | — |
| `java8_request_path_confusion`, `java11_request_path_confusion`, `java17_request_path_confusion` | Normalization changes path structure or reveals control characters in a sensitive route. | The backports have a TeamCity-specific normal-path exclusion. |
| `java8_request_remote_job_submission`, `java11_request_remote_job_submission`, `java17_request_remote_job_submission` | — | Spark and YARN check the configured servlet role after job creation or submission has been prepared. |
| `java8_request_session_file_deserialization`, `java11_request_session_file_deserialization`, `java17_request_session_file_deserialization` | — | The file-backed servlet session use case interprets a filesystem-shaped JSESSIONID. The cookie alone does not prove deserialization. |
| `java8_request_template_source`, `java11_request_template_source`, `java17_request_template_source` | A template or preview parameter selects a remote source. This branch uses route and parameter conventions. | — |
| `java8_request_typed_payload_deserialization`, `java11_request_typed_payload_deserialization`, `java17_request_typed_payload_deserialization` | — | The typed request payload matches known class names or implementation-specific triggers. |
| `java8_script_engine_runtime_execution`, `java11_script_engine_runtime_execution`, `java17_script_engine_runtime_execution` | Script text at an evaluation API contains runtime execution primitives. | — |
| `java8_sql_identifier_injection`, `java11_sql_identifier_injection`, `java17_sql_identifier_injection` | An identifier argument contains SQL control syntax. | The MyBatis branch requires mapper substitution provenance at JDBC handoff. |
| `java8_sql_statement_injection`, `java11_sql_statement_injection`, `java17_sql_statement_injection` | SQL control syntax is assessed at a database statement boundary. | — |
| `java8_ssrf_cloud_metadata`, `java11_ssrf_cloud_metadata`, `java17_ssrf_cloud_metadata` | — | The outbound destination matches known provider metadata endpoints. |
| `java8_ssrf_loopback_admin`, `java11_ssrf_loopback_admin`, `java17_ssrf_loopback_admin` | An outbound destination matches a loopback administrative-location policy. | — |
| `java8_ssrf_request_parameter_url`, `java11_ssrf_request_parameter_url`, `java17_ssrf_request_parameter_url` | The outbound URL is correlated with a supplied request value. | — |
| `java8_xml_decoder_runtime_execution`, `java11_xml_decoder_runtime_execution`, `java17_xml_decoder_runtime_execution` | JavaBeans XML decoding is correlated with a runtime or script-file operation. | — |
| `java8_xml_decoder_script_file_write`, `java11_xml_decoder_script_file_write`, `java17_xml_decoder_script_file_write` | JavaBeans XML decoding is correlated with a runtime or script-file operation. | — |
| `java8_xxe_external_entity_protocol`, `java11_xxe_external_entity_protocol`, `java17_xxe_external_entity_protocol` | The XML parser opens an external entity transport after resolver and input selection. | — |

## Verified algorithm signatures

The acceptance scripts contain literal event assertions for these algorithm identifiers. Runtime evidence for individual environments is tracked in the [Vulhub coverage ledger](../../docs/development/vulhub-coverage.md).

- `java11_command_execution_exploit_primitive`
- `java11_file_script_write`
- `java11_file_sensitive_read`
- `java11_jdbc_h2_code_execution`
- `java11_jmx_script_file_write`
- `java11_request_default_jwt_secret`
- `java11_request_typed_payload_deserialization`
- `java11_script_engine_runtime_execution`
- `java17_command_execution_exploit_primitive`
- `java17_file_sensitive_read`
- `java17_jdbc_h2_code_execution`
- `java17_jmx_remote_config_source`
- `java17_request_debug_process_launch`
- `java17_request_internal_forward`
- `java17_request_jwt_verification_failure`
- `java17_request_ogc_filter_sql_injection`
- `java17_request_path_confusion`
- `java17_ssrf_request_parameter_url`
- `java17_xxe_external_entity_protocol`
- `java8_archive_entry_traversal_write`
- `java8_classloader_remote_codebase`
- `java8_command_execution_exploit_primitive`
- `java8_command_execution_shell_meta`
- `java8_deserialization_gadget_class`
- `java8_el_runtime_execution`
- `java8_file_generated_plot_script_command`
- `java8_file_script_write`
- `java8_file_sensitive_read`
- `java8_jaas_jndi_remote_provider`
- `java8_jdbc_h2_code_execution`
- `java8_jdbc_mysql_deserialization`
- `java8_jexl_runtime_execution`
- `java8_jndi_remote_lookup`
- `java8_request_default_crypto_cookie`
- `java8_request_forged_include_attribute`
- `java8_request_internal_identity`
- `java8_request_path_confusion`
- `java8_request_remote_job_submission`
- `java8_request_session_file_deserialization`
- `java8_request_template_source`
- `java8_script_engine_runtime_execution`
- `java8_sql_identifier_injection`
- `java8_xxe_external_entity_protocol`

## Tested vulnerability matrix

End-to-end acceptance scenarios that run a real vulnerable application under
the agent and assert the expected detection/block. Counts by JDK line:

| JDK | Scenarios |
|-----|----------:|
| java7-legacy | 9 |
| java8 | 96 |
| java11 | 10 |
| java17 | 12 |
| java21 | 3 |
| java6-legacy | 5 |
| unknown | 1 |
| **total** | **136** |

Top application families by scenario count:

| Application | Scenarios |
|-------------|----------:|
| struts2 | 19 |
| spring | 10 |
| weblogic | 7 |
| ofbiz | 6 |
| activemq | 5 |
| elasticsearch | 5 |
| solr | 5 |
| coldfusion | 4 |
| geoserver | 4 |
| nexus | 4 |
| tomcat | 4 |
| dataease | 3 |
| h2 | 3 |
| jboss | 3 |
| jenkins | 3 |
| rmi | 3 |
| druid | 2 |
| flink | 2 |
| hugegraph | 2 |
| log4j | 2 |

<details><summary>Full scenario list</summary>

### java7-legacy (9)

- activemq-3088
- activemq-5254
- jackson
- jboss-12149
- jboss-7504
- jboss-jmxinvoker
- mojarra-viewstate
- spring-webflow
- tomcat8-manager

### java8 (96)

- aj-report
- apereo-cas-415
- coldfusion-3066
- cxf
- druid
- druid-25194
- dubbo
- elasticsearch-110216
- elasticsearch-1427
- elasticsearch-3120
- elasticsearch-3337
- elasticsearch-5531
- fastjson
- flink
- flink-17519
- glassfish-1000028
- h2-10054
- h2-23221
- h2-42392
- hadoop-yarn
- jenkins-1000353
- jenkins-1000861
- jetty-28164
- jira-11581-setup-boundary
- jmeter-1297
- kkfileview
- liferay-7961
- linkis-44645
- log4j-5645
- log4j-solr
- metersphere-45788
- metersphere-plugin
- nacos
- nacos-29441
- neo4j-34371
- nexus-10199
- nexus-10204
- nexus-4956
- nexus-7238
- ofbiz-38856
- ofbiz-45195
- ofbiz-45507
- ofbiz-49070
- ofbiz-51467
- ofbiz-9496
- opentsdb
- rmi-codebase
- rmi-registry-bypass
- rmi-registry-direct
- rocketmq
- rocketmq-37582
- shiro
- shiro-4437
- skywalking
- solr-dataimport
- solr-remotestreaming
- solr-runexec
- solr-velocity
- solr-xxe
- spark
- spring-data-commons
- spring-data-rest
- spring-function
- spring-gateway
- spring-messaging
- spring-security-22978
- spring-security-oauth
- struts2-s2001
- struts2-s2005
- struts2-s2007
- struts2-s2008
- struts2-s2009
- struts2-s2012
- struts2-s2013
- struts2-s2015
- struts2-s2016
- struts2-s2032
- struts2-s2045
- struts2-s2046
- struts2-s2048
- struts2-s2052
- struts2-s2053
- struts2-s2057
- struts2-s2059
- struts2-s2061
- tomcat-12615
- tomcat-1938
- tomcat-24813
- tomcat-34486
- unomi
- weblogic-14883
- weblogic-21839
- weblogic-2894
- xstream-21351
- xstream-29505
- xxljob

### java11 (10)

- activemq
- activemq-46604
- coldfusion-26360
- coldfusion-29300
- hertzbeat
- hugegraph
- hugegraph-43441
- metabase-38646
- metabase-41277
- spring

### java17 (12)

- activemq
- geoserver
- geoserver-24816
- geoserver-25157
- geoserver-40822
- jenkins-23897
- jimureport
- openfire
- spring-boot-jetty
- struts2-upload
- teamcity-27198
- teamcity-42793

### java21 (3)

- dataease-32966
- dataease-49001
- dataease-56511

### java6-legacy (5)

- coldfusion-2861
- weblogic-10271
- weblogic-2628
- weblogic-uddi-ssrf
- weblogic-weak-password

### unknown (1)

- confluence-setup-boundaries

</details>

