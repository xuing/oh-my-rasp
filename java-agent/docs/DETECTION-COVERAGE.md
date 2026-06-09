# OhMyRASP Detection Coverage

> **Generated** by `scripts/gen-detection-coverage.py` — derived from the agent
> sources and acceptance suite, not written by hand. Re-run after changing hooks,
> detectors, or acceptance scripts. `--check` fails CI when this file is stale.

## Summary

| Metric | Count |
|--------|------:|
| Hook families (instrumentation points) | 27 |
| Detector capabilities (engine entry points) | 52 |
| Verified algorithm signatures (asserted by tests) | 42 |
| End-to-end vulnerability acceptance scenarios | 127 |
| JDK lines exercised | 5 |

## Hook families

Instrumentation points registered by `HookRegistry.defaults()`. Each module
rewrites a family of risky call sites and routes them to the detector engine.

| Family | Hook module |
|--------|-------------|
| Archive | `ArchiveHookModule` |
| ArgumentParser | `ArgumentParserHookModule` |
| ClassLoader | `ClassLoaderHookModule` |
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
| SpringConfig | `SpringConfigHookModule` |
| Sql | `SqlHookModule` |
| XmlAttachment | `XmlAttachmentHookModule` |
| XmlRpc | `XmlRpcHookModule` |
| Xxe | `XxeHookModule` |

## Detector capabilities

The engine exposes **52** detection entry points:

- `detectArchiveExtraction` · `detectArgumentFileExpansion` · `detectClassLoaderUrl`
- `detectCommand` · `detectDeserialization` · `detectDirectoryList`
- `detectDns` · `detectEval` · `detectExpression`
- `detectFileDelete` · `detectFileRead` · `detectFileUpload`
- `detectFileWrite` · `detectGeneratedScriptFileWrite` · `detectHessianType`
- `detectHttpInvokerDeserialization` · `detectHttpObjectStreamDeserialization` · `detectInclude`
- `detectJaasConfig` · `detectJavaCompilation` · `detectJdbcUrl`
- `detectJmxMBeanInvoke` · `detectJndi` · `detectJwtVerificationFailure`
- `detectLink` · `detectLoadLibrary` · `detectOgnl`
- `detectPolymorphicType` · `detectProtocolClassInstantiation` · `detectRemoteJobSubmission`
- `detectRename` · `detectRequest` · `detectResponseDataLeak`
- `detectRmiRegistryBind` · `detectServletIncludeAttributes` · `detectSessionDeserialization`
- `detectSpringConfigLocation` · `detectSql` · `detectSqlException`
- `detectSqlRegex` · `detectUrl` · `detectWebdavUpload`
- `detectWebshellCallable` · `detectWebshellCommand` · `detectWebshellEval`
- `detectWebshellFileWrite` · `detectWebshellLdPreload` · `detectXmlAttachmentReference`
- `detectXmlDecoderExpression` · `detectXmlRpcSerializableValue` · `detectXssEcho`
- `detectXxeEntity`

## Verified algorithm signatures

Algorithm identifiers asserted by the acceptance suite — i.e. detections that
are proven end-to-end, not merely implemented.

**java11** (7)

- `java11_command_execution_exploit_primitive`
- `java11_file_script_write`
- `java11_file_sensitive_read`
- `java11_jdbc_h2_code_execution`
- `java11_jmx_script_file_write`
- `java11_request_default_jwt_secret`
- `java11_script_engine_runtime_execution`

**java17** (11)

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

**java8** (24)

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
| java8 | 94 |
| java11 | 9 |
| java17 | 12 |
| java21 | 3 |
| **total** | **127** |

Top application families by scenario count:

| Application | Scenarios |
|-------------|----------:|
| struts2 | 19 |
| spring | 10 |
| ofbiz | 6 |
| activemq | 5 |
| elasticsearch | 5 |
| solr | 5 |
| geoserver | 4 |
| nexus | 4 |
| tomcat | 4 |
| dataease | 3 |
| h2 | 3 |
| jboss | 3 |
| jenkins | 3 |
| rmi | 3 |
| coldfusion | 2 |
| druid | 2 |
| flink | 2 |
| hugegraph | 2 |
| log4j | 2 |
| metabase | 2 |

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

### java8 (94)

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
- weblogic-2894
- xstream-21351
- xstream-29505
- xxljob

### java11 (9)

- activemq
- activemq-46604
- coldfusion-26360
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

</details>

