# Algorithm Coverage

This PoC migrates the JavaScript detector behavior into Java-native detector
methods in `DetectorEngine`. Runtime API hooks call these methods directly where
there is a concrete Java API to instrument. Semantic hook methods exist for
policy families whose original hook point is language- or framework-specific,
so the playground can still verify policy execution and JSONL log collection.

## Accepted Algorithms

`scripts/acceptance.sh` currently requires these algorithms to appear in
`logs/protected/events.jsonl`:

- `request_scanner`
- `request_unusual`
- `xss_userinput`
- `request_internal_identity`
- `request_default_jwt_secret`
- `request_jwt_verification_failure`
- `request_default_crypto_cookie`
- `request_serialized_client_state`
- `request_default_credential`
- `request_empty_credential_bypass`
- `request_setup_state_reset`
- `request_server_side_script_put`
- `request_upload_filename_override`
- `request_scheduler_shell_job`
- `request_debug_process_launch`
- `request_dynamic_script_config`
- `request_message_selector_expression`
- `request_expression_header`
- `request_jndi_lookup`
- `request_expression_parameter`
- `request_json_patch_expression`
- `request_expression_parameter_name`
- `request_expression_path`
- `request_xxe_payload`
- `request_typed_parameter_deserialization`
- `request_typed_payload_deserialization`
- `request_xml_polymorphic_gadget`
- `request_template_parameter`
- `request_template_source`
- `request_remote_content_stream`
- `request_remote_import_script_write`
- `request_repository_webroot_write`
- `request_plot_command_injection`
- `request_sql_sort_injection`
- `request_sql_identifier_injection`
- `request_ogc_filter_sql_injection`
- `request_remote_job_submission`
- `request_internal_forward`
- `request_java_bean_pollution`
- `request_path_confusion`
- `request_internal_resource`
- `request_forged_include_attribute`
- `command_reflect`
- `command_userinput`
- `command_common`
- `command_error`
- `command_dnslog`
- `command_config_listener`
- `command_config_injection`
- `readFile_userinput`
- `readFile_userinput_http`
- `readFile_userinput_unwanted`
- `readFile_unwanted`
- `readFile_outsideWebroot`
- `readFile_argument_expansion`
- `writeFile_NTFS`
- `writeFile_script`
- `writeFile_reflect`
- `writeFile_config_path`
- `writeFile_generated_script`
- `deleteFile_userinput`
- `directory_reflect`
- `directory_userinput`
- `directory_unwanted`
- `ssrf_userinput`
- `ssrf_aws`
- `ssrf_common`
- `ssrf_obfuscate`
- `ssrf_protocol`
- `dns_blacklist`
- `jndi_disable_all`
- `jndi_jaas_config`
- `classloader_remote`
- `spring_remote_config`
- `jmx_remote_config`
- `jmx_file_write`
- `sql_userinput`
- `sql_policy`
- `sql_regex`
- `sql_exception`
- `sql_h2_code_execution`
- `jdbc_h2_init`
- `sql_derby_code_execution`
- `jdbc_mysql_deserialization`
- `deserialization_blacklist`
- `deserialization_gadget`
- `deserialization_cluster_message`
- `deserialization_logging_message`
- `deserialization_webflow_state`
- `deserialization_rmi_transport`
- `deserialization_remoting_transport`
- `deserialization_jms_object_message`
- `deserialization_signed_object`
- `deserialization_session_file`
- `deserialization_protocol_class`
- `deserialization_http_invoker`
- `deserialization_http_object_stream`
- `deserialization_hessian_type`
- `deserialization_xmlrpc_serialized`
- `deserialization_rmi_registry_bind`
- `deserialization_polymorphic_type`
- `xml_decoder_runtime`
- `xml_decoder_webshell`
- `xxe_protocol`
- `xxe_file`
- `include_userinput`
- `include_protocol`
- `fileUpload_multipart_script`
- `fileUpload_multipart_expression`
- `fileUpload_path_traversal`
- `fileUpload_multipart_html`
- `fileUpload_multipart_exe`
- `fileUpload_java_archive`
- `fileUpload_webdav`
- `rename_webshell`
- `link_webshell`
- `archive_traversal`
- `ognl_blacklist`
- `ognl_length_limit`
- `spel_runtime`
- `jexl_runtime`
- `el_runtime`
- `javascript_runtime`
- `jiffle_runtime`
- `script_runtime`
- `xpath_runtime`
- `java_compile_runtime`
- `template_runtime`
- `eval_regex`
- `loadLibrary_unc`
- `response_dataLeak`
- `xss_echo`
- `webshell_eval`
- `webshell_command`
- `webshell_file_put_contents`
- `webshell_callable`
- `webshell_ld_preload`

## Hook Architecture Notes

- The ASM transformer delegates hook selection to `HookRegistry`. Each runtime
  family has its own small `HookModule`, such as process, file, network, JNDI,
  expression engines, polymorphic deserialization, SQL, servlet, and XXE. This keeps hook-point expansion
  modular as more middleware and dynamically deployed policies are added.
- `request_path_confusion` covers request URIs whose raw, decoded, double
  decoded, low-byte Unicode-decoded, overlong UTF-8-decoded, or lenient
  percent-decoded path forms introduce parent-directory segments, control
  characters on sensitive paths, or canonicalization-only changes such as `.`
  segments and duplicate slashes that collapse onto a sensitive control path.
  This targets routing/authentication bypass classes such as Shiro
  CVE-2020-1957 `..;`, Shiro CVE-2010-3863 `/./admin` and `//admin`
  canonicalization bypasses, Nexus CVE-2024-4956 repeated encoded-slash
  traversal to `/etc/passwd`,
  whitelist-prefix traversal, encoded traversal, GlassFish overlong UTF-8
  traversal such as `%c0%ae` to `.`, Openfire setup traversal using
  `%u002e%u002e` segments, Openfire/Jetty lenient hex decoding such as `%2>`
  to `.`, Spring Security RegexRequestMatcher newline confusion on
  sensitive control paths, Spring/Jetty CVE-2025-41242 ghost-bits traversal
  where high-bit Unicode characters low-byte-collapse into `.%u002e`,
  DataEase CVE-2024-56511 whitelist-prefix traversal such as
  `/geo/../dataease/de2api/datasource/types`,
  Flink CVE-2020-17519 double-encoded
  `/jobmanager/logs/..%252f...%252fetc%252fpasswd` traversal, Elasticsearch
  CVE-2015-3337 plugin traversal such as
  `/_plugin/head/../../etc/passwd`, Elasticsearch CVE-2015-5531 snapshot
  traversal such as `/_snapshot/test/backdata%2f..%2fetc%2fpasswd`,
  and Jetty/Spring
  path decoding inconsistencies without depending on product-specific endpoint
  names. The acceptance suite includes Vulhub-shaped Spring Security
  CVE-2022-22978 RegexRequestMatcher bypass requests for both `%0a` and `%0d`
  control-character forms, plus Openfire CVE-2023-32315 setup traversal
  requests for both `%u002e%u002e` and `%2>` bypass forms.
- `request_internal_resource` covers requests where a protected Java web
  application resource directory such as `WEB-INF` or `META-INF` only appears
  after percent, double-percent, Unicode, or lenient decoding. This targets
  Jetty ConcatServlet and ambiguous protected-resource disclosure shapes,
  including CVE-2021-28164 `%2e/WEB-INF/web.xml`,
  CVE-2021-28169 `static?/%2557EB-INF/web.xml`, and CVE-2021-34429
  `%u002e`, `.%00`, and `..%00` variants, while ignoring ordinary direct
  `/WEB-INF/...` requests that a normal container will reject by itself.
- `request_forged_include_attribute` covers top-level servlet requests that
  carry `javax.servlet.include.*` or `jakarta.servlet.include.*` attributes for
  protected web resources, server-side scripts, or traversal-shaped targets.
  This targets Tomcat AJP/Ghostcat-style arbitrary file read/include behavior
  while suppressing normal `RequestDispatcher.include` stacks used by
  legitimate application rendering.
- `request_internal_identity` covers requests that present an internal service
  identity header or user agent on sensitive auth, user-management, admin, or
  ops paths. This targets Nacos-style `User-Agent: Nacos-Server` authentication
  bypasses, including Vulhub Nacos CVE-2021-29441 list-user and create-user
  requests to `/nacos/v1/auth/users`, while allowing the same internal identity
  on non-control service discovery paths.
- `request_java_bean_pollution` covers Java bean/data-binding parameter names
  that traverse into `class`, `module`, or `classLoader` metadata and then reach
  dangerous mutable runtime targets such as Tomcat AccessLogValve
  `resources.context.parent.pipeline.first.*` fields. This targets Vulhub
  Spring Framework CVE-2022-22965 `GET /` Spring4Shell requests that write a JSP
  through Tomcat logging, while ignoring ordinary `className`, `module`, or
  `classLoaderName` fields and redacting matched binder values from logs.
- `request_default_jwt_secret` verifies HMAC bearer JWT signatures against
  known hardcoded or default application secrets and logs the key identifier
  without storing the token. This covers HugeGraph-style JWT authentication
  bypasses caused by a default `auth.token_secret` while ignoring malformed
  tokens and tokens whose signatures do not validate with a known weak secret.
- `request_jwt_verification_failure` covers request-time JWT library
  verification failures on API/control paths when the request carries a compact
  JWT in an authentication token header. This targets DataEase
  CVE-2025-49001-style flows where an invalid `X-DE-TOKEN` signature is caught
  but request processing continues, and logs only the token source, mechanism,
  exception class, method, and URI rather than the token value.
- `request_default_crypto_cookie` decrypts only plausible encrypted
  `rememberMe` cookies with known default AES keys and reports a match when the
  plaintext starts with Java serialization stream magic. This covers Shiro-style
  default-key remember-me deserialization chains, including the Vulhub Shiro
  CVE-2016-4437 `GET /` request with a forged `rememberMe` cookie, while logging
  only the cookie name, key identifier, and cipher family rather than the cookie
  value or decrypted bytes.
- `request_serialized_client_state` covers client-side state parameters such as
  JSF/Mojarra `javax.faces.ViewState` or equivalent `viewState` fields when a
  bounded Base64 decode, optionally followed by gzip decompression, starts with
  Java serialization stream magic. This targets unencrypted JSF ViewState
  deserialization before the framework decodes and deserializes the state while
  logging only parameter name, encoding, value length, and decoded payload
  length rather than the state value or object bytes.
- `request_default_credential` covers HTTP Basic or form login attempts that
  use known default Java management credentials on admin, manager, console,
  Jolokia/API, OAuth, CAS, or other control paths. This targets Tomcat Manager,
  ActiveMQ, WebLogic, Jenkins lab, and Spring OAuth-style default credential
  footholds while ignoring the same username/password strings outside control
  paths and logging only username, credential identifier, mechanism, and source
  field rather than the password.
- `request_empty_credential_bypass` covers control/admin endpoint requests that
  submit empty username and password parameters together with an account-state
  bypass flag such as `requirePasswordChange`. This targets OFBiz-style
  pre-auth bypass chains that expose XMLRPC deserialization or Groovy execution
  endpoints while ignoring ordinary blank login submissions outside control
  paths.
- `request_setup_state_reset` covers request parameter binding attempts that
  force application setup-completion state back to false through
  setup/bootstrap/status property chains. This targets Confluence
  CVE-2023-22515-style requests such as
  `bootstrapStatusProvider.applicationConfig.setupComplete=false` while
  ignoring ordinary nested `setupComplete` fields outside setup context and
  logging only parameter name, reset value, method, and URI.
- `request_server_side_script_put` covers HTTP `PUT` requests whose decoded path
  targets a server-side script extension, including trailing slash or semicolon
  bypass forms. This targets writable DefaultServlet/WebDAV upload paths such
  as Tomcat CVE-2017-12615 `PUT /1.jsp/` while ignoring read-only requests and
  ordinary static asset uploads.
- `request_upload_filename_override` covers mutating multipart upload requests
  where framework filename-binding parameters such as `fileFileName` or
  `top.fileFileName` provide traversal, absolute, encoded traversal, or NUL
  shaped paths that can override a safely-normalized upload part filename. This
  targets Struts2 S2-066/S2-067 upload basename bypasses while ignoring ordinary
  filename metadata in non-multipart requests and logging only parameter name,
  target type, and value length rather than the attacker-selected path.
- `request_scheduler_shell_job` covers request-time scheduler or executor job
  dispatch payloads that select a shell/script job type and provide a non-empty
  command source field. It targets XXL-JOB-style unauthorized executor `/run`
  chains where low-signal commands may be executed later, while requiring
  scheduler path or metadata signals and logging only field names, type, and
  source length rather than the command source.
- `request_debug_process_launch` covers mutating requests to debug/process
  control endpoints that provide an executable or command parameter such as
  `exePath`. This targets TeamCity CVE-2023-42793-style debug process launch
  chains before the request reaches the later process-spawn hook, while logging
  only the parameter name and command length.
- `request_dynamic_script_config` covers request-time control-plane payloads
  that submit dynamic route, data import, search, or script configuration with
  runtime execution primitives. This targets Spring Cloud Gateway
  CVE-2022-22947 actuator route SpEL injection, Solr CVE-2019-0193
  DataImportHandler `dataConfig` scripts,
  Elasticsearch
  CVE-2014-3120 MVEL `_search` script fields, Elasticsearch CVE-2015-1427
  Groovy `_search` script fields with sibling `lang=groovy`, Jenkins/Groovy script validation, AJ-Report
  validation-rule JavaScript, Apache Druid CVE-2021-25646 sampler JavaScript
  bodies, Apache Unomi context/personalization JSON MVEL or OGNL conditions, HugeGraph
  Gremlin-Groovy JSON submissions that use reflective process execution, OFBiz
  ProgramExport Groovy submissions including unicode-escaped `execute()` calls,
  Metabase H2 setup-validation `init` scripts, H2 Console CVE-2022-23221
  JDBC URLs carrying executable `INIT` triggers, WebLogic
  CVE-2020-14882/14883-style console `handle` parameters that instantiate MVEL
  shell sessions or remote Spring XML application contexts, and DataEase
  datasource-validation requests carrying base64-encoded H2 JDBC `INIT`
  configurations while requiring a
  config/search/data-import, sampler, verification, script-validation, Gremlin,
  setup-validation, H2 console login, admin console, datasource-validation, or context endpoint or a
  config-shaped field name and logging only field name, inferred engine, and
  source length. The playground and acceptance suite include Vulhub-shaped
  `/actuator/gateway/routes/hacktest` JSON route posts for Spring Cloud Gateway
  CVE-2022-22947 and `/h2-console/login.do` JDBC URL form posts for H2
  CVE-2022-23221.
- `request_message_selector_expression` covers STOMP/SockJS-style message
  frames where a message `selector:` header contains a runtime expression
  primitive instead of an ordinary selector predicate. This targets Spring
  Messaging CVE-2018-1270 selector SpEL injection while requiring message-frame
  context with a destination and logging only inferred engine and selector
  length.
- `request_expression_header` covers request headers that are explicitly shaped
  as expression or script routing controls and whose values contain runtime
  execution primitives. It also covers parser-sensitive headers such as
  `Content-Type` or `Content-Disposition` when the value itself is a clearly
  dangerous OGNL expression. This targets Spring Cloud Function
  CVE-2022-22963 `spring.cloud.function.routing-expression` SpEL injection and Struts2
  multipart parser OGNL injection before the expressions are evaluated, while
  logging only header name, inferred engine, and expression length. The
  playground and acceptance suite include Vulhub-shaped `/functionRouter` POSTs
  with the routing-expression header and `/index.action` POSTs with a Struts2
  S2-045 `Content-Type` OGNL payload.
- `request_jndi_lookup` covers request parameters or headers that carry
  Log4j-style `${jndi:...}` lookup payloads resolving to remote naming
  protocols such as LDAP, RMI, or DNS. It also covers request-time JNDI
  driver/provider configuration, such as H2 Console CVE-2021-42392
  `driver=javax.naming.InitialContext&url=ldap://...`, when a remote naming URL
  is paired with a JNDI driver class. This targets lookup injection before
  vulnerable logging, interpolation, or console connection code reaches JNDI,
  while logging only source, field name, protocol, and value length. The
  playground and acceptance suite include the Vulhub-shaped Log4j
  CVE-2021-44228 `/solr/admin/cores?action=${jndi:ldap://...}` request and the
  `/h2-console/login.do` JNDI driver form post.
- `request_expression_parameter` covers request parameters and bounded JSON
  body string fields or string arrays whose values contain expression-language
  syntax such as OGNL `%{...}`, OGNL static method calls, SpEL `#{...}`, or
  Nexus-style escaped EL markers together with Java runtime/process execution
  primitives. For JSON control-plane bodies, it also infers sibling engine
  markers such as Nexus ExtDirect `previewAssets` filters carrying
  `property=expression`, `type=jexl`, and a runtime `value`, covering
  CVE-2019-7238. It also covers OGNL
  expressions that delegate evaluation to another request parameter when that
  delegated value contains a dangerous expression or template execution
  primitive. It decodes Java-style Unicode escapes before classification,
  covering WebWork/Confluence CVE-2021-26084 `queryString` payloads that wrap
  `ScriptEngineManager.eval(...)` in `\u0027`-escaped expression text. This
  targets Struts2 OGNL, Spring Security OAuth CVE-2016-4977 whitelabel
  `response_type` SpEL, Nexus `previewAssets` JEXL plus `roles` and
  `memberNames` JSON EL injection used by CVE-2020-10204 and CVE-2020-10199,
  Confluence template/Velocity OGNL `findValue` delegation,
  including CVE-2023-22527,
  GeoServer CVE-2024-36401 OGC `valueReference`/`propertyName` XPath runtime
  expressions for both query-parameter and XML-body WFS forms, and
  similar expression injection before the framework evaluator runs, while
  ignoring benign expressions that do not contain runtime execution primitives
  and logging only field name, inferred engine, and expression length. The
  playground and acceptance suite include Vulhub-shaped
  `/oauth/authorize?response_type=...` requests for Spring Security OAuth
  CVE-2016-4977 and Struts2 form/query payloads for S2-001, S2-007, S2-008,
  S2-009, S2-012, S2-013, S2-048,
  S2-053, S2-059, and S2-061, including the S2-061
  `freemarker.template.utility.Execute` OGNL sandbox-bypass primitive.
- `request_json_patch_expression` covers `application/json-patch+json` PATCH
  request bodies whose JSON Patch `path` field carries a runtime expression
  payload. This targets Spring Data REST CVE-2017-8046 JSON Patch SpEL
  injection before the patch path is evaluated, while logging only inferred
  engine, body length, and expression length rather than the raw body. The
  playground and acceptance suite include Vulhub-shaped `PATCH /customers/1`
  requests with `application/json-patch+json` bodies.
- `request_expression_parameter_name` covers request parameter names that embed
  expression-language syntax with runtime execution primitives, such as Spring
  Data Commons CVE-2018-1273 property-path SpEL payloads in `username[...]`
  and Spring WebFlow CVE-2017-4971 binding-field expressions shaped like
  `_(...).start()`. It also
  covers Struts2 OGNL-evaluated parameter names such as S2-005 expression
  evaluation, S2-016 `redirect:`/`action:` prefixes, and S2-032 dynamic-method
  invocation `method:` prefixes. It redacts the dangerous key in both query
  strings and parameter maps while preserving only a safe field prefix,
  inferred engine, and expression length. The playground and acceptance suite
  include Vulhub-shaped `/hotels/booking` and `/users?page=&size=5` Spring
  binding payloads, plus `/example/HelloWorld.action` and `/index.action`
  parameter-name payloads for S2-005, S2-016, and S2-032.
- `request_expression_path` covers request URI paths that decode to
  expression-language payloads with runtime execution primitives. This targets
  Confluence and Struts2 namespace/path OGNL injection before the framework
  evaluates the path expression, while redacting the logged URI and recording
  only inferred engine, method, and expression length. The playground and
  acceptance suite include the Vulhub-shaped Confluence CVE-2022-26134
  URL-encoded OGNL path under `/`, plus the Struts2 S2-057 namespace path under
  `/struts2-showcase/.../actionChain1.action`.
- `request_xxe_payload` covers request parameters whose values contain XML
  doctypes with external entity declarations using unsafe protocols such as
  `file:`, `jar:`, HTTP, FTP, LDAP, or RMI. This targets Solr CVE-2017-12629
  XML parser query XXE payloads before XML resolution while ignoring
  internal-only doctypes and logging only parameter name, scheme, and XML
  length.
- `request_typed_parameter_deserialization` covers request parameter names that
  declare a Java binding type, such as `+field:fully.qualified.Class=value`,
  when that type is a known dangerous polymorphic construction or
  deserialization gadget. This targets Liferay JSONWS-style typed parameter
  binding to C3P0, TemplatesImpl, Spring XML contexts, and related classes
  while ignoring ordinary DTO class names and logging only field name, class,
  and value length. The playground and acceptance suite include the
  Vulhub-shaped `/api/jsonws/invoke` POST used by Liferay Portal
  CVE-2020-7961.
- `request_typed_payload_deserialization` covers submitted XML, JSON, or YAML
  payloads that declare a dangerous Java binding type and pair it with a
  deserialization trigger such as a remote JNDI provider URL, serialized object
  marker, or executable H2 JDBC `INIT` URL. This targets ColdFusion
  WDDX/XML-style typed object binding such as CVE-2023-29300
  `JdbcRowSetImpl` plus `dataSourceName=ldap://...`, and Apache HertzBeat
  CVE-2024-42323 SnakeYAML imports where `!!org.h2.jdbc.JdbcConnection` opens
  an H2 URL containing an executable `INIT` payload, while ignoring safe DTO
  types and dangerous class names that are not paired with an execution or
  deserialization trigger. The playground and acceptance suite include the
  Vulhub-shaped `/api/monitors/import` YAML import body.
- `request_xml_polymorphic_gadget` covers XML request bodies that declare
  dangerous Java polymorphic gadget types through XML class attributes, class
  elements, or fully qualified Java tag names before an XML object mapper
  unmarshals them. This targets Struts2 S2-052-style REST/XStream payloads
  whose object graph reaches classes such as `java.lang.ProcessBuilder`,
  XStream CVE-2021-21351-style `JdbcRowSetImpl` JNDI chains, and
  XStream CVE-2021-29505-style `RegistryImpl_Stub` RMI callback chains, while
  ignoring ordinary XML class metadata for safe Java collection/DTO types and
  logging only class name, source, and body length.
- `request_template_parameter` covers request parameters and bounded JSON body
  string fields that are explicitly shaped as template bodies or custom
  template sources, plus message-like fields on template-rendered
  contact/support surfaces when the value also has Velocity/FreeMarker syntax.
  Values must contain Java runtime or template command execution primitives.
  This targets Solr Velocity CVE-2019-17558 `v.template.custom` payloads, Jira
  contact administrator Velocity/i18n reflection payloads, and JimuReport-style
  FreeMarker `Execute` payloads embedded in report/query JSON before the
  template engine evaluates them, while logging only parameter or field name,
  inferred engine, and source length. The playground and acceptance suite
  include the Vulhub-shaped `/jmreport/queryFieldBySql` JSON `sql` POST for
  JimuReport CVE-2023-4450.
- `request_template_loader_enable` covers mutating configuration requests that
  enable request-parameter-backed template resource loading, such as
  `params.resource.loader.enabled=true`, when the same request carries a
  template engine signal like VelocityResponseWriter or `name=velocity`. This
  targets the Solr Velocity CVE-2019-17558 Config API enablement step before a
  later request can supply a malicious `v.template.custom` body, while ignoring
  ordinary template payloads, non-mutating requests, and engine-less config
  JSON.
- `request_template_source` covers request parameters or bounded JSON body
  string fields that select a server-side template source path or URL in a
  macro, preview, render, template, decorator, screen, control, view, admin, or
  resource-loading context when the selected source is a remote URL, local URL,
  protected web resource, traversal path, or sensitive local file. This targets
  Confluence macro-preview `_template` path traversal, OFBiz-style
  `statsDecoratorLocation=http://.../payload.xml` remote screen/decorator
  loading, ColdFusion CVE-2023-26360-style metadata `classname` source
  selection such as `_variables._metadata.classname=../../proc/self/environ`,
  and ColdFusion CVE-2010-2861-style `locale=../../etc/passwd%00en` resource
  traversal before the server reads or evaluates the selected source. The
  playground and acceptance suite include the Vulhub-shaped
  `/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc` and
  `/CFIDE/administrator/enter.cfm` requests. It logs only source location, field
  name, target type, and value length.
- `request_remote_content_stream` covers request-time control-plane payloads
  that enable remote/content streaming or pass content-stream URL parameters to
  local file, JAR, dangerous SSRF, or internal HTTP targets. This targets
  Solr RemoteStreaming JSON configuration
  `requestDispatcher.requestParsers.enableRemoteStreaming=true` and
  `stream.url=file:///...` read or SSRF chains while logging only mode,
  parameter, scheme, and source length.
- `request_remote_import_script_write` covers request-time import or data-file
  workflows that combine remote source URLs with a server-side script save
  target and an import/control context or explicit URL-source flag. This targets
  OFBiz-style remote CSV/XML import chains that write a JSP webshell while
  logging only source/target parameter names, target type, and source count.
- `request_repository_webroot_write` covers mutating backup, repository, or
  snapshot control-plane requests that configure server-side persistence under a
  web deployment directory while the repository/snapshot selector carries a
  server-side script extension. This targets Elasticsearch-style snapshot
  repository webshell writes, including WooYun-2015-110216-style
  `/_snapshot/yz.jsp` requests with
  `settings.location=/usr/local/tomcat/webapps/wwwroot/`, while ignoring ordinary
  snapshot repositories under application data directories and logging only
  field name, target type, location class, and value length.
- `request_plot_command_injection` covers graphing or plotting control
  requests where bounded plot parameters such as `yrange`, `y2range`, or `key`
  carry interpreter command directives like `system(...)`. This targets
  OpenTSDB CVE-2020-35476 `yrange=[0:system(...)]` and CVE-2023-25826
  `key=;system ...` Gnuplot injection before the generated plot script is
  written, while requiring graph/query endpoint context and multiple plot
  markers.
- `request_sql_sort_injection` covers JSON list/search/table APIs where sort or
  order metadata fields carry SQL control expressions instead of ordinary
  direction values such as `asc` or `desc`. This targets MeterSphere-style
  order-by injection in `orders[].type`, while requiring a JSON sort/order body
  context and logging only field name and value length.
- `request_sql_identifier_injection` covers JSON and GraphQL API bodies where
  identifier-like fields such as `metricName`, `tableName`, or `columnName`
  carry SQL control syntax instead of ordinary identifier values. This targets
  SkyWalking GraphQL metric-name SQL injection while ignoring normal metric
  names such as `service_instance_jvm_memory.max` and logging only field name
  and value length.
- `request_ogc_filter_sql_injection` covers OGC/WFS/WMS/WPS filter parameters
  such as `CQL_FILTER`, `ECQL_FILTER`, or `FILTER` when they carry SQL-only
  control primitives like nested `SELECT`, `CAST(SELECT ...)`, comments, or
  time-delay functions. This targets GeoServer CVE-2023-25157 OGC filter SQL
  injection before the filter is translated into datastore SQL, while requiring OGC request
  context and logging only parameter name and value length.
- `request_remote_job_submission` covers request-time job/application
  descriptors that submit a remote Java executable artifact together with an
  entry class, or a shell command in a container/job command field, to a job
  control endpoint. This targets Apache Spark standalone REST application
  submission and Hadoop YARN ResourceManager REST container command submission
  shapes while logging only mechanism, URI, descriptor length, artifact
  scheme/type, or command length rather than the submitted descriptor. The
  playground and acceptance suite include both the Spark REST
  `appResource`/`mainClass` shape and the Vulhub-shaped Hadoop
  `/ws/v1/cluster/apps` `am-container-spec.commands.command` reverse-shell
  submission.
- `request_internal_forward` covers request-controlled internal forwarding or
  view selection parameters that point to sensitive control paths using servlet
  path-parameter JSP suffix confusion, such as TeamCity-style
  `jsp=/app/rest/users;.jsp` authentication bypasses. It is gated by
  forward/view parameter names, an absolute internal target, and a sensitive
  control path to avoid flagging ordinary JSP view selection. The acceptance
  suite includes the Vulhub-shaped TeamCity CVE-2024-27198 internal-forward
  request shape.
- `xpath_runtime` covers JAXP/Xalan, Jaxen, and Apache Commons JXPath entry
  points, including GeoTools-style property expressions that can otherwise be
  evaluated as XPath-like runtime calls.
- `jexl_runtime` and `el_runtime` cover Commons JEXL and Java/Jakarta Unified
  EL expression creation/evaluation paths when the expression attempts direct
  or reflective runtime process execution, covering Nexus-style JEXL/EL payloads
  without product-specific request signatures.
- `script_runtime` also covers command execution reached through dynamic script
  stack frames, including Groovy/Gremlin and JSR-223 script paths where the
  launched command may be a low-signal value such as `id`.
- `javascript_runtime` covers embedded JavaScript source evaluation through
  Rhino and JavaScript stack-attributed process execution. This targets Apache
  Druid-style request-supplied JavaScript parser functions while leaving
  harmless scripts alone unless they reach runtime execution primitives.
- `jiffle_runtime` covers JAI-EXT Jiffle map algebra scripts that contain Java
  runtime execution primitives before they are translated into Java source and
  compiled by Janino. This targets GeoServer/JAI-EXT CVE-2022-24816 and
  CVE-2023-35042 without depending on the GeoServer WMS/WPS endpoint path. The
  playground and acceptance suite include the Vulhub-shaped `/geoserver/wms`
  WPS XML `script` literal flow, and the detector logs script length rather
  than the raw script body.
- `command_config_listener` covers process launches reached through
  server-configured executable listener stacks, such as Solr
  CVE-2017-12629 `RunExecutableListener` post-commit execution. This catches
  persisted configuration-triggered commands that are not necessarily present
  in the later trigger request body.
- `command_config_injection` covers command launches reached from mutable
  runtime configuration launchers, such as RocketMQ filter-server startup
  commands built from broker configuration in CVE-2023-33246. This is
  stack-gated so ordinary scheduler-launched low-signal commands such as
  `touch /tmp/success` are not treated as attacks by themselves.
- `writeFile_config_path` covers runtime configuration persistence stacks that
  write to unsafe filesystem targets, such as RocketMQ NameServer
  CVE-2023-37582 `configStorePath` updates that redirect config persistence to
  `/tmp`, web roots, cron/systemd paths, or other attacker-meaningful
  destinations.
- `writeFile_generated_script` covers request-controlled generated interpreter
  scripts that contain execution primitives such as `system(...)` before the
  script is persisted. This targets OpenTSDB CVE-2020-35476 and
  CVE-2023-25826 Gnuplot injection where graph parameters are written into a
  temporary plot script and later executed by an external interpreter.
- `jmx_remote_config` covers request-time JMX/MBean invocations that mutate
  runtime configuration with a remote Spring/XBean-style config source. This
  targets Jolokia management-bridge RCE chains such as ActiveMQ
  `addNetworkConnector` plus `brokerConfig=xbean:http://...` while ignoring
  read-only or background MBean activity. The playground and acceptance suite
  include the Vulhub-shaped ActiveMQ `/api/jolokia/` Broker MBean invocation
  used by the CVE-2024-32114 plus CVE-2026-34197 chain.
- `jmx_file_write` covers request-time JMX/MBean invocations that pass a
  server-side script path to a mutating operation. This targets Jolokia MBean
  write chains such as Log4j2 configuration rewrites and JFR `copyTo` webshell
  writes without product-specific endpoint matching. The playground and
  acceptance suite include the Vulhub-shaped ActiveMQ CVE-2022-41678
  `/api/jolokia/` `setConfigText` file-write flow.
- `deserialization_gadget` extends Java object stream coverage beyond exact
  blacklist types to known ysoserial gadget families, including BeanShell,
  ROME, C3P0, and Commons BeanUtils classes used by vulhub cases such as JMeter
  RMI, ActiveMQ object message deserialization, and ColdFusion AMF payloads.
  The playground and acceptance suite include the Vulhub-shaped
  `/flex2gateway/amf` `application/x-amf` Java object stream path for Adobe
  ColdFusion CVE-2017-3066.
- `deserialization_cluster_message` covers dangerous Java deserialization
  gadget classes resolved while a cluster or message replication transport is
  unmarshalling data, such as Tomcat Tribes stack frames. This targets
  Tomcat CVE-2026-34486-style EncryptInterceptor bypass chains where an
  attacker sends a serialized gadget to the cluster receiver port, while
  avoiding ordinary cluster traffic that deserializes only benign application
  classes. Events include a `securityInterceptor` detail when the stack contains
  Tomcat Tribes `EncryptInterceptor`, and the playground and acceptance suite
  include the Vulhub-shaped CommonsCollections gadget resolution path under
  `EncryptInterceptor`, `XByteBuffer`, and `NioReplicationTask`.
- `deserialization_logging_message` covers dangerous Java deserialization
  gadget classes resolved while a logging socket/server transport is
  unmarshalling remote log events. This targets Log4j CVE-2017-5645-style TCP
  server payloads while avoiding normal remote logging events that deserialize
  only Log4j event classes.
- `deserialization_webflow_state` covers dangerous Java deserialization gadget
  classes resolved while Spring WebFlow client-state repositories or CAS
  encrypted transcoders are restoring a flow execution snapshot. This targets
  Apereo CAS 4.1-style encrypted `execution` state payloads that decrypt into a
  ysoserial object stream, while avoiding ordinary WebFlow state restoration
  that only deserializes framework flow execution objects. The playground and
  acceptance suite include the Vulhub-shaped `/cas/login` POST with an
  `execution` client-state parameter.
- `deserialization_rmi_transport` covers dangerous Java deserialization gadget
  classes resolved while RMI server/registry transport dispatch is unmarshalling
  remote call arguments. This targets JMeter CVE-2018-1297-style
  distributed-test RMI payloads, Java RMI Registry gadget submissions, and
  Neo4j Shell CVE-2021-34371-style `setSessionVariable` calls carrying Rhino
  `NativeJavaObject` gadget graphs while avoiding ordinary RMI calls that
  deserialize only benign service DTOs. The playground and acceptance suite
  include the Vulhub-shaped `/neo4j-shell/setSessionVariable` RMI unmarshalling
  path with Neo4j Shell stack frames.
- `deserialization_remoting_transport` covers dangerous Java deserialization
  gadget classes resolved while an application-server remoting transport is
  unmarshalling protocol frames. The initial transport family is WebLogic T3 and
  IIOP dispatch, covering CVE-2018-2628-style T3 JRMPClient payloads and
  CVE-2023-21839-style IIOP/JNDI remote-reference flows while avoiding ordinary
  remoting calls that deserialize only benign peer metadata or service DTOs.
- `deserialization_jms_object_message` covers dangerous Java deserialization
  gadget classes resolved while a JMS provider is deserializing an
  `ObjectMessage` body. This targets ActiveMQ CVE-2015-5254-style broker or web
  console message browsing flows while avoiding ordinary JMS text/map/bytes
  messages and `ObjectMessage` values that deserialize only benign application
  DTOs.
- `deserialization_signed_object` covers `java.security.SignedObject`
  deserialization on remote CLI/remoting object-stream stacks. This targets
  Jenkins CVE-2017-1000353-style SignedObject blacklist-bypass payloads while
  avoiding ordinary application signature verification flows outside remote CLI
  transports.
- `deserialization_session_file` covers file-backed servlet session
  deserialization when the session identifier is filesystem-shaped, such as a
  hidden-file name, traversal, slash, or encoded path separator. This targets
  Tomcat-style partial PUT session-store chains where a serialized object is
  written under the session work directory and later loaded through a crafted
  `JSESSIONID`, including URLDNS-style payloads that may not use a known gadget
  class.
- `deserialization_protocol_class` covers message-protocol unmarshalling that
  attempts to instantiate an attacker-selected Java class, with ActiveMQ
  OpenWire throwable unmarshalling as the runtime hook. It is distinct from
  ordinary Java object streams and JSON/YAML polymorphic type resolution, and
  catches dangerous gadget families or Spring/XBean application context classes
  such as the CVE-2023-46604 remote XML payload shape.
- `deserialization_http_invoker` covers Spring HTTP Invoker endpoints when they
  deserialize a Java object stream for a remote invocation request. This targets
  Dubbo HTTP protocol/Spring remoting shapes such as CVE-2019-17564 at the
  framework boundary before any particular gadget class is resolved, and logs
  only request metadata such as method, URI, content type, and mechanism.
- `deserialization_http_object_stream` covers Java `ObjectInputStream`
  construction over a servlet/request-body input stream during an active HTTP
  request, plus Java-serialized request content types and known middleware
  HTTP-invoker stacks. This targets JBoss HTTPInvoker, JMXInvokerServlet, and
  JBossMQ HTTPIL object-stream deserialization boundaries before relying on a
  particular gadget class, while ignoring file/background object streams. The
  playground and acceptance suite include the Vulhub-shaped `/invoker/readonly`,
  `/invoker/JMXInvokerServlet`, and `/jbossmq-httpil/HTTPServerILServlet` POST
  flows for JBoss CVE-2017-12149, the classic JMXInvokerServlet issue, and
  CVE-2017-7504.
- `deserialization_hessian_type` covers Hessian/Burlap-style RPC
  deserialization when the wire type name resolves to a known dangerous gadget,
  Java runtime/JNDI class, Spring/XBean application context, or other blocked
  construction type. This targets older XXL-JOB Hessian-RCE style executor
  chains without blocking ordinary Hessian requests that only carry benign
  maps, lists, DTOs, or primitives.
- `deserialization_xmlrpc_serialized` covers Apache XML-RPC extension values
  where a `<serializable>` XML element is decoded and passed to
  `ObjectInputStream` during request handling. This targets Apache OFBiz XMLRPC
  deserialization chains, including CVE-2020-9496 and CVE-2023-49070, without
  blocking ordinary XML-RPC primitives, arrays, structs, or base64 byte values.
- `deserialization_rmi_registry_bind` covers RMI Registry `bind`/`rebind`
  calls that arrive through RMI transport dispatch and carry a proxy or
  UnicastRef-style remote reference. This targets Java RMI Registry
  deserialization and JRMP listener bypass shapes while ignoring ordinary local
  application registry binds and logging only operation, binding name, remote
  object class, and transport source.
- `deserialization_polymorphic_type` covers parser-supplied dangerous class
  resolution in Fastjson, Jackson, XStream, and SnakeYAML. This includes
  Fastjson autoType `JdbcRowSetImpl` JNDI chains, Fastjson 1.2.47-style
  `java.lang.Class` bypasses that later resolve the concrete dangerous class,
  Jackson wrapper-array `TemplatesImpl` and Spring XML application context
  gadgets, and SnakeYAML construction of `org.h2.jdbc.JdbcConnection`, which
  can immediately open attacker-controlled H2 JDBC URLs with `INIT` payloads as
  seen in HertzBeat-style YAML import RCE chains. The playground and acceptance
  suite include Vulhub-shaped `/fastjson` JSON POSTs for CVE-2017-18349 and
  Fastjson 1.2.47, plus `/exploit` JSON POSTs for Jackson CVE-2017-7525 and
  its Spring XML context bypass, and a SnakeYAML `JdbcConnection` constructor
  hook for the HertzBeat CVE-2024-42323 parser boundary.
- `sql_h2_code_execution` covers H2 SQL statements that load remote scripts or
  define executable Java code through aliases, triggers, or similar code
  containers. This targets H2 console RCE flows such as CVE-2018-10054 without
  blocking ordinary H2 DDL like safe aliases for JDK methods, because the rule
  requires both an H2 code container and a dangerous execution primitive. The
  playground and acceptance suite include the Vulhub-shaped authenticated
  `/h2-console/query.do` SQL form post.
- `jdbc_mysql_deserialization` covers request-controlled MySQL/MariaDB JDBC
  URLs that enable Connector/J deserialization behavior through
  `autoDeserialize` plus interceptor or custom-collation trigger options. This
  targets Linkis-style rogue/fake MySQL datasource testing chains without
  blocking ordinary configured database connections. The playground and
  acceptance suite include the Vulhub-shaped Linkis CVE-2022-44645
  `/api/rest_j/v1/data-source-manager/op/connect/json` datasource test body.
- `sql_derby_code_execution` covers request-time Derby SQL that installs JARs,
  mutates `derby.database.classpath`, or creates Java external routines. This
  targets Nacos-style Derby ops endpoints that load attacker-provided Java code
  through SQL while avoiding startup/migration routines outside an active
  request. The playground and acceptance suite include the Vulhub-shaped Nacos
  CVE-2021-29442 `/nacos/v1/cs/ops/derby?sql=...` endpoint.
- `jndi_jaas_config` covers request-time JAAS configuration strings that select
  `com.sun.security.auth.module.JndiLoginModule` with remote provider URLs such
  as `ldap://` or `rmi://`. This targets Kafka-client/Druid-style
  `sasl.jaas.config` injection before the later JNDI lookup is attempted. The
  playground and acceptance suite include the Vulhub-shaped Kafka
  CVE-2023-25194 `POST /druid/indexer/v1/sampler?for=connect` sampler body.
- `readFile_argument_expansion` covers request-time command argument parsers
  that expand `@file` arguments into local file contents, such as args4j in
  Jenkins CLI handling. The detector is gated to args4j and sensitive absolute
  or traversal-shaped paths, so ordinary local argfiles are ignored. The
  playground and acceptance suite include Vulhub-shaped Jenkins
  CVE-2024-23897 CLI vectors for `help 1 "@/proc/self/environ"` and
  `connect-node "@/etc/passwd"`.
- `ssrf_userinput` covers outbound network requests to internal addresses or
  raw URL values copied from the active request parameters. This targets
  GeoServer `TestWfsPost` CVE-2021-40822-style unauthenticated relays where a
  `url=` parameter is passed to a server-side HTTP client, and WebLogic UDDI
  Explorer SSRF where an `operator=` URL targets internal HTTP or Redis
  services, including CRLF-shaped Redis command payloads, while public external
  URLs that are not request-controlled remain allowed.
- `ssrf_protocol`, `ssrf_userinput`, and related SSRF algorithms also cover XML
  attachment resolvers that fall back from MTOM/XOP content IDs to URL loading.
  This targets Apache CXF Aegis-style `xop:Include href` SSRF/file reads while
  leaving ordinary `cid:` attachments and public HTTP references alone. The
  playground and acceptance suite include the Vulhub-shaped
  `/test` multipart SOAP request for Apache CXF CVE-2024-28752.
- `fileUpload_path_traversal` covers multipart upload filenames that contain
  parent-directory or absolute-path attempts, including encoded forms. This
  targets arbitrary file writes such as Apache Flink `/jars/upload` filename
  traversal while still allowing ordinary relative subdirectory filenames.
- `fileUpload_multipart_script` covers multipart uploads of server-side script
  and server config files such as JSP, JSPX, `.htaccess`, and `.user.ini`.
  This targets WebLogic CVE-2018-2894-style Web Service Test Page uploads to
  `/ws_utc/resources/setting/keystore` as well as other webshell upload
  surfaces.
- `fileUpload_multipart_expression` covers multipart upload filenames whose
  filename value itself contains a dangerous expression payload, including
  Struts2 S2-046-style OGNL parser expressions in the part `filename` header
  with NUL suffix splitting. It logs only inferred engine and filename length
  so expression payloads are not echoed into security logs. The playground and
  acceptance suite include the Vulhub-shaped `/index.action` multipart upload
  filename payload for S2-046.
- `fileUpload_java_archive` covers uploads of Java executable archives such as
  JAR, WAR, EAR, or `.class` files only when the active request context is a
  plugin, extension, driver, connector, job, or JAR deployment surface. This
  targets plugin/JAR execution surfaces such as MeterSphere plugin upload and
  Flink JAR upload without blocking ordinary repository artifact uploads.
- `fileUpload_webdav` covers WebDAV-style `MOVE`/`COPY` operations that produce
  server-side script files or write to unsafe absolute filesystem destinations.
  This targets ActiveMQ fileserver CVE-2016-3088 shapes such as moving an
  uploaded file from `/fileserver/2.txt` to
  `file:///opt/activemq/webapps/api/s.jsp` or `file:///etc/cron.d/root` while
  ignoring ordinary WebDAV renames inside the shared file area.
- `archive_traversal` covers archive extraction where the current ZIP entry
  contains parent-directory, absolute-path, or NUL-path traversal and the
  subsequent file write uses that unsafe entry as the output path. This targets
  ZipSlip-style document preview chains such as kkFileView 4.3 writing a
  crafted `uno.py` under LibreOffice while ignoring sanitized extraction that
  rewrites unsafe entries to safe destinations. The playground and acceptance
  suite include the Vulhub-shaped `/onlinePreview` preview flow with the
  kkFileView POC ZIP entry.
- `java_compile_runtime` covers request-time Java source compilation through
  JDK `JavacTool` and Janino-style source APIs when the source contains runtime
  execution primitives, covering GeoServer/JAI-EXT Jiffle-style code injection
  without matching product-specific request signatures.
- `xml_decoder_runtime` and `xml_decoder_webshell` cover JavaBeans XMLDecoder
  object graphs that invoke process/runtime primitives or create server-side
  script writers, covering WebLogic WorkContext XMLDecoder-style RCE without a
  WebLogic-specific path signature. The playground and acceptance suite include
  the Vulhub-shaped `/wls-wsat/CoordinatorPortType` SOAP `WorkContext`
  `XMLDecoder` flow for CVE-2017-10271.
- The servlet hook module supports both `javax.servlet` and `jakarta.servlet`
  service descriptors, which lets the same detector and policy path run across
  Tomcat 9, 10, and 11.

## Notes

- Commented or disabled-by-default policy toggles from the source JavaScript
  catalog, such as broad "log every command" or "log every native library load",
  are intentionally not enabled in acceptance because they are not abnormal
  behavior signals by themselves.
- Dynamic hook delivery is still future work, but the current agent can register
  with the control plane, report heartbeats, pull policy assignment metadata,
  and upload attack detections to `/api/v1/events/attack`.
