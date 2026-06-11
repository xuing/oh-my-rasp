# Algorithm Coverage

This PoC migrates the JavaScript detector behavior into Java-native detector
methods in `DetectorEngine`. Runtime API hooks call these methods directly where
there is a concrete Java API to instrument. Semantic hook methods exist for
policy families whose original hook point is language- or framework-specific,
so the playground can still verify policy execution and JSONL log collection.

For the per-component Vulhub progress tracker, update
[`vulhub-java-coverage-checklist.md`](vulhub-java-coverage-checklist.md) in the
same patch as any new Java-compatible Vulhub replay.

## Runtime Era Tracks

- The primary `agent` module remains the Java 25 Tomcat 11 -> 10 -> 9 replay
  target and owns the accepted algorithm list below.
- The dedicated `agent-java8` module is a separate Java 8 era track for Vulhub
  images that cannot run the Java 25 production agent. It now has a functional
  ASM hook for `ProcessBuilder.start` and `Runtime.exec` command sinks. The
  Java 8 command hook logs `java8_command_execution_exploit_primitive` for
  exploit-grade process primitives such as `/etc/passwd` reads, reverse-shell
  patterns, and curl/wget-to-shell pipelines, and
  `java8_command_execution_shell_meta` for shell `-c` invocations containing
  command metacharacters. It logs by default and only blocks when
  `ohmyrasp.java8.block` or `OHMYRASP_JAVA8_BLOCK` is enabled.
  It also treats process execution reached from Solr
  `org.apache.solr.core.RunExecutableListener` as exploit-grade behavior,
  because the command value has already crossed the vulnerable Solr config API
  and post-commit listener boundary.
  Process execution reached from dynamic expression-language stacks such as
  MVEL, Elasticsearch-shaded MVEL, OGNL, Groovy, Apache Commons JEXL, Spring
  SpEL, and Spring WebFlow also
  logs `java8_command_execution_exploit_primitive`. Process execution reached
  from database Java routine stacks such as Derby, H2, or HSQLDB is treated the
  same way. Process execution reached from JAI-EXT/Jiffle runtime stacks is
  treated the same way for GeoServer/JAI-EXT CVE-2022-24816-style payloads.
  Process execution reached during Spring `ApplicationContext`
  refresh and `AbstractAutowireCapableBeanFactory` bean initialization is also
  treated as exploit-grade behavior, covering remote Spring XML/XBean
  configuration chains without inspecting payload strings; plain
  `Runtime.exec("touch ...")` or `Runtime.exec("id")` outside those stacks
  remains quiet.
  Process execution reached while Java object stream deserialization is active
  is also treated as exploit-grade behavior, including standard
  `ObjectInputStream`, Axis2 `SafeObjectInputStream`, and BlazeDS AMF
  deserialization frames. `scripts/acceptance-vulhub-coldfusion-3066-java8.sh`
  provides real Vulhub evidence: ColdFusion 11u3 CVE-2017-3066 baseline accepts
  a ColdFusionPwn CommonsBeanutils1 AMF body and creates
  `/tmp/ohmyrasp-coldfusion-3066-success`, while protected mode keeps
  ColdFusion startup quiet and blocks the deserialization-triggered
  `Runtime.exec(String)` sink with `java8_command_execution_exploit_primitive`.
  The 2026-06-06 full LTS Tomcat rerun after this stack-correlation refinement
  passed Java 17 Tomcat 11 -> 10.1 -> 9, Java 11 Tomcat 10.1 -> 9, and
  Java 8 Tomcat 10.0 -> 9 -> 8.5.
  Exact OS/system inventory probes such as `getconf CLK_TCK`,
  `getconf PAGE_SIZE`, `getconf PAGESIZE`, `lscpu -p=cpu,node`, and
  `vcgencmd measure_temp`, `dmidecode -t 4`, and `cpuid -1r`, plus local
  identity checks such as `id hadoop`, stay quiet even from Spring
  bean-initialization stacks, matching GeoServer OSHI startup behavior and
  Linkis service-user readiness checks.
  Process execution reached from XStream XML unmarshalling or Struts2 REST
  XStream handler stacks is also treated as exploit-grade behavior, covering
  XML polymorphic gadget chains without requiring suspicious command text.
  Scheduler script execution stacks such as XXL-JOB `ScriptJobHandler` also
  map shell interpreters running generated script files to
  `java8_command_execution_shell_meta`, while ordinary shell script execution
  outside scheduler stacks remains quiet. kkFileView
  `cn.keking.service.OfficePluginManager` LibreOffice cleanup commands for
  `soffice.bin` process counting and termination are ignored only from that
  stack to avoid protected-mode startup false positives. Apache Tika
  `ExternalParser.check` availability probes for media tools such as `ffmpeg`,
  `exiftool`, and `tesseract`, plus local browser launch chains that open only
  `localhost`/`127.0.0.1` URLs, are also treated as normal startup behavior.
  `scripts/acceptance-vulhub-solr-runexec-java8.sh` provides real Vulhub
  application evidence: Solr 7.0.1 CVE-2017-12629 baseline adds a post-commit
  `RunExecutableListener` and creates `/tmp/ohmyrasp-solr12629-success`, while
  protected mode keeps startup and the config API quiet and blocks the
  listener-triggered runtime sink.
  `scripts/acceptance-vulhub-rocketmq-java8.sh` provides real Vulhub
  application evidence for shell-metacharacter process sinks: RocketMQ 5.1.0
  CVE-2023-33246 baseline uses `rocketmq-attack` to mutate broker
  filter-server configuration and create
  `/tmp/ohmyrasp-rocketmq33246-success`, while protected mode keeps startup
  quiet and blocks the filter-server `Runtime.exec(String[])` shell command.
  `scripts/acceptance-vulhub-xxljob-java8.sh` provides real Vulhub application
  evidence for scheduler shell jobs: XXL-JOB 2.2.0 executor baseline accepts an
  unauthenticated `POST /run` `GLUE_SHELL` job and creates
  `/tmp/ohmyrasp-xxljob-success`, while protected mode keeps startup quiet and
  blocks the later `Runtime.exec(String[])` sink as
  `java8_command_execution_shell_meta`.
  `scripts/acceptance-vulhub-solr-velocity-java8.sh` provides real Vulhub
  application evidence: Solr 8.2.0 CVE-2019-17558 baseline enables
  `VelocityResponseWriter` parameter templates and executes
  `Runtime.exec("cat /etc/passwd")`, while protected mode keeps startup and the
  config API quiet and blocks the Velocity-triggered runtime sink.
  `scripts/acceptance-vulhub-unomi-java8.sh` provides real Vulhub application
  evidence for expression-language stacks: Unomi 1.5.1 CVE-2020-13942 baseline
  evaluates a `/context.json` MVEL `profilePropertyCondition` payload and
  creates `/tmp/ohmyrasp-unomi-touch-success`, while protected mode keeps
  readiness quiet and blocks the MVEL-triggered `Runtime.exec(String)` sink.
  `scripts/acceptance-vulhub-elasticsearch-3120-java8.sh` provides real Vulhub
  application evidence for Elasticsearch-shaded MVEL search-script stacks:
  Elasticsearch 1.1.1 CVE-2014-3120 baseline indexes a document, evaluates a
  `_search` `script_fields` MVEL payload, and creates
  `/tmp/ohmyrasp-es-3120-success`, while protected mode keeps startup and
  indexing quiet and blocks the MVEL-triggered `Runtime.exec(String)` sink.
  `scripts/acceptance-vulhub-elasticsearch-1427-java8.sh` provides real Vulhub
  application evidence for Groovy search-script stacks: Elasticsearch 1.4.2
  CVE-2015-1427 baseline indexes a document, evaluates a `script_fields`
  Groovy sandbox-bypass payload, and creates
  `/tmp/ohmyrasp-es-1427-success`, while protected mode keeps startup and
  indexing quiet and blocks the Groovy-triggered `Runtime.exec(String)` sink.
  `scripts/acceptance-vulhub-spring-security-oauth-java8.sh` provides real
  Vulhub application evidence for Spring Security OAuth whitelabel SpEL:
  2.0.8 baseline authenticates as `admin:admin`, sends a Vulhub-style
  no-whitespace `response_type` expression, and creates
  `/tmp/ohmyrasp-spring4977-success`, while protected mode keeps startup quiet
  and blocks the error-page `Runtime.exec(String)` sink.
  `scripts/acceptance-vulhub-spring-gateway-java8.sh` provides real Vulhub
  application evidence for Spring SpEL route configuration: Spring Cloud
  Gateway 3.1.0 CVE-2022-22947 baseline registers an actuator route, refreshes
  it, and creates `/tmp/ohmyrasp-spring22947-success`, while protected mode
  keeps startup and route registration quiet and blocks the refresh-time
  `Runtime.exec(String[])` sink.
  `scripts/acceptance-vulhub-spring-function-java8.sh` provides real Vulhub
  application evidence for Spring Cloud Function routing expressions: 3.2.2
  baseline posts to `/functionRouter` with the
  `spring.cloud.function.routing-expression` header and creates
  `/tmp/ohmyrasp-spring22963-success`, while protected mode keeps startup quiet
  and blocks the routing-expression-triggered `Runtime.exec(String)` sink.
  `scripts/acceptance-vulhub-spring-data-rest-java8.sh` provides real Vulhub
  application evidence for Spring Data REST JSON Patch expressions: 2.6.6
  baseline sends a `PATCH /customers/1` JSON Patch path expression and creates
  `/tmp/ohmyrasp-spring8046-success`, while protected mode keeps startup quiet
  and blocks the SpEL-triggered `Runtime.exec(String)` sink.
  `scripts/acceptance-vulhub-spring-data-commons-java8.sh` provides real
  Vulhub application evidence for Spring Data Commons binder property paths:
  2.0.5 baseline posts a `username[...]` parameter-name SpEL payload and
  creates `/tmp/ohmyrasp-spring1273-success`, while protected mode keeps
  startup quiet and blocks the binder-triggered `Runtime.exec(String)` sink.
  `scripts/acceptance-vulhub-spring-messaging-java8.sh` provides real Vulhub
  application evidence for Spring Messaging STOMP selector expressions: 5.0.4
  baseline opens the SockJS downgrade stream, subscribes with a SpEL
  `selector` header, sends to `/app/hello`, and creates
  `/tmp/ohmyrasp-spring1270-success`, while protected mode keeps startup quiet
  and blocks the selector-triggered `Runtime.exec(String)` sink.
  `scripts/acceptance-vulhub-jenkins-1000861-java8.sh` provides real Vulhub
  application evidence for Groovy validation stacks: Jenkins 2.138
  CVE-2018-1000861 baseline invokes the unauthenticated
  `SecureGroovyScript/checkScript` syntax-validation path and creates
  `/tmp/ohmyrasp-jenkins-1000861-success`, while protected mode keeps startup
  quiet and blocks the Groovy-triggered `Runtime.exec(String)` sink.
  `scripts/acceptance-vulhub-ofbiz-51467-java8.sh` provides real Vulhub
  application evidence for OFBiz ProgramExport Groovy execution: 18.12.10
  baseline reaches the unauthenticated
  `/webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y`
  path and returns `uid=0(root)` from `'id'.execute().text`, while protected
  mode keeps startup/readiness quiet and blocks the Groovy-triggered
  `Runtime.exec(String)` sink with `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-ofbiz-38856-java8.sh` provides follow-up evidence
  for OFBiz 18.12.14 CVE-2024-38856: the baseline multipart
  `/webtools/control/main/ProgramExport` request uses the README
  Unicode-escaped `\u0065xecute()` bypass and returns `uid=0(root)`, while
  protected mode still blocks the decoded Groovy-triggered
  `Runtime.exec(String)` sink with the same generic expression-stack command
  algorithm.
  `scripts/acceptance-vulhub-nacos-java8.sh` provides real Vulhub application
  evidence for database Java routine stacks: Nacos 1.4.0 CVE-2021-29442
  baseline uses Derby SQLJ to load an `Exec.exec` function and returns
  `uid=0(root)`, while protected mode blocks the Derby-triggered
  `Runtime.exec("id")` sink.
  `scripts/acceptance-vulhub-struts2-s2045-java8.sh` provides real Vulhub
  application evidence for OGNL expression stacks: Struts2 2.3.30 S2-045
  baseline sends a `Content-Type` OGNL payload and returns `uid=0(root)`,
  while protected mode keeps Jetty/Struts XML startup and readiness quiet,
  blocks the OGNL `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`, and returns no command output.
  `scripts/acceptance-vulhub-struts2-s2046-java8.sh` uses the same Struts2
  2.3.30 image to verify S2-046: baseline sends the Vulhub raw multipart
  filename OGNL payload with a NUL separator and returns `uid=0(root)`, while
  protected mode blocks the later `ProcessBuilder.start` sink with the same
  generic OGNL expression-stack command algorithm.
  `scripts/acceptance-vulhub-struts2-s2048-java8.sh` verifies Struts2
  2.3.32 showcase S2-048/CVE-2017-9791: baseline posts the Gangster Name OGNL
  payload to `/integration/saveGangster.action` and returns `uid=0(root)`,
  while protected mode blocks the OGNL `Runtime.exec(String)` sink with
  `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2001-java8.sh` verifies local Vulhub
  Struts2 S2-001 on OpenJDK 8u121: baseline posts a validation-error
  `/login.action` form whose `username` value is evaluated during Struts field
  repopulation and creates `/tmp/ohmyrasp-s2001-success`, while protected mode
  blocks the later `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2005-java8.sh` verifies local Vulhub
  Struts2 S2-005 on OpenJDK 8u121: baseline sends the Vulhub
  `\u0023`-escaped parameter-name OGNL chain to
  `/example/HelloWorld.action` and creates `/tmp/ohmyrasp-s2005-success`,
  while protected mode starts quietly after the XWork local XML include
  refinement and blocks the later `Runtime.exec(String[])` sink with
  `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2016-java8.sh` verifies local Vulhub
  Struts2 S2-016 on OpenJDK 8u121: baseline sends the redirect-prefix
  parameter-name OGNL chain to `/index.action`, uses the Vulhub
  `denyMethodExecution=false` and `allowStaticMethodAccess` bypass, and
  creates `/tmp/ohmyrasp-s2016-success`, while protected mode blocks the later
  `Runtime.exec(String)` sink with `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2032-java8.sh` verifies Vulhub Struts2
  S2-032/CVE-2016-3081 on OpenJDK 8u252: baseline sends the README-shaped
  dynamic-method-invocation `method:` parameter-name OGNL chain to
  `/index.action`, creates `/tmp/ohmyrasp-s2032-success`, and returns the
  command response, while protected mode blocks the later
  `Runtime.exec(String)` sink with `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2015-java8.sh` verifies local Vulhub
  Struts2 S2-015 on OpenJDK 8u121: baseline sends an action-name path
  `${...}.action` payload through the wildcard `/{1}.jsp` result, uses the
  Vulhub `denyMethodExecution=false` and `allowStaticMethodAccess` bypass, and
  creates `/usr/local/tomcat/ohmyrasp-s2015-success`, while protected mode
  blocks the later `Runtime.exec(String)` sink with
  `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2007-java8.sh` verifies local Vulhub
  Struts2 S2-007 on OpenJDK 8u121: baseline posts an integer-conversion-error
  `/user.action` form whose `age` value is evaluated during validation error
  rendering and creates `/tmp/ohmyrasp-s2007-success`, while protected mode
  blocks the later `Runtime.exec(String)` sink with
  `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2008-java8.sh` verifies local Vulhub
  Struts2 S2-008 on OpenJDK 8u121: baseline sends the devMode
  `/devmode.action?debug=command&expression=...` OGNL command flow and creates
  `/tmp/ohmyrasp-s2008-success`, while protected mode blocks the later
  `Runtime.exec(String)` sink with `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2009-java8.sh` verifies local Vulhub
  Struts2 S2-009 on OpenJDK 8u121: baseline delegates OGNL evaluation through
  the `name` and `z[(name)('meh')]` query parameters and creates
  `/tmp/ohmyrasp-s2009-success`, while protected mode blocks the later
  `Runtime.exec(String)` sink with `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2012-java8.sh` verifies local Vulhub
  Struts2 S2-012 on OpenJDK 8u121: baseline posts a non-empty
  `/user.action` `name` form value that is evaluated by the redirect result
  `/index.jsp?name=${name}` and creates `/tmp/ohmyrasp-s2012-success`, while
  protected mode blocks the later `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2013-java8.sh` verifies local Vulhub
  Struts2 S2-013/S2-014 on OpenJDK 8u121: baseline sends a dollar-OGNL
  `GET /link.action?a=${...}` includeParams value, the rendered `<s:a>` link
  contains a `java.lang.*Process` result, and
  `/tmp/ohmyrasp-s2013-success` is created, while protected mode blocks the
  later `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2052-java8.sh` verifies Struts2
  2.5.12 REST/XStream S2-052: baseline posts the Vulhub XML polymorphic
  gadget to `/orders/3/edit` and creates `/tmp/ohmyrasp-s2052-success`, while
  protected mode blocks the XStream-triggered `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2053-java8.sh` verifies Struts2 S2-053:
  baseline posts the Vulhub `redirectUri` OGNL value with its required
  trailing newline to `/hello.action` and returns `uid=0(root)`, while
  protected mode blocks the OGNL `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2057-java8.sh` verifies Struts2
  2.3.34 showcase S2-057/CVE-2018-11776 namespace OGNL: baseline requests the
  Vulhub action-chain redirect URL and returns `uid=0(root)` in the redirect
  response, while protected mode keeps Tomcat/Struts startup quiet and blocks
  the OGNL `Runtime.exec` sink with `java8_command_execution_exploit_primitive`.
  `scripts/acceptance-vulhub-struts2-s2059-java8.sh` provides real Vulhub
  evidence for Struts2 2.5.16 S2-059 forced OGNL double evaluation: baseline
  sends the two-step Vulhub `id` parameter payload and creates
  `/tmp/ohmyrasp-s2059-success`, while protected mode blocks the second-step
  OGNL `Runtime.exec` sink with `java8_command_execution_exploit_primitive`.
- The Java 8 era track also hooks `InitialContext.lookup` and `lookupLink`.
  Remote LDAP/RMI/IIOP/CORBA naming URLs log `java8_jndi_remote_lookup`; local
  `java:comp/env` lookups are ignored. This targets JNDI exploitation behavior
  without turning request payload strings into WAF signatures.
  `scripts/acceptance-vulhub-fastjson-java8.sh` provides real Vulhub
  application evidence: Fastjson 1.2.24 and 1.2.45 baselines reach an outbound
  JRMI listener through `JdbcRowSetImpl`, while protected mode blocks the JNDI
  lookup before any outbound connection is made.
  `scripts/acceptance-vulhub-log4j-solr-java8.sh` provides real Vulhub
  Log4Shell evidence: Solr 8.11.0 on Java 8u102 logs the Solr admin
  `${jndi:ldap://...}` action value and reaches an outbound LDAP listener in
  baseline mode, while protected mode blocks the Log4j-triggered
  `InitialContext.lookup` sink before any outbound LDAP connection is made.
  `scripts/acceptance-vulhub-h2-42392-java8.sh` provides real Vulhub
  application evidence: H2 Console CVE-2021-42392 baseline submits
  `driver=javax.naming.InitialContext` with an LDAP URL and reaches an
  outbound LDAP listener, while protected mode blocks `InitialContext.lookup`
  before any outbound LDAP connection is made.
  `scripts/acceptance-vulhub-xstream-21351-java8.sh` provides real Vulhub
  application evidence: XStream 1.4.15 CVE-2021-21351 baseline unmarshals the
  `JdbcRowSetImpl` XML gadget and reaches an outbound LDAP listener, while
  protected mode blocks `InitialContext.lookup` before any outbound LDAP
  connection is made.
- The Java 8 era track hooks `ObjectInputStream.resolveClass` and
  `resolveProxyClass`, including RMI `MarshalInputStream`, Spring HTTP Invoker
  `ConfigurableObjectInputStream` and `CodebaseAwareObjectInputStream`
  subclasses. High-risk gadget or execution primitive classes such as
  `TemplatesImpl`, `JdbcRowSetImpl`, commons-collections transformer gadgets,
  BeanShell interpreter/proxy gadgets, Groovy closure gadgets, Spring factory
  gadgets, and `ProcessBuilder` log `java8_deserialization_gadget_class`;
  ordinary class resolution, such as string deserialization, is ignored.
  The Java 8 era track also hooks Hessian `SerializerFactory.getDeserializer`
  type resolution and emits `java8_deserialization_hessian_type` for dangerous
  Hessian wire types such as `org.apache.commons.beanutils.BeanComparator`
  while ignoring benign DTO/container types.
  `scripts/acceptance-vulhub-dubbo-java8.sh` provides real Vulhub application
  evidence: Dubbo 2.7.3 CVE-2019-17564 baseline deserializes a
  CommonsCollections6 HTTP Invoker body and creates
  `/tmp/ohmyrasp-dubbo-success`, while protected mode keeps startup quiet and
  blocks `org.apache.commons.collections.functors.ChainedTransformer` class
  resolution before the marker file is created.
  `scripts/acceptance-vulhub-log4j-5645-java8.sh` provides real Vulhub
  application evidence: Log4j 2.8.1 CVE-2017-5645 baseline accepts a
  CommonsCollections5 payload on TCP port 4712 and creates
  `/tmp/ohmyrasp-log4j5645-success`, while protected mode blocks
  `org.apache.commons.collections.functors.ChainedTransformer` class
  resolution before the marker file is created.
  `scripts/acceptance-vulhub-jmeter-1297-java8.sh` provides real Vulhub
  application evidence: JMeter 3.3 CVE-2018-1297 baseline accepts a
  `RMIRegistryExploit` BeanShell1 payload and creates
  `/tmp/ohmyrasp-jmeter1297-success`, while protected mode blocks
  `bsh.XThis$Handler` class resolution inside RMI `MarshalInputStream` before
  the marker file is created.
  `scripts/acceptance-vulhub-neo4j-34371-java8.sh` provides real Vulhub
  application evidence: Neo4j Shell 3.4.18 CVE-2021-34371 baseline accepts the
  Vulhub `rhino_gadget` `setSessionVariable` RMI request and creates
  `/tmp/ohmyrasp-neo4j34371-success`, while protected mode blocks
  `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` class
  resolution before the marker file is created.
  `scripts/acceptance-vulhub-ofbiz-9496-java8.sh` provides real Vulhub
  application evidence: OFBiz 17.12.01 CVE-2020-9496 baseline deserializes a
  CommonsBeanutils1 XML-RPC `<serializable>` value and creates
  `/tmp/ohmyrasp-ofbiz-9496-success`, while protected mode keeps startup and
  readiness quiet and blocks `TemplatesImpl` class resolution before the
  marker file is created.
  `scripts/acceptance-vulhub-rmi-registry-direct-java8.sh` provides real
  Vulhub application evidence for the `<= 8u111` RMI Registry direct-bind
  boundary: baseline accepts ysoserial `RMIRegistryExploit`
  CommonsCollections6 against `vulhub/j2ee:8u111` and creates
  `/tmp/ohmyrasp-rmi-registry-direct-success`, while protected mode blocks
  `org.apache.commons.collections.functors.ChainedTransformer` class
  resolution before the marker file is created. The current Vulhub compose tag
  for this path is `8u131`, which is outside that vulnerable direct-bind
  boundary and rejects the same direct gadget payloads through the JDK
  `ObjectInputFilter`.
  `scripts/acceptance-vulhub-xstream-29505-java8.sh` provides real Vulhub
  application evidence: XStream 1.4.16 CVE-2021-29505 baseline accepts the
  `RegistryImpl_Stub` XML body, reaches a ysoserial JRMPListener, receives a
  CommonsCollections6 second-stage object, and creates
  `/tmp/ohmyrasp-xstream29505-success`, while protected mode blocks
  `org.apache.commons.collections.functors.ChainedTransformer` class
  resolution before the marker file is created.
- The Java 8 era track hooks `FileInputStream`, `FileOutputStream`,
  `RandomAccessFile`, `File.renameTo`, and `java.nio.file.Files` content
  read/write, byte-channel open, path-to-path copy, and path-to-path move APIs.
  Sensitive reads such as `/etc/passwd`,
  `/proc/self/environ`, SSH private keys, and Windows hosts files log
  `java8_file_sensitive_read`; script or executable writes are logged as
  `java8_file_script_write` only when the target path is webroot-like or uses
  traversal. Ordinary temporary file reads and writes are ignored, and normal
  ColdFusion runtime compilation writes to `WEB-INF/cfclasses/*.class` are
  treated like existing `WEB-INF/classes` deployment artifacts instead of
  server-side script writes.
  `scripts/acceptance-vulhub-solr-remotestreaming-java8.sh` provides real
  Vulhub application evidence: Solr 8.8.1 RemoteStreaming baseline returns
  `/etc/passwd` through `stream.url=file:///etc/passwd`, while protected mode
  keeps startup and the config API quiet and blocks the sensitive Java file
  read before passwd content is disclosed.
  `scripts/acceptance-vulhub-elasticsearch-3337-java8.sh` provides real
  Vulhub application evidence for plugin resource traversal: Elasticsearch
  1.4.4 CVE-2015-3337 baseline serves `/etc/passwd` through the preinstalled
  `head` site plugin path, while protected mode keeps startup/readiness quiet
  and blocks the lower-level `FileInputStream.open` sink before passwd content
  is disclosed.
  `scripts/acceptance-vulhub-elasticsearch-5531-java8.sh` provides real
  Vulhub application evidence for snapshot repository traversal:
  Elasticsearch 1.6.0 CVE-2015-5531 baseline registers the Vulhub filesystem
  snapshot repositories and returns `/etc/passwd` bytes in the parse-error
  body, while protected mode keeps startup and repository setup quiet and
  blocks the lower-level `FileInputStream.open` sink before passwd bytes are
  disclosed.
  `scripts/acceptance-vulhub-elasticsearch-110216-java8.sh` provides real
  Vulhub application evidence for snapshot repository webroot writes:
  Elasticsearch 1.5.1-with-Tomcat WooYun-2015-110216 baseline indexes a JSP
  scriptlet field, creates a filesystem snapshot repository under Tomcat
  `webapps/wwwroot`, and exposes the generated JSP snapshot artifact through
  Tomcat, while protected mode keeps startup and repository setup quiet and
  blocks the lower-level `FileOutputStream.open` sink before the JSP artifact
  is created.
  `scripts/acceptance-vulhub-ofbiz-45195-java8.sh` provides real Vulhub
  application evidence for OFBiz webapp JSP writes: OFBiz 18.12.15
  CVE-2024-45195 baseline uses the unauthenticated
  `/webtools/control/forgotPassword/viewdatafile` remote CSV/XML import to
  replace `applications/accounting/webapp/accounting/index.jsp` and returns
  `uid=0(root)` from `/accounting/index.jsp?cmd=id`, while protected mode
  keeps startup/readiness and remote payload fetch quiet and blocks the
  lower-level `FileOutputStream.open` sink with `java8_file_script_write`
  before the original `index.jsp` is replaced.
  `scripts/acceptance-vulhub-cxf-java8.sh` provides real Vulhub application
  evidence for XML attachment file reads: Apache CXF 3.2.14 CVE-2024-28752
  baseline resolves an Aegis/XOP `href="file:///etc/hosts"` reference and
  returns base64-encoded hosts content, while protected mode blocks the
  lower-level Java file read before that content is returned.
  `scripts/acceptance-vulhub-rocketmq-37582-java8.sh` provides real Vulhub
  application evidence for script/executable writes: RocketMQ NameServer 5.1.0
  CVE-2023-37582 baseline redirects `configStorePath` to a traversal `.sh`
  marker under `/tmp`, while protected mode blocks `FileOutputStream.open`
  before the marker content is created.
  `scripts/acceptance-vulhub-flink-java8.sh` provides real Vulhub application
  evidence for upload file moves: Flink 1.11.2 CVE-2020-17518 baseline accepts
  a `/jars/upload` multipart filename traversal and writes a `.jar` marker
  under `/tmp`, while protected mode blocks the destination file-write sink
  before marker content is created.
  `scripts/acceptance-vulhub-tomcat-12615-java8.sh` provides real Vulhub
  application evidence for server-side script writes: Tomcat 8.5.19
  CVE-2017-12615 baseline accepts `PUT /ohmyrasp12615.jsp/` and executes the
  uploaded JSP, while protected mode blocks the webroot JSP write before the
  file can be executed.
  `scripts/acceptance-vulhub-flink-17519-java8.sh` provides real Vulhub
  application evidence for Netty REST local file reads: Flink 1.11.2
  CVE-2020-17519 baseline returns `/etc/passwd` through a double-encoded
  `/jobmanager/logs/..%252f...` traversal, while protected mode blocks the
  lower-level `FileInputStream.open` sink before passwd content is disclosed.
  Generated plot script writes are inspected at `FileOutputStream.write` only
  after a same-thread plot script path such as `.gnuplot`, `.gp`, `.plt`, or
  `.plot` is opened; bounded plot controls such as `yrange`, `y2range`, and
  `key` that contain command directives log
  `java8_file_generated_plot_script_command`, while ordinary generated plot
  scripts remain quiet. `scripts/acceptance-vulhub-opentsdb-java8.sh` provides
  real Vulhub application evidence: OpenTSDB 2.4.0 and 2.4.1 baselines create
  marker files through Gnuplot `system` directives, while protected mode blocks
  the generated `.gnuplot` write before either marker is created.
- The Java 8 era track hooks `URL.openConnection` and `openStream`. Cloud
  metadata targets such as `169.254.169.254`, `169.254.170.2`,
  `100.100.100.200`, `metadata.google.internal`, and `fd00:ec2::254` log
  `java8_ssrf_cloud_metadata`; loopback administrative paths such as
  `/actuator`, `/jolokia`, `/manager`, `/console`, and `/solr/admin` log
  `java8_ssrf_loopback_admin`; and active-request parameters named like
  `url`, `uri`, `href`, `endpoint`, `target`, `callback`, or `webhook` that
  are copied into same-thread outbound HTTP(S) URL sinks log or block
  `java8_ssrf_request_parameter_url`. Normal public HTTP(S) URLs that are not
  request-controlled are ignored. DataEase APISIX route self-checks to
  `127.0.0.1:9180/apisix/admin/...` stay quiet only from the DataEase
  `XpackRouteManage` Spring ready-event startup stack; the same URL outside
  that stack still blocks as loopback admin SSRF.
- The Java 8 era track hooks `ZipEntry.getName` and SevenZipBinding
  `SimpleInArchiveItemImpl.getPath`, then correlates dangerous entry names with
  the next Java file-write sink on the same thread. Absolute paths, Windows
  absolute paths, and `../` traversal entries log
  `java8_archive_entry_traversal_write`; safe archive entries are ignored.
  `scripts/acceptance-vulhub-kkfileview-java8.sh` provides real Vulhub
  application evidence: kkFileView 4.3.0 baseline previews a crafted ZIP that
  overwrites LibreOffice `uno.py` and creates
  `/tmp/ohmyrasp-kkfileview-success` during ODT conversion, while protected mode
  blocks the SevenZipBinding extraction write before `uno.py` is overwritten.
- The Java 8 era track hooks `DriverManager.getConnection` and direct H2
  `org.h2.jdbc.JdbcConnection` constructors. H2 `INIT` URLs carrying
  `RUNSCRIPT`, `CREATE ALIAS`, trigger, runtime, JNDI, or classloader
  primitives log `java8_jdbc_h2_code_execution`; Derby SQLJ/classpath Java
  loading URLs log `java8_jdbc_derby_code_loading`; MySQL URLs that combine
  `autoDeserialize` with interceptor or custom-collation triggers log
  `java8_jdbc_mysql_deserialization`. Ordinary JDBC URLs are ignored.
  `scripts/acceptance-vulhub-h2-23221-java8.sh` provides real Vulhub
  application evidence: H2 Console CVE-2022-23221 on OpenJDK 8 returns
  `uid=0(root)` from a baseline `INIT=CREATE TRIGGER ... //javascript` login
  URL, while protected mode keeps startup quiet and blocks the H2 JDBC URL
  sink before command output is produced.
  `scripts/acceptance-vulhub-linkis-44645-java8.sh` provides real Vulhub
  application evidence for the MySQL branch: baseline Linkis 1.3.0 on OpenJDK
  8 authenticates with `hadoop` / `hadoop` and connects to an attacker-controlled
  rogue MySQL listener through `autoDeserialize=true` and
  `ServerStatusDiffInterceptor`, while protected mode keeps startup, login, and
  normal datasource readiness quiet, blocks the lower-level
  `DriverManager.getConnection` sink with `java8_jdbc_mysql_deserialization`,
  and the rogue listener receives no connection.
  The Java 8 JDBC-era transformer also hooks SkyWalking 8.3.0
  `H2LogQueryDAO.queryLogs(String, ...)` and treats `metricName` as a SQL
  identifier argument: comment, statement-separator, expression, boolean
  comparison, and keyword-control syntax log or block
  `java8_sql_identifier_injection`, while ordinary metric names such as
  `service_instance_jvm_memory.max` stay quiet. Real Vulhub evidence is
  provided by `scripts/acceptance-vulhub-skywalking-java8.sh`: baseline
  SkyWalking on OpenJDK 8 includes the malicious GraphQL `metricName` in the H2
  `select count(1) total from ...` error, while protected mode blocks in the
  OAP JVM before the SQL is built and does not store the raw metric value in
  the event log.
  The Java 8/11/17 JDBC-era transformers also hook MyBatis
  `org.apache.ibatis.mapping.BoundSql` construction. When the final SQL
  contains an `order by` clause, the hook inspects MyBatis parameter objects
  for sort metadata such as `orders[].type`, `orders[].name`, and
  `orders[].prefix`; suspicious identifier or direction values log or block
  the era-specific `javaX_sql_identifier_injection` algorithm while normal
  values such as `desc` stay quiet. Real Java 8 Vulhub evidence is provided by
  `scripts/acceptance-vulhub-metersphere-45788-java8.sh`: baseline
  MeterSphere 1.15.4 reaches the time-delay order-by path, while protected mode
  blocks at `MyBatis.BoundSql` with `java8_sql_identifier_injection` and does
  not log the session id, CSRF token, or raw SQL value.
- The Java 8 era track hooks `URLClassLoader` constructors, `addURL`, and
  `RMIClassLoader` codebase APIs. Remote HTTP(S), FTP, LDAP, or RMI codebases,
  including `jar:` URLs that wrap one of those remote schemes, log
  `java8_classloader_remote_codebase`; local `file:` classpath URLs are
  ignored. Felix/OSGi internal extension-bundle codebases whose host is
  exactly `felix.extensions` are also ignored so GlassFish/Felix startup does
  not look like attacker-controlled remote bytecode loading.
  `scripts/acceptance-vulhub-rmi-codebase-java8.sh` provides real Vulhub
  application evidence: `vulhub/j2ee:8u222` `java/rmi-codebase` baseline sends
  an `ICalc.sum(List)` call carrying a serializable class annotated with a
  temporary HTTP `java.rmi.server.codebase` and creates
  `/tmp/ohmyrasp-rmi-codebase-success` during server-side deserialization,
  while protected mode blocks `RMIClassLoader` before the remote class can be
  loaded.
  `scripts/acceptance-vulhub-liferay-7961-java8.sh` provides real Vulhub
  application evidence for Liferay Portal CVE-2020-7961 on OpenJDK 8:
  baseline posts the JSONWS typed C3P0/Jackson parameter, loads
  `LifExp.class` from the attacker HTTP server, and creates
  `/tmp/ohmyrasp-liferay-7961-success`, while protected mode keeps Liferay's
  Tika and local-browser startup checks quiet and blocks the remote
  `URLClassLoader` codebase with `java8_classloader_remote_codebase`.
- The Java 8 era track hooks `ScriptEngine.eval(String...)` and
  `compile(String...)` sources through `AbstractScriptEngine`, Nashorn, and
  `ScriptEngineImpl` implementations, plus Rhino/Mozilla
  `Context.evaluateString`, `Context.compileString`, and
  `Context.compileFunction`.
  Runtime, reflective runtime, `ProcessBuilder`, nested script-engine eval, or
  string-literal `.execute()` primitives log
  `java8_script_engine_runtime_execution`; ordinary arithmetic and data
  transformation scripts are ignored.
  `scripts/acceptance-vulhub-solr-dataimport-java8.sh` provides real Vulhub
  application evidence: Solr 8.1.1 CVE-2019-0193 baseline evaluates a
  request-supplied DataImportHandler `dataConfig` JavaScript that creates
  `/tmp/ohmyrasp-solr0193-success`, while protected mode keeps startup quiet
  and blocks the script evaluation before the marker file is created.
  `scripts/acceptance-vulhub-h2-10054-java8.sh` provides real Vulhub
  application evidence for compiled scripts: H2 1.4.197 CVE-2018-10054
  baseline compiles a console-submitted trigger JavaScript and returns
  `uid=0(root)`, while protected mode keeps startup and safe login quiet and
  blocks Nashorn script compilation before command output is produced.
  `scripts/acceptance-vulhub-aj-report-java8.sh` provides real Vulhub
  application evidence for request-supplied validation scripts: AJ-Report
  1.4.0 CNVD-2024-15077 baseline evaluates a `validationRules` JavaScript body
  and returns `uid=0(root)`, while protected mode keeps startup quiet and
  blocks `ScriptEngine.eval` before command output is returned.
  `scripts/acceptance-vulhub-druid-java8.sh` provides real Vulhub application
  evidence for Rhino-backed JavaScript parser functions: Druid 0.20.0
  CVE-2021-25646 baseline evaluates the sampler JavaScript and returns
  `uid=0(root)`, while protected mode keeps startup quiet across Druid's child
  Java processes and blocks Rhino `Context.compileFunction` before command
  output is returned.
- The Java 8 era track hooks Java source compilation through
  `JavacTool.getTask` and Janino-style `cook`/`compile(String...)` sources.
  Source containing `Runtime.exec`, `ProcessBuilder.start`, or nested
  `ScriptEngine.eval` primitives logs `java8_java_compile_runtime_execution`;
  ordinary source compilation is ignored.
- The Java 8 era track hooks JAAS `AppConfigurationEntry` construction.
  `JndiLoginModule` entries with remote `user.provider.url` or
  `group.provider.url` values over LDAP/RMI/IIOP/CORBA schemes log
  `java8_jaas_jndi_remote_provider`; Kerberos, SCRAM, and other ordinary JAAS
  login modules are ignored.
- The Java 8 era track hooks `JmxMBeanServer.invoke`. Mutating MBean
  operations that pass remote broker/Spring/XML configuration sources log
  `java8_jmx_remote_config_source`; mutating operations that pass
  server-side script or executable write targets log
  `java8_jmx_script_file_write`; read-only MBean calls and benign log-file
  targets are ignored.
- The Java 8 era track hooks JavaBeans `Statement.execute`,
  `Expression.getValue`, and XMLDecoder `DocumentHandler` exception handling.
  XMLDecoder object graphs that reach `ProcessBuilder.start`, `Runtime.exec`,
  or reflective invocation log `java8_xml_decoder_runtime_execution`;
  XMLDecoder object graphs that construct server-side script writers log
  `java8_xml_decoder_script_file_write`; ordinary JavaBeans statements outside
  an XMLDecoder stack are ignored.
- The Java 8 era track hooks Xerces `XMLEntityManager.setupCurrentEntity`.
  XML external entities that resolve to `file:`, `jar:`, HTTP(S), FTP, LDAP,
  RMI/IIOP/CORBA-style, SMB/UNC, or similar remote-capable protocols log
  `java8_xxe_external_entity_protocol`; ordinary XML without external
  entities is ignored. Exact framework runtime DTD URLs for Jetty, Java
  EE/Servlet/JSP/JSF, Spring, MyBatis mapper/config XML, embedded Tomcat
  modeler and Struts plugin metadata loaded from local fat JARs, standard local
  Struts2/XWork descriptor XML files such as classpath `struts*.xml`, simple
  classpath-root XML includes loaded by XWork `XmlConfigurationProvider`, and
  trusted local Struts/XWork `*-validation.xml` action metadata are treated as
  normal bootstrapping metadata, while arbitrary HTTP(S) DTDs, out-of-stack
  local app XML reads, and untrusted local validation XML paths remain covered.
  `scripts/acceptance-vulhub-solr-xxe-java8.sh` provides real Vulhub
  application evidence: Solr 7.0.1 CVE-2017-12629 baseline uses
  `defType=xmlparser` with the Lucene query-parser JAR DTD indirection to
  disclose `/etc/passwd` in the Solr error response, while protected mode keeps
  startup quiet and blocks Xerces external entity resolution before passwd
  content is disclosed. `scripts/acceptance-vulhub-aj-report-java8.sh`
  verifies the MyBatis mapper DTD startup path stays quiet under the Java 8
  agent.
- The Java 8 era track hooks `javax.servlet.http.HttpServlet.service`,
  `jakarta.servlet.http.HttpServlet.service`, Tomcat
  `AuthenticatorBase.invoke`/`StandardWrapperValve.invoke`, and
  Jersey/Grizzly `ServerRuntime.process(ContainerRequest)` for request
  behavior, and hooks Shiro `AbstractShiroFilter.doFilterInternal` so
  rememberMe cookies can be inspected before Shiro deserializes them.
  Dot-segment, duplicate-slash, semicolon path-parameter, percent, Unicode,
  overlong UTF-8, and lenient-percent variants that normalize onto a sensitive
  control path log or block `java8_request_path_confusion`; ordinary direct
  admin paths are ignored. Default-key encrypted Shiro `rememberMe` cookies
  whose decrypted plaintext starts with Java serialization stream magic log or
  block `java8_request_default_crypto_cookie` while recording only the cookie
  name and key family. `Nacos-Server` or `Nacos-Server/...` user agents on
  sensitive auth, user-management, admin, or ops paths log or block
  `java8_request_internal_identity`, while the same identity on non-control
  service-discovery paths and normal user agents on sensitive paths stay quiet.
  Known weak-HMAC bearer JWTs log or block
  `java8_request_default_jwt_secret` after validating the signature, while the
  token value itself is never stored in the event log. The Java 8 request hook
  also logs or blocks `java8_request_session_file_deserialization` for
  filesystem-shaped `JSESSIONID` values such as hidden-file names, traversal,
  slash, or encoded separator forms, while ordinary route-suffix session ids
  stay quiet. The Java 8 request hook normalizes both Servlet request objects,
  Tomcat connector request objects, and Jersey/Grizzly `ContainerRequest`
  URI/header accessors before classification.
  `scripts/acceptance-vulhub-nacos-29441-java8.sh` provides real Vulhub
  application evidence: Nacos 1.4.0 CVE-2021-29441 baseline lists users and
  creates a user through `/nacos/v1/auth/users` with `User-Agent: Nacos-Server`,
  while protected mode keeps startup quiet and blocks both spoofed requests
  before `create user ok!` is returned.
  `scripts/acceptance-vulhub-shiro-java8.sh` provides real Vulhub application
  evidence: Shiro 1.0.0 CVE-2010-3863 `/./admin` and Shiro 1.5.1
  CVE-2020-1957 `/xxx/..;/admin/` both bypass the baseline containers and are
  blocked by the protected Java 8 agent.
  `scripts/acceptance-vulhub-glassfish-1000028-java8.sh` provides real Vulhub
  application evidence for GlassFish CVE-2017-1000028: the baseline overlong
  UTF-8 `/%c0%ae%c0%ae/` traversal discloses `/etc/passwd`, while protected
  mode keeps startup quiet and blocks the servlet request before the file is
  returned with `java8_request_path_confusion`.
  `scripts/acceptance-vulhub-spring-security-22978-java8.sh` provides real
  Vulhub application evidence for Spring Security RegexRequestMatcher newline
  confusion: 5.6.3 baseline denies `/admin/index` but discloses the admin page
  for `/admin/%0atest` and `/admin/%0dtest`, while protected mode blocks both
  request paths before the admin page is returned.
  `scripts/acceptance-vulhub-shiro-4437-java8.sh` provides real Vulhub
  application evidence for Shiro CVE-2016-4437: the baseline sends a
  default-key `rememberMe` cookie carrying a CommonsBeanutils1 payload and
  creates `/tmp/ohmyrasp-shiro-4437-success`, while protected mode keeps
  startup quiet and blocks the Shiro filter request before marker creation.
- The Java 8 era track now has a Tomcat baseline/protected matrix:
  `playground-java8`, `Dockerfile.java8`, `docker-compose.java8.yml`, and
  `scripts/acceptance-java8.sh` run Java 8 WARs across
  `tomcat:10.0-jdk8-temurin`, `tomcat:9.0-jdk8-temurin`, and
  `tomcat:8.5-jdk8-temurin`. Tomcat 9 is the currently supported Java 8+
  line; Tomcat 10.0 is an EOL but Java 8-compatible Jakarta Servlet line, so
  `playground-java8-jakarta` builds the same Java 8 probes against
  `jakarta.servlet`; Tomcat 8.5 remains relevant for the Vulhub-era image
  group. The matrix verifies the Java 8 request hook startup marker on every
  Tomcat line, then baseline access and protected blocking for the 21
  pre-request-hook Java 8 behavior algorithms: command execution, remote JNDI,
  gadget deserialization, sensitive file read, server-side script write, SSRF
  metadata and loopback-admin URL access, archive traversal writes,
  H2/Derby/MySQL JDBC code-loading or deserialization URLs, remote classloader
  codebases, script-engine runtime execution, Java compilation runtime
  execution, JAAS remote provider configuration, JMX remote configuration and
  script-write operations, XMLDecoder runtime and script-writer object graphs,
  and XXE external entity protocols. Normal traffic stays quiet. This is
  runtime-era injection evidence, with Shiro providing real Java 8 Vulhub
  request-path acceptance and Solr CVE-2017-12629 providing real runtime XXE
  sink acceptance.
- The dedicated `agent-java11` module is a separate Java 11 era startup-probe
  track for Vulhub images that cannot run the Java 25 production agent but are
  newer than the Java 8/Tomcat 8 group. `playground-java11` covers the
  `javax.servlet` Tomcat 9 line, `playground-java11-jakarta` covers the
  `jakarta.servlet` Tomcat 10.1 line, and `scripts/acceptance-java11.sh` runs
  both `tomcat:10.1-jdk11-temurin` and `tomcat:9.0-jdk11-temurin`
  baseline/protected pairs. This follows Apache Tomcat's supported Java
  version matrix: Tomcat 10.1 requires Java 11+, Tomcat 9 requires Java 8+,
  and Tomcat 11 is deferred to Java 17+ tracks.
- The Java 11 era track hooks process execution:
  `ProcessBuilder.start` and `Runtime.exec` are transformed by the dedicated
  Java 11 agent. Exploit-grade process primitives log or block
  `java11_command_execution_exploit_primitive`; shell `-c` invocations
  containing command metacharacters log or block
  `java11_command_execution_shell_meta`; normal `/bin/true` smoke and Tomcat
  traffic stay quiet. Dynamic expression-language stacks such as MVEL, OGNL,
  Groovy, Apache Commons JEXL, Spring SpEL, and Spring WebFlow are attributed to
  the exploit-primitive command family for parity with the Java 8 Unomi
  evidence. Database Java routine stacks such as Derby, H2, and HSQLDB are also
  attributed to the exploit-primitive command family for parity with the Java 8
  Nacos evidence. Spring `ApplicationContext` refresh and
  `AbstractAutowireCapableBeanFactory` bean-initialization stacks are attributed
  to the same family when they reach a process sink, covering remote Spring
  XML/XBean configuration chains without inspecting payload strings. XStream
  XML unmarshalling and Struts2 REST XStream handler stacks are attributed to
  the same family when they reach a process sink, matching the Java 8 S2-052
  evidence. JAI-EXT/Jiffle runtime stacks are attributed to the same command
  family for parity with the Java 17 GeoServer CVE-2022-24816 evidence.
  Scheduler script execution stacks such as XXL-JOB `ScriptJobHandler` map
  shell interpreters running generated script files to
  `java11_command_execution_shell_meta`, while ordinary shell script execution
  outside scheduler stacks remains quiet. Exact OS/system inventory probes such
  as `getconf CLK_TCK`, `getconf PAGE_SIZE`, `getconf PAGESIZE`,
  `lscpu -p=cpu,node`, `vcgencmd measure_temp`, `dmidecode -t 4`, and
  `cpuid -1r` stay quiet even from Spring bean-initialization stacks, matching
  GeoServer OSHI startup behavior.
  HugeGraph 1.2.0 provides real Vulhub
  application evidence for `java11_command_execution_exploit_primitive`; the
  ActiveMQ CVE-2023-46604 acceptance also verifies the Spring XML bean-init
  path blocks the OpenWire-triggered `ProcessBuilder.start` before the marker
  file is created. The Java 11 track still needs more application acceptance
  before claiming complete Java 11 vulnerability coverage.
- The Java 11 era track also hooks `InitialContext.lookup` and `lookupLink`.
  Remote LDAP/RMI/IIOP/CORBA naming URLs log or block
  `java11_jndi_remote_lookup`; local `java:comp/env` lookups are ignored. The
  Java 11 Tomcat matrix baseline-tests the remote lookup endpoint and
  protected-block-tests it under the dedicated Java 11 agent.
- The Java 11 era track now hooks `ObjectInputStream.resolveClass` and
  `resolveProxyClass`, including RMI `MarshalInputStream`, Spring HTTP Invoker
  `ConfigurableObjectInputStream` and `CodebaseAwareObjectInputStream`
  subclasses. High-risk gadget or execution primitive classes such as
  `JdbcRowSetImpl`, `TemplatesImpl`, commons-collections transformer gadgets,
  BeanShell interpreter/proxy gadgets, Groovy closure gadgets, Spring factory
  gadgets, and `ProcessBuilder` log or block
  `java11_deserialization_gadget_class`; ordinary string deserialization is
  ignored. The Java 11 Tomcat matrix baseline-tests a crafted high-risk class
  descriptor and protected-block-tests it under the dedicated Java 11
  agent.
- The Java 11 era track also hooks Hessian
  `SerializerFactory.getDeserializer` type resolution and emits
  `java11_deserialization_hessian_type` for dangerous Hessian wire types such
  as `org.apache.commons.beanutils.BeanComparator`, while ordinary
  DTO/container types stay quiet.
- The Java 11 era track hooks `FileInputStream`, `FileOutputStream`,
  `RandomAccessFile`, `File.renameTo`, and `java.nio.file.Files` content
  read/write, byte-channel open, path-to-path copy, and path-to-path move APIs.
  Sensitive reads such as `/etc/passwd`,
  `/proc/self/environ`, SSH private keys, and Windows hosts files log or block
  `java11_file_sensitive_read`; script or executable writes log or block
  `java11_file_script_write` only when the target path is webroot-like or uses
  traversal. Ordinary temporary file access and Tomcat `WEB-INF` deployment
  artifacts are ignored, and the Java 11 Tomcat matrix baseline-tests and
  protected-block-tests both file behaviors. Metabase 0.40.4 provides real
  Vulhub application evidence for `java11_file_sensitive_read`: the baseline
  CVE-2021-41277 GeoJSON `file:////etc/passwd` URL discloses passwd content,
  while protected mode blocks the sink at `FileInputStream.open`. ColdFusion
  2018.0.15 provides another real Vulhub sink proof in
  `scripts/acceptance-vulhub-coldfusion-26360-java11.sh`: baseline
  CVE-2023-26360 metadata `classname` traversal returns the `cfuser`
  `/proc/self/environ` contents, while protected mode blocks the same local
  file load at `FileInputStream.open`. Generated plot script content writes use
  the same path-scoped inspection as Java 8 and emit
  `java11_file_generated_plot_script_command`.
- The Java 11 era track now hooks `ZipEntry.getName` and SevenZipBinding
  `SimpleInArchiveItemImpl.getPath`, then correlates dangerous archive entry
  names with the next Java file-write sink on the same thread. Absolute paths,
  Windows absolute paths, and `../` traversal entries log or block
  `java11_archive_entry_traversal_write`; safe archive entries and ordinary
  temporary extraction writes stay quiet. The Java 11 Tomcat 10.1 and Tomcat 9
  matrix verifies the behavior in both baseline and protected containers.
- The Java 11 era track hooks `URL.openConnection` and `openStream`. Cloud
  metadata targets such as `169.254.169.254`, `169.254.170.2`,
  `100.100.100.200`, `metadata.google.internal`, and `fd00:ec2::254` log or
  block `java11_ssrf_cloud_metadata`; loopback administrative paths such as
  `/actuator`, `/jolokia`, `/manager`, `/console`, and `/solr/admin` log or
  block `java11_ssrf_loopback_admin`; and active-request parameters named like
  `url`, `uri`, `href`, `endpoint`, `target`, `callback`, or `webhook` that
  are copied into same-thread outbound HTTP(S) URL sinks log or block
  `java11_ssrf_request_parameter_url`. Normal public HTTP(S) URLs that are not
  request-controlled are ignored,
  and DataEase APISIX route self-checks to
  `127.0.0.1:9180/apisix/admin/...` stay quiet only from the DataEase
  `XpackRouteManage` Spring ready-event startup stack. The same URL outside
  that stack still blocks as loopback admin SSRF, and the Java 11 Tomcat
  10.1/Tomcat 9 matrix verifies both SSRF behaviors.
- The Java 11 era track hooks `URLClassLoader` constructors and `addURL`, plus
  `RMIClassLoader` codebase APIs. Remote HTTP(S), FTP, LDAP, and RMI
  codebases, including `jar:` URLs that wrap remote schemes, log or block
  `java11_classloader_remote_codebase`; local `file:` classpath URLs are
  ignored, as are Felix/OSGi internal `felix.extensions` extension-bundle
  codebases. The Java 11 Tomcat 10.1/Tomcat 9 matrix verifies URLClassLoader and
  RMIClassLoader remote codebase behavior.
- The Java 11 era track hooks `DriverManager.getConnection` and direct H2
  `org.h2.jdbc.JdbcConnection` constructors. H2 `INIT` URLs carrying
  `RUNSCRIPT`, alias, trigger, runtime, JNDI, or classloader primitives log or
  block `java11_jdbc_h2_code_execution`; Derby SQLJ or Java classpath loading
  URLs log or block `java11_jdbc_derby_code_loading`; MySQL URLs that combine
  `autoDeserialize` with interceptor or custom-collation triggers log or block
  `java11_jdbc_mysql_deserialization`. Ordinary JDBC URLs are ignored, and the
  Java 11 Tomcat 10.1/Tomcat 9 matrix verifies all three JDBC behaviors. The
  Java 11 track also carries the SkyWalking 8.3.0
  `H2LogQueryDAO.queryLogs(String, ...)` SQL identifier hook for the GraphQL
  `metricName` argument, logging or blocking `java11_sql_identifier_injection`
  for the same control-syntax shapes while ignoring ordinary metric names.
- The Java 11 era track also ports the Java 8 era runtime primitive sinks:
  `ScriptEngine.eval(String...)`, `JavacTool.getTask`, Janino-style
  `cook`/`compile(String...)`, `AppConfigurationEntry`, `JmxMBeanServer.invoke`,
  JavaBeans `Statement`/`Expression` under XMLDecoder stacks, XMLDecoder
  `DocumentHandler` exception rethrow, and Xerces `XMLEntityManager`.
  The script hook also covers Rhino/Mozilla `Context.evaluateString`,
  `Context.compileString`, and `Context.compileFunction`, keeping the Java 11
  LTS behavior aligned with the Java 8 Druid evidence.
  Suspicious script strings log or block `java11_script_engine_runtime_execution`;
  dynamic Java sources with process/script primitives log or block
  `java11_java_compile_runtime_execution`; JAAS `JndiLoginModule` remote provider
  URLs log or block `java11_jaas_jndi_remote_provider`; mutating JMX operations
  with remote broker/Spring/XML config sources or script-write targets log or
  block `java11_jmx_remote_config_source` and `java11_jmx_script_file_write`;
  XMLDecoder object graphs that reach process execution or server-side script
  writers log or block `java11_xml_decoder_runtime_execution` and
  `java11_xml_decoder_script_file_write`; external XML entities using file,
  jar, HTTP(S), FTP, LDAP/RMI/IIOP/CORBA-style, or similar protocols log or
  block `java11_xxe_external_entity_protocol`. Metabase 0.46.6 provides real
  Vulhub application evidence for the Java 11 script sink: CVE-2023-38646
  baseline executes an H2 `init` trigger submitted through
  `/api/setup/validate`, while protected mode blocks the trigger body at
  `ScriptEngine.eval` with `java11_script_engine_runtime_execution`.
- The Java 11 era track hooks `javax.servlet.http.HttpServlet.service`,
  `jakarta.servlet.http.HttpServlet.service`, Tomcat
  `AuthenticatorBase.invoke`/`StandardWrapperValve.invoke`, and Jersey/Grizzly
  `org.glassfish.jersey.server.ServerRuntime.process(ContainerRequest)` for
  the same generic request behavior as the Java 8 and Java 17 tracks.
  Dot-segment, semicolon path-parameter, duplicate-slash, percent, Unicode,
  overlong UTF-8, and lenient-percent variants that normalize onto a sensitive
  control path log or block `java11_request_path_confusion`, while ordinary
  direct admin paths are ignored. Internal-service `Nacos-Server` user agents
  on sensitive control paths log or block `java11_request_internal_identity`,
  with non-control paths and normal user agents left quiet. Known weak-HMAC
  bearer JWTs log or block `java11_request_default_jwt_secret` after validating
  the signature and recording only the weak-key identifier. Filesystem-shaped
  `JSESSIONID` values log or block
  `java11_request_session_file_deserialization` before Tomcat-backed session
  file loading. HugeGraph 1.3.0 CVE-2024-43441 provides real Vulhub
  Jersey/Grizzly evidence: baseline
  accepts the README default-secret JWT for `/graphs`, while protected mode
  blocks the request before graph metadata is returned.
  `scripts/acceptance-java11.sh` now verifies the `request_hook:"installed"`
  startup marker across Tomcat 10.1/JDK11 and Tomcat 9/JDK11 before running the
  existing protected behavior matrix.
- `scripts/acceptance-vulhub-activemq-java11.sh` is the first real Java 11
  Vulhub application acceptance. It runs `vulhub/activemq:5.17.3` twice:
  baseline authenticates to Jolokia, verifies the CVE-2022-41678 Log4j2
  `setConfigText` configuration rewrite writes and executes `/admin/shell.jsp`,
  then verifies the JFR `copyTo` webroot write path can reach
  `jdk.management.jfr:type=FlightRecorder.copyTo`; protected mode injects
  `agent-java11`, keeps startup quiet, blocks the Log4j2 webroot write before
  `shell.jsp` appears, and blocks the same JFR `copyTo` operation with
  `java11_jmx_script_file_write`.
- `scripts/acceptance-vulhub-spring-java11.sh` runs the first real Java 11
  Spring WebMVC Vulhub application acceptance. It starts
  `vulhub/spring-webmvc:5.3.17` baseline/protected pairs for CVE-2022-22965.
  Baseline uses Spring data binding to reconfigure Tomcat AccessLogValve,
  writes `webapps/ROOT/tomcatwar.jsp`, and verifies the JSP executes `id`;
  protected mode injects `agent-java11`, keeps normal Tomcat WAR expansion and
  Jasper JSP compilation quiet, and blocks the AccessLogValve JSP write with
  `java11_file_script_write`.
- `scripts/acceptance-vulhub-hertzbeat-java11.sh` runs the first real
  HertzBeat Java 11 Vulhub application acceptance. It starts
  `vulhub/hertzbeat:1.4.4` baseline/protected pairs for CVE-2024-42323.
  Baseline authenticates as `admin/hertzbeat`, uploads a SnakeYAML document
  that directly constructs `org.h2.jdbc.JdbcConnection`, and verifies the H2
  `INIT` payload creates `/tmp/ohmyrasp-hertzbeat-success`; protected mode
  injects `agent-java11`, keeps Netty `/etc/hosts` resolver startup quiet, and
  blocks the direct H2 constructor URL with
  `java11_jdbc_h2_code_execution`.
- `scripts/acceptance-vulhub-hugegraph-java11.sh` runs the first real
  HugeGraph Java 11 Vulhub application acceptance. It starts
  `vulhub/hugegraph:1.2.0` baseline/protected pairs for CVE-2024-27348.
  Baseline submits an unauthenticated Gremlin/Groovy payload that reflects
  into `ProcessBuilder.start` and writes `/tmp/ohmyrasp-hugegraph-success`;
  protected mode injects `agent-java11`, waits for the Gremlin backend to be
  ready, and blocks the same payload with
  `java11_command_execution_exploit_primitive`.
- `scripts/acceptance-vulhub-hugegraph-43441-java11.sh` runs the real
  HugeGraph 1.3.0 CVE-2024-43441 default-JWT acceptance. Baseline proves
  unauthenticated `/graphs` is rejected but the README HS256 default-secret JWT
  returns `{"graphs":["hugegraph"]}`; protected mode injects `agent-java11`
  through HugeGraph `JAVA_OPTIONS`, keeps readiness quiet, and blocks the
  Jersey/Grizzly request with `java11_request_default_jwt_secret` before graph
  metadata is disclosed.
- `scripts/acceptance-vulhub-metabase-41277-java11.sh` runs the first real
  Metabase Java 11 Vulhub application acceptance. It starts
  `vulhub/metabase:0.40.4` baseline/protected pairs for CVE-2021-41277.
  Baseline fetches `/api/geojson?url=file:////etc/passwd` and receives passwd
  content; protected mode injects `agent-java11`, keeps startup quiet, and
  blocks the same local file load with `java11_file_sensitive_read`.
- `scripts/acceptance-vulhub-metabase-38646-java11.sh` runs the first real
  Metabase setup-validation Java 11 Vulhub application acceptance. It starts
  `vulhub/metabase:0.46.6` baseline/protected pairs for CVE-2023-38646,
  retrieves the real setup token from `/api/session/properties`, and submits
  the H2 `init` trigger to `/api/setup/validate`. Baseline creates
  `/tmp/ohmyrasp-metabase38646-success`; protected mode injects
  `agent-java11`, keeps startup and token retrieval quiet, and blocks the H2
  trigger JavaScript with `java11_script_engine_runtime_execution`.
- The dedicated `agent-java17` module is a separate Java 17 LTS track for
  Vulhub images and Tomcat lines that require Java 17 or later. `playground-java17`
  covers the `javax.servlet` Tomcat 9 line, `playground-java17-jakarta` covers
  the `jakarta.servlet` Tomcat 10.1 and 11 lines, and
  `scripts/acceptance-java17.sh` runs `tomcat:11.0-jdk17-temurin`,
  `tomcat:10.1-jdk17-temurin`, and `tomcat:9.0-jdk17-temurin`
  baseline/protected pairs in that order.
- The Java 17 era track currently ports and extends the Java 11 low-level
  behavior hooks: process execution, remote JNDI lookup, deserialization class
  resolution including RMI `MarshalInputStream`, Spring HTTP Invoker
  object-stream subclasses, BeanShell gadget classes, file read/write sinks
  including `File.renameTo` and `java.nio.file.Files`
  content, byte-channel, path-to-path copy, and path-to-path move APIs,
  archive entry traversal writes, URL open sinks,
  remote classloader codebases, JDBC URL code-loading primitives,
  script-engine evaluation, dynamic Java compilation, JAAS remote providers,
  JMX remote config/script-write operations, XMLDecoder object graphs, XXE
  external entities, and servlet request path-confusion checks. It
  logs or blocks
  `java17_command_execution_exploit_primitive`,
  `java17_command_execution_shell_meta`, `java17_jndi_remote_lookup`,
  `java17_deserialization_gadget_class`, `java17_file_sensitive_read`, and
  `java17_deserialization_hessian_type` for dangerous Hessian
  `SerializerFactory.getDeserializer` wire types, and
  `java17_file_script_write`, `java17_file_generated_plot_script_command` for
  generated plot script command directives,
  `java17_archive_entry_traversal_write` for ZipEntry and SevenZipBinding
  ZipSlip-style entry extraction, plus
  `java17_ssrf_cloud_metadata` for cloud metadata hosts and
  `java17_ssrf_loopback_admin` for loopback administrative paths, and
  `java17_ssrf_request_parameter_url` for active-request parameters copied into
  same-thread outbound HTTP(S) URL sinks. DataEase APISIX route self-checks to
  `127.0.0.1:9180/apisix/admin/...` stay quiet only from the DataEase
  `XpackRouteManage` Spring ready-event startup stack; the same URL outside
  that stack still blocks as loopback admin SSRF. It also logs or blocks
  `java17_classloader_remote_codebase` for URLClassLoader or
  RMIClassLoader remote codebases. Process sinks reached from MVEL, OGNL,
  Groovy, Apache Commons JEXL, Spring SpEL, Spring WebFlow, or database Java
  routine stacks are also attributed to the exploit-primitive command family
  for parity with the Java 8 Unomi and Nacos evidence. Process sinks reached
  during Spring `ApplicationContext` refresh and
  `AbstractAutowireCapableBeanFactory` bean initialization are treated the same
  way, matching the Java 11 ActiveMQ CVE-2023-46604 evidence. Process sinks
  reached from XStream XML unmarshalling and Struts2 REST XStream handler
  stacks are also treated as exploit primitives, matching the Java 8 S2-052
  evidence. Process sinks reached from JAI-EXT/Jiffle runtime stacks are also
  treated as exploit primitives, matching the real GeoServer CVE-2022-24816
  Vulhub acceptance. Exact OS/system inventory probes such as `getconf CLK_TCK`,
  `getconf PAGE_SIZE`, `getconf PAGESIZE`, `lscpu -p=cpu,node`,
  `vcgencmd measure_temp`, `dmidecode -t 4`, and `cpuid -1r` stay quiet even
  from Spring bean-initialization stacks, matching GeoServer OSHI startup
  behavior. Scheduler script
  execution stacks such as XXL-JOB `ScriptJobHandler` also map generated shell
  script files to `java17_command_execution_shell_meta`. It also logs or blocks
  `java17_jdbc_h2_code_execution`, `java17_jdbc_derby_code_loading`, and
  `java17_jdbc_mysql_deserialization` for H2/Derby/MySQL JDBC URL primitives,
  including direct H2 `org.h2.jdbc.JdbcConnection` constructors,
  plus `java17_script_engine_runtime_execution`,
  `java17_java_compile_runtime_execution`, `java17_jaas_jndi_remote_provider`,
  `java17_jmx_remote_config_source`, `java17_jmx_script_file_write`,
  `java17_xml_decoder_runtime_execution`,
  `java17_xml_decoder_script_file_write`, and
  `java17_xxe_external_entity_protocol` for the corresponding runtime-era
  primitive sinks. The Java 17 script hook also includes Rhino/Mozilla
  `Context.evaluateString`, `Context.compileString`, and
  `Context.compileFunction` for parity with the Java 8 Druid evidence, plus
  the SkyWalking 8.3.0 `H2LogQueryDAO.queryLogs(String, ...)` SQL identifier
  hook for GraphQL `metricName`, which logs or blocks
  `java17_sql_identifier_injection` for SQL control syntax and ignores
  ordinary metric names. The Java 17 request hook also covers
  `java17_request_path_confusion` for Openfire/Jetty-style
  `%u002e`, lenient `%2>`, overlong UTF-8, low-byte Unicode, duplicate-slash,
  and dot-segment request path confusion, `java17_request_internal_identity`
  for internal-service `Nacos-Server` user agents on sensitive control paths,
  `java17_request_default_jwt_secret` for validated weak-HMAC bearer JWTs, and
  `java17_request_jwt_verification_failure` for auth0 `java-jwt`
  verification failures correlated with active API/control requests.
  The Java 17 request hook also recognizes Tomcat
  `AuthenticatorBase.invoke`/`StandardWrapperValve.invoke` and Jersey/Grizzly
  `ServerRuntime.process(ContainerRequest)` request objects in addition to
  `javax.servlet` and `jakarta.servlet` service calls. Filesystem-shaped
  `JSESSIONID` values log or block
  `java17_request_session_file_deserialization` before Tomcat-backed session
  file loading.
  Normal process, local JNDI, ordinary
  deserialization,
  temporary file access, safe archive entries, local `file:` classpath URLs,
  ordinary JDBC URLs, safe script/compile/JAAS/JMX/XML traffic, Tomcat
  deployment artifacts, and ordinary public URLs that are not
  request-controlled stay quiet.
- `scripts/acceptance-vulhub-activemq-java17.sh` is the first real Java 17
  Vulhub application acceptance. It runs `vulhub/activemq:6.1.1` twice and
  verifies unauthenticated Jolokia access plus an
  `addNetworkConnector(java.lang.String)` Broker MBean invocation for
  CVE-2024-32114 plus CVE-2026-34197. It also runs
  `vulhub/activemq:6.2.2` baseline/protected pairs, verifies unauthenticated
  Jolokia returns 401, then authenticates with `admin:admin` for the
  CVE-2026-34197 MBean invocation. Protected mode injects `agent-java17`,
  verifies startup stays quiet for ActiveMQ's local JSP tag-library runtime
  DTDs, and blocks the same JMX remote configuration request with
  `java17_jmx_remote_config_source` on both ActiveMQ versions.
- `scripts/acceptance-vulhub-geoserver-java17.sh` runs the first real Java 17
  GeoServer Vulhub application acceptance. It starts `vulhub/geoserver:2.23.2`
  baseline/protected pairs for CVE-2024-36401 WFS `valueReference` expression
  execution. Baseline reaches `Runtime.exec` and returns the expected
  `ProcessImpl` type error; protected mode injects `agent-java17`, keeps
  Jetty/Servlet/Spring runtime DTD startup quiet, and blocks the same request
  with `java17_command_execution_exploit_primitive`.
- `scripts/acceptance-vulhub-geoserver-40822-java17.sh` runs real Java 17
  GeoServer Vulhub application acceptance for CVE-2021-40822. It starts
  `vulhub/geoserver:2.19.1` baseline/protected pairs, verifies the baseline
  `/geoserver/TestWfsPost` form post relays a request-parameter-controlled
  `url` to an isolated listener, keeps protected startup quiet for OSHI system
  inventory probes, and blocks the same outbound URL sink with
  `java17_ssrf_request_parameter_url` before the listener receives the relay.
- `scripts/acceptance-vulhub-geoserver-25157-java17.sh` runs real Java 17
  GeoServer Vulhub application acceptance for CVE-2023-25157/CVE-2023-25158.
  It starts `vulhub/geoserver:2.22.1` with
  `postgis/postgis:14-3.3-alpine` baseline/protected pairs, verifies the
  baseline WFS `GetFeature` `CQL_FILTER` payload reaches PostGIS and returns
  PostgreSQL cast-error evidence, keeps protected startup and normal CQL
  traffic quiet, and blocks the same CQL SQL injection request with
  `java17_request_ogc_filter_sql_injection` before SQL reaches PostGIS.
- `scripts/acceptance-vulhub-dataease-32966-java21.sh` runs real DataEase
  Vulhub application acceptance on the image's OpenJDK 21 runtime. It starts
  `vulhub/dataease:2.10.7` plus `mysql:8.4` baseline/protected pairs for
  CVE-2025-32966, verifies the baseline forged-token
  `/de2api/datasource/validate` H2 JDBC payload creates
  `/tmp/ohmyrasp-dataease-32966`, keeps protected startup quiet for the local
  APISIX admin route self-check, and blocks the direct H2 constructor URL with
  `java17_jdbc_h2_code_execution` before the marker is created.
- `scripts/acceptance-vulhub-dataease-56511-java21.sh` runs real DataEase
  Vulhub application acceptance on the image's OpenJDK 21 runtime. It starts
  `vulhub/dataease:2.10.3` plus `mysql:8.4` baseline/protected pairs for
  CVE-2024-56511, verifies the baseline direct
  `/dataease/de2api/datasource/types` request is rejected while
  `--path-as-is /geo/../dataease/de2api/datasource/types` returns the
  datasource type list, keeps protected startup and the direct request quiet,
  and blocks the traversal-shaped request with
  `java17_request_path_confusion`.
- `scripts/acceptance-vulhub-dataease-49001-java21.sh` runs real DataEase
  Vulhub application acceptance on the image's OpenJDK 21 runtime. It starts
  `vulhub/dataease:2.10.7` plus `mysql:8.4` baseline/protected pairs for
  CVE-2025-49001, verifies the baseline no-token `/de2api/user/info` request
  returns a clean `401` while a valid-format arbitrary-secret admin JWT reaches
  the continuation path and returns `400` with the signature failure in
  `DE-GATEWAY-FLAG`, keeps protected startup and the no-token rejection quiet,
  and blocks the auth0 `java-jwt` verification failure with
  `java17_request_jwt_verification_failure` without logging the token value.
- `scripts/acceptance-vulhub-struts2-upload-java17.sh` runs the first real
  Struts2 Java 17 Vulhub application acceptance. It starts
  `vulhub/struts2:s2-066` and `vulhub/struts2:s2-067` baseline/protected
  pairs for S2-066/CVE-2023-50164 and S2-067/CVE-2024-53677. Baseline uses
  `fileFileName=../shell.jsp` and `top.fileFileName=../shell.jsp` multipart
  fields to write `/usr/local/tomcat/webapps/ROOT/shell.jsp` and verifies the
  JSP executes; protected mode injects `agent-java17`, keeps Tomcat WAR
  deployment quiet, and blocks both writes with `java17_file_script_write`.
- `scripts/acceptance-vulhub-jimureport-java17.sh` runs the first real
  JimuReport Java 17 Vulhub application acceptance. It starts
  `vulhub/jimureport:1.6.0` plus MySQL baseline/protected pairs for
  CVE-2023-4450. Baseline submits the vulnerable FreeMarker SSTI SQL body and
  verifies `cat /etc/passwd` output is returned; protected mode injects
  `agent-java17`, keeps startup quiet, and blocks the FreeMarker `Execute`
  process sink with `java17_command_execution_exploit_primitive`.
- `scripts/acceptance-vulhub-spring-boot-jetty-java17.sh` runs the first real
  Spring Boot Jetty Java 17 Vulhub application acceptance. It starts
  `vulhub/spring-boot-jetty:3.2.4` baseline/protected pairs for
  CVE-2025-41242. Baseline sends the raw ghost-bits path traversal request and
  verifies `/etc/passwd` is returned; protected mode injects `agent-java17`,
  keeps startup quiet, and blocks the request path confusion before the file
  read with `java17_request_path_confusion`.
- `scripts/acceptance-vulhub-jenkins-23897-java17.sh` provides real Java 17
  Vulhub application evidence for sensitive file reads. It starts
  `vulhub/jenkins:2.441`, downloads `jnlpJars/jenkins-cli.jar`, and verifies
  the CVE-2024-23897 CLI `connect-node "@/etc/passwd"` baseline discloses
  passwd content through server-side args4j `@file` expansion. Protected mode
  injects `agent-java17`, keeps startup quiet, and blocks
  `FileInputStream.open` with `java17_file_sensitive_read`.
- `scripts/acceptance-vulhub-openfire-java17.sh` runs the first real Openfire
  Java 17 Vulhub application acceptance. It starts `vulhub/openfire:4.7.4`
  baseline/protected pairs for CVE-2023-32315. Baseline sends the
  `%u002e%u002e` setup traversal and verifies the new administrator is
  persisted in `OFUSER` and `admin.authorizedJIDs`; protected mode injects
  `agent-java17`, keeps startup quiet, and blocks both `%u002e%u002e` and
  lenient `%2>` traversal variants with `java17_request_path_confusion`.
- `scripts/acceptance-vulhub-teamcity-27198-java17.sh` provides real Java 17
  Vulhub application evidence for TeamCity CVE-2024-27198. It verifies
  `vulhub/teamcity:2023.11.3` runs on Java 17 LTS, confirms baseline
  `GET /hax?jsp=/app/rest/users;.jsp` exposes unauthenticated users XML, and
  confirms baseline `POST` to the same forwarded REST endpoint creates a
  `SYSTEM_ADMIN` user. Protected mode injects `agent-java17`, keeps startup
  quiet after TeamCity metadata-verifier and bundled-plugin unpack
  false-positive refinements, and blocks both GET and POST with
  `java17_request_internal_forward`.
- `scripts/acceptance-vulhub-teamcity-42793-java17.sh` provides real Java 17
  Vulhub application evidence for TeamCity CVE-2023-42793. It verifies
  `vulhub/teamcity:2023.05.3` runs on Java 17 LTS, confirms baseline creates
  the `/RPC2` bearer token, enables `rest.debug.processes.enable=true`, and
  executes `id` through `/app/rest/debug/processes?exePath=id`. Protected mode
  injects `agent-java17`, keeps startup and ordinary login traffic quiet after
  TeamCity metadata-verifier and install-links false-positive refinements, and
  blocks the debug process-launch request with
  `java17_request_debug_process_launch` without logging the bearer token or raw
  command value.

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
- `request_template_loader_enable`
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
- The Java 8/11/17 era fat agent jars relocate their bundled ASM dependency
  under `io.ohmyrasp.agent.shaded.asm` before appending themselves to the
  bootstrap search path. This keeps bootstrap-visible hook classes available
  without shadowing application-provided ASM versions; the Struts2 S2-057
  Vulhub acceptance covers a real Struts convention plugin startup path that
  carries ASM 3.3 in `WEB-INF/lib`.
- `request_path_confusion` covers request URIs whose raw, decoded, double
  decoded, low-byte Unicode-decoded, overlong UTF-8-decoded, or lenient
  percent-decoded path forms introduce parent-directory segments, control
  characters on sensitive paths, or canonicalization-only changes such as `.`
  segments and duplicate slashes that collapse onto a sensitive control path.
  This targets routing/authentication bypass classes such as Shiro
  CVE-2020-1957 `..;`, Shiro CVE-2010-3863 `/./admin` and `//admin`
  canonicalization bypasses, Nexus CVE-2024-4956 repeated encoded-slash
  traversal to `/etc/passwd`, Spring MVC CVE-2018-1271-style path
  normalization where empty encoded segments collapse into a traversal,
  whitelist-prefix traversal, encoded traversal, GlassFish overlong UTF-8
  traversal such as `%c0%ae` to `.`, Openfire CVE-2008-6508 setup traversal
  using `../` segments, Openfire CVE-2023-32315 setup traversal using
  `%u002e%u002e` segments, Openfire/Jetty lenient hex decoding such as `%2>`
  to `.`, Spring Security RegexRequestMatcher newline confusion on
  sensitive control paths, Spring/Jetty CVE-2025-41242 ghost-bits traversal
  where high-bit Unicode characters low-byte-collapse into `.%u002e`,
  DataEase CVE-2024-56511 whitelist-prefix traversal such as
  `/geo/../dataease/de2api/datasource/types` (real OpenJDK 21 runtime
  acceptance: `scripts/acceptance-vulhub-dataease-56511-java21.sh` blocks
  `java17_request_path_confusion`),
  Flink CVE-2020-17519 double-encoded
  `/jobmanager/logs/..%252f...%252fetc%252fpasswd` traversal shape
  (the real Vulhub Netty runtime is enforced by the lower-level Java file-read
  sink because it is not a Servlet request path), Elasticsearch CVE-2015-3337
  plugin traversal such as
  `/_plugin/head/../../etc/passwd`, Elasticsearch CVE-2015-5531 snapshot
  traversal such as `/_snapshot/test/backdata%2f..%2fetc%2fpasswd`,
  and Jetty/Spring
  path decoding inconsistencies without depending on product-specific endpoint
  names. The acceptance suite includes Vulhub-shaped Spring Security
  CVE-2022-22978 RegexRequestMatcher bypass requests for both `%0a` and `%0d`
  control-character forms, Spring CVE-2025-41242 raw ghost-bits traversal
  using `阮严灵丰丰甲来` path segments, plus Openfire CVE-2008-6508 and
  CVE-2023-32315 setup traversal requests for `../`, `%u002e%u002e`, and `%2>`
  bypass forms. The Java 8 era track adds real Shiro application acceptance for
  `/./admin` and `/xxx/..;/admin/` plus real Spring Security 5.6.3 acceptance
  for the same CVE-2022-22978 `%0a` and `%0d` RegexRequestMatcher bypasses.
  CVE-2010-3863 `/./admin` and CVE-2020-1957 `/xxx/..;/admin/` through
  `scripts/acceptance-vulhub-shiro-java8.sh`. The Java 8 track also proves the
  real Vulhub GlassFish CVE-2017-1000028 overlong UTF-8 traversal in
  `scripts/acceptance-vulhub-glassfish-1000028-java8.sh`: baseline discloses
  `/etc/passwd`, while protected mode blocks `java8_request_path_confusion`
  before the file is returned. Real WebLogic evidence is provided by
  `scripts/acceptance-vulhub-weblogic-14883-java8.sh`: baseline
  WebLogic 12.2.1.3 accepts the
  `/console/css/%252e%252e%252fconsole.portal` auth-bypass path with a
  `ShellSession` handle and creates
  `/tmp/ohmyrasp-weblogic-14883-success`, while protected mode blocks the
  encoded console path before the MVEL ShellSession command executes.
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
  tracked as CVE-2020-1938/CNVD-2020-10487,
  while suppressing normal `RequestDispatcher.include` stacks used by
  legitimate application rendering. The playground and acceptance suite include
  the Vulhub-shaped Tomcat CVE-2020-1938 AJP request to `/asdf` with
  `javax.servlet.include.path_info=WEB-INF/web.xml`. Real Java 8 Vulhub
  evidence is provided by
  `scripts/acceptance-vulhub-tomcat-1938-java8.sh`: baseline Tomcat 9.0.30 on
  OpenJDK 8u242 discloses `WEB-INF/web.xml` through AJP, while protected mode
  blocks `java8_request_forged_include_attribute` before the file is returned.
- `request_internal_identity` covers requests that present an internal service
  identity header or user agent on sensitive auth, user-management, admin, or
  ops paths. This targets Nacos-style `User-Agent: Nacos-Server` authentication
  bypasses, including Vulhub Nacos CVE-2021-29441 list-user and create-user
  requests to `/nacos/v1/auth/users`, while allowing the same internal identity
  on non-control service discovery paths. The dedicated Java 8/11/17 servlet
  request hooks emit the era-specific
  `java8_request_internal_identity`, `java11_request_internal_identity`, and
  `java17_request_internal_identity` families; the real Java 8 Vulhub
  acceptance `scripts/acceptance-vulhub-nacos-29441-java8.sh` proves the
  baseline list/create requests succeed and protected mode blocks both before
  user creation completes.
- `request_java_bean_pollution` covers Java bean/data-binding parameter names
  that traverse into `class`, `module`, or `classLoader` metadata and then reach
  dangerous mutable runtime targets such as Tomcat AccessLogValve
  `resources.context.parent.pipeline.first.*` fields. This targets Vulhub
  Spring Framework CVE-2022-22965 `GET /` Spring4Shell requests that write a JSP
  through Tomcat logging, while ignoring ordinary `className`, `module`, or
  `classLoaderName` fields and redacting matched binder values from logs.
- `request_default_jwt_secret` verifies HMAC bearer JWT signatures against
  known hardcoded or default application secrets and logs the key identifier
  without storing the token. The dedicated LTS-era request hooks emit the
  matching `java8_request_default_jwt_secret`,
  `java11_request_default_jwt_secret`, or `java17_request_default_jwt_secret`
  variant. This covers HugeGraph-style JWT authentication bypasses caused by a
  default `auth.token_secret` while ignoring malformed tokens and tokens whose
  signatures do not validate with a known weak secret. The playground and
  acceptance suite include the Vulhub-shaped HugeGraph CVE-2024-43441
  `GET /graphs` request with a default-secret bearer token, and the real Java
  11 Vulhub acceptance blocks HugeGraph 1.3.0 through the Jersey/Grizzly
  request entry before graph metadata is returned.
- `request_jwt_verification_failure` covers request-time JWT library
  verification failures on API/control paths when the request carries a compact
  JWT in an authentication token header. This targets DataEase
  CVE-2025-49001-style flows where an invalid `X-DE-TOKEN` signature is caught
  but request processing continues. The Java 8/11/17 era agents transform auth0
  `java-jwt` `JWTVerifier.verify(...)` and
  `algorithms.*Algorithm.verify(DecodedJWT)`, then correlate verification
  exceptions only with the active request's compact JWT token header on
  API/control paths. Events log only the token source, mechanism, exception
  class, method, and URI rather than the token value. The playground and
  acceptance suite include the Vulhub-shaped `GET /de2api/user/info` request
  with a forged `uid`/`oid` token, and the real OpenJDK 21 DataEase
  CVE-2025-49001 acceptance blocks the same continuation path with
  `java17_request_jwt_verification_failure`.
- `request_default_crypto_cookie` decrypts only plausible encrypted
  `rememberMe` cookies with known default AES keys and reports a match when the
  plaintext starts with Java serialization stream magic. This covers Shiro-style
  default-key remember-me deserialization chains, including the Vulhub Shiro
  CVE-2016-4437 `GET /` request with a forged `rememberMe` cookie, while logging
  only the cookie name, key identifier, and cipher family rather than the cookie
  value or decrypted bytes. The Java 8 era agent now has real Vulhub evidence
  for this behavior through `scripts/acceptance-vulhub-shiro-4437-java8.sh`,
  using a Shiro filter hook so detection runs before rememberMe
  deserialization.
- `request_serialized_client_state` covers client-side state parameters such as
  JSF/Mojarra `javax.faces.ViewState` or equivalent `viewState` fields when a
  bounded Base64 decode, optionally followed by gzip decompression, starts with
  Java serialization stream magic. This targets unencrypted JSF ViewState
  deserialization before the framework decodes and deserializes the state while
  logging only parameter name, encoding, value length, and decoded payload
  length rather than the state value or object bytes. The playground and
  acceptance suite include the Vulhub-shaped Mojarra `POST /index.xhtml`
  `javax.faces.ViewState` flow. `scripts/acceptance-vulhub-mojarra-viewstate-java7-legacy.sh`
  records the real Vulhub Mojarra boundary: baseline Java 7u21/Mojarra 2.1.28
  accepts a ysoserial `Jdk7u21` ViewState payload and creates
  `/tmp/ohmyrasp-mojarra-viewstate-success`, while the current Java 8 LTS agent
  cannot inject into that Java 7 runtime because it rejects classfile major
  version 52.0.
- `request_default_credential` covers HTTP Basic or form login attempts that
  use known default Java management credentials on admin, manager, console,
  Jolokia/API, OAuth, CAS, or other control paths. This targets Tomcat Manager,
  ActiveMQ, WebLogic, Jenkins lab, and Spring OAuth-style default credential
  footholds while ignoring the same username/password strings outside control
  paths and logging only username, credential identifier, mechanism, and source
  field rather than the password. The playground and acceptance suite include
  the Vulhub-shaped Tomcat7+/Tomcat8 `GET /manager/html` Basic-auth request
  with `tomcat` / `tomcat` and WebLogic weak-password
  `POST /console/j_security_check` form login with `weblogic` / `Oracle@123`.
  `scripts/acceptance-vulhub-tomcat8-manager-java7-legacy.sh` records the real
  Vulhub Tomcat8 Manager boundary: baseline OpenJDK 7u121/Tomcat 8.0.43 accepts
  `tomcat` / `tomcat`, deploys a WAR through `/manager/text/deploy`, and runs a
  JSP marker, while the current Java 8 LTS agent cannot inject into that Java 7
  runtime because it rejects classfile major version 52.0.
- `request_empty_credential_bypass` covers control/admin endpoint requests that
  submit empty username and password parameters together with an account-state
  bypass flag such as `requirePasswordChange`. This targets OFBiz-style
  pre-auth bypass chains that expose XMLRPC deserialization or Groovy execution
  endpoints while ignoring ordinary blank login submissions outside control
  paths. The real OFBiz 18.12.10 CVE-2023-51467 Java 8 acceptance exercises
  this unauthenticated ProgramExport path and confirms the later Groovy process
  sink is blocked by `java8_command_execution_exploit_primitive`.
- `request_setup_state_reset` covers request parameter binding attempts that
  force application setup-completion state back to false through
  setup/bootstrap/status property chains. This targets Confluence
  CVE-2023-22515-style requests such as
  `bootstrapStatusProvider.applicationConfig.setupComplete=false` while
  ignoring ordinary nested `setupComplete` fields outside setup context and
  logging only parameter name, reset value, method, and URI. The scripted
  Confluence setup-boundary probe confirms `vulhub/confluence:8.5.1` is
  injectable in principle, but the uninitialized environment keeps the
  setup-state reset and administrator creation flow behind the manual
  setup/license sequence, so it is tracked as a setup boundary rather than a
  protected acceptance.
- `request_server_side_script_put` covers HTTP `PUT` requests whose decoded path
  targets a server-side script extension, including trailing slash or semicolon
  bypass forms. This targets writable DefaultServlet/WebDAV upload paths such
  as Tomcat CVE-2017-12615 `PUT /1.jsp/` while ignoring read-only requests and
  ordinary static asset uploads. The playground and acceptance suite include a
  direct Vulhub-shaped `PUT /1.jsp/` probe; the real Java 8 Tomcat 8.5.19
  Vulhub acceptance is enforced by the lower-level webroot JSP file-write sink.
- `request_upload_filename_override` covers mutating multipart upload requests
  where framework filename-binding parameters such as `fileFileName` or
  `top.fileFileName` provide traversal, absolute, encoded traversal, or NUL
  shaped paths that can override a safely-normalized upload part filename. This
  targets Struts2 S2-066/CVE-2023-50164 and S2-067/CVE-2024-53677 upload
  basename bypasses while ignoring ordinary
  filename metadata in non-multipart requests and logging only parameter name,
  target type, and value length rather than the attacker-selected path. The
  playground and acceptance suite include Vulhub-shaped S2-066/CVE-2023-50164
  and S2-067/CVE-2024-53677 `POST /index.action` multipart uploads with
  `fileFileName=../shell.jsp` and `top.fileFileName=../shell.jsp` override
  fields.
- `request_scheduler_shell_job` covers request-time scheduler or executor job
  dispatch payloads that select a shell/script job type and provide a non-empty
  command source field. It targets XXL-JOB-style unauthorized executor `/run`
  chains where low-signal commands may be executed later, while requiring
  scheduler path or metadata signals and logging only field names, type, and
  source length rather than the command source. The playground and acceptance
  suite include the Vulhub-shaped XXL-JOB unauthenticated executor JSON
  submission to `/run` with `glueType=GLUE_SHELL` and a `glueSource` command.
  The real Java 8 Vulhub executor is enforced at the later process sink by
  `scripts/acceptance-vulhub-xxljob-java8.sh`, because XXL-JOB writes the
  request body into a generated shell script before invoking it.
- `request_debug_process_launch` covers mutating requests to debug/process
  control endpoints that provide an executable or command parameter such as
  `exePath`. This targets TeamCity CVE-2023-42793-style debug process launch
  chains before the request reaches the later process-spawn hook, while logging
  only the parameter name and command length. The dedicated Java 8/11/17 agents
  carry the same servlet-request rule and emit
  `java8_request_debug_process_launch`, `java11_request_debug_process_launch`,
  or `java17_request_debug_process_launch`. The playground and acceptance suite
  include a Vulhub-shaped TeamCity CVE-2023-42793 replay for
  `POST /app/rest/debug/processes?exePath=id`; real Java 17 evidence is
  `scripts/acceptance-vulhub-teamcity-42793-java17.sh`, where baseline launches
  the debug process and protected mode blocks before execution.
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
  CVE-2022-22947; the real Java 8 Vulhub acceptance verifies the same route
  registration and refresh flow, with enforcement at the later process sink.
  The playground and acceptance suite also include Apache Druid CVE-2021-25646
  `/druid/indexer/v1/sampler` JavaScript parser requests, Apache HugeGraph
  CVE-2024-27348 `/gremlin` Gremlin-Groovy submissions that reflectively
  launch `ProcessBuilder`, Apache Unomi CVE-2020-13942 `/context.json` MVEL requests, Jenkins CVE-2018-1000861
  `/securityRealm/.../checkScript` Groovy validation requests, OFBiz
  CVE-2023-51467 `/webtools/control/ProgramExport/` Groovy posts, OFBiz
  CVE-2024-38856 `/webtools/control/main/ProgramExport` multipart Groovy
  posts, Metabase CVE-2023-38646 `/api/setup/validate` JSON posts with H2
  trigger `init` scripts, DataEase CVE-2025-32966
  `/de2api/datasource/validate` JSON posts with base64 H2 datasource
  configuration, WebLogic CVE-2020-14882/CVE-2020-14883
  `/console/css/%252e%252e%252fconsole.portal` `handle=ShellSession(...)`
  requests, WebLogic CVE-2019-2725-style
  `handle=FileSystemXmlApplicationContext(...)` requests, AJ-Report
  CNVD-2024-15077
  `/dataSetParam/verification;swagger-ui/` JSON posts with a
  `validationRules` JavaScript body field, and `/h2-console/login.do` JDBC URL
  form posts for H2 CVE-2022-23221. The Java 8 Solr CVE-2019-0193 Vulhub
  acceptance verifies the lower-level script-evaluation sink for the same
  DataImportHandler playground, and the Java 8 H2 CVE-2022-23221 Vulhub
  acceptance verifies the lower-level H2 JDBC URL sink for the H2 console
  login playground. The Java 8 Elasticsearch CVE-2014-3120 Vulhub acceptance
  verifies the real `/website/blog/` index plus `/_search?pretty` MVEL
  `script_fields` flow with enforcement at the later
  `Runtime.exec(String)` sink. The Java 8 Elasticsearch CVE-2015-1427 Vulhub acceptance
  verifies the real `/website/blog/` index plus `/_search?pretty` Groovy
  `script_fields` flow with enforcement at the later
  `Runtime.exec(String)` sink. The Java 8 AJ-Report CNVD-2024-15077 Vulhub acceptance
  verifies the real `/dataSetParam/verification;swagger-ui/` validation-rule
  flow and lower-level `ScriptEngine.eval` block for request-supplied
  JavaScript. The Java 8 Apache Druid CVE-2021-25646 Vulhub acceptance verifies
  the real `/druid/indexer/v1/sampler` flow and lower-level Rhino
  `Context.compileFunction` block for request-supplied JavaScript. The Java 8
  Apache Unomi CVE-2020-13942 Vulhub acceptance verifies the real
  `/context.json` MVEL flow and lower-level `Runtime.exec(String)` command-sink
  block for request-supplied expression conditions. The Java 11
  Metabase CVE-2023-38646 Vulhub acceptance verifies the real setup-token flow
  and lower-level `ScriptEngine.eval` block for the H2 setup-validation
  trigger.
- `request_message_selector_expression` covers STOMP/SockJS-style message
  frames where a message `selector:` header contains a runtime expression
  primitive instead of an ordinary selector predicate. This targets Spring
  Messaging CVE-2018-1270 selector SpEL injection while requiring message-frame
  context with a destination and logging only inferred engine and selector
  length. The playground and acceptance suite include the Vulhub-shaped
  SockJS downgrade POST to `/gs-guide-websocket/123/abc/xhr_send` with a STOMP
  `SUBSCRIBE` frame for `/topic/greetings`; the real Java 8 Vulhub acceptance
  verifies Spring Messaging 5.0.4 with the full SockJS `htmlfile` session and
  `xhr_send` flow, with protected-mode enforcement at the later
  `Runtime.exec(String)` process sink.
- `request_expression_header` covers request headers that are explicitly shaped
  as expression or script routing controls and whose values contain runtime
  execution primitives. It also covers parser-sensitive headers such as
  `Content-Type` or `Content-Disposition` when the value itself is a clearly
  dangerous OGNL expression. This targets Spring Cloud Function
  CVE-2022-22963 `spring.cloud.function.routing-expression` SpEL injection and Struts2
  multipart parser OGNL injection before the expressions are evaluated, while
  logging only header name, inferred engine, and expression length. The
  playground and acceptance suite include Vulhub-shaped `/functionRouter` POSTs
  with the routing-expression header, and the real Java 8 Vulhub acceptance
  verifies the same Spring Cloud Function 3.2.2 route with enforcement at the
  later process sink. `scripts/acceptance-vulhub-struts2-s2045-java8.sh`
  verifies the real Struts2 S2-045/CVE-2017-5638 `Content-Type` OGNL flow with
  protected-mode enforcement at the later `ProcessBuilder.start` sink, and
  `scripts/acceptance-vulhub-struts2-s2046-java8.sh` verifies the sibling
  S2-046 multipart filename OGNL path with the same process-sink enforcement.
  `scripts/acceptance-vulhub-struts2-s2057-java8.sh` verifies the S2-057
  namespace path OGNL flow through the Vulhub action-chain redirect with the
  same process-sink enforcement.
  `scripts/acceptance-vulhub-struts2-s2059-java8.sh` verifies the Struts2
  S2-059/CVE-2019-0230 forced tag-attribute double-evaluation path with the
  same generic OGNL process-sink enforcement.
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
  `/h2-console/login.do` JNDI driver form post. The Java 8 runtime track also
  proves the same Solr 8.11.0, H2 2.0.204, and XStream 1.4.15 Vulhub
  applications through sink-level baseline/protected acceptances in
  `scripts/acceptance-vulhub-log4j-solr-java8.sh` and
  `scripts/acceptance-vulhub-h2-42392-java8.sh`, and
  `scripts/acceptance-vulhub-xstream-21351-java8.sh`.
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
  `memberNames` JSON EL injection used by CVE-2018-16621, CVE-2020-10204, and
  CVE-2020-10199,
  Confluence template/Velocity OGNL `findValue` delegation, including
  CVE-2023-22527,
  GeoServer CVE-2022-41852 and CVE-2024-36401 OGC
  `valueReference`/`propertyName` XPath runtime expressions for both
  query-parameter and XML-body WFS forms, and
  similar expression injection before the framework evaluator runs, while
  ignoring benign expressions that do not contain runtime execution primitives
  and logging only field name, inferred engine, and expression length. The
  playground and acceptance suite include Vulhub-shaped
  `/oauth/authorize?response_type=...` requests for Spring Security OAuth
  CVE-2016-4977, Confluence `/pages/doenterpagevariables.action` and
  `/template/aui/text-inline.vm` requests for CVE-2021-26084 and
  CVE-2023-22527, and Struts2 form/query payloads for S2-001, S2-007, S2-008,
  S2-009, S2-012, S2-013, S2-014, S2-048,
  S2-053, S2-059/CVE-2019-0230, and S2-061/CVE-2020-17530, including the
  S2-061 `freemarker.template.utility.Execute` OGNL sandbox-bypass primitive.
  The real Java 8 Spring Security OAuth Vulhub acceptance verifies the same
  `/oauth/authorize` `response_type` SpEL flow with protected-mode enforcement
  at the later `Runtime.exec(String)` process sink. The scripted Confluence
  setup-boundary probe confirms the 7.4.10 and 8.5.3 images are injectable in
  principle, but the uninitialized environments redirect the CVE-2021-26084 and
  CVE-2023-22527 requests to setup before OGNL evaluation, so they are tracked
  as setup boundaries rather than protected acceptances. The real Java 8 Struts2
  S2-001 Vulhub
  acceptance verifies the validation-error
  `/login.action` form value OGNL flow with enforcement at the later
  `ProcessBuilder.start` sink. The real Java 8 Struts2 S2-007 Vulhub acceptance
  verifies the integer conversion-error `/user.action` `age` value OGNL flow
  with enforcement at the later `Runtime.exec(String)` sink. The real Java 8
  Struts2 S2-008 Vulhub acceptance verifies the devMode
  `/devmode.action?debug=command&expression=...` OGNL command flow with
  enforcement at the later `Runtime.exec(String)` sink. The real Java 8
  Struts2 S2-009 Vulhub acceptance verifies the delegated `name` and
  `z[(name)('meh')]` query-parameter OGNL flow with enforcement at the later
  `Runtime.exec(String)` sink. The real Java 8 Struts2 S2-012 Vulhub
  acceptance verifies the redirect-result `/index.jsp?name=${name}` OGNL flow
  with enforcement at the later `ProcessBuilder.start` sink. The real Java 8
  Struts2 S2-013/S2-014 Vulhub acceptance verifies the dollar-OGNL
  includeParams `/link.action?a=${...}` flow with enforcement at the later
  `ProcessBuilder.start` sink. The real Java 8 Struts2 S2-048 Vulhub acceptance
  verifies the showcase Gangster Name OGNL form flow with enforcement at the
  later `Runtime.exec(String)` sink. The real Java 8 Struts2 S2-061 Vulhub
  acceptance verifies
  `vulhub/struts2:2.5.25`
  multipart OGNL baseline execution with protected-mode enforcement at the
  resulting FreeMarker `Execute` process sink. The real Java 8 Struts2 S2-053
  Vulhub acceptance verifies the Freemarker-parsed `redirectUri` OGNL value,
  including the required trailing newline, with enforcement at the later
  `ProcessBuilder.start` sink.
- `request_json_patch_expression` covers `application/json-patch+json` PATCH
  request bodies whose JSON Patch `path` field carries a runtime expression
  payload. This targets Spring Data REST CVE-2017-8046 JSON Patch SpEL
  injection before the patch path is evaluated, while logging only inferred
  engine, body length, and expression length rather than the raw body. The
  playground and acceptance suite include Vulhub-shaped `PATCH /customers/1`
  requests with `application/json-patch+json` bodies; the real Java 8 Vulhub
  acceptance verifies the same Spring Data REST 2.6.6 flow with enforcement at
  the later process sink.
- `request_expression_parameter_name` covers request parameter names that embed
  expression-language syntax with runtime execution primitives, such as Spring
  Data Commons CVE-2018-1273 property-path SpEL payloads in `username[...]`
  and Spring WebFlow CVE-2017-4971 binding-field expressions shaped like
  `_(...).start()`. It also
  covers Struts2 OGNL-evaluated parameter names such as S2-003 escaped-hash
  bypasses, S2-005 expression evaluation, S2-016 `redirect:`/`action:`
  prefixes, and S2-032/CVE-2016-3081
  dynamic-method invocation `method:` prefixes. It redacts the dangerous key in both query
  strings and parameter maps while preserving only a safe field prefix,
  inferred engine, and expression length. The playground and acceptance suite
  include Vulhub-shaped `/hotels/booking` and `/users?page=&size=5` Spring
  binding payloads; the real Java 8 Spring Data Commons Vulhub acceptance
  verifies the `/users?page=&size=5` binder flow with enforcement at the later
  process sink. The real Spring WebFlow Vulhub probe verifies the hotel
  booking confirm-state baseline RCE on OpenJDK 7u121 and records that current
  Java 8+ LTS agents cannot inject into that legacy JVM because it rejects
  classfile major version 52.0. The playground also includes
  `/example/HelloWorld.action` and
  `/index.action` parameter-name payloads for S2-003, S2-005, S2-016, and
  S2-032/CVE-2016-3081. The real Java 8 Struts2 S2-005 Vulhub acceptance
  verifies the same `\u0023`-escaped `/example/HelloWorld.action`
  parameter-name OGNL chain with enforcement at the later
  `Runtime.exec(String[])` sink. The real Java 8 Struts2 S2-016 Vulhub
  acceptance verifies the redirect-prefix `/index.action?redirect:${...}`
  parameter-name OGNL chain with enforcement at the later
  `Runtime.exec(String)` sink. The real Java 8 Struts2 S2-032 Vulhub
  acceptance verifies the README-shaped dynamic-method-invocation
  `/index.action?method:...` parameter-name OGNL chain with enforcement at the
  later `Runtime.exec(String)` sink.
- `request_expression_path` covers request URI paths that decode to
  expression-language payloads with runtime execution primitives. This targets
  Confluence and Struts2 namespace/path OGNL injection before the framework
  evaluates the path expression, while redacting the logged URI and recording
  only inferred engine, method, and expression length. The playground and
  acceptance suite include the Vulhub-shaped Confluence CVE-2022-26134
  URL-encoded OGNL path under `/`, tested through both the policy fixture and a
  direct `--path-as-is` request, the Struts2 S2-015 action-name OGNL path, and
  the Struts2 S2-057/CVE-2018-11776 namespace path under
  `/struts2-showcase/.../actionChain1.action`. The Java 8 S2-015 Vulhub
  acceptance confirms the real action-name wildcard-result baseline and
  protected enforcement at the later `Runtime.exec(String)` sink. The Java 8
  S2-057 Vulhub acceptance confirms the real action-chain redirect baseline
  and protected enforcement at the later `Runtime.exec` sink. The scripted
  Confluence setup-boundary probe confirms the current CVE-2022-26134 image
  redirects the direct encoded path payload to setup with no `X-Cmd-Response`.
- `request_xxe_payload` covers request parameters whose values contain XML
  doctypes with external entity declarations using unsafe protocols such as
  `file:`, `jar:`, HTTP, FTP, LDAP, or RMI. This targets Solr CVE-2017-12629
  XML parser query XXE payloads before XML resolution while ignoring
  internal-only doctypes and logging only parameter name, scheme, and XML
  length. The Java 8 Solr CVE-2017-12629 Vulhub acceptance also verifies the
  lower-level Xerces entity-resolution sink for the same playground.
- `request_typed_parameter_deserialization` covers request parameter names that
  declare a Java binding type, such as `+field:fully.qualified.Class=value`,
  when that type is a known dangerous polymorphic construction or
  deserialization gadget. This targets Liferay JSONWS-style typed parameter
  binding to C3P0, TemplatesImpl, Spring XML contexts, and related classes
  while ignoring ordinary DTO class names and logging only field name, class,
  and value length. The playground and acceptance suite include the
  Vulhub-shaped `/api/jsonws/invoke` POST used by Liferay Portal
  CVE-2020-7961; the real Java 8 acceptance verifies that the same flow is
  blocked at the lower-level remote classloader sink before the attacker class
  can create its marker file.
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
  Vulhub-shaped ColdFusion CVE-2023-29300
  `/CFIDE/adminapi/accessmanager.cfc?method=foo&_cfclient=true`
  `argumentCollection` WDDX POST and the `/api/monitors/import` YAML import
  body. The Java 8/11/17 backport request hooks implement the same parameter
  value heuristic with era-prefixed algorithms
  `java8_request_typed_payload_deserialization`,
  `java11_request_typed_payload_deserialization`, and
  `java17_request_typed_payload_deserialization` without reading raw request
  bodies. Real Java 11 Vulhub evidence is provided by
  `scripts/acceptance-vulhub-coldfusion-29300-java11.sh`: baseline reaches a
  host LDAP listener from ColdFusion 2018.0.15, while protected mode blocks the
  same WDDX POST at `HttpServlet.service` before the outbound LDAP connection.
- `request_xml_polymorphic_gadget` covers XML request bodies that declare
  dangerous Java polymorphic gadget types through XML class attributes, class
  elements, or fully qualified Java tag names before an XML object mapper
  unmarshals them. This targets Struts2 S2-052-style REST/XStream payloads
  whose object graph reaches classes such as `java.lang.ProcessBuilder`,
  XStream CVE-2021-21351-style `JdbcRowSetImpl` JNDI chains, and
  XStream CVE-2021-29505-style `RegistryImpl_Stub` RMI callback chains, while
  ignoring ordinary XML class metadata for safe Java collection/DTO types and
  logging only class name, source, and body length. The playground and
  acceptance suite include the Vulhub-shaped Struts2 S2-052
  `POST /orders/3/edit` REST XML body, XStream CVE-2021-21351
  `JdbcRowSetImpl` LDAP/JNDI XML body, and XStream CVE-2021-29505
  `RegistryImpl_Stub` RMI XML body. The real Java 8 XStream CVE-2021-21351
  Vulhub acceptance verifies the same XML gadget shape with enforcement at the
  later Java naming sink. The real Java 8 XStream CVE-2021-29505 Vulhub
  acceptance verifies the XML-to-JRMP callback shape and enforcement at the
  later Java deserialization sink when the JRMPListener returns the
  CommonsCollections6 second stage. The real Java 8 Struts2 S2-052 Vulhub
  acceptance verifies the REST/XStream XML polymorphic `ProcessBuilder` gadget
  with enforcement at the later process sink.
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
  include the Vulhub-shaped `/secure/ContactAdministrators.jspa` form POST for
  Jira CVE-2019-11581 and `/jmreport/queryFieldBySql` JSON `sql` POST for
  JimuReport CVE-2023-4450. The real Jira 8.1.0 Vulhub environment is also
  tracked by
  `scripts/acceptance-vulhub-jira-11581-setup-boundary-java8.sh`: it confirms
  the Java 8u212 runtime and shows that the uninitialized image redirects the
  Contact Administrators GET/POST payload flow to setup before the vulnerable
  form can be exercised. The Java 8 runtime track also proves Solr 8.2.0
  CVE-2019-17558 in `scripts/acceptance-vulhub-solr-velocity-java8.sh`,
  where the final protection is the generic `Runtime.exec` sink rather than a
  Velocity-specific block.
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
  Confluence CVE-2019-3396 macro-preview `_template` path traversal, OFBiz-style
  `statsDecoratorLocation=http://.../payload.xml` remote screen/decorator
  loading, ColdFusion CVE-2023-26360-style metadata `classname` source
  selection such as `_variables._metadata.classname=../../proc/self/environ`,
  and ColdFusion CVE-2010-2861-style `locale=../../etc/passwd%00en` resource
  traversal before the server reads or evaluates the selected source. The
  playground and acceptance suite include the Vulhub-shaped OFBiz
  CVE-2024-45507 `/webtools/control/forgotPassword/StatsSinceStart`
  remote-decorator request, plus ColdFusion
  `/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc` and
  `/CFIDE/administrator/enter.cfm` requests. The real Java 8 Vulhub acceptance
  for CVE-2024-45507 verifies that `java8_request_template_source` blocks at
  `HttpServlet.service` before the remote Widget-Screen XML is fetched or the
  marker command is evaluated. The real ColdFusion CVE-2023-26360 Java 11
  acceptance verifies the same metadata classname source reaches a sensitive
  file load in the product runtime; final enforcement there is
  `java11_file_sensitive_read` at `FileInputStream.open`, before
  `/proc/self/environ` is returned. The scripted ColdFusion CVE-2010-2861
  Vulhub probe proves the README-shaped `locale=.../etc/passwd%00en` baseline
  disclosure, but the image runs Java 6u04 and rejects the Java 8 agent
  classfile version, so it is tracked as a legacy runtime boundary rather than a
  protected LTS acceptance. The scripted Confluence CVE-2019-3396 Java 8 Vulhub
  setup-boundary probe confirms the image runtime is injectable in principle,
  but the uninitialized environment keeps the macro-preview `_template` request
  behind the setup/license flow and returns `503 Setup in progress`, so that
  target is tracked as a Vulhub setup boundary rather than a protected
  acceptance. It logs only source location, field name, target type, and value
  length.
- `request_remote_content_stream` covers request-time control-plane payloads
  that enable remote/content streaming or pass content-stream URL parameters to
  local file, JAR, dangerous SSRF, or internal HTTP targets. This targets
  Solr RemoteStreaming JSON configuration
  `requestDispatcher.requestParsers.enableRemoteStreaming=true` and
  `stream.url=file:///...` read or SSRF chains while logging only mode,
  parameter, scheme, and source length. The Java 8 Solr RemoteStreaming
  Vulhub acceptance also verifies the lower-level sensitive file-read sink for
  the same playground. The Java 8 Elasticsearch CVE-2015-3337 Vulhub
  acceptance verifies the lower-level sensitive file-read sink for plugin
  resource traversal to `/etc/passwd`. The Java 8 Elasticsearch CVE-2015-5531
  Vulhub acceptance verifies the lower-level sensitive file-read sink for
  snapshot repository traversal to `/etc/passwd`.
  `scripts/acceptance-vulhub-nexus-4956-java8.sh` provides real Vulhub
  application evidence for Nexus Repository CVE-2024-4956 encoded-slash
  traversal: Nexus 3.68.0 on OpenJDK 8 serves `/etc/passwd` from the
  README-shaped unauthenticated path in baseline mode, while protected mode
  keeps ordinary UI readiness quiet and blocks the lower-level
  `FileInputStream.open` sink with `java8_file_sensitive_read` before passwd
  bytes are disclosed.
- `request_remote_import_script_write` covers request-time import or data-file
  workflows that combine remote source URLs with a server-side script save
  target and an import/control context or explicit URL-source flag. This targets
  OFBiz-style remote CSV/XML import chains that write a JSP webshell while
  logging only source/target parameter names, target type, and source count.
  The playground and acceptance suite include the Vulhub-shaped OFBiz
  CVE-2024-32113, CVE-2024-36104, and CVE-2024-45195
  `/webtools/control/forgotPassword/viewdatafile` remote CSV/XML import
  request that saves into an accounting JSP path; the real Java 8
  CVE-2024-45195 Vulhub acceptance verifies the lower-level
  `java8_file_script_write` block for the same chain.
- `request_repository_webroot_write` covers mutating backup, repository, or
  snapshot control-plane requests that configure server-side persistence under a
  web deployment directory while the repository/snapshot selector carries a
  server-side script extension. This targets Elasticsearch-style snapshot
  repository webshell writes, including WooYun-2015-110216-style
  `/_snapshot/yz.jsp` requests with
  `settings.location=/usr/local/tomcat/webapps/wwwroot/`, while ignoring ordinary
  snapshot repositories under application data directories and logging only
  field name, target type, location class, and value length. The Java 8
  WooYun-2015-110216 Vulhub acceptance verifies the lower-level webroot JSP
  file-write sink for the same snapshot repository workflow.
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
  context and logging only field name and value length. The playground and
  acceptance suite include the Vulhub-shaped MeterSphere
  `POST /test/case/list/1/10` case-list request.
- `request_sql_identifier_injection` covers JSON and GraphQL API bodies where
  identifier-like fields such as `metricName`, `tableName`, or `columnName`
  carry SQL control syntax instead of ordinary identifier values. This targets
  SkyWalking GraphQL metric-name SQL injection and MyBatis order-by metadata
  injection such as MeterSphere CVE-2021-45788, while ignoring normal metric
  names such as `service_instance_jvm_memory.max` and normal sort directions
  such as `asc` or `desc`. The request classifier logs only field name and
  value length; the lower-level MyBatis `BoundSql` hook logs only source,
  parameter, reason, and value length for `orders[].type`, `orders[].name`, and
  `orders[].prefix`. The playground and acceptance suite include the
  Vulhub-shaped SkyWalking 8.3.0 `POST /graphql` `metricName` request. Real
  Java 8 SkyWalking Vulhub evidence is provided by
  `scripts/acceptance-vulhub-skywalking-java8.sh`: baseline SkyWalking 8.3.0
  passes the GraphQL `metricName` into the H2-backed query and returns an SQL
  error containing the injected table expression, while protected mode blocks
  the lower-level `H2LogQueryDAO.queryLogs` identifier argument with
  `java8_sql_identifier_injection`. Real Java 8 MeterSphere Vulhub evidence is
  provided by `scripts/acceptance-vulhub-metersphere-45788-java8.sh`: baseline
  MeterSphere 1.15.4 delays through the case-list sort direction, while
  protected mode blocks the lower-level MyBatis `BoundSql` order metadata with
  `java8_sql_identifier_injection` without logging the session id, CSRF token,
  or raw SQL value.
- `request_ogc_filter_sql_injection` covers OGC/WFS/WMS/WPS filter parameters
  such as `CQL_FILTER`, `ECQL_FILTER`, or `FILTER` when they carry SQL-only
  control primitives like nested `SELECT`, `CAST(SELECT ...)`, comments, or
  time-delay functions. This targets GeoServer CVE-2023-25157/CVE-2023-25158 OGC filter SQL
  injection before the filter is translated into datastore SQL, while requiring OGC request
  context and logging only parameter name and value length. The Java 8/11/17
  era servlet hooks also enforce this request classification as
  `javaX_request_ogc_filter_sql_injection`; real Java 17 Vulhub evidence is
  provided by `scripts/acceptance-vulhub-geoserver-25157-java17.sh`.
- `request_remote_job_submission` covers request-time job/application
  descriptors that submit a remote Java executable artifact together with an
  entry class, or a shell command in a container/job command field, to a job
  control endpoint. This targets Apache Spark standalone REST application
  submission and Hadoop YARN ResourceManager REST container command submission
  shapes while logging only mechanism, URI, descriptor length, artifact
  scheme/type, or command length rather than the submitted descriptor. The
  playground and acceptance suite include both the Vulhub-shaped Spark REST
  `/v1/submissions/create` `appResource`/`mainClass` shape and the
  Vulhub-shaped Hadoop `/ws/v1/cluster/apps`
  `am-container-spec.commands.command` reverse-shell submission.
  The dedicated Java 8/11/17 agents also hook Spark standalone REST
  `handleSubmit` and Hadoop YARN ResourceManager
  `RMWebServices.submitApplication`, emitting
  `javaX_request_remote_job_submission` for the remote artifact plus
  entry-class shape or for AM/container command submission. Real Java 8 Vulhub
  evidence is provided by `scripts/acceptance-vulhub-spark-java8.sh`, where
  Spark 2.3.1 baseline fetches a hosted payload JAR and the worker creates
  `/tmp/ohmyrasp-spark-success`, and by
  `scripts/acceptance-vulhub-hadoop-yarn-java8.sh`, where Hadoop 2.8.1
  baseline schedules a NodeManager command that creates
  `/tmp/ohmyrasp-yarn-success`; protected mode blocks each REST submission
  before the worker/container marker is created.
- `request_internal_forward` covers request-controlled internal forwarding or
  view selection parameters that point to sensitive control paths using servlet
  path-parameter JSP suffix confusion, such as TeamCity-style
  `jsp=/app/rest/users;.jsp` authentication bypasses. It is gated by
  forward/view parameter names, an absolute internal target, and a sensitive
  control path to avoid flagging ordinary JSP view selection. The dedicated
  Java 8/11/17 agents carry the same servlet-request rule and emit
  `java8_request_internal_forward`, `java11_request_internal_forward`, or
  `java17_request_internal_forward`. Real evidence is
  `scripts/acceptance-vulhub-teamcity-27198-java17.sh`: TeamCity baseline
  exposes unauthenticated users XML and creates a `SYSTEM_ADMIN` user through
  the forwarded REST endpoint, while protected mode blocks both requests.
- `request_path_confusion` also covers ambiguous servlet-container path
  decoding where an encoded single-dot or double-slash variant canonicalizes
  into protected deployment resources such as `WEB-INF` or `META-INF`. This
  targets Jetty CVE-2021-28164 style `/%2e/WEB-INF/web.xml` disclosure while
  leaving a direct `/WEB-INF/web.xml` request quiet. The dedicated Java 8
  evidence is `scripts/acceptance-vulhub-jetty-28164-java8.sh`, where Jetty
  9.4.37 baseline discloses `web.xml` and protected mode blocks with
  `java8_request_path_confusion`.
- `xpath_runtime` covers JAXP/Xalan, Jaxen, and Apache Commons JXPath entry
  points, including GeoTools-style property expressions that can otherwise be
  evaluated as XPath-like runtime calls.
- `jexl_runtime` and `el_runtime` cover Commons JEXL and Java/Jakarta Unified
  EL expression creation/evaluation paths when the expression attempts direct
  or reflective runtime process execution, covering Nexus-style JEXL/EL payloads
  without product-specific request signatures. The real Java 8 Nexus
  Repository CVE-2019-7238 Vulhub acceptance verifies that the Commons JEXL
  evaluation hook blocks the ExtDirect `previewAssets` JEXL filter at
  `CommonsJEXL.evaluate` with `java8_jexl_runtime_execution`, before the
  expression reaches `Runtime.exec(String)`, and logs only engine and expression
  length rather than the raw payload. The real Java 8 Nexus Repository
  CVE-2020-10204 Vulhub acceptance verifies the Java/Jakarta Unified EL hook
  against the authenticated ExtDirect `coreui_User.update` role payload on
  Nexus 3.21.1, blocking at `UnifiedEL.evaluate` with
  `java8_el_runtime_execution` before the reflective `Runtime.exec` call
  creates `/tmp/ohmyrasp-nexus10204-success`; CVE-2020-10199 verifies the same
  generic hook through the authenticated
  `POST /service/rest/beta/repositories/go/group` `memberNames` validation
  path before `/tmp/ohmyrasp-nexus10199-success` is created. In both cases, the
  protected log records only engine and expression length and never the raw
  marker-bearing payload.
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
  than the raw script body. The real Java 17 Vulhub acceptance
  `scripts/acceptance-vulhub-geoserver-24816-java17.sh` verifies the full
  GeoServer 2.17.2 path: baseline returns `uid=` from the injected
  `ras:Jiffle` script, while protected mode starts quietly and blocks the
  lower-level `Runtime.exec(String)` sink as
  `java17_command_execution_exploit_primitive` from the Jiffle runtime stack.
- `command_config_listener` covers process launches reached through
  server-configured executable listener stacks, such as Solr
  CVE-2017-12629 `RunExecutableListener` post-commit execution. This catches
  persisted configuration-triggered commands that are not necessarily present
  in the later trigger request body.
- `command_config_injection` covers command launches reached from mutable
  runtime configuration launchers, such as RocketMQ filter-server startup
  commands built from broker configuration in CVE-2023-33246. This is
  stack-gated so ordinary scheduler-launched low-signal commands such as
  `touch /tmp/success` are not treated as attacks by themselves. The real
  Java 8 RocketMQ Vulhub acceptance also verifies that the lower-level
  filter-server shell command emitted by `rocketmq-attack` is blocked as
  `java8_command_execution_shell_meta` before the marker file is created.
- `readFile_userinput_unwanted` covers request-controlled file read targets
  that use unwanted local or interpreter protocols such as `file:` or `php:`.
  This targets Metabase CVE-2021-41277-style GeoJSON fetches like
  `GET /api/geojson?url=file:////etc/passwd` at the file-read sink, without
  treating ordinary external map or feed URLs as local file reads. The
  playground and acceptance suite include the Vulhub-shaped `/api/geojson`
  request; `scripts/acceptance-vulhub-metabase-41277-java11.sh` verifies the
  real Java 11 Vulhub container blocks this sink with
  `java11_file_sensitive_read`.
- `readFile_userinput` covers request-controlled local file paths that reach a
  Java file-read sink. This targets direct file-disclosure helpers such as the
  Vulhub WebLogic weak-password lab `GET /hello/file.jsp?path=/etc/passwd`,
  while keeping the decision at the file API boundary rather than on endpoint
  names alone. The real WebLogic weak-password Vulhub legacy-boundary script
  proves the Java 6 baseline discloses `/etc/passwd` and that the current Java
  8 agent cannot inject into that runtime because the JVM rejects classfile
  major version 52.0.
- `writeFile_config_path` covers runtime configuration persistence stacks that
  write to unsafe filesystem targets, such as RocketMQ NameServer
  CVE-2023-37582 `configStorePath` updates that redirect config persistence to
  `/tmp`, web roots, cron/systemd paths, or other attacker-meaningful
  destinations. The real Java 8 RocketMQ NameServer Vulhub acceptance also
  verifies that the lower-level traversal `.sh` file-write sink is blocked as
  `java8_file_script_write` before the marker content is created.
- `writeFile_generated_script` covers request-controlled generated interpreter
  scripts that contain execution primitives such as `system(...)` before the
  script is persisted. This targets OpenTSDB CVE-2020-35476 and
  CVE-2023-25826 Gnuplot injection where graph parameters are written into a
  temporary plot script and later executed by an external interpreter. The
  real Java 8 Vulhub acceptance verifies the lower-level
  `java8_file_generated_plot_script_command` sink against both OpenTSDB 2.4.0
  and 2.4.1.
- `classloader_remote` covers Java classloader codebase sources that use remote
  schemes such as HTTP, HTTPS, LDAP, or RMI, including `RMIClassLoader`
  codebase loading. This targets Vulhub `java/rmi-codebase`-style remote
  bytecode loading while ignoring local `file:`, application classpath JAR
  resources, and Felix/OSGi internal `felix.extensions` extension-bundle
  pseudo-codebases. The playground and acceptance suite include a direct
  RMIClassLoader-shaped codebase replay and log only mechanism, scheme,
  abbreviated URL, and request-control status. The Java 8 runtime track also
  proves the real `vulhub/j2ee:8u222` RMI server through a
  baseline/protected acceptance in
  `scripts/acceptance-vulhub-rmi-codebase-java8.sh`.
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
  `/api/jolokia/` Log4j2 `setConfigText` and FlightRecorder `copyTo`
  file-write flows.
- `deserialization_gadget` extends Java object stream coverage beyond exact
  blacklist types to known ysoserial gadget families, including BeanShell,
  ROME, C3P0, and Commons BeanUtils classes used by vulhub cases such as JMeter
  RMI, ActiveMQ object message deserialization, and ColdFusion AMF payloads.
  The playground and acceptance suite include the Vulhub-shaped
  `/flex2gateway/amf` `application/x-amf` Java object stream path for Adobe
  ColdFusion CVE-2017-3066. Real Java 8 Vulhub evidence is provided by
  `scripts/acceptance-vulhub-coldfusion-3066-java8.sh`: baseline command
  execution succeeds through the AMF gadget chain, while protected mode blocks
  the same request at the later `Runtime.exec(String)` sink because the process
  execution occurs inside the Java deserialization stack.
- `deserialization_cluster_message` covers dangerous Java deserialization
  gadget classes resolved while a cluster or message replication transport is
  unmarshalling data, such as Tomcat Tribes stack frames. This targets
  Tomcat CVE-2026-29146 post-padding-oracle deserialization sinks and
  CVE-2026-34486-style EncryptInterceptor bypass chains where an attacker sends
  a serialized gadget to the cluster receiver port, while avoiding ordinary
  cluster traffic that deserializes only benign application classes. Events
  include a `securityInterceptor` detail when the stack contains Tomcat Tribes
  `EncryptInterceptor`, and the playground and acceptance suite include the
  Vulhub-shaped CommonsCollections gadget resolution path under
  `EncryptInterceptor`, `XByteBuffer`, and `NioReplicationTask`. Real Java 8
  Vulhub evidence is provided by
  `scripts/acceptance-vulhub-tomcat-34486-java8.sh`: baseline
  `vulhub/tomcat:9.0.116` accepts the Vulhub-framed unencrypted
  CommonsCollections6 payload on the Tribes receiver and creates
  `/tmp/ohmyrasp-tomcat-34486-success`, while protected mode blocks
  `ObjectInputStream.resolveClass` with `java8_deserialization_gadget_class`
  on `org.apache.commons.collections.functors.ChainedTransformer` before the
  marker is created.
- `deserialization_logging_message` covers dangerous Java deserialization
  gadget classes resolved while a logging socket/server transport is
  unmarshalling remote log events. This targets Log4j CVE-2017-5645-style TCP
  server payloads while avoiding normal remote logging events that deserialize
  only Log4j event classes. The Java 8 runtime track proves the real
  `vulhub/log4j:2.8.1` SocketServer through a baseline/protected acceptance in
  `scripts/acceptance-vulhub-log4j-5645-java8.sh`.
- `deserialization_webflow_state` covers dangerous Java deserialization gadget
  classes resolved while Spring WebFlow client-state repositories or CAS
  encrypted transcoders are restoring a flow execution snapshot. This targets
  Apereo CAS 4.1-style encrypted `execution` state payloads that decrypt into a
  ysoserial object stream, while avoiding ordinary WebFlow state restoration
  that only deserializes framework flow execution objects. The playground and
  acceptance suite include the Vulhub-shaped `/cas/login` POST with an
  `execution` client-state parameter. The real Java 8 Apereo CAS 4.1.5 Vulhub
  acceptance generates the default-key encrypted CommonsCollections4 state with
  Apereo-CAS-Attack: baseline creates `/tmp/ohmyrasp-cas415-success`, while
  protected mode blocks `ObjectInputStream.resolveClass` with
  `java8_deserialization_gadget_class` on the CommonsCollections4
  `ChainedTransformer` gadget before the marker command is executed.
- `deserialization_rmi_transport` covers dangerous Java deserialization gadget
  classes resolved while RMI server/registry transport dispatch is unmarshalling
  remote call arguments. This targets JMeter CVE-2018-1297-style
  distributed-test RMI payloads, Java RMI Registry gadget submissions, and
  Neo4j Shell CVE-2021-34371-style `setSessionVariable` calls carrying Rhino
  `NativeJavaObject` gadget graphs while avoiding ordinary RMI calls that
  deserialize only benign service DTOs. The playground and acceptance suite
  include the Vulhub-shaped `/neo4j-shell/setSessionVariable` RMI unmarshalling
  path with Neo4j Shell stack frames. The Java 8 runtime track also proves the
  real `vulhub/jmeter:3.3` RMI server through
  `scripts/acceptance-vulhub-jmeter-1297-java8.sh` and the real
  `vulhub/neo4j:3.4.18` Neo4j Shell server through
  `scripts/acceptance-vulhub-neo4j-34371-java8.sh`. It also proves the real
  `vulhub/j2ee:8u111` RMI Registry direct-bind path through
  `scripts/acceptance-vulhub-rmi-registry-direct-java8.sh`, where the
  protected server blocks the direct CommonsCollections `ChainedTransformer`
  gadget before the marker file is created, and the real `vulhub/j2ee:8u111`
  RMI Registry JRMP bypass path through
  `scripts/acceptance-vulhub-rmi-registry-bypass-java8.sh`, where the
  protected server blocks the second-stage CommonsCollections
  `ChainedTransformer` gadget before the marker file is created.
- `deserialization_remoting_transport` covers dangerous Java deserialization
  gadget classes resolved while an application-server remoting transport is
  unmarshalling protocol frames. The initial transport family is WebLogic T3 and
  IIOP dispatch, covering CVE-2018-2628-style T3 JRMPClient payloads and
  CVE-2023-21839-style IIOP/JNDI remote-reference flows while avoiding ordinary
  remoting calls that deserialize only benign peer metadata or service DTOs. The
  playground and acceptance suite include Vulhub-shaped WebLogic CVE-2018-2628
  T3 JRMPClient and CVE-2023-21839 IIOP/JNDI deserialization replays. The real
  Java 6 WebLogic CVE-2018-2628 Vulhub boundary in
  `scripts/acceptance-vulhub-weblogic-2628-java6-legacy.sh` proves the baseline
  JRMPClient2 replay reaches the JRMP listener and creates a marker, while the
  current Java 8 agent cannot inject into the Java 6u45 runtime. The real Java
  8 WebLogic CVE-2023-21839 Vulhub acceptance proves the baseline IIOP/JNDI
  replay reaches an outbound LDAP listener and protected mode blocks the same
  remote lookup with `java8_jndi_remote_lookup` before the listener is reached.
- `deserialization_jms_object_message` covers dangerous Java deserialization
  gadget classes resolved while a JMS provider is deserializing an
  `ObjectMessage` body. This targets ActiveMQ CVE-2015-5254-style broker or web
  console message browsing flows while avoiding ordinary JMS text/map/bytes
  messages and `ObjectMessage` values that deserialize only benign application
  DTOs. The playground and acceptance suite include the Vulhub-shaped ActiveMQ
  web-console `GET /admin/message.jsp` browse flow. The real ActiveMQ
  CVE-2015-5254 Vulhub probe verifies the jmet ROME `ObjectMessage` baseline
  on Oracle Java 7u21/ActiveMQ 5.11.1 and records that current Java 8+ LTS
  agents cannot inject into that legacy JVM because it rejects classfile major
  version 52.0.
- `deserialization_signed_object` covers `java.security.SignedObject`
  deserialization on remote CLI/remoting object-stream stacks. This targets
  Jenkins CVE-2017-1000353-style SignedObject blacklist-bypass payloads while
  avoiding ordinary application signature verification flows outside remote CLI
  transports. The playground and acceptance suite include the direct
  Vulhub-shaped Jenkins CLI `POST /cli` stream. Real Java 8 Vulhub evidence is
  provided by `scripts/acceptance-vulhub-jenkins-1000353-java8.sh`: baseline
  Jenkins 2.46.1 accepts the CLI upload/download stream and creates
  `/tmp/ohmyrasp-jenkins-1000353-success`, while protected mode blocks
  `java8_deserialization_gadget_class` on the Commons Collections
  `ChainedTransformer` gadget before marker creation.
- `deserialization_session_file` covers file-backed servlet session
  deserialization when the session identifier is filesystem-shaped, such as a
  hidden-file name, traversal, slash, or encoded path separator. This targets
  Tomcat-style partial PUT session-store chains where a serialized object is
  written under the session work directory and later loaded through a crafted
  `JSESSIONID`, including URLDNS-style payloads that may not use a known gadget
  class. The playground and acceptance suite include the Vulhub-shaped Tomcat
  CVE-2025-24813 flow and assert on the `GET /` session load with
  `JSESSIONID=.deserialize`. Real Java 8 Vulhub evidence is provided by
  `scripts/acceptance-vulhub-tomcat-24813-java8.sh`: baseline Tomcat 9.0.97
  accepts the partial `PUT /deserialize/session` session file, then resolves
  the URLDNS payload during the cookie-triggered session load, while protected
  mode hooks Tomcat `AuthenticatorBase.invoke` early and blocks
  `java8_request_session_file_deserialization` before the protected DNS
  lookup occurs.
- `deserialization_protocol_class` covers message-protocol unmarshalling that
  attempts to instantiate an attacker-selected Java class, with ActiveMQ
  OpenWire throwable unmarshalling as the runtime hook. It is distinct from
  ordinary Java object streams and JSON/YAML polymorphic type resolution, and
  catches dangerous gadget families or Spring/XBean application context classes
  such as the CVE-2023-46604 remote XML payload shape. The playground and
  acceptance suite include the direct Vulhub-shaped ActiveMQ `/api/openwire`
  flow with an OpenWire-selected Spring context class and remote `poc.xml`.
  `scripts/acceptance-vulhub-activemq-46604-java11.sh` provides real Vulhub
  application evidence: baseline loads the remote Spring XML and creates
  `/tmp/ohmyrasp-activemq46604-success`, while protected mode blocks the
  Spring bean-init `ProcessBuilder.start` sink as
  `java11_command_execution_exploit_primitive`.
- `deserialization_http_invoker` covers Spring HTTP Invoker endpoints when they
  deserialize a Java object stream for a remote invocation request. This targets
  Dubbo HTTP protocol/Spring remoting shapes such as CVE-2019-17564 at the
  framework boundary before any particular gadget class is resolved, and logs
  only request metadata such as method, URI, content type, and mechanism. The
  playground and acceptance suite include the Vulhub-shaped Dubbo
  `/org.vulhub.api.CalcService` POST flow, and the Java 8 Vulhub acceptance
  verifies the lower-level Spring HTTP Invoker object-stream sink blocks a
  CommonsCollections6 payload before gadget side effects.
- `deserialization_http_object_stream` covers Java `ObjectInputStream`
  construction over a servlet/request-body input stream during an active HTTP
  request, plus Java-serialized request content types and known middleware
  HTTP-invoker stacks. This targets JBoss HTTPInvoker, JMXInvokerServlet, and
  JBossMQ HTTPIL object-stream deserialization boundaries before relying on a
  particular gadget class, while ignoring file/background object streams. The
  playground and acceptance suite include the Vulhub-shaped `/invoker/readonly`,
  `/invoker/JMXInvokerServlet`, and `/jbossmq-httpil/HTTPServerILServlet` POST
  flows for JBoss CVE-2017-12149, the classic JMXInvokerServlet issue, and
  CVE-2017-7504. The real JBoss CVE-2017-12149 Vulhub probe verifies the
  `/invoker/readonly` CommonsCollections5 object-stream baseline on Java
  7u221/JBoss AS 6.1.0 and records that current Java 8+ LTS agents cannot
  inject into that legacy JVM because it rejects classfile major version 52.0.
  The real JBoss JMXInvokerServlet Vulhub probe verifies the
  `/invoker/JMXInvokerServlet` CommonsCollections5 object-stream baseline on
  Java 7u221/JBoss AS 6.1.0 and records the same Java 7 runtime boundary for
  current Java 8+ LTS agents.
  The real JBossMQ CVE-2017-7504 Vulhub probe verifies the
  `/jbossmq-httpil/HTTPServerILServlet` CommonsCollections5 object-stream
  baseline on Java 7u221/JBoss AS 4.0.5 and records the same Java 7 runtime
  boundary for current Java 8+ LTS agents.
- `deserialization_hessian_type` covers Hessian/Burlap-style RPC
  deserialization when the wire type name resolves to a known dangerous gadget,
  Java runtime/JNDI class, Spring/XBean application context, or other blocked
  construction type. This targets older XXL-JOB Hessian-RCE style executor
  chains without blocking ordinary Hessian requests that only carry benign
  maps, lists, DTOs, or primitives. The playground and acceptance suite include
  the Vulhub-shaped XXL-JOB `POST /xxl-job-admin/api` Hessian request with
  `Content-Type: x-application/hessian`. The Java 8/11/17 backports now carry
  era-prefixed Hessian type hooks (`java8_deserialization_hessian_type`,
  `java11_deserialization_hessian_type`, and
  `java17_deserialization_hessian_type`); the current Vulhub
  `xxl-job/unacc` 2.2.0 image was probed and records only a non-graduated
  candidate because its admin/core jars do not contain the old Hessian
  dependency referenced by the README for pre-2.2.0 deployments.
- `deserialization_xmlrpc_serialized` covers Apache XML-RPC extension values
  where a `<serializable>` XML element is decoded and passed to
  `ObjectInputStream` during request handling. This targets Apache OFBiz XMLRPC
  deserialization chains, including CVE-2020-9496 and CVE-2023-49070, without
  blocking ordinary XML-RPC primitives, arrays, structs, or base64 byte values.
  The playground and acceptance suite include the Vulhub-shaped
  `/webtools/control/xmlrpc` XML-RPC serialized-value POST flow. Real Java 8
  Vulhub evidence is provided by
  `scripts/acceptance-vulhub-ofbiz-9496-java8.sh`: baseline OFBiz 17.12.01
  creates `/tmp/ohmyrasp-ofbiz-9496-success`, while protected mode blocks
  `java8_deserialization_gadget_class` on `TemplatesImpl` before the marker is
  created. `scripts/acceptance-vulhub-ofbiz-49070-java8.sh` covers the
  unauthenticated OFBiz 18.12.09
  `/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=&requirePasswordChange=Y`
  variant: baseline creates `/tmp/ohmyrasp-ofbiz-49070-success`, while
  protected mode blocks the same gadget class before marker creation.
- `deserialization_rmi_registry_bind` covers RMI Registry `bind`/`rebind`
  calls that arrive through RMI transport dispatch and carry a proxy or
  UnicastRef-style remote reference. This targets Java RMI Registry
  deserialization and JRMP listener bypass shapes while ignoring ordinary local
  application registry binds and logging only operation, binding name, remote
  object class, and transport source. The playground and acceptance suite
  include both the Vulhub proxy-bind payload and the UnicastRef/JRMP listener
  bypass shape.
- `deserialization_polymorphic_type` covers parser-supplied dangerous class
  resolution in Fastjson, Jackson, XStream, and SnakeYAML. This includes
  Fastjson autoType `JdbcRowSetImpl` JNDI chains, Fastjson 1.2.47-style
  `java.lang.Class` bypasses that later resolve the concrete dangerous class,
  Jackson wrapper-array `TemplatesImpl` and Spring XML application context
  gadgets, and SnakeYAML construction of `org.h2.jdbc.JdbcConnection`, which
  can immediately open attacker-controlled H2 JDBC URLs with `INIT` payloads as
  seen in HertzBeat-style YAML import RCE chains. The playground and acceptance
  suite include Vulhub-shaped `/fastjson` JSON POSTs for CVE-2017-18349 and
  Fastjson 1.2.47, plus real Java 8 Fastjson 1.2.24 and 1.2.45
  baseline/protected containers in `scripts/acceptance-vulhub-fastjson-java8.sh`.
  They also include `/exploit` JSON POSTs for Jackson CVE-2017-7525 and its
  Spring XML context bypass, and a SnakeYAML `JdbcConnection` constructor hook
  for the HertzBeat CVE-2024-42323 parser boundary. The real Jackson Vulhub
  probe verifies both the CVE-2017-7525 `TemplatesImpl` baseline and the
  CVE-2017-17485 Spring XML baseline on Java 7u21, then records that current
  Java 8+ LTS agents cannot inject into that legacy JVM because it rejects
  classfile major version 52.0.
- `sql_h2_code_execution` covers H2 SQL statements that load remote scripts or
  define executable Java code through aliases, triggers, or similar code
  containers. This targets H2 console RCE flows such as CVE-2018-10054 without
  blocking ordinary H2 DDL like safe aliases for JDK methods, because the rule
  requires both an H2 code container and a dangerous execution primitive. The
  playground and acceptance suite include the Vulhub-shaped authenticated
  `/h2-console/query.do` SQL form post, plus the real Java 8 H2 1.4.197
  baseline/protected acceptance in `scripts/acceptance-vulhub-h2-10054-java8.sh`.
  The real DataEase CVE-2025-32966 OpenJDK 21 runtime acceptance verifies the
  adjacent H2 JDBC constructor sink: baseline creates a marker through a
  forged-token datasource validation request, and protected mode blocks at
  `org.h2.jdbc.JdbcConnection.<init>` with `java17_jdbc_h2_code_execution`.
- `jdbc_mysql_deserialization` covers request-controlled MySQL/MariaDB JDBC
  URLs that enable Connector/J deserialization behavior through
  `autoDeserialize` plus interceptor or custom-collation trigger options. This
  targets Linkis-style rogue/fake MySQL datasource testing chains without
  blocking ordinary configured database connections. The playground and
  acceptance suite include the Vulhub-shaped Linkis CVE-2022-44645
  `/api/rest_j/v1/data-source-manager/op/connect/json` datasource test body,
  with aliases for the later JDBC-parameter blacklist bypass family
  CVE-2023-27987, CVE-2023-29215, and CVE-2023-46801. Real Java 8 Vulhub
  evidence is provided by `scripts/acceptance-vulhub-linkis-44645-java8.sh`:
  baseline Linkis connects to a rogue MySQL listener, while protected mode
  blocks at `DriverManager.getConnection` with
  `java8_jdbc_mysql_deserialization` before any rogue server connection is
  made.
- `sql_derby_code_execution` covers request-time Derby SQL that installs JARs,
  mutates `derby.database.classpath`, or creates Java external routines. This
  targets Nacos-style Derby ops endpoints that load attacker-provided Java code
  through SQL while avoiding startup/migration routines outside an active
  request. The playground and acceptance suite include the Vulhub-shaped Nacos
  CVE-2021-29442 `/nacos/v1/cs/ops/derby?sql=...` endpoint. The Java 8 Nacos
  Vulhub acceptance also verifies the lower-level database Java routine command
  sink blocks the loaded `Exec.exec` function before command output is returned.
- `jndi_jaas_config` covers request-time JAAS configuration strings that select
  `com.sun.security.auth.module.JndiLoginModule` with remote provider URLs such
  as `ldap://` or `rmi://`. This targets Kafka-client/Druid-style
  `sasl.jaas.config` injection before the later JNDI lookup is attempted. The
  playground and acceptance suite include the Vulhub-shaped Kafka
  CVE-2023-25194 `POST /druid/indexer/v1/sampler?for=connect` sampler body.
  The real Java 8 Druid/Kafka Vulhub acceptance starts Druid 25.0.0 on Oracle
  Java 8u172: baseline reaches an attacker-controlled LDAP listener from the
  README-shaped sampler request, while protected mode blocks
  `AppConfigurationEntry.<init>` with `java8_jaas_jndi_remote_provider` before
  the LDAP connection is made.
- `readFile_argument_expansion` covers request-time command argument parsers
  that expand `@file` arguments into local file contents, such as args4j in
  Jenkins CLI handling. The detector is gated to args4j and sensitive absolute
  or traversal-shaped paths, so ordinary local argfiles are ignored. The
  playground and acceptance suite include Vulhub-shaped Jenkins
  CVE-2024-23897 CLI vectors for `help 1 "@/proc/self/environ"` and
  `connect-node "@/etc/passwd"`.
- `ssrf_userinput` covers outbound network requests to internal addresses or
  raw URL values copied from the active request parameters. The Java 8/11/17
  URL hooks preserve same-thread servlet request parameter URLs and emit
  `java8_ssrf_request_parameter_url`, `java11_ssrf_request_parameter_url`, or
  `java17_ssrf_request_parameter_url` when the same absolute HTTP(S) URL is
  opened by the server. This targets GeoServer `TestWfsPost`
  CVE-2021-40822-style unauthenticated relays where a `url=` parameter is
  passed to a server-side HTTP client; the real Java 17 Vulhub acceptance
  verifies the baseline listener relay and protected block. It also covers
  WebLogic UDDI Explorer SSRF where an `operator=` URL targets internal HTTP or
  Redis services, including CRLF-shaped Redis command payloads; the real Vulhub
  UDDI script proves the Java 6u45 baseline relay to a host listener, but records
  the target as a legacy runtime boundary because the Java 6 JVM rejects the
  Java 8 agent classfile version. Public external URLs that are not
  request-controlled remain allowed.
- `ssrf_protocol`, `ssrf_userinput`, and related SSRF algorithms also cover XML
  attachment resolvers that fall back from MTOM/XOP content IDs to URL loading.
  This targets Apache CXF Aegis-style `xop:Include href` SSRF/file reads while
  leaving ordinary `cid:` attachments and public HTTP references alone. The
  playground and acceptance suite include the Vulhub-shaped
  `/test` multipart SOAP request for Apache CXF CVE-2024-28752, and the real
  Java 8 Vulhub acceptance verifies the lower-level file-read sink blocks the
  same `file:///etc/hosts` XOP reference before disclosure.
- `fileUpload_path_traversal` covers multipart upload filenames that contain
  parent-directory or absolute-path attempts, including encoded forms. This
  targets arbitrary file writes such as Apache Flink `/jars/upload` filename
  traversal while still allowing ordinary relative subdirectory filenames. The
  playground and acceptance suite include the Vulhub-shaped Flink
  CVE-2020-17518 `POST /jars/upload` multipart request.
- `fileUpload_multipart_script` covers multipart uploads of server-side script
  and server config files such as JSP, JSPX, `.htaccess`, and `.user.ini`.
  Java 8/11/17 upload transformers cover Servlet `Part`, Commons FileUpload,
  Jetty multipart, Spring `MultipartFile`, and Jersey
  `org.glassfish.jersey.media.multipart.ContentDisposition.getFileName`. This
  targets WebLogic CVE-2018-2894-style Web Service Test Page uploads to
  `/ws_utc/resources/setting/keystore` as well as other webshell upload
  surfaces. The real Java 8 Vulhub acceptance
  `scripts/acceptance-vulhub-weblogic-2894-java8.sh` verifies baseline
  execution of an uploaded JSP and protected blocking before the JSP is written.
- `fileUpload_multipart_expression` covers multipart upload filenames whose
  filename value itself contains a dangerous expression payload, including
  Struts2 S2-046/CVE-2017-5638-style OGNL parser expressions in the part
  `filename` header with NUL suffix splitting. It logs only inferred engine and
  filename length so expression payloads are not echoed into security logs. The
  playground and acceptance suite include the Vulhub-shaped `/index.action`
  multipart upload filename payload for S2-046/CVE-2017-5638.
- `fileUpload_java_archive` covers uploads of Java executable archives such as
  JAR, WAR, EAR, or `.class` files only when the active request context is a
  plugin, extension, driver, connector, job, or JAR deployment surface. This
  targets plugin/JAR execution surfaces such as MeterSphere plugin upload and
  Flink JAR upload without blocking ordinary repository artifact uploads. The
  playground and acceptance suite include the Vulhub-shaped MeterSphere
  `POST /plugin/add` multipart `Evil.jar` upload across Java 17/Tomcat
  11/10.1/9, Java 11/Tomcat 10.1/9, and Java 8/Tomcat 10.0/9/8.5. Real
  Vulhub evidence is `scripts/acceptance-vulhub-metersphere-plugin-java8.sh`:
  baseline MeterSphere 1.16.3 loads the official Vulhub Backdoor plugin and
  executes `org.vulhub.Evil`, while protected mode blocks the same upload at
  `MultipartUpload.filename` before the plugin JAR is written or loaded. The
  real Java 8 Flink Vulhub acceptance also verifies that the lower-level
  file-move sink blocks a traversal `.jar` upload before the marker content is
  created.
- `fileUpload_webdav` covers WebDAV-style `MOVE`/`COPY` operations that produce
  server-side script files or write to unsafe absolute filesystem destinations.
  This targets ActiveMQ fileserver CVE-2016-3088 shapes such as moving an
  uploaded file from `/fileserver/2.txt` to
  `file:///opt/activemq/webapps/api/s.jsp` or `file:///etc/cron.d/root` while
  ignoring ordinary WebDAV renames inside the shared file area. The real
  ActiveMQ CVE-2016-3088 Vulhub probe verifies the PUT/MOVE webroot JSP write
  baseline on Oracle Java 7u21/ActiveMQ 5.11.1 and records that current Java
  8+ LTS agents cannot inject into that legacy JVM because it rejects classfile
  major version 52.0.
- `archive_traversal` covers archive extraction where the current archive entry
  contains parent-directory, absolute-path, or NUL-path traversal and the
  subsequent file write uses that unsafe entry as the output path. The Java
  agents capture both JDK `ZipEntry.getName()` and SevenZipBinding
  `SimpleInArchiveItemImpl.getPath()` entries. This targets ZipSlip-style
  document preview chains such as kkFileView 4.3 writing a crafted `uno.py`
  under LibreOffice while ignoring sanitized extraction that rewrites unsafe
  entries to safe destinations. The playground and acceptance suite include the
  Vulhub-shaped `/onlinePreview` preview flow with the kkFileView POC ZIP
  entry.
- `java_compile_runtime` covers request-time Java source compilation through
  JDK `JavacTool` and Janino-style source APIs when the source contains runtime
  execution primitives, covering GeoServer/JAI-EXT Jiffle-style code injection
  without matching product-specific request signatures.
- `xml_decoder_runtime` and `xml_decoder_webshell` cover JavaBeans XMLDecoder
  object graphs that invoke process/runtime primitives or create server-side
  script writers, covering WebLogic WorkContext XMLDecoder-style RCE without a
  WebLogic-specific path signature. The playground and acceptance suite include
  the Vulhub-shaped `/wls-wsat/CoordinatorPortType` SOAP `WorkContext`
  `XMLDecoder` flow for CVE-2017-10271. The real Vulhub WebLogic
  CVE-2017-10271 script proves baseline Java 6u45 marker creation through
  `ProcessBuilder.start`, but records the environment as a legacy runtime
  boundary because the Java 6 JVM rejects the Java 8 agent classfile version.
- `xxe_external_entity_protocol` ignores trusted local framework metadata
  resources required for normal startup, including WebLogic's local
  `jar:file:/u01/oracle/wlserver/modules/com.oracle.weblogic.security.service.store.jar!/com/bea/common/security/store/data/package.jdo`
  security-store descriptor. This keeps WebLogic 12.2.1.3 startup quiet while
  preserving detection for arbitrary local-file, local-jar, and remote-protocol
  external entities. The 2026-06-06 full LTS Tomcat rerun passed Java 17
  Tomcat 11 -> 10.1 -> 9, Java 11 Tomcat 10.1 -> 9, and Java 8 Tomcat 10.0
  -> 9 -> 8.5 after this allowlist refinement.
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
