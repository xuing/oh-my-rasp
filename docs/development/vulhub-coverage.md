# Vulhub Java Coverage Checklist

Use this checklist before selecting or implementing another Java-compatible
Vulhub target. A checked item means this repository has a behavior rule or sink
hook plus playground/acceptance coverage; the protected-side acceptance key is
listed in backticks where one exists.

Update this file in the same patch as any new Vulhub coverage. If a target is
only being evaluated, add it under "Candidates" first, then move it to the
covered section after the baseline/protected acceptance rows pass.

## Execution Rules

- [x] Keep this file as the durable work ledger: every evaluated Vulhub target
  must appear here with its component, CVE or path, expected baseline proof,
  matching LTS agent, and protected-side block condition before probing starts.
- [x] Do not mark a vulnerability or component as real Vulhub acceptance until
  the baseline container proves exploitation and the protected container blocks
  the same behavior with the matching Java LTS agent.
- [x] When a target graduates from "Candidates", add or update the checked
  component/vulnerability row under "Covered Targets" and leave a new
  placeholder candidate row behind for the next target.
- [x] If an agent hook or shared detector behavior changes, rerun the Tomcat
  compatibility matrix in LTS order: Java 17 with Tomcat 11 -> 10.1 -> 9,
  Java 11 with Tomcat 10.1 -> 9, then Java 8 with Tomcat 10.0 -> 9 -> 8.5.
- [x] During iterative main-Tomcat work, test Tomcat 11 first by default and
  run Tomcat 10/9 only after the current coverage work is complete, unless the
  changed code requires the full LTS matrix immediately.
- [x] Run `python3 java-agent/scripts/check-vulhub-java-coverage.py` after
  updating this ledger to verify every scoped Java/JVM README path is
  mentioned, every scoped CVE token is present in the coverage corpus, every
  checked Covered Targets row has either real acceptance evidence or an
  explicit boundary reason, the Source Audit counts match the audited
  snapshot, and the placeholder candidate row remains present.

## Source Audit

Last audited Vulhub snapshot: `/tmp/vulhub-ohmyrasp-20260603` at commit
`d277a86`; `git pull --ff-only` returned `Already up to date` on 2026-06-11.

**Root-completeness re-verified 2026-06-20.** An exhaustive enumeration of all
152 environments in the snapshot — byte-identical to the live clone at
`/home/ubuntu/vulhub` (same commit `d277a86`, no dir diffs) — confirms every
Java/JVM environment maps to one of the 53 roots below. The only non-covered
directories that even reference a Java/Tomcat base image are `base/` (Vulhub's
shared base images, not a vulnerability env) and `httpd/` (an Apache HTTP Server
/ C env whose Tomcat image is only an SSRF proxy backend, not a Java app a Java
RASP can protect); `zabbix/` and the remainder are non-Java. **No uncovered Java
vulnerability environment remains in the corpus at this commit.** The
"Continue expanding Java 8/11/17" items below therefore refer to deeper
per-root CVE / runtime-matrix depth, **not** new roots; only a future upstream
`vulhub` pull could introduce a new Java root to scope.

Java/JVM source scope currently covers 53 Vulhub roots and 148 README
environment or alias paths:

`activemq`, `aj-report`, `apache-cxf`, `apache-druid`, `apereo-cas`,
`coldfusion`, `confluence`, `dataease`, `dubbo`, `elasticsearch`, `fastjson`,
`flink`, `geoserver`, `glassfish`, `h2database`, `hadoop`, `hertzbeat`,
`hugegraph`, `jackson`, `java`, `jboss`, `jenkins`, `jetty`, `jimureport`,
`jira`, `jmeter`, `kafka`, `kkfileview`, `liferay-portal`, `linkis`, `log4j`,
`metabase`, `metersphere`, `mojarra`, `nacos`, `neo4j`, `nexus`, `ofbiz`,
`openfire`, `opentsdb`, `rocketmq`, `shiro`, `skywalking`, `solr`, `spark`,
`spring`, `struts2`, `teamcity`, `tomcat`, `unomi`, `weblogic`, `xstream`,
and `xxl-job`.

The Java/JVM README CVE-token audit is currently balanced: 130 unique Vulhub
CVE tokens are present in this checklist, `java-agent/scripts/acceptance.sh`,
or `docs/development/algorithm-coverage.md`. Non-CVE or alias paths checked in
the same audit:

- [x] `fastjson/vuln` is a redirect README to `fastjson/1.2.24-rce`.
- [x] `kafka/CVE-2023-25194` is replayed through the Apache Druid sampler flow
  (`jndi_kafka_cve_2023_25194_druid_sampler_jaas`).
- [x] `geoserver/CVE-2022-24816` also names CVE-2023-35042 for the same
  JAI-EXT/Jiffle behavior.
- [x] `geoserver/CVE-2023-25157` also references CVE-2023-25158 for the same
  CQL filter SQL injection family.
- [x] `geoserver/CVE-2024-36401` also references CVE-2022-41852 for WFS
  `valueReference` XPath execution.
- [x] `nexus/CVE-2020-10204` also references the CVE-2018-16621 patch-bypass
  predecessor.
- [x] `nexus/CVE-2024-4956` also references Spring MVC CVE-2018-1271 path
  normalization behavior.
- [x] `ofbiz/CVE-2024-45195` also references CVE-2024-32113,
  CVE-2024-36104, and CVE-2024-38856 as incomplete-fix predecessors.
- [x] `tomcat/CVE-2026-34486` also references CVE-2026-29146 as the
  EncryptInterceptor padding-oracle predecessor.
- [x] `teamcity/CVE-2024-27198` also references CVE-2024-27199 for the same
  JetBrains TeamCity authentication-bypass vulnerability family.
- [x] `weblogic/CVE-2020-14882` also references the CVE-2020-14883 ShellSession
  execution half and the CVE-2019-2725 FileSystemXmlApplicationContext handle
  chain.

Image-backed Java service boundary audit:

- [x] `httpd/CVE-2021-40438` includes `vulhub/tomcat:8.5.19`, but the
  vulnerable process is Apache httpd `mod_proxy`; Tomcat is only the backend
  demonstration service and cannot protect the proxy SSRF path through Java
  RASP injection.
- [x] `kibana/CVE-2018-17246`, `kibana/CVE-2019-7609`, and
  `kibana/CVE-2020-7012` include Elasticsearch services, but the vulnerable
  process is Kibana's Node.js runtime; Elasticsearch is supporting storage and
  is not the injectable vulnerable Java application for these environments.
- [x] `base/jeecg-boot/3.5.3` is a Java base image only; there is no matching
  top-level Vulhub vulnerability README environment in the current snapshot.

## Runtime Era Compatibility Audit

Current Java agent build and acceptance coverage are Java 25 based:

- [x] `java-agent/build.gradle.kts` uses `JavaLanguageVersion.of(25)` and
  `options.release.set(25)`.
- [x] `java-agent/Dockerfile` builds with `gradle:jdk25`.
- [x] `java-agent/docker-compose.yml` defines Tomcat 9, 10, and 11
  `tomcat:*-jdk25` images; `java-agent/scripts/acceptance.sh` runs them in the
  required order Tomcat 11 -> 10 -> 9.
- [x] Iterative main-Tomcat validation defaults to Tomcat 11 first; Tomcat 10
  and Tomcat 9 are run after the current coverage work is complete.
- [x] Tomcat validation is paired with the target JDK LTS compatibility
  matrix, using Apache Tomcat's supported Java version table as the source of
  truth: each LTS agent track must cover every currently supported Tomcat major
  version that can run on that JDK, with the correct Servlet namespace for that
  Tomcat line.
- [x] The compatibility matrix also records EOL-but-JDK-compatible Tomcat
  lines that matter for Vulhub-era coverage: Java 8 gets Tomcat 10.0
  (`jakarta.servlet`), Tomcat 9, and Tomcat 8.5; Java 11 gets Tomcat 10.1 and
  9; Java 17 gets Tomcat 11, 10.1, and 9. Apache Tomcat's 2026 version table
  lists currently supported Tomcat lines as 11.0/Java 17+, 10.1/Java 11+, and
  9.0/Java 8+, with 10.0/Java 8+ and 8.5/Java 7+ already EOL.
- [x] `ControlPlaneClient` reports non-Java-25 runtimes as outside the primary
  supported range and tells operators to use the agent build matching the
  runtime LTS line.

Vulhub Java/JVM base-image runtime spread is not Java 25. The current snapshot
has 110 Java-ish final `FROM` lines under `base/`: 84 Java 8/Tomcat 8 style
images, 4 Java 11 images, 11 Java 17 images, 8 Java 7/Tomcat 7 legacy images,
and 4 vendor or indirect images (`adobecoldfusion/coldfusion2018`,
`vulhub/elasticsearch:1.5.1`, `docker.elastic.co/elasticsearch:7.6.2`, and
`tomcat:6`).

Runtime-era work that is still required before claiming real Vulhub injection
coverage, separate from the Java 25 behavioral replay suite:

- [x] Build a dedicated Java 8 era startup-probe agent scaffold under
  `java-agent/agent-java8`; `:agent-java8:check` verifies compiled classfiles
  are Java 8 compatible (`major version: 52`), and a Temurin 8 `-javaagent`
  smoke run emitted `instrumentation:"available"`.
- [x] Add the first functional Java 8 era behavior hook:
  `ProcessBuilder.start` and `Runtime.exec` are transformed by the dedicated
  Java 8 agent, suspicious command-execution primitives emit
  `java8_command_execution_exploit_primitive` or
  `java8_command_execution_shell_meta`, normal `/bin/true` smoke traffic emits
  no detection, and block mode records `action:"block"` before throwing
  `Java8RaspBlockException` on Temurin 8.
- [x] Add the second functional Java 8 era behavior hook: `InitialContext.lookup`
  and `lookupLink` are transformed by the dedicated Java 8 agent, remote
  LDAP/RMI/IIOP/CORBA naming URLs emit `java8_jndi_remote_lookup`,
  `java:comp/env` smoke traffic emits no detection, and block mode records
  `action:"block"` before throwing `Java8RaspBlockException` on Temurin 8.
- [x] Add the third functional Java 8 era behavior hook:
  `ObjectInputStream.resolveClass` and `resolveProxyClass` are transformed by
  the dedicated Java 8 agent, including Spring HTTP Invoker
  `ConfigurableObjectInputStream` and `CodebaseAwareObjectInputStream`
  subclasses, high-risk gadget/execution primitive classes emit
  `java8_deserialization_gadget_class`, normal string deserialization emits no
  detection, and block mode records `action:"block"` before throwing
  `Java8RaspBlockException` on Temurin 8.
- [x] Add the fourth functional Java 8 era behavior hook: `FileInputStream`,
  `FileOutputStream`, `RandomAccessFile`, and `java.nio.file.Files` content
  read/write and byte-channel open APIs are transformed by the dedicated Java 8
  agent, sensitive reads emit `java8_file_sensitive_read`, webroot
  script/executable writes emit `java8_file_script_write`, normal temporary
  file read/write smoke traffic emits no detection, and block mode records
  `action:"block"` before throwing `Java8RaspBlockException` on Temurin 8.
- [x] Add the fifth functional Java 8 era behavior hook: `URL.openConnection`
  and `openStream` are transformed by the dedicated Java 8 agent, cloud
  metadata URLs emit `java8_ssrf_cloud_metadata`, loopback administrative paths
  emit `java8_ssrf_loopback_admin`, normal public URL smoke traffic emits no
  detection, and block mode records `action:"block"` before throwing
  `Java8RaspBlockException` on Temurin 8.
- [x] Add the sixth functional Java 8 era behavior hook: `ZipEntry.getName`
  is transformed by the dedicated Java 8 agent and correlated with subsequent
  Java file-write sinks, archive entry traversal emits
  `java8_archive_entry_traversal_write`, safe archive entry smoke traffic emits
  no detection, and block mode records `action:"block"` before throwing
  `Java8RaspBlockException` on Temurin 8.
- [x] Add the seventh functional Java 8 era behavior hook:
  `DriverManager.getConnection` and direct H2 `org.h2.jdbc.JdbcConnection`
  constructors are transformed by the dedicated Java 8 agent, H2 `INIT`
  code-execution URLs emit `java8_jdbc_h2_code_execution`, Derby Java
  code-loading JDBC URLs emit `java8_jdbc_derby_code_loading`, MySQL
  `autoDeserialize` interceptor/custom-collation JDBC URLs emit
  `java8_jdbc_mysql_deserialization`, normal JDBC URL smoke traffic emits no
  detection, and block mode records `action:"block"` before throwing
  `Java8RaspBlockException` on Temurin 8.
- [x] Add the eighth functional Java 8 era behavior hook: `URLClassLoader`
  constructors, `URLClassLoader.addURL`, and `RMIClassLoader` codebase APIs are
  transformed by the dedicated Java 8 agent, remote HTTP(S)/FTP/LDAP/RMI
  codebases and `jar:`-wrapped remote codebases emit
  `java8_classloader_remote_codebase`, local `file:` classpath URLs emit no
  detection, Felix/OSGi internal `http://felix.extensions:<port>/`
  extension-bundle codebases emit no detection, and block mode records
  `action:"block"` before throwing `Java8RaspBlockException` on Temurin 8.
- [x] Add the ninth functional Java 8 era behavior hook:
  `ScriptEngine.eval(String...)` is transformed through `AbstractScriptEngine`,
  Nashorn, and `ScriptEngineImpl` implementations, runtime/reflective runtime,
  `ProcessBuilder`, nested script-engine eval, or string-literal `.execute()`
  primitives emit `java8_script_engine_runtime_execution`, ordinary arithmetic
  script smoke traffic emits no detection, and block mode records
  `action:"block"` before throwing `Java8RaspBlockException` on Temurin 8.
- [x] Add the tenth functional Java 8 era behavior hook: Java source
  compilation is transformed through `JavacTool.getTask` and Janino-style
  `cook`/`compile(String...)` sources, source containing `Runtime.exec`,
  `ProcessBuilder.start`, or nested `ScriptEngine.eval` primitives emits
  `java8_java_compile_runtime_execution`, ordinary source compilation smoke
  traffic emits no detection, and block mode records `action:"block"` before
  throwing `Java8RaspBlockException` on Temurin 8.
- [x] Add the eleventh functional Java 8 era behavior hook:
  `AppConfigurationEntry` construction is transformed by the dedicated Java 8
  agent, JAAS `JndiLoginModule` entries with remote `user.provider.url` or
  `group.provider.url` values emit `java8_jaas_jndi_remote_provider`, ordinary
  Kerberos/SCRAM JAAS smoke traffic emits no detection, and block mode records
  `action:"block"` before throwing `Java8RaspBlockException` on Temurin 8.
- [x] Add the twelfth functional Java 8 era behavior hook:
  `JmxMBeanServer.invoke` is transformed by the dedicated Java 8 agent,
  mutating MBean operations with remote broker/Spring/XML configuration sources
  emit `java8_jmx_remote_config_source`, mutating MBean operations with
  server-side script or executable write targets emit
  `java8_jmx_script_file_write`, read-only MBean smoke traffic and benign log
  paths emit no detection, and block mode records `action:"block"` before
  throwing `Java8RaspBlockException` on Temurin 8.
- [x] Add the thirteenth functional Java 8 era behavior hook: JavaBeans
  `Statement.execute`, `Expression.getValue`, and XMLDecoder
  `DocumentHandler` exception handling are transformed by the dedicated Java 8
  agent, XMLDecoder object graphs that reach `ProcessBuilder.start`,
  `Runtime.exec`, or reflective invocation emit
  `java8_xml_decoder_runtime_execution`, XMLDecoder object graphs that
  construct server-side script writers emit
  `java8_xml_decoder_script_file_write`, ordinary JavaBeans statements outside
  an XMLDecoder stack emit no detection, and block mode records
  `action:"block"` before throwing `Java8RaspBlockException` on Temurin 8.
- [x] Add the fourteenth functional Java 8 era behavior hook: Xerces
  `XMLEntityManager.setupCurrentEntity` is transformed by the dedicated Java 8
  agent, XML external entities that resolve to `file:`, `jar:`, HTTP(S), FTP,
  LDAP, RMI/IIOP/CORBA-style, SMB/UNC, or similar remote-capable protocols emit
  `java8_xxe_external_entity_protocol`, ordinary XML without external entities
  emits no detection, and block mode records `action:"block"` before throwing
  `Java8RaspBlockException` on Temurin 8.
- [x] Refine the Java 8/11/17 XXE local runtime-resource allowlist after the
  WebLogic 12.2.1.3 startup probe: WebLogic's security store bootstrap parses
  the local embedded JDO metadata
  `jar:file:/u01/oracle/wlserver/modules/com.oracle.weblogic.security.service.store.jar!/com/bea/common/security/store/data/package.jdo`.
  That exact local `jar:file:` resource now stays quiet across Java 8/11/17,
  while arbitrary `file:`, `jar:`, and remote protocol external entities still
  emit the era-specific `xxe_external_entity_protocol` algorithms.
- [x] Run the real Java 8 WebLogic CVE-2020-14882/CVE-2020-14883 Vulhub
  application acceptance: `scripts/acceptance-vulhub-weblogic-14883-java8.sh`
  starts `vulhub/weblogic:12.2.1.3-2018` on Oracle JDK 8u151. Baseline
  reaches `/console/css/%252e%252e%252fconsole.portal` with the README-shaped
  `ShellSession("Runtime.exec('touch ...')")` handle and creates
  `/tmp/ohmyrasp-weblogic-14883-success`; protected mode starts quietly after
  the WebLogic JDO metadata allowlist refinement and blocks the encoded console
  auth-bypass path with `java8_request_path_confusion` before ShellSession
  command execution.
- [x] Refine Java 8/11/17 multipart upload filename coverage for real Jersey
  multipart stacks: the dedicated upload transformers now hook
  `org.glassfish.jersey.media.multipart.ContentDisposition.getFileName`, and
  `beforeFileUpload` classifies server-side script, expression-bearing,
  traversal, HTML, executable, and Java-archive upload filenames. This keeps
  ordinary image uploads quiet while making the previously documented
  `fileUpload_multipart_*` algorithms effective in real frameworks.
- [x] Run the real Java 8 WebLogic CVE-2018-2894 Vulhub application
  acceptance: `scripts/acceptance-vulhub-weblogic-2894-java8.sh` starts
  `vulhub/weblogic:12.2.1.3-2018` on Oracle JDK 8u151, waits through the
  WS_UTC on-demand deployment page, and sets Work Home Dir to the README static
  `ws_utc/css` path. Baseline uploads `ohmyrasp-wl2894.jsp` through
  `/ws_utc/resources/setting/keystore` and executes it from
  `/ws_utc/css/config/keystore/<id>_ohmyrasp-wl2894.jsp`; protected mode starts
  quietly and blocks the same Jersey multipart filename at
  `MultipartUpload.filename` with `fileUpload_multipart_script`, so no JSP is
  written.
- [x] Run the real Java 8 WebLogic CVE-2023-21839 Vulhub application
  acceptance: `scripts/acceptance-vulhub-weblogic-21839-java8.sh` starts
  `vulhub/weblogic:12.2.1.3-2018` on Oracle JDK 8u151. The baseline IIOP/JNDI
  replay binds a foreign opaque reference and resolves it, causing WebLogic to
  connect to a local LDAP listener; protected mode starts quietly, blocks the
  same remote lookup at `InitialContext.lookup` with
  `java8_jndi_remote_lookup`, and the protected LDAP listener receives no
  connection. Evidence:
  `/tmp/ohmyrasp-weblogic-21839-java8-20260611002449.log`.
- [x] Record the real Java 6 WebLogic weak-password/file-read legacy boundary:
  `scripts/acceptance-vulhub-weblogic-weak-password-java6-legacy.sh` starts
  `vulhub/weblogic:10.3.6.0-2017` with the Vulhub `/hello` WAR mounted. The
  baseline `GET /hello/file.jsp?path=/etc/passwd` discloses passwd content;
  the image reports `java version "1.6.0_45"`, and the current Java 8 agent
  cannot inject because the Java 6 JVM rejects classfile major version 52.0.
  This is recorded as a legacy runtime boundary rather than a protected LTS
  acceptance. Evidence:
  `/tmp/ohmyrasp-weblogic-weak-password-java6-20260611004044.log`.
- [x] Script the real Java 6 WebLogic CVE-2017-10271 WorkContext XMLDecoder
  legacy boundary: `scripts/acceptance-vulhub-weblogic-10271-java6-legacy.sh`
  starts `vulhub/weblogic:10.3.6.0-2017` on Java 6u45. The baseline
  README-shaped `/wls-wsat/CoordinatorPortType` SOAP `WorkContext` XMLDecoder
  payload reaches `ProcessBuilder.start` and creates
  `/tmp/ohmyrasp-weblogic-10271-success`; the current Java 8 agent cannot inject
  because the Java 6 JVM rejects classfile major version 52.0. This is recorded
  as a legacy runtime boundary rather than a protected LTS acceptance. Evidence:
  `/tmp/ohmyrasp-weblogic-10271-java6-20260611023347.log`.
- [x] Script the real Java 6 WebLogic CVE-2018-2628 T3/JRMPClient legacy
  boundary: `scripts/acceptance-vulhub-weblogic-2628-java6-legacy.sh` starts
  `vulhub/weblogic:10.3.6.0-2017` on Java 6u45 and uses the pinned
  `ysoserial-cve-2018-2628` JRMPClient2 payload plus the pinned T3 PoC source.
  The baseline T3 replay reaches the JRMP listener and creates
  `/tmp/ohmyrasp-weblogic-2628-success`; the current Java 8 agent cannot inject
  because the Java 6 JVM rejects classfile major version 52.0. This is recorded
  as a legacy runtime boundary rather than a protected LTS acceptance. Evidence:
  `/tmp/ohmyrasp-weblogic-2628-java6-20260611034352.log`.
- [x] Script the real Java 6 WebLogic UDDI Explorer SSRF legacy boundary:
  `scripts/acceptance-vulhub-weblogic-uddi-ssrf-java6-legacy.sh` starts
  `vulhub/weblogic:10.3.6.0-2017` on Java 6u45 with host-gateway resolution.
  Baseline first lets the on-demand UDDI application deploy, then the
  README-shaped `/uddiexplorer/SearchPublicRegistries.jsp` request relays
  `operator=http://host.docker.internal:<port>/...` to a host HTTP listener.
  The current Java 8 agent cannot inject because the Java 6 JVM rejects
  classfile major version 52.0. This is recorded as a legacy runtime boundary
  rather than a protected LTS acceptance. Evidence:
  `/tmp/ohmyrasp-weblogic-uddi-ssrf-java6-20260611024442.log`.
- [x] Script the real Java 6 Adobe ColdFusion CVE-2010-2861 legacy boundary:
  `scripts/acceptance-vulhub-coldfusion-2861-java6-legacy.sh` starts
  `vulhub/coldfusion:8.0.1` on Java 6u04. The baseline README-shaped
  `locale=../../../../../../../../../../etc/passwd%00en` request discloses
  passwd content; the image reports `java version "1.6.0_04"` from
  `/opt/coldfusion8/runtime/jre/bin/java`, and the current Java 8 agent cannot
  inject because the Java 6 JVM rejects classfile major version 52.0. This is
  recorded as a legacy runtime boundary rather than a protected LTS acceptance.
  Evidence: `/tmp/ohmyrasp-coldfusion-2861-java6-20260611022734.log`.
- [x] Remove duplicate candidate rows for boundaries already represented in
  Covered Targets on 2026-06-11: Struts2 S2-003 and WebLogic CVE-2019-2725 are
  source-availability boundaries because the audited Vulhub snapshot has no
  matching directories, and XXL-JOB Hessian is a dependency-version boundary
  because the current `vulhub/xxl-job:2.2.0-admin` image lacks the old Hessian
  classes referenced for pre-2.2.0 deployments.
- [x] Record the Confluence CVE-2019-3396 real-runtime setup boundary:
  `vulhub/confluence:6.10.2` reports OpenJDK 8 (`1.8.0_171`) and Tomcat
  9.0.10, so it is injectable by the Java 8 agent in principle. The baseline
  uninitialized Vulhub environment redirects `/` to
  `/bootstrap/selectsetupstep.action`, redirects setup to
  `/setup/setupstart.action`, leaves zero public tables in the Postgres
  `confluence` database, and returns `503 Setup in progress` for the
  README-shaped `/rest/tinymce/1/macro/preview` `_template` payload across 12
  stable-state attempts. This remains a setup/license boundary rather than a
  protected LTS acceptance. Evidence:
  `/tmp/ohmyrasp-confluence-3396-stable-probe-20260611010637.log`.
- [x] Script the Confluence real-runtime setup/license boundaries:
  `scripts/acceptance-vulhub-confluence-setup-boundaries.sh` starts the current
  Vulhub Confluence 6.10.2, 7.4.10, 7.13.6, 8.5.1, and 8.5.3 environments with
  their matching Postgres versions. The images report Java 8u171 or Java 11 LTS
  runtimes and are injectable in principle, but every uninitialized environment
  redirects `/` to `/bootstrap/selectsetupstep.action` and has zero public
  Confluence tables. The script verifies the README-shaped CVE-2019-3396,
  CVE-2021-26084, CVE-2022-26134, CVE-2023-22515, and CVE-2023-22527 payloads
  stay behind setup/license state: 3396 returns `503 Setup in progress`, 26084,
  26134, and 22527 redirect to setup with no `X-Cmd-Response`, and 22515's
  setup reset redirects while administrator creation returns the uninitialized
  Spring-context HTTP 500. Evidence:
  `/tmp/ohmyrasp-confluence-setup-boundaries-20260611030941.log`.
- [x] Script the Jira CVE-2019-11581 real Java 8 setup/license boundary:
  `scripts/acceptance-vulhub-jira-11581-setup-boundary-java8.sh` starts
  `vulhub/jira:8.1.0`, verifies OpenJDK 8u212 and an empty Jira home, then
  proves the uninitialized Vulhub runtime redirects `/`,
  `/secure/ContactAdministrators!default.jspa`, and the README-shaped
  `/secure/ContactAdministrators.jspa` Velocity/i18n payload POST to
  `/startup.jsp` before the Contact Administrators form can be exercised. This
  remains a setup/license/SMTP/sample-project boundary rather than a protected
  LTS acceptance. Evidence:
  `/tmp/ohmyrasp-jira-11581-setup-boundary-java8-20260611032206.log`.
- [x] Re-run the primary `agent-jdk25` live baseline-vs-protected acceptance on
  2026-06-20 to validate the 2026-06-20 detector-precision changes against real
  containers, closing the gap that the prior recorded matrix (2026-06-11)
  predated them. `scripts/acceptance.sh` rebuilt the Tomcat 11/10/9 `jdk25`
  baseline and protected images from current source (so the freshly compiled
  agent jar carries the L2 scheme-aware JNDI fix `d867d45` and the L3
  execution-vector XSS retightening `292d9f5`) and passed across Tomcat 11, 10,
  and 9: 414 required block-event confirmations, 0 missing. The detector changes
  hold under live HTTP — `xss_userinput`, `xss_echo`, `jndi_disable_all`, and
  `request_jndi_lookup` each emitted `action:"block"` on all three Tomcat
  versions while baseline/normal-traffic checks stayed clean. Evidence: 2,825
  protected events across `logs/tomcat{9,10,11}-protected/events.jsonl`; full
  run log `/tmp/acceptance-l8-1781963376.log`. The companion unit gate
  (`gradle :agent-jdk25:test`) is also green on the same HEAD.
- [x] Re-run the current full LTS Tomcat compatibility matrix on 2026-06-11
  after the Java 8/11/17 agent checks and Vulhub coverage-ledger automation:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9 with
  `java17_rc=0`, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9 with
  `java11_rc=0`, and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9
  -> 8.5 with `java8_rc=0`. Full log:
  `/tmp/ohmyrasp-full-lts-matrix-current-20260611015826.log`.
- [x] Re-run the newest real Vulhub/boundary scripts on 2026-06-11 after the
  full LTS Tomcat matrix: `scripts/acceptance-vulhub-coldfusion-29300-java11.sh`
  passed with `coldfusion_29300_rc=0`,
  `scripts/acceptance-vulhub-weblogic-21839-java8.sh` passed with
  `weblogic_21839_rc=0`, and
  `scripts/acceptance-vulhub-weblogic-weak-password-java6-legacy.sh` passed
  with `weblogic_weak_password_rc=0`. Full log:
  `/tmp/ohmyrasp-new-vulhub-scripts-rerun-20260611020716.log`.
- [x] Re-run the Java 8/11/17 agent Gradle checks in a non-root container after
  restoring ownership of root-created generated directories and external Gradle
  caches on 2026-06-11: `:agent-java8:check`, `:agent-java11:check`, and
  `:agent-java17:check` passed with `gradle_rc=0`. Full log:
  `/tmp/ohmyrasp-agent-era-gradle-check-nonroot-20260611021944.log`.
- [x] Re-run the full LTS Tomcat compatibility matrix after the WebLogic XXE
  JDO metadata allowlist refinement on 2026-06-06:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [x] Add the first Java 8/Tomcat 8 baseline-vs-protected harness:
  `playground-java8`, `Dockerfile.java8`, `docker-compose.java8.yml`, and
  `scripts/acceptance-java8.sh` run a Java 8-compatible WAR on
  `tomcat:8.5-jdk8-temurin`; baseline Tomcat 8 reaches the normal, command,
  file-read, JNDI, and XXE endpoints, while protected Tomcat 8 stays quiet for
  normal traffic and blocks `java8_command_execution_exploit_primitive`,
  `java8_file_sensitive_read`, `java8_jndi_remote_lookup`, and
  `java8_xxe_external_entity_protocol` under the dedicated Java 8 agent.
- [x] Expand the Java 8/Tomcat 8 harness to every current Java 8 behavior
  algorithm: `scripts/acceptance-java8.sh` now baseline-tests and
  protected-block-tests command shell metacharacters, gadget deserialization,
  script file writes, SSRF metadata and loopback-admin URLs, archive traversal,
  H2/Derby/MySQL JDBC URL primitives, URLClassLoader and RMIClassLoader remote
  codebases, script-engine runtime execution, Java compilation runtime
  execution, JAAS remote provider configuration, JMX remote config and
  script-write operations, XMLDecoder runtime and script-writer object graphs,
  plus the original command/file/JNDI/XXE checks, covering all 21
  pre-request-hook `java8_*` behavior algorithms in a real
  `tomcat:8.5-jdk8-temurin` baseline/protected container pair.
- [x] Expand the Java 8 era harness to the JDK8/Tomcat compatibility matrix:
  `scripts/acceptance-java8.sh` now runs Tomcat 10.0/JDK8 first, Tomcat 9/JDK8
  second, and Tomcat 8.5/JDK8 third, baseline-testing and
  protected-block-testing all 21 pre-request-hook `java8_*` behavior
  algorithms on
  `tomcat:10.0-jdk8-temurin`, `tomcat:9.0-jdk8-temurin`, and
  `tomcat:8.5-jdk8-temurin`; `playground-java8-jakarta` keeps the Tomcat 10.0
  deployment on the correct `jakarta.servlet` namespace while still compiling
  the probe code to Java 8 bytecode.
- [x] Add the Java 8 era request path-confusion hook:
  `javax.servlet.http.HttpServlet.service` and
  `jakarta.servlet.http.HttpServlet.service` are transformed by the dedicated
  Java 8 agent, Shiro-style `/./admin` and `/xxx/..;/admin/` authentication
  bypass paths emit `java8_request_path_confusion`, ordinary direct admin
  paths emit no detection, and block mode records `action:"block"` before
  throwing `Java8RaspBlockException`.
- [x] Re-run the Java 8/Tomcat compatibility matrix after the request hook on
  2026-06-04: `scripts/acceptance-java8.sh` now checks
  `request_hook:"installed"` and passed Tomcat 10.0 -> 9 -> 8.5 with all
  existing protected behavior algorithms still blocking and normal traffic
  quiet.
- [x] Run the first real Java 8 Vulhub application acceptance:
  `scripts/acceptance-vulhub-shiro-java8.sh` starts `vulhub/shiro:1.0.0`
  baseline/protected containers for CVE-2010-3863 and `vulhub/shiro:1.5.1`
  baseline/protected containers for CVE-2020-1957. The baselines redirect
  direct `/admin` or `/admin/` requests to login while `/./admin` and
  `/xxx/..;/admin/` bypass authentication and reach the admin/account page;
  the protected Java 8 agent starts quietly and blocks both bypasses with
  `java8_request_path_confusion`.
- [x] Run the first real Java 8 Fastjson Vulhub application acceptance:
  `scripts/acceptance-vulhub-fastjson-java8.sh` starts
  `vulhub/fastjson:1.2.24` baseline/protected containers for CVE-2017-18349
  and `vulhub/fastjson:1.2.45` baseline/protected containers for the 1.2.47
  autoType bypass. The baselines parse `JdbcRowSetImpl` RMI/JNDI payloads and
  reach an outbound JRMI listener; the protected Java 8 agent starts quietly,
  blocks the same JNDI sink with `java8_jndi_remote_lookup`, and no protected
  outbound listener receives a connection.
- [x] Run the first real Java 8 Log4j/Solr Vulhub application acceptance:
  `scripts/acceptance-vulhub-log4j-solr-java8.sh` starts
  `vulhub/solr:8.11.0` baseline/protected containers for Log4j
  CVE-2021-44228. The baseline Solr admin request logs a
  `${jndi:ldap://...}` action value and reaches an outbound LDAP listener; the
  protected Java 8 agent starts quietly and blocks the same Log4j-triggered
  `InitialContext.lookup` sink with `java8_jndi_remote_lookup`, so the
  protected outbound listener receives no connection.
- [x] Run the real Java 8 Log4j TCP SocketServer Vulhub application
  acceptance: `scripts/acceptance-vulhub-log4j-5645-java8.sh` starts
  `vulhub/log4j:2.8.1` baseline/protected containers for CVE-2017-5645 on
  OpenJDK 8u151. The baseline sends a ysoserial CommonsCollections5 payload to
  TCP port 4712 and creates `/tmp/ohmyrasp-log4j5645-success`; the protected
  Java 8 agent starts quietly and blocks
  `org.apache.commons.collections.functors.ChainedTransformer` class
  resolution at `ObjectInputStream.resolveClass` with
  `java8_deserialization_gadget_class`, so the marker file is not created.
- [x] Run the real Java 8 Apache JMeter Vulhub application acceptance:
  `scripts/acceptance-vulhub-jmeter-1297-java8.sh` starts
  `vulhub/jmeter:3.3` baseline/protected containers for CVE-2018-1297 on
  Java 8u20. The baseline sends the README-style ysoserial
  `RMIRegistryExploit` BeanShell1 payload to RMI port 1099 and creates
  `/tmp/ohmyrasp-jmeter1297-success`; the protected Java 8 agent starts
  quietly with `jmeter.home` pinned for JMeter's classpath home detection and
  blocks `bsh.XThis$Handler` class resolution in RMI `MarshalInputStream` with
  `java8_deserialization_gadget_class`, so the marker file is not created.
- [x] Run the real Java 8 Neo4j Shell Vulhub application acceptance:
  `scripts/acceptance-vulhub-neo4j-34371-java8.sh` starts
  `vulhub/neo4j:3.4.18` baseline/protected containers for CVE-2021-34371 on
  Java 8u292 with host networking for Neo4j Shell RMI ports 1337 and 34444.
  The baseline builds and runs the Vulhub `rhino_gadget` attacker against
  `setSessionVariable` and creates `/tmp/ohmyrasp-neo4j34371-success`; the
  protected Java 8 agent starts quietly through `dbms.jvm.additional` and
  blocks `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` class
  resolution at `ObjectInputStream.resolveClass` with
  `java8_deserialization_gadget_class`, so the marker file is not created.
- [x] Run the real Java 8 RMI codebase Vulhub application acceptance:
  `scripts/acceptance-vulhub-rmi-codebase-java8.sh` starts
  `vulhub/j2ee:8u222` baseline/protected containers for
  `java/rmi-codebase` with host networking for RMI Registry port 1099 and the
  exported remote object port 64000. The baseline sends an `ICalc.sum(List)`
  call carrying a serializable class annotated with a temporary HTTP
  `java.rmi.server.codebase` and creates
  `/tmp/ohmyrasp-rmi-codebase-success` during server-side deserialization; the
  protected Java 8 agent starts quietly and blocks the remote HTTP codebase at
  `RMIClassLoader` with `java8_classloader_remote_codebase`, so the marker file
  is not created.
- [x] Run the real Java 8 RMI Registry direct-bind Vulhub application
  acceptance: `scripts/acceptance-vulhub-rmi-registry-direct-java8.sh` starts
  `vulhub/j2ee:8u111` baseline/protected containers for
  `java/rmi-registry-bind-deserialization` with host networking for Registry
  port 1099. The baseline sends ysoserial `RMIRegistryExploit`
  CommonsCollections6 directly to the Registry and creates
  `/tmp/ohmyrasp-rmi-registry-direct-success`; the protected Java 8 agent
  starts quietly and blocks
  `org.apache.commons.collections.functors.ChainedTransformer` class
  resolution in RMI `MarshalInputStream` with
  `java8_deserialization_gadget_class`, so the marker file is not created. The
  current Vulhub compose file names `vulhub/j2ee:8u131`, but the README and
  vulnerability boundary are `<= 8u111`; direct CommonsCollections and
  BeanShell payloads against 8u131 are rejected by the JDK
  `ObjectInputFilter` before gadget execution.
- [x] Run the real Java 8 RMI Registry bypass Vulhub application acceptance:
  `scripts/acceptance-vulhub-rmi-registry-bypass-java8.sh` starts
  `vulhub/j2ee:8u111` baseline/protected containers for
  `java/rmi-registry-bind-deserialization-bypass` with host networking for
  Registry port 1099 and a temporary JRMP listener on port 8888. The baseline
  binds a dynamic `Remote` proxy whose `UnicastRef` points to the JRMP listener,
  receives the CommonsCollections6 second-stage payload, and creates
  `/tmp/ohmyrasp-rmi-registry-bypass-success`; the protected Java 8 agent
  starts quietly and blocks
  `org.apache.commons.collections.functors.ChainedTransformer` class resolution
  at `ObjectInputStream.resolveClass` with
  `java8_deserialization_gadget_class`, so the marker file is not created.
- [x] Run the first real Java 8 Solr Velocity Vulhub application acceptance:
  `scripts/acceptance-vulhub-solr-velocity-java8.sh` starts
  `vulhub/solr:8.2.0` baseline/protected containers for Solr CVE-2019-17558.
  Both containers first enable `VelocityResponseWriter` parameter templates
  through the Solr config API. The baseline `v.template.custom` payload reaches
  `Runtime.exec("cat /etc/passwd")` and returns passwd content; the protected
  Java 8 agent starts quietly, treats the config API request as benign, and
  blocks the Velocity-triggered runtime execution sink with
  `java8_command_execution_exploit_primitive`.
- [x] Run the first real Java 8 Solr RunExecutableListener Vulhub application
  acceptance: `scripts/acceptance-vulhub-solr-runexec-java8.sh` starts
  `vulhub/solr:7.0.1` baseline/protected containers for Solr CVE-2017-12629
  RCE. Both containers first add a post-commit `solr.RunExecutableListener`
  through the Solr config API. The baseline update commit executes
  `sh -c touch /tmp/ohmyrasp-solr12629-success` and creates the marker file;
  the protected Java 8 agent starts quietly, treats the config API request as
  benign, and blocks the listener-triggered `Runtime.exec(String[])` sink with
  `java8_command_execution_exploit_primitive`.
- [x] Run the first real Java 8 Solr XML parser XXE Vulhub application
  acceptance: `scripts/acceptance-vulhub-solr-xxe-java8.sh` starts
  `vulhub/solr:7.0.1` baseline/protected containers for Solr CVE-2017-12629
  XXE. The baseline `defType=xmlparser` query uses the
  `lucene-queryparser-7.0.1.jar` DTD indirection path to read `/etc/passwd`
  into Solr's error response; the protected Java 8 agent starts quietly and
  blocks Xerces external entity resolution with
  `java8_xxe_external_entity_protocol` before passwd content is disclosed.
- [x] Run the first real Java 8 Solr RemoteStreaming Vulhub application
  acceptance: `scripts/acceptance-vulhub-solr-remotestreaming-java8.sh`
  starts `vulhub/solr:8.8.1` baseline/protected containers for the
  RemoteStreaming arbitrary file-read playground. Both containers first enable
  `requestDispatcher.requestParsers.enableRemoteStreaming` through the Solr
  config API. The baseline `stream.url=file:///etc/passwd` debug dump returns
  passwd content; the protected Java 8 agent starts quietly, treats the config
  API request as benign, and blocks the sensitive file-read sink with
  `java8_file_sensitive_read` before passwd content is disclosed.
- [x] Run the first real Java 8 Solr DataImportHandler Vulhub application
  acceptance: `scripts/acceptance-vulhub-solr-dataimport-java8.sh` starts
  `vulhub/solr:8.1.1` baseline/protected containers for Solr CVE-2019-0193.
  The baseline `dataConfig` script runs
  `java.lang.Runtime.getRuntime().exec("touch /tmp/ohmyrasp-solr0193-success")`
  and creates the marker file; the protected Java 8 agent starts quietly and
  blocks request-supplied script evaluation with
  `java8_script_engine_runtime_execution`, so the import fails and the marker
  file is not created.
- [x] Run the first real Java 8 H2 Console Vulhub application acceptance:
  `scripts/acceptance-vulhub-h2-23221-java8.sh` starts
  `vulhub/spring-with-h2database:2.0.206` baseline/protected containers for H2
  CVE-2022-23221 on OpenJDK 8. The baseline `/h2-console/login.do` JDBC URL
  uses `INIT=CREATE TRIGGER ... //javascript` to execute `id` and returns
  `uid=0(root)` in the H2 error response; the protected Java 8 agent starts
  quietly and blocks the H2 JDBC URL sink with
  `java8_jdbc_h2_code_execution` before command output is produced.
- [x] Run the first real Java 8 H2 Console JNDI-driver Vulhub application
  acceptance: `scripts/acceptance-vulhub-h2-42392-java8.sh` starts
  `vulhub/spring-with-h2database:2.0.204` baseline/protected containers for H2
  CVE-2021-42392 on OpenJDK 8. The baseline `/h2-console/login.do` request
  uses `driver=javax.naming.InitialContext` and an LDAP URL, reaching an
  outbound LDAP listener; the protected Java 8 agent starts quietly and blocks
  `InitialContext.lookup` with `java8_jndi_remote_lookup`, so the protected
  outbound listener receives no connection.
- [x] Run the first real Java 8 XStream Vulhub application acceptance:
  `scripts/acceptance-vulhub-xstream-21351-java8.sh` starts
  `vulhub/xstream:1.4.15` baseline/protected containers for
  CVE-2021-21351 on OpenJDK 8u292. The baseline posts the Vulhub
  `JdbcRowSetImpl`/`RdnEntry` XML gadget with a `dataSource` LDAP URL pointing
  at the Docker gateway and reaches an outbound LDAP listener; the protected
  Java 8 agent starts quietly and blocks `InitialContext.lookup` with
  `java8_jndi_remote_lookup`, so the protected outbound listener receives no
  connection.
- [x] Run the real Java 8 XStream CVE-2021-29505 Vulhub application
  acceptance: `scripts/acceptance-vulhub-xstream-29505-java8.sh` starts
  `vulhub/xstream:1.4.16` baseline/protected containers on Oracle Java
  8u102. The baseline posts the Vulhub `RegistryImpl_Stub` XML body, reaches a
  ysoserial JRMPListener on the Docker gateway, receives a CommonsCollections6
  second-stage object, and creates `/tmp/ohmyrasp-xstream29505-success`; the
  protected Java 8 agent starts quietly and blocks
  `org.apache.commons.collections.functors.ChainedTransformer` with
  `java8_deserialization_gadget_class` before marker creation.
- [x] Run the first real Java 8 H2 Console post-login SQL Vulhub application
  acceptance: `scripts/acceptance-vulhub-h2-10054-java8.sh` starts
  `vulhub/spring-with-h2database:1.4.197` baseline/protected containers for H2
  CVE-2018-10054 on OpenJDK 8. Both containers first log in to
  `jdbc:h2:mem:test`; the baseline `/h2-console/query.do` trigger JavaScript
  executes `id` and returns `uid=0(root)` in the H2 error response, while the
  protected Java 8 agent starts quietly, keeps the safe login quiet, and blocks
  Nashorn script compilation with `java8_script_engine_runtime_execution`
  before command output is produced.
- [x] Run the first real Java 8 AJ-Report Vulhub application acceptance:
  `scripts/acceptance-vulhub-aj-report-java8.sh` starts
  `vulhub/aj-report:1.4.0` plus MySQL 5.7 baseline/protected container pairs
  for CNVD-2024-15077. The baseline
  `/dataSetParam/verification;swagger-ui/` validation-rule JavaScript executes
  `id` and returns `uid=0(root)`; the protected Java 8 agent starts quietly,
  including no MyBatis mapper DTD startup false positive, and blocks the
  request-supplied script at `ScriptEngine.eval` with
  `java8_script_engine_runtime_execution`.
- [x] Run the first real Java 8 Apache Druid Vulhub application acceptance:
  `scripts/acceptance-vulhub-druid-java8.sh` starts
  `vulhub/apache-druid:0.20.0` baseline/protected containers for
  CVE-2021-25646 on OpenJDK 8. The baseline
  `/druid/indexer/v1/sampler` JavaScript parser function executes `id` and
  returns `uid=0(root)`; the protected Java 8 agent starts quietly across
  Druid's child Java processes and blocks Rhino `Context.compileFunction` with
  `java8_script_engine_runtime_execution` before command output is returned.
- [x] Run the first real Java 8 Apache Unomi Vulhub application acceptance:
  `scripts/acceptance-vulhub-unomi-java8.sh` starts
  `vulhub/unomi:1.5.1` plus Elasticsearch 7.9.3 baseline/protected pairs for
  CVE-2020-13942 on OpenJDK 8. The baseline `/context.json` MVEL
  `profilePropertyCondition` payload executes
  `Runtime.exec("touch /tmp/ohmyrasp-unomi-touch-success")` and creates the
  marker file; the protected Java 8 agent starts quietly, keeps normal Unomi
  readiness quiet, and blocks the MVEL-triggered `Runtime.exec(String)` sink
  with `java8_command_execution_exploit_primitive`.
- [x] Run the real Java 8 Apache OFBiz XML-RPC deserialization Vulhub
  application acceptance: `scripts/acceptance-vulhub-ofbiz-9496-java8.sh`
  starts `vulhub/ofbiz:17.12.01` baseline/protected containers for
  CVE-2020-9496 on OpenJDK 8u342. The baseline
  `/webtools/control/xmlrpc` request deserializes a CommonsBeanutils1
  `<serializable>` value and creates `/tmp/ohmyrasp-ofbiz-9496-success`,
  while protected mode keeps startup/readiness quiet and blocks
  `ObjectInputStream.resolveClass` with `java8_deserialization_gadget_class`
  on `TemplatesImpl` before marker creation.
- [x] Run the real Java 8 Apache OFBiz XML-RPC auth-bypass deserialization
  Vulhub application acceptance:
  `scripts/acceptance-vulhub-ofbiz-49070-java8.sh` starts
  `vulhub/ofbiz:18.12.09` baseline/protected containers for CVE-2023-49070 on
  OpenJDK 8u342. The baseline
  `/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=&requirePasswordChange=Y`
  request deserializes a CommonsBeanutils1 `<serializable>` value and creates
  `/tmp/ohmyrasp-ofbiz-49070-success`, while protected mode keeps
  startup/readiness quiet and blocks `ObjectInputStream.resolveClass` with
  `java8_deserialization_gadget_class` on `TemplatesImpl` before marker
  creation.
- [x] Run the real Java 11 Adobe ColdFusion CVE-2023-26360 Vulhub application
  acceptance: `scripts/acceptance-vulhub-coldfusion-26360-java11.sh` starts
  `vulhub/coldfusion:2018.0.15`, verifies the image JRE is Java 11.0.12,
  injects `agent-java11` through ColdFusion `jvm.config`, and keeps normal
  administrator readiness quiet. Baseline sends the Vulhub
  `/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc`
  `_variables._metadata.classname=../../../../../../../../proc/self/environ`
  payload and receives the `cfuser` process environment; protected mode blocks
  the same local file load at `FileInputStream.open` with
  `java11_file_sensitive_read`, so `/proc/self/environ` is not returned.
- [x] Add Java 8/11/17 request-level typed-payload detection to the backport
  agents: request parameters that combine a dangerous Java binding type such as
  `JdbcRowSetImpl` with a JNDI, serialized-object, or H2 `INIT` trigger now emit
  the era-specific `request_typed_payload_deserialization` algorithms before
  application deserialization code runs, while safe DTO types or dangerous
  classes without a trigger remain quiet.
- [x] Run the real Java 11 Adobe ColdFusion CVE-2023-29300 Vulhub application
  acceptance: `scripts/acceptance-vulhub-coldfusion-29300-java11.sh` starts
  `vulhub/coldfusion:2018.0.15` baseline/protected containers on Java 11.0.12.
  Baseline posts the README-shaped WDDX `argumentCollection` payload containing
  `xcom.sun.rowset.JdbcRowSetImplx` and reaches a host LDAP listener through
  `dataSourceName`; protected mode keeps startup quiet and blocks the same POST
  at `HttpServlet.service` with `java11_request_typed_payload_deserialization`
  before any outbound LDAP connection.
- [x] Add Java 8/11/17 Hessian `SerializerFactory.getDeserializer` type
  resolution detection to the backport agents: dangerous wire types such as
  `org.apache.commons.beanutils.BeanComparator` now emit
  `java8_deserialization_hessian_type`,
  `java11_deserialization_hessian_type`, or
  `java17_deserialization_hessian_type`, while benign Hessian DTO/container
  types remain quiet. This is hook parity with the JDK 25 Hessian detector; the
  current XXL-JOB 2.2.0 Vulhub Hessian candidate remains non-graduated because
  the image does not contain the old Hessian dependency referenced for
  pre-2.2.0 deployments.
- [x] Re-run the full LTS Tomcat compatibility matrix after adding the Java
  8/11/17 Hessian backport transformer registration on 2026-06-10:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9 at
  23:07:30+09:00, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9 at
  23:08:44+09:00, and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9
  -> 8.5 at 23:10:00+09:00. Full log:
  `/tmp/ohmyrasp-full-lts-matrix-hessian-20260610230606.log`.
- [x] Re-run the full LTS Tomcat compatibility matrix after the Java 8/11/17
  typed-payload request hook and playground matrix coverage on 2026-06-10:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5. Each matrix now
  includes baseline/protected `typed_payload` checks for
  `java8_request_typed_payload_deserialization`,
  `java11_request_typed_payload_deserialization`, and
  `java17_request_typed_payload_deserialization`.
- [x] Refine Java 8/11/17 file-write false-positive handling for ColdFusion
  runtime compilation: normal ColdFusion writes under `WEB-INF/cfclasses/*.class`
  now stay quiet like existing `WEB-INF/classes` deployment artifacts, while JSP,
  JAR/WAR, traversal, and other webroot-like script writes still emit the
  era-specific `file_script_write` algorithms.
- [x] Add Java 8/11/17 command-sink correlation for Java object
  deserialization stacks: process execution reached while the call stack contains
  `java.io.ObjectInputStream`, Axis2 `SafeObjectInputStream`, or BlazeDS AMF
  deserialization frames now emits the era-specific
  `command_execution_exploit_primitive` algorithms without depending on
  product-specific request paths or gadget class names.
- [x] Run the real Java 8 Adobe ColdFusion CVE-2017-3066 Vulhub application
  acceptance: `scripts/acceptance-vulhub-coldfusion-3066-java8.sh` starts
  `vulhub/coldfusion:11u3`, verifies the image JRE is Java 8u25, builds a
  README-style ColdFusionPwn/CommonsBeanutils1 AMF body, and keeps protected
  ColdFusion startup quiet after the `WEB-INF/cfclasses` allowlist refinement.
  Baseline posts `application/x-amf` to `/flex2gateway/amf` and creates
  `/tmp/ohmyrasp-coldfusion-3066-success`; protected mode blocks the
  deserialization-triggered `Runtime.exec(String)` sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Re-run the full LTS Tomcat compatibility matrix after the ColdFusion
  `WEB-INF/cfclasses` file-write refinement and Java deserialization command
  stack correlation on 2026-06-06: `scripts/acceptance-java17.sh` passed
  Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat
  10.1 -> 9, and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5
  with baseline/protected checks for every current LTS-era behavior algorithm.
- [x] Run the real Java 8 Apache OFBiz ProgramExport Vulhub application
  acceptance: `scripts/acceptance-vulhub-ofbiz-51467-java8.sh` starts
  `vulhub/ofbiz:18.12.10` baseline/protected containers for CVE-2023-51467 on
  OpenJDK 8u342. The baseline unauthenticated
  `/webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y`
  Groovy submission returns `java.lang.Exception: uid=0(root)` from
  `'id'.execute().text`; the protected Java 8 agent starts quietly and blocks
  the Groovy-triggered `Runtime.exec(String)` sink with
  `java8_command_execution_exploit_primitive` before command output is
  returned.
- [x] Run the real Java 8 Apache OFBiz multipart ProgramExport Vulhub
  application acceptance: `scripts/acceptance-vulhub-ofbiz-38856-java8.sh`
  starts `vulhub/ofbiz:18.12.14` baseline/protected containers for
  CVE-2024-38856 on OpenJDK 8u342. The baseline unauthenticated
  `/webtools/control/main/ProgramExport` multipart Groovy submission uses the
  README Unicode `\u0065xecute()` bypass and returns
  `java.lang.Exception: uid=0(root)`; the protected Java 8 agent starts
  quietly and blocks the decoded Groovy-triggered `Runtime.exec(String)` sink
  with `java8_command_execution_exploit_primitive` before command output is
  returned.
- [x] Run the real Java 8 Apache OFBiz viewdatafile Vulhub application
  acceptance: `scripts/acceptance-vulhub-ofbiz-45195-java8.sh` starts
  `vulhub/ofbiz:18.12.15` baseline/protected containers for CVE-2024-45195 on
  OpenJDK 8u342. The baseline unauthenticated
  `/webtools/control/forgotPassword/viewdatafile` remote CSV/XML import writes
  a JSP webshell over `applications/accounting/webapp/accounting/index.jsp`
  and executes `id` through `/accounting/index.jsp?cmd=id`, returning
  `uid=0(root)`; the protected Java 8 agent starts quietly, keeps remote
  payload fetch quiet, and blocks the webroot JSP write at
  `FileOutputStream.open` with `java8_file_script_write` before the original
  `index.jsp` is replaced.
- [x] Re-run the real Java 8 Apache OFBiz viewdatafile acceptance on
  2026-06-10 after the current backport hook changes:
  `scripts/acceptance-vulhub-ofbiz-45195-java8.sh` passed again
  (`/tmp/ohmyrasp-ofbiz-45195-family-java8-20260610232558.log`). This current
  evidence is used for the CVE-2024-32113 and CVE-2024-36104 predecessor rows
  because the Vulhub CVE-2024-45195 README identifies them as incomplete-fix
  predecessors of the same controller-view map state desynchronization family.
- [x] Run the real Java 8 Apache OFBiz remote decorator Vulhub application
  acceptance: `scripts/acceptance-vulhub-ofbiz-45507-java8.sh` starts
  `vulhub/ofbiz:18.12.15` baseline/protected containers for CVE-2024-45507 on
  OpenJDK 8u342. The baseline unauthenticated
  `/webtools/control/forgotPassword/StatsSinceStart` request loads a remote
  Widget-Screen XML through `statsDecoratorLocation` and creates
  `/tmp/ohmyrasp-ofbiz45507-success`; the protected Java 8 agent starts
  quietly and blocks the request at `HttpServlet.service` with
  `java8_request_template_source`, before the remote XML is fetched or the
  marker command is evaluated.
- [x] Run the real Java 8 Nexus Repository Vulhub application acceptance:
  `scripts/acceptance-vulhub-nexus-7238-java8.sh` starts
  `vulhub/nexus:3.14.0` baseline/protected containers for CVE-2019-7238 on
  Oracle Java 8u192. Both containers first upload a minimal Maven artifact to
  `maven-releases`; the baseline unauthenticated `/service/extdirect`
  `previewAssets` JEXL filter executes the README-shaped
  `Runtime.exec("touch ...")` expression and creates
  `/tmp/ohmyrasp-nexus7238-success`; the protected Java 8 agent starts
  quietly with the Commons JEXL hook installed and blocks at
  `CommonsJEXL.evaluate` with `java8_jexl_runtime_execution` before the
  expression reaches `Runtime.exec(String)`.
- [x] Run the real Java 8 Nexus Repository Vulhub application acceptance for
  CVE-2018-16621 family coverage:
  `scripts/acceptance-vulhub-nexus-10204-java8.sh` starts
  `vulhub/nexus:3.21.1` baseline/protected containers. The baseline ExtDirect
  `coreui_User` `updateRole` `memberNames` EL payload creates
  `/tmp/ohmyrasp-nexus10204-success`; the protected Java 8 agent starts
  quietly and blocks the same Unified EL runtime expression with
  `java8_el_runtime_execution` before marker creation. This covers the
  CVE-2018-16621 predecessor bypass referenced by the same Vulhub README
  family. Evidence:
  `/tmp/ohmyrasp-nexus-16621-family-java8-20260610235234.log`.
- [x] Run the real Java 8 Nexus Repository Vulhub application acceptance for
  Spring CVE-2018-1271 path-normalization family coverage:
  `scripts/acceptance-vulhub-nexus-4956-java8.sh` starts
  `vulhub/nexus:3.68.0` baseline/protected containers for CVE-2024-4956. The
  baseline repeated-encoded-slash traversal discloses `/etc/passwd`; the
  protected Java 8 agent starts quietly and blocks the same sensitive file read
  with `java8_file_sensitive_read` before passwd content is returned. This
  covers the Spring MVC CVE-2018-1271 canonicalization root cause referenced by
  the same Vulhub README family. Evidence:
  `/tmp/ohmyrasp-spring-1271-family-java8-20260610235902.log`.
- [x] Run the first real Java 8 Apache Dubbo Vulhub application acceptance:
  `scripts/acceptance-vulhub-dubbo-java8.sh` starts
  `vulhub/dubbo:2.7.3` plus Zookeeper 3.7.0 baseline/protected pairs for
  CVE-2019-17564 on OpenJDK 8. The baseline HTTP Invoker POST to
  `/org.vulhub.api.CalcService` deserializes a CommonsCollections6 object
  stream and creates `/tmp/ohmyrasp-dubbo-success`; the protected Java 8 agent
  starts quietly and blocks Spring HTTP Invoker class resolution at
  `ObjectInputStream.resolveClass` with `java8_deserialization_gadget_class`
  before the marker file is created.
- [x] Run the first real Java 8 Apache CXF Vulhub application acceptance:
  `scripts/acceptance-vulhub-cxf-java8.sh` starts
  `vulhub/apache-cxf:3.2.14` baseline/protected containers for CVE-2024-28752
  on OpenJDK 8. The baseline `/test` multipart SOAP request uses an Aegis/XOP
  `href="file:///etc/hosts"` reference and returns the base64-encoded hosts
  file in the SOAP fault; the protected Java 8 agent starts quietly and blocks
  the lower-level local file read with `java8_file_sensitive_read` before
  hosts content is returned.
- [x] Run the first real Java 8 Alibaba Nacos Vulhub application acceptance:
  `scripts/acceptance-vulhub-nacos-java8.sh` starts
  `vulhub/nacos:1.4.0` baseline/protected containers for CVE-2021-29442 on
  OpenJDK 8. The baseline Vulhub `poc.py` loads a Derby SQLJ JAR through the
  unauthenticated `/nacos/v1/cs/ops/data/removal` and
  `/nacos/v1/cs/ops/derby` flow, creates an `Exec.exec` Java function, and
  returns `uid=0(root)` from `Runtime.exec("id")`; the protected Java 8 agent
  starts quietly and blocks the database Java routine process sink with
  `java8_command_execution_exploit_primitive`.
- [x] Run the real Java 8 Alibaba Nacos CVE-2021-29441 Vulhub application
  acceptance: `scripts/acceptance-vulhub-nacos-29441-java8.sh` starts
  `vulhub/nacos:1.4.0` baseline/protected containers on OpenJDK 8. The baseline
  lists users and creates a new user through `/nacos/v1/auth/users` with
  `User-Agent: Nacos-Server`; the protected Java 8 agent starts quietly, blocks
  the spoofed list and create requests at `HttpServlet.service` with
  `java8_request_internal_identity`, and the create response never reaches
  `create user ok!`.
- [x] Run the first real Java 8 Struts2 S2-045 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2045-java8.sh` starts
  `vulhub/struts2:2.3.30` baseline/protected containers for
  S2-045/CVE-2017-5638. The baseline `Content-Type` OGNL payload executes
  `id` and returns `uid=0(root)`; the protected Java 8 agent starts and serves
  readiness quietly after the Jetty/Struts local XML descriptor false-positive
  fixes, blocks the OGNL `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`, and returns no command output.
- [x] Run the first real Java 8 Struts2 S2-046 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2046-java8.sh` starts the same
  `vulhub/struts2:2.3.30` baseline/protected image for S2-046/CVE-2017-5638.
  The baseline raw multipart filename payload keeps the Vulhub NUL separator,
  executes `id`, and returns `uid=0(root)`; the protected Java 8 agent starts
  quietly and blocks the OGNL `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`, so command output is not
  returned.
- [x] Run the first real Java 8 Struts2 S2-001 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2001-java8.sh` builds the local Vulhub
  `struts2/s2-001` image from `S2-001.war` on `vulhub/tomcat:8.5` and starts
  baseline/protected containers on OpenJDK 8u121. The baseline
  validation-error `POST /login.action` flow evaluates the submitted
  `username` OGNL value during Struts form-field repopulation and creates
  `/tmp/ohmyrasp-s2001-success`; the protected Java 8 agent starts quietly and
  blocks the OGNL `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Run the first real Java 8 Struts2 S2-005 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2005-java8.sh` builds the local Vulhub
  `struts2/s2-005` image from `S2-005.war` on `vulhub/tomcat:8.5` and starts
  baseline/protected containers on OpenJDK 8u121. The baseline
  `/example/HelloWorld.action` parameter-name OGNL payload uses the
  Vulhub-style `\u0023` escape chain, executes
  `Runtime.exec(String[])`, and creates `/tmp/ohmyrasp-s2005-success`; the
  protected Java 8 agent starts quietly after the local XWork XML include
  refinement and blocks the later process sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
  Because this changed shared XXE local Struts/XWork metadata handling,
  2026-06-05 LTS Tomcat validation passed in strict order: Java 17 Tomcat
  11 -> 10.1 -> 9, Java 11 Tomcat 10.1 -> 9, and Java 8 Tomcat
  10.0 -> 9 -> 8.5.
- [x] Run the first real Java 8 Struts2 S2-016 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2016-java8.sh` builds the local Vulhub
  `struts2/s2-016` image from the upstream `ROOT.war` on
  `vulhub/tomcat:8.5` and starts baseline/protected containers on OpenJDK
  8u121. The baseline `GET /index.action?redirect:${...}` parameter-name flow
  uses the Vulhub `denyMethodExecution=false` and `allowStaticMethodAccess`
  bypass chain, executes `Runtime.exec(String)`, and creates
  `/tmp/ohmyrasp-s2016-success`; the protected Java 8 agent starts quietly and
  blocks the later process sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Run the first real Java 8 Struts2 S2-032 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2032-java8.sh` starts the Vulhub
  `vulhub/struts2:2.3.28` baseline/protected image on OpenJDK 8u252. The
  baseline `GET /index.action?method:...&cmd=touch /tmp/ohmyrasp-s2032-success`
  dynamic-method-invocation parameter-name flow evaluates the submitted method
  OGNL expression, executes `Runtime.exec(String)`, returns the README-shaped
  command response, and creates `/tmp/ohmyrasp-s2032-success`; the protected
  Java 8 agent starts quietly and blocks the later process sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Run the first real Java 8 Struts2 S2-015 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2015-java8.sh` builds the local Vulhub
  `struts2/s2-015` image from `S2-015.war` on `vulhub/tomcat:8.5` and starts
  baseline/protected containers on OpenJDK 8u121. The baseline action-name
  path `${...}.action` flow reaches the wildcard result `/{1}.jsp`, uses the
  Vulhub `denyMethodExecution=false` and `allowStaticMethodAccess` bypass
  chain, executes `Runtime.exec(String)`, returns the missing evaluated JSP
  result, and creates `/usr/local/tomcat/ohmyrasp-s2015-success`; the protected
  Java 8 agent starts quietly and blocks the later process sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Run the first real Java 8 Struts2 S2-007 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2007-java8.sh` builds the local Vulhub
  `struts2/s2-007` image from `S2-007.war` on `vulhub/tomcat:8.5` and starts
  baseline/protected containers on OpenJDK 8u121. The baseline integer
  conversion-error `POST /user.action` flow evaluates the submitted `age` OGNL
  value during Struts validation error rendering and creates
  `/tmp/ohmyrasp-s2007-success`; the protected Java 8 agent starts quietly and
  blocks the OGNL `Runtime.exec(String)` sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Run the first real Java 8 Struts2 S2-008 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2008-java8.sh` builds the local Vulhub
  `struts2/s2-008` image from `S2-008.war` on `vulhub/tomcat:8.5` and starts
  baseline/protected containers on OpenJDK 8u121. The baseline devMode
  `GET /devmode.action?debug=command&expression=...` flow evaluates the command
  expression and creates `/tmp/ohmyrasp-s2008-success`; the protected Java 8
  agent starts quietly and blocks the OGNL `Runtime.exec(String)` sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Run the first real Java 8 Struts2 S2-048 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2048-java8.sh` starts
  `vulhub/struts2:2.3.32-showcase` baseline/protected containers for
  S2-048/CVE-2017-9791 on Java 8u181. The baseline showcase
  `/integration/saveGangster.action` Gangster Name OGNL payload returns
  `uid=0(root)`; the protected Java 8 agent starts quietly and blocks the OGNL
  `Runtime.exec(String)` sink with `java8_command_execution_exploit_primitive`,
  so command output is not returned.
- [x] Run the first real Java 8 Struts2 S2-009 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2009-java8.sh` builds the local Vulhub
  `struts2/s2-009` image from `S2-009.war` on `vulhub/tomcat:8.5` and starts
  baseline/protected containers on OpenJDK 8u121. The baseline delegated OGNL
  `name` plus `z[(name)('meh')]` query creates
  `/tmp/ohmyrasp-s2009-success`; the protected Java 8 agent starts quietly after
  the local Struts validation XML refinement and blocks the OGNL
  `Runtime.exec(String)` sink with `java8_command_execution_exploit_primitive`,
  so the marker is not created.
  Because this changed shared XXE local Struts metadata handling, 2026-06-05
  LTS Tomcat validation passed in strict order: Java 17 Tomcat 11 -> 10.1 -> 9,
  Java 11 Tomcat 10.1 -> 9, and Java 8 Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the first real Java 8 Struts2 S2-012 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2012-java8.sh` builds the local Vulhub
  `struts2/s2-012` image from `S2-012.war` on `vulhub/tomcat:8.5` and starts
  baseline/protected containers on OpenJDK 8u121. The baseline non-empty
  `POST /user.action` `name` flow reaches the redirect result
  `/index.jsp?name=${name}`, evaluates the submitted OGNL value, and creates
  `/tmp/ohmyrasp-s2012-success`; the protected Java 8 agent starts quietly and
  blocks the OGNL `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Run the first real Java 8 Struts2 S2-013/S2-014 Vulhub application
  acceptance: `scripts/acceptance-vulhub-struts2-s2013-java8.sh` builds the
  local Vulhub `struts2/s2-013` image from `S2-013.war` on
  `vulhub/tomcat:8.5` and starts baseline/protected containers on OpenJDK
  8u121. The baseline `GET /link.action?a=${...}` includeParams flow evaluates
  the submitted dollar-OGNL value while rendering the `<s:a>` URL, returns a
  link containing `a=java.lang.*Process`, and creates
  `/tmp/ohmyrasp-s2013-success`; the protected Java 8 agent starts quietly and
  blocks the OGNL `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Run the first real Java 8 Struts2 S2-052 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2052-java8.sh` starts
  `vulhub/struts2:2.5.12-rest-showcase` baseline/protected containers for
  S2-052. The baseline Vulhub REST/XStream XML polymorphic gadget reaches
  `ProcessBuilder.start` and creates `/tmp/ohmyrasp-s2052-success`; the
  protected Java 8 agent starts quietly and blocks the XStream-triggered
  process sink with `java8_command_execution_exploit_primitive`, so the marker
  is not created.
  Because this changed shared command-hook handling for XStream
  deserialization stacks, 2026-06-05 LTS Tomcat validation passed in order:
  `scripts/acceptance-java17.sh` for Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` for Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` for Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the first real Java 8 Struts2 S2-053 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2053-java8.sh` starts
  `vulhub/struts2:s2-053` baseline/protected containers for S2-053 on Java
  8u121. The baseline `redirectUri` payload keeps the Vulhub-required trailing
  newline and returns `uid=0(root)` from `/hello.action`; the protected Java 8
  agent starts quietly and blocks the OGNL `ProcessBuilder.start` sink with
  `java8_command_execution_exploit_primitive`, so command output is not
  returned.
- [x] Run the first real Java 8 Struts2 S2-057 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2057-java8.sh` starts
  `vulhub/struts2:2.3.34-showcase` baseline/protected containers for
  S2-057/CVE-2018-11776 with the Vulhub `struts-actionchaining.xml` override.
  The baseline namespace OGNL URL under
  `/struts2-showcase/.../actionChain1.action` executes `id` and returns
  `uid=0(root)` from the action-chain redirect flow; the protected Java 8
  agent starts quietly after the JSF/Struts XML metadata whitelist and shaded
  ASM packaging fixes, blocks the OGNL `Runtime.exec` sink with
  `java8_command_execution_exploit_primitive`, and returns no command output.
  Because this changed shared hook metadata handling and agent packaging,
  2026-06-05 LTS Tomcat validation passed in order:
  `scripts/acceptance-java17.sh` for Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` for Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` for Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the first real Java 8 Struts2 S2-059 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2059-java8.sh` starts
  `vulhub/struts2:2.5.16` baseline/protected containers for
  S2-059/CVE-2019-0230. The baseline two-step `id` parameter OGNL payload
  creates `/tmp/ohmyrasp-s2059-success`; the protected Java 8 agent starts
  quietly and blocks the second-step OGNL `Runtime.exec` sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created.
- [x] Run the first real Java 8 Struts2 S2-061 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-s2061-java8.sh` starts
  `vulhub/struts2:2.5.25` baseline/protected containers for
  S2-061/CVE-2020-17530. The baseline Vulhub multipart `id` parameter OGNL
  payload instantiates FreeMarker `Execute` and returns `uid=0(root)` from
  `/index.action`; the protected Java 8 agent starts quietly and blocks the
  resulting `Runtime.exec(String)` sink with
  `java8_command_execution_exploit_primitive`, so command output is not
  returned.
- [x] Run the first real Java 8 Liferay Portal Vulhub application acceptance:
  `scripts/acceptance-vulhub-liferay-7961-java8.sh` starts
  `vulhub/liferay-portal:7.2.0-ga1` sequential baseline/protected containers
  for CVE-2020-7961 on OpenJDK 8. The baseline JSONWS
  `+defaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource` payload
  loads a controlled `LifExp.class` from the attacker HTTP server and creates
  `/tmp/ohmyrasp-liferay-7961-success`; the protected Java 8 agent starts
  quietly after the Tika external-parser and localhost browser-launch
  false-positive fixes and blocks the remote `URLClassLoader` codebase with
  `java8_classloader_remote_codebase`, so the marker is not created.
  Because this changed shared command-hook false-positive handling,
  2026-06-05 LTS Tomcat validation passed in order:
  `scripts/acceptance-java17.sh` for Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` for Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` for Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the first real Java 8 Apache RocketMQ Vulhub application acceptance:
  `scripts/acceptance-vulhub-rocketmq-java8.sh` starts
  `vulhub/rocketmq:5.1.0` baseline/protected containers for CVE-2023-33246 on
  OpenJDK 8. The baseline `rocketmq-attack` `AttackBroker` flow mutates broker
  filter-server configuration and creates
  `/tmp/ohmyrasp-rocketmq33246-success`; the protected Java 8 agent starts
  quietly and blocks the filter-server `Runtime.exec(String[])` shell command
  with `java8_command_execution_shell_meta` before the marker file is created.
- [x] Run the first real Java 8 Apache RocketMQ NameServer Vulhub application
  acceptance: `scripts/acceptance-vulhub-rocketmq-37582-java8.sh` starts
  `vulhub/rocketmq:5.1.0` baseline/protected NameServer containers for
  CVE-2023-37582 on OpenJDK 8. The baseline `rocketmq-attack` `AttackNamesrv`
  flow mutates `configStorePath` and writes attacker content to a traversal
  `.sh` marker under `/tmp`; the protected Java 8 agent starts quietly and
  blocks the NameServer `FileOutputStream.open` sink with
  `java8_file_script_write` before the marker content is created.
- [x] Run the first real Java 8 Apache Flink Vulhub application acceptance:
  `scripts/acceptance-vulhub-flink-java8.sh` starts `vulhub/flink:1.11.2`
  baseline/protected containers for CVE-2020-17518 on OpenJDK 8. The baseline
  REST `/jars/upload` multipart request uses a traversal `.jar` filename and
  writes attacker content under `/tmp`; the protected Java 8 agent starts
  quietly and blocks the upload file-move sink with
  `java8_file_script_write` before the marker content is created.
- [x] Run the real Java 8 Apache Flink JobManager logs Vulhub application
  acceptance: `scripts/acceptance-vulhub-flink-17519-java8.sh` starts
  `vulhub/flink:1.11.2` baseline/protected containers for CVE-2020-17519 on
  OpenJDK 8. The baseline Netty REST `/jobmanager/logs/..%252f...` traversal
  returns `/etc/passwd`; the protected Java 8 agent starts quietly and blocks
  the lower-level `FileInputStream.open` sink with
  `java8_file_sensitive_read` before passwd content is disclosed.
- [x] Run the real Java 8 Apache Tomcat Vulhub application acceptance:
  `scripts/acceptance-vulhub-tomcat-12615-java8.sh` builds the
  `vulhub/tomcat:8.5.19`-derived CVE-2017-12615 image and starts
  baseline/protected containers on Java 8u141. The baseline `PUT
  /ohmyrasp12615.jsp/` writes a JSP and `GET /ohmyrasp12615.jsp` executes it;
  the protected Java 8 agent starts quietly and blocks the Tomcat webroot JSP
  write with `java8_file_script_write`, so the uploaded JSP returns 404 and
  never executes.
- [x] Run the real Java 8 Apache Spark Vulhub application acceptance:
  `scripts/acceptance-vulhub-spark-java8.sh` starts standalone Spark 2.3.1
  baseline/protected master and worker containers on Java 8u171 plus a local
  payload JAR server. The baseline unauthenticated REST
  `/v1/submissions/create` request fetches the Java payload JAR and the worker
  creates `/tmp/ohmyrasp-spark-success`; the protected Java 8 agent starts
  quietly in the master and blocks the same submit request at
  `SparkRest.handleSubmit` with `java8_request_remote_job_submission`, so the
  marker is never created.
- [x] Extend Java 8/11/17 remote job submission hooks after the Spark
  unauthenticated REST gap: Spark standalone REST `handleSubmit` bodies are
  inspected for remote executable artifacts plus entry classes and emit
  `javaX_request_remote_job_submission`, covering job-control RCE submissions
  without broadening ordinary process-execution command blocking.
- [x] Re-run the LTS Tomcat compatibility matrix after the Spark remote-job
  submission hook on 2026-06-04: `scripts/acceptance-java17.sh` passed Tomcat
  11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9,
  and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [x] Run the real Java 8 Apache Hadoop YARN Vulhub application acceptance:
  `scripts/acceptance-vulhub-hadoop-yarn-java8.sh` starts the
  `vulhub/hadoop:2.8.1` ResourceManager/NodeManager cluster on Java 8u131.
  The baseline unauthenticated REST `/ws/v1/cluster/apps` submit request
  schedules an application master command and the NodeManager creates
  `/tmp/ohmyrasp-yarn-success`; the protected Java 8 agent starts quietly in
  the ResourceManager and blocks the same submit request at
  `RMWebServices.submitApplication` with
  `java8_request_remote_job_submission`, so no NodeManager container starts.
- [x] Extend Java 8/11/17 remote job submission hooks after the Hadoop YARN
  unauthenticated REST gap: ResourceManager
  `RMWebServices.submitApplication` application contexts are inspected for
  AM/container command fields and emit `javaX_request_remote_job_submission`
  with only command count and hash in the event details.
- [x] Re-run the LTS Tomcat compatibility matrix after the Hadoop YARN
  remote-job submission hook on 2026-06-05: `scripts/acceptance-java17.sh`
  passed Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed
  Tomcat 10.1 -> 9, and `scripts/acceptance-java8.sh` passed Tomcat
  10.0 -> 9 -> 8.5 with baseline/protected checks for every current
  LTS-era behavior algorithm.
- [x] Run the real Java 8 Eclipse Jetty Vulhub application acceptance:
  `scripts/acceptance-vulhub-jetty-28164-java8.sh` starts
  `vulhub/jetty:9.4.37` on Java 8u292 with the Vulhub `ROOT` webapp. The
  baseline direct `/WEB-INF/web.xml` request returns 404, while the ambiguous
  `/%2e/WEB-INF/web.xml` request discloses the deployment descriptor; the
  protected Java 8 agent starts quietly and blocks the ambiguous request at
  `HttpServlet.service` with `java8_request_path_confusion`.
- [x] Extend Java 8/11/17 request path-confusion hooks after the Jetty
  CVE-2021-28164 gap: ambiguous dot-segment or double-slash decoded path
  variants that canonicalize into protected servlet resources such as
  `WEB-INF` or `META-INF` now emit `javaX_request_path_confusion`, while plain
  direct `/WEB-INF/...` requests remain quiet.
- [x] Re-run the LTS Tomcat compatibility matrix after the Jetty
  path-confusion hook on 2026-06-05: `scripts/acceptance-java17.sh` passed
  Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat
  10.1 -> 9, and `scripts/acceptance-java8.sh` passed Tomcat
  10.0 -> 9 -> 8.5.
- [x] Run the real Java 8 XXL-JOB Vulhub application acceptance:
  `scripts/acceptance-vulhub-xxljob-java8.sh` starts the Vulhub XXL-JOB 2.2.0
  db/admin/executor stack. The baseline unauthenticated executor `POST /run`
  accepts a `GLUE_SHELL` job and creates `/tmp/ohmyrasp-xxljob-success`; the
  protected Java 8 executor starts quietly and blocks the later script
  execution at `Runtime.exec(String[])` with
  `java8_command_execution_shell_meta` before the marker file is created.
- [x] Extend Java 8/11/17 command hooks after the XXL-JOB `GLUE_SHELL` gap:
  shell interpreters that execute script files from scheduler script execution
  stacks such as `com.xxl.job.core.handler.impl.ScriptJobHandler` now emit the
  `javaX_command_execution_shell_meta` family, while ordinary shell script
  execution outside scheduler stacks remains quiet.
- [x] Re-run the LTS Tomcat compatibility matrix after the XXL-JOB scheduler
  shell command hook on 2026-06-05: `scripts/acceptance-java17.sh` passed
  Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat
  10.1 -> 9, and `scripts/acceptance-java8.sh` passed Tomcat
  10.0 -> 9 -> 8.5.
- [x] Run the real Java 8 kkFileView Vulhub application acceptance:
  `scripts/acceptance-vulhub-kkfileview-java8.sh` starts
  `vulhub/kkfileview:4.3.0`. The baseline previews the crafted `test.zip`,
  overwrites LibreOffice `uno.py`, then previews `sample.odt` and creates
  `/tmp/ohmyrasp-kkfileview-success`; the protected Java 8 container starts
  quietly and blocks the SevenZipBinding extraction write at
  `ArchiveEntry.write` with `java8_archive_entry_traversal_write`, leaving
  both `uno.py` and the marker untouched.
- [x] Extend Java 8/11/17 archive hooks after the kkFileView ZipSlip gap:
  SevenZipBinding `net.sf.sevenzipjbinding.simple.impl.SimpleInArchiveItemImpl`
  `getPath()` results are now correlated with the next Java file-write sink,
  matching the existing `ZipEntry.getName()` traversal behavior.
- [x] Refine Java 8/11/17 command hooks after the kkFileView startup false
  positive: `cn.keking.service.OfficePluginManager` LibreOffice cleanup
  commands such as the `soffice.bin` `ps|grep|wc` and `awk ... | sh` probes
  remain quiet, while generic shell metacharacter commands still log or block
  outside that stack.
- [x] Re-run the LTS Tomcat compatibility matrix after the kkFileView archive
  hook and Office cleanup command false-positive refinement on 2026-06-05:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the real Java 8 OpenTSDB Vulhub application acceptance:
  `scripts/acceptance-vulhub-opentsdb-java8.sh` starts
  `vulhub/opentsdb:2.4.0` for CVE-2020-35476 and
  `vulhub/opentsdb:2.4.1` for CVE-2023-25826. The baselines create
  `/tmp/ohmyrasp-opentsdb-35476-success` through `yrange=system(...)` and
  `/tmp/ohmyrasp-opentsdb-25826-success` through `key=;system ...`; the
  protected Java 8 containers start quietly and block the generated gnuplot
  script write at `FileOutputStream.write` with
  `java8_file_generated_plot_script_command` before either marker is created.
- [x] Run the first real Java 8 Elasticsearch CVE-2015-1427 Vulhub application
  acceptance: `scripts/acceptance-vulhub-elasticsearch-1427-java8.sh` starts
  isolated `vulhub/elasticsearch:1.4.2` baseline/protected clusters on OpenJDK
  8u181. The baseline indexes one document, posts the README-shaped Groovy
  `script_fields` sandbox-bypass search payload, executes
  `Runtime.exec(String)`, and creates `/tmp/ohmyrasp-es-1427-success`; the
  protected Java 8 agent starts quietly and blocks the later process sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created and
  Elasticsearch returns a shard failure wrapping `Java8RaspBlockException`.
- [x] Run the real Java 8 Elasticsearch CVE-2014-3120 Vulhub application
  acceptance: `scripts/acceptance-vulhub-elasticsearch-3120-java8.sh` starts
  isolated `vulhub/elasticsearch:1.1.1` baseline/protected clusters on OpenJDK
  8u181. The baseline indexes one document, posts the README-shaped MVEL
  `_search` `script_fields` payload, executes `Runtime.exec(String)`, and
  creates `/tmp/ohmyrasp-es-3120-success`; the protected Java 8 agent starts
  and indexes quietly, then blocks the shaded MVEL-triggered process sink with
  `java8_command_execution_exploit_primitive`, so the marker is not created and
  Elasticsearch returns a shard failure wrapping `Java8RaspBlockException`.
  This required adding Java 8/11/17 attribution for Elasticsearch-shaded MVEL
  stacks (`org.elasticsearch.common.mvel2.*` and
  `org.elasticsearch.script.mvel.*`); on 2026-06-05 the full LTS Tomcat matrix
  was rerun in order: `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1
  -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the real Java 8 Elasticsearch CVE-2015-3337 Vulhub application
  acceptance: `scripts/acceptance-vulhub-elasticsearch-3337-java8.sh` builds
  the Vulhub `vulhub/elasticsearch:1.4.4` plus `elasticsearch-head` plugin
  image and starts isolated baseline/protected clusters on OpenJDK 8u181. The
  baseline README-shaped `/_plugin/head/../../.../etc/passwd` request returns
  passwd content; the protected Java 8 agent starts quietly and blocks the
  lower-level plugin resource `FileInputStream.open` with
  `java8_file_sensitive_read`, so passwd content is not disclosed and
  Elasticsearch returns a `Java8RaspBlockException` JSON error.
- [x] Run the real Java 8 Elasticsearch CVE-2015-5531 Vulhub application
  acceptance: `scripts/acceptance-vulhub-elasticsearch-5531-java8.sh` builds
  the Vulhub `vulhub/elasticsearch:1.6.0` image with `path.repo` configured
  and starts isolated baseline/protected clusters on OpenJDK 8u181. Both sides
  register the README-shaped filesystem snapshot repositories quietly; the
  baseline encoded `/_snapshot/test/backdata%2f..%2f...%2fetc%2fpasswd`
  traversal returns passwd bytes in Elasticsearch's parse-error body, while
  the protected Java 8 agent blocks the lower-level snapshot
  `FileInputStream.open` with `java8_file_sensitive_read`, so passwd bytes are
  not disclosed and Elasticsearch returns a `Java8RaspBlockException` JSON
  error.
- [x] Run the real Java 8 Elasticsearch WooYun-2015-110216 Vulhub application
  acceptance: `scripts/acceptance-vulhub-elasticsearch-110216-java8.sh` starts
  `vulhub/elasticsearch:1.5.1-with-tomcat` baseline/protected containers on
  OpenJDK 8u181 and verifies both co-resident Java processes are injectable.
  The baseline indexes a JSP scriptlet field, creates the README-shaped
  filesystem snapshot repository under `/usr/local/tomcat/webapps/wwwroot/`,
  snapshots `yz.jsp`, and exposes the generated JSP snapshot artifact through
  Tomcat. The protected Java 8 agent keeps startup and repository setup quiet,
  then blocks the snapshot `FileOutputStream.open` with
  `java8_file_script_write`, so the JSP artifact is not created and
  Elasticsearch returns a `Java8RaspBlockException` JSON error.
- [x] Run the real Java 8 GlassFish CVE-2017-1000028 Vulhub application
  acceptance: `scripts/acceptance-vulhub-glassfish-1000028-java8.sh` starts
  `vulhub/glassfish:4.1` baseline/protected containers on OpenJDK 8u342. The
  baseline README-shaped overlong UTF-8 `/theme/META-INF/%c0%ae%c0%ae/...`
  traversal returns `/etc/passwd`; the protected Java 8 agent starts quietly
  after the Felix extension codebase refinement and blocks the request at
  `HttpServlet.service` with `java8_request_path_confusion`, so passwd content
  is not disclosed and GlassFish returns a `Java8RaspBlockException` error
  page.
- [x] Re-run the LTS Tomcat compatibility matrix after the Felix/OSGi
  classloader false-positive refinement on 2026-06-05:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  URLClassLoader/RMIClassLoader remote codebase blocking still intact.
- [x] Extend Java 8/11/17 file hooks after the OpenTSDB Gnuplot gap:
  `FileOutputStream.write(byte[],...)` now inspects content only for the
  current same-thread generated plot script path (`.gnuplot`, `.gp`, `.plt`,
  or `.plot`) and emits `javaX_file_generated_plot_script_command` when bounded
  plot controls such as `yrange`, `y2range`, or `key` contain command
  directives. Safe generated plot scripts remain quiet.
- [x] Refine Java 8/11/17 command hooks after the OpenTSDB/HBase startup false
  positive: low-risk `stty ... < /dev/tty` terminal state probes without shell
  separators, pipelines, command substitution, or output redirection remain
  quiet, while generic shell metacharacter command chains still log or block.
- [x] Re-run the LTS Tomcat compatibility matrix after the OpenTSDB generated
  plot script file-content hook and HBase TTY probe command refinement on
  2026-06-05: `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Refine Java 8/11/17 JEXL transformers after the Jenkins 2.46.1 startup
  regression: Commons JEXL 1 classes compiled before Java 5 are skipped before
  bytecode injection, avoiding `VerifyError: Illegal type in constant pool` in
  normal Jenkins Jelly/JEXL page rendering while retaining lower-level command
  sink enforcement for exploit flows.
- [x] Run the real Java 8 Jenkins CVE-2017-1000353 Vulhub application
  acceptance: `scripts/acceptance-vulhub-jenkins-1000353-java8.sh` starts
  `vulhub/jenkins:2.46.1` on OpenJDK 8u212 and generates the Vulhub
  `SignedObject` CLI payload with OpenJDK 8u292. The baseline `/cli`
  upload/download exploit creates `/tmp/ohmyrasp-jenkins-1000353-success`;
  the protected Java 8 container starts quietly after the JEXL classfile
  compatibility refinement and blocks `ObjectInputStream.resolveClass` with
  `java8_deserialization_gadget_class` on the Commons Collections
  `ChainedTransformer` gadget before marker creation.
- [x] Re-run the LTS Tomcat compatibility matrix after the JEXL old-classfile
  transformer refinement on 2026-06-05: `scripts/acceptance-java17.sh` passed
  Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1
  -> 9, and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the real Java 8 Jenkins CVE-2018-1000861 Vulhub application
  acceptance: `scripts/acceptance-vulhub-jenkins-1000861-java8.sh` starts
  `vulhub/jenkins:2.138`. The baseline creates
  `/tmp/ohmyrasp-jenkins-1000861-success` through the unauthenticated
  `SecureGroovyScript/checkScript?sandbox=true` Groovy syntax-validation chain;
  the protected Java 8 container starts quietly and blocks the
  `Runtime.exec(String)` sink with `java8_command_execution_exploit_primitive`
  before the marker is created.
- [x] Run the real Java 17 Jenkins CVE-2024-23897 Vulhub application
  acceptance: `scripts/acceptance-vulhub-jenkins-23897-java17.sh` starts
  `vulhub/jenkins:2.441` on Temurin 17.0.9. The baseline downloads
  `jnlpJars/jenkins-cli.jar` and discloses `/etc/passwd` through
  `connect-node "@/etc/passwd"`; the protected Java 17 container starts
  quietly and blocks the server-side `args4j` `@file` expansion at
  `FileInputStream.open` with `java17_file_sensitive_read` before passwd
  content is disclosed.
- [x] Run the real Java 8 Shiro CVE-2016-4437 Vulhub application acceptance:
  `scripts/acceptance-vulhub-shiro-4437-java8.sh` starts
  `vulhub/shiro:1.2.4` on OpenJDK 8u102. The baseline sends a default-key
  `rememberMe` cookie carrying a ysoserial CommonsBeanutils1 payload and
  creates `/tmp/ohmyrasp-shiro-4437-success`; the protected Java 8 container
  starts quietly and blocks at the Shiro filter request entry with
  `java8_request_default_crypto_cookie` before rememberMe deserialization and
  before marker creation.
- [x] Extend Java 8/11/17 request hooks after the Shiro CVE-2016-4437 gap:
  `AbstractShiroFilter.doFilterInternal` is now instrumented so default-key
  encrypted `rememberMe` cookies are checked before Shiro parses them. The
  check decrypts only plausible AES-CBC cookies with the known default key and
  emits `javaX_request_default_crypto_cookie` only when the plaintext starts
  with Java serialization stream magic; logs record the cookie name and key
  family, not the cookie value or plaintext.
- [x] Re-run the LTS Tomcat compatibility matrix after the Shiro default
  crypto cookie request hook and Shiro filter instrumentation on 2026-06-05:
  `scripts/acceptance-java17.sh` passed Java 17 Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Java 11 Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Java 8 Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the real Java 8 Spring Security OAuth CVE-2016-4977 Vulhub
  application acceptance:
  `scripts/acceptance-vulhub-spring-security-oauth-java8.sh` starts
  `vulhub/spring-security-oauth2:2.0.8` on OpenJDK 8u162. The baseline uses
  `admin:admin` Basic Auth and a Vulhub-style no-whitespace
  `Character.toString(...).concat(...)` SpEL payload in `response_type` to
  create `/tmp/ohmyrasp-spring4977-success` through `Runtime.exec(String)`;
  the protected Java 8 container starts quietly and blocks the whitelabel
  error-page command sink with `java8_command_execution_exploit_primitive`
  before marker creation.
- [x] Run the real Java 8 Spring Security CVE-2022-22978 Vulhub application
  acceptance: `scripts/acceptance-vulhub-spring-security-22978-java8.sh`
  starts `vulhub/spring-security:5.6.3` on OpenJDK 8u212. The baseline denies
  `/admin/index` with 403 but returns the admin page for `/admin/%0atest` and
  `/admin/%0dtest`; the protected Java 8 container starts quietly and blocks
  both RegexRequestMatcher LF/CR bypasses at `HttpServlet.service` with
  `java8_request_path_confusion` before the admin page is disclosed.
- [x] Run the real Java 8 Spring Cloud Gateway CVE-2022-22947 Vulhub
  application acceptance: `scripts/acceptance-vulhub-spring-gateway-java8.sh`
  starts `vulhub/spring-cloud-gateway:3.1.0` on OpenJDK 8u292. The baseline
  registers an actuator route with an `AddResponseHeader` SpEL value, refreshes
  the gateway, and creates `/tmp/ohmyrasp-spring22947-success` through
  `Runtime.exec(String[])`; the protected Java 8 container starts quietly and
  blocks the refresh-time command sink with
  `java8_command_execution_exploit_primitive` before marker creation.
- [x] Run the real Java 8 Spring Cloud Function CVE-2022-22963 Vulhub
  application acceptance: `scripts/acceptance-vulhub-spring-function-java8.sh`
  starts `vulhub/spring-cloud-function:3.2.2` on OpenJDK 8u292. The baseline
  sends `POST /functionRouter` with the
  `spring.cloud.function.routing-expression` SpEL header and creates
  `/tmp/ohmyrasp-spring22963-success` through `Runtime.exec(String)`; the
  protected Java 8 container starts quietly and blocks the function-routing
  command sink with `java8_command_execution_exploit_primitive` before marker
  creation.
- [x] Run the real Java 8 Spring Data REST CVE-2017-8046 Vulhub application
  acceptance: `scripts/acceptance-vulhub-spring-data-rest-java8.sh` starts
  `vulhub/spring-rest-data:2.6.6` on OpenJDK 8u162. The baseline sends
  `PATCH /customers/1` with a JSON Patch SpEL path and creates
  `/tmp/ohmyrasp-spring8046-success` through `Runtime.exec(String)` even though
  the vulnerable request returns 400 after SpEL evaluation; the protected Java
  8 container starts quietly and blocks the JSON Patch command sink with
  `java8_command_execution_exploit_primitive` before marker creation.
- [x] Run the real Java 8 Spring Data Commons CVE-2018-1273 Vulhub
  application acceptance:
  `scripts/acceptance-vulhub-spring-data-commons-java8.sh` starts
  `vulhub/spring-data-commons:2.0.5` on OpenJDK 8u162. The baseline sends
  `POST /users?page=&size=5` with a `username[...]` SpEL parameter name and
  creates `/tmp/ohmyrasp-spring1273-success` through `Runtime.exec(String)`;
  the protected Java 8 container starts quietly and blocks the binder-triggered
  command sink with `java8_command_execution_exploit_primitive` before marker
  creation.
- [x] Run the real Java 8 Spring Messaging CVE-2018-1270 Vulhub application
  acceptance: `scripts/acceptance-vulhub-spring-messaging-java8.sh` starts
  `vulhub/spring-messaging:5.0.4` on OpenJDK 8u162. The baseline uses the
  Vulhub SockJS downgrade flow, subscribes with a STOMP `selector` SpEL header,
  sends to `/app/hello`, and creates `/tmp/ohmyrasp-spring1270-success`
  through `Runtime.exec(String)`; the protected Java 8 container starts
  quietly and blocks the selector-triggered command sink with
  `java8_command_execution_exploit_primitive` before marker creation.
- [x] Record the real Java 7 Spring WebFlow CVE-2017-4971 legacy boundary:
  `scripts/acceptance-vulhub-spring-webflow-java7-legacy.sh` starts
  `vulhub/spring-webflow:2.4.4` on OpenJDK 7u121/Tomcat 8.0.43. The baseline
  logs in, enters the hotel booking WebFlow, submits the malicious field name
  on the `reviewBooking` confirm state that lacks an explicit `<binder>`, and
  creates `/tmp/ohmyrasp-spring4971-success`; the current Java 8 LTS agent
  cannot inject because the Java 7 JVM rejects classfile major version 52.0,
  so this is recorded as a legacy runtime boundary rather than claimed as a
  protected LTS acceptance.
- [x] Record the real Java 7 Jackson CVE-2017-7525/CVE-2017-17485 legacy
  boundary:
  `scripts/acceptance-vulhub-jackson-java7-legacy.sh` starts
  `vulhub/spring-with-jackson:2.8.8` on Java 7u21. The baseline sends the
  README `TemplatesImpl` wrapper-array JSON body for CVE-2017-7525 and creates
  `/tmp/prove1.txt`; it also sends the README
  `FileSystemXmlApplicationContext` polymorphic JSON body for CVE-2017-17485,
  loads a temporary Spring XML document over HTTP, and creates
  `/tmp/ohmyrasp-jackson-17485-success` through `ProcessBuilder.start`. The
  current Java 8 LTS agent cannot inject because the Java 7 JVM rejects
  classfile major version 52.0, so this is recorded as a legacy runtime
  boundary rather than claimed as a protected LTS acceptance.
- [x] Record the real Java 7 Mojarra JSF ViewState deserialization legacy
  boundary:
  `scripts/acceptance-vulhub-mojarra-viewstate-java7-legacy.sh` starts
  `vulhub/mojarra:2.1.28` on Java 7u21/Mojarra 2.1.28. The baseline submits a
  gzip+Base64 `javax.faces.ViewState` value generated with ysoserial's
  `Jdk7u21` gadget to `/index.xhtml`, reaches JSF client-state
  deserialization, and creates `/tmp/ohmyrasp-mojarra-viewstate-success`. The
  current Java 8 LTS agent cannot inject because the Java 7 JVM rejects
  classfile major version 52.0, so this is recorded as a legacy runtime
  boundary rather than claimed as a protected LTS acceptance.
- [x] Record the real Java 7 JBoss CVE-2017-12149 legacy boundary:
  `scripts/acceptance-vulhub-jboss-12149-java7-legacy.sh` starts
  `vulhub/jboss:as-6.1.0` on Java 7u221/JBoss AS 6.1.0, posts a ysoserial
  CommonsCollections5 serialized body to `/invoker/readonly`, receives the
  expected JBoss 500 cast failure after deserialization, and creates
  `/tmp/ohmyrasp-jboss12149-success`. The current Java 8 LTS agent cannot
  inject because the Java 7 JVM rejects classfile major version 52.0, so this
  is recorded as a legacy runtime boundary rather than claimed as a protected
  LTS acceptance.
- [x] Record the real Java 7 JBoss JMXInvokerServlet legacy boundary:
  `scripts/acceptance-vulhub-jboss-jmxinvoker-java7-legacy.sh` starts
  `vulhub/jboss:as-6.1.0` on Java 7u221/JBoss AS 6.1.0, posts a ysoserial
  CommonsCollections5 serialized body to `/invoker/JMXInvokerServlet`,
  receives the expected JBoss response after deserialization, and creates
  `/tmp/ohmyrasp-jbossjmx-success`. The current Java 8 LTS agent cannot inject
  because the Java 7 JVM rejects classfile major version 52.0, so this is
  recorded as a legacy runtime boundary rather than claimed as a protected LTS
  acceptance.
- [x] Record the real Java 7 JBossMQ CVE-2017-7504 legacy boundary:
  `scripts/acceptance-vulhub-jboss-7504-java7-legacy.sh` starts
  `vulhub/jboss:as-4.0.5` on Java 7u221/JBoss AS 4.0.5, posts a ysoserial
  CommonsCollections5 serialized body to
  `/jbossmq-httpil/HTTPServerILServlet`, receives the expected serialized
  JBossMQ error response after deserialization, and creates
  `/tmp/ohmyrasp-jboss7504-success`. The current Java 8 LTS agent cannot
  inject because the Java 7 JVM rejects classfile major version 52.0, so this
  is recorded as a legacy runtime boundary rather than claimed as a protected
  LTS acceptance.
- [x] Record the real Java 7 ActiveMQ CVE-2016-3088 legacy boundary:
  `scripts/acceptance-vulhub-activemq-3088-java7-legacy.sh` starts
  `vulhub/activemq:5.11.1-with-cron` on Oracle Java 7u21/ActiveMQ 5.11.1. The
  baseline sends `PUT /fileserver/ohmyrasp-3088.txt`, then `MOVE` with
  `Destination: file:///opt/activemq/webapps/api/ohmyrasp-3088.jsp`; both
  requests return 204, the moved JSP is present, and authenticated
  `/api/ohmyrasp-3088.jsp` renders `ohmyrasp-3088-proof`. The current Java 8
  LTS agent cannot inject because the Java 7 JVM rejects classfile major
  version 52.0, so this is recorded as a legacy runtime boundary rather than
  claimed as a protected LTS acceptance.
- [x] Record the real Java 7 ActiveMQ CVE-2015-5254 legacy boundary:
  `scripts/acceptance-vulhub-activemq-5254-java7-legacy.sh` starts
  `vulhub/activemq:5.11.1` on Oracle Java 7u21/ActiveMQ 5.11.1. The baseline
  uses jmet to send a ROME gadget JMS `ObjectMessage` to the `event` queue,
  authenticates to `/admin/browse.jsp?JMSDestination=event`, visits the
  discovered `message.jsp` detail link, and creates
  `/tmp/ohmyrasp-activemq5254-success`. The current Java 8 LTS agent cannot
  inject because the Java 7 JVM rejects classfile major version 52.0, so this
  is recorded as a legacy runtime boundary rather than claimed as a protected
  LTS acceptance.
- [x] Record the real Java 7 Tomcat 7+/8 Manager weak-credential legacy
  boundary: `scripts/acceptance-vulhub-tomcat8-manager-java7-legacy.sh` starts
  `vulhub/tomcat:8.0` with Vulhub's `tomcat-users.xml` and Manager
  `context.xml` mounts on OpenJDK 7u121/Tomcat 8.0.43. The baseline
  authenticates to `/manager/html` with `tomcat` / `tomcat`, deploys a WAR via
  `/manager/text/deploy?path=/ohmyrasp-manager&update=true`, and verifies the
  deployed JSP marker renders `ohmyrasp-tomcat8-manager:1.7.0_121`. The
  current Java 8 LTS agent cannot inject because the Java 7 JVM rejects
  classfile major version 52.0, so this is recorded as a legacy runtime
  boundary rather than claimed as a protected LTS acceptance.
- [x] Extend Java 8/11/17 command hooks after the ActiveMQ CVE-2023-46604
  gap: process sinks reached during Spring `ApplicationContext` refresh and
  `AbstractAutowireCapableBeanFactory` bean initialization now emit the same
  `javaX_command_execution_exploit_primitive` family, while plain
  `touch ...` outside the Spring bean initialization stack remains quiet.
- [x] Refine the Java 8/11/17 Spring bean-initialization command hook after the
  Linkis CVE-2022-44645 protected startup probe: exact local identity probes
  such as `id hadoop` stay quiet during Spring application-context refresh,
  while exploit-grade Spring bean process sinks such as `touch /tmp/...` still
  emit the `javaX_command_execution_exploit_primitive` family.
- [x] Re-run the real Java 8 Apache Linkis MySQL JDBC datasource acceptance on
  2026-06-10 after the current backport hook changes:
  `scripts/acceptance-vulhub-linkis-44645-java8.sh` passed against Linkis 1.3.0
  on OpenJDK 8. The baseline connected to a rogue MySQL listener through the
  Vulhub `autoDeserialize` datasource test flow; protected mode blocked the
  generic MySQL JDBC deserialization sink with
  `java8_jdbc_mysql_deserialization` before the rogue listener received a
  connection. This evidence also covers the later Linkis JDBC blacklist bypass
  family entries, which reuse the same sink behavior.
- [x] Re-run the LTS Tomcat compatibility matrix after the Linkis identity-probe
  command-hook refinement on 2026-06-06: `scripts/acceptance-java17.sh` passed
  Java 17 Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed
  Java 11 Tomcat 10.1 -> 9, and `scripts/acceptance-java8.sh` passed Java 8
  Tomcat 10.0 -> 9 -> 8.5.
- [x] Refine the Java 8/11/17 Spring bean-initialization command hook after the
  GeoServer 2.17.2 CVE-2022-24816 protected startup probe: exact OSHI
  processor inventory probes `dmidecode -t 4` and `cpuid -1r` stay quiet, while
  exploit-grade Spring bean process sinks remain covered.
- [x] Extend Java 8/11/17 command hooks for JAI-EXT Jiffle runtime stacks:
  process sinks reached from `it.geosolutions.jaiext.jiffle.*`,
  `it.geosolutions.jaiext.jiffleop.*`, `org.jaitools.jiffle.*`, or
  `org.geotools.process.raster.JiffleProcess` emit the matching
  `javaX_command_execution_exploit_primitive` family. Real Java17 evidence is
  `scripts/acceptance-vulhub-geoserver-24816-java17.sh`: baseline GeoServer
  2.17.2 returns `uid=` from the Vulhub `ras:Jiffle` WPS XML request, while
  protected mode starts quietly and blocks `Runtime.exec("id")` with
  `Jiffle runtime reached a Java 17 process sink`.
- [x] Re-run the LTS Tomcat compatibility matrix after the GeoServer
  Jiffle/OSHI command-hook refinements on 2026-06-06, in required order:
  `scripts/acceptance-java17.sh` passed Java 17 Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Java 11 Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Java 8 Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the real Java 11 ActiveMQ CVE-2023-46604 Vulhub application
  acceptance: `scripts/acceptance-vulhub-activemq-46604-java11.sh` starts
  `vulhub/activemq:5.17.3`, serves a temporary Spring XML over HTTP, and sends
  Vulhub's OpenWire `poc.py` frame naming
  `org.springframework.context.support.ClassPathXmlApplicationContext`.
  Baseline creates `/tmp/ohmyrasp-activemq46604-success`; protected mode starts
  quietly with `agent-java11`, blocks the Spring XML `ProcessBuilder.start`
  sink with `java11_command_execution_exploit_primitive`, and the marker file
  is absent.
- [x] Re-run the LTS Tomcat compatibility matrix after the ActiveMQ
  CVE-2023-46604 Spring bean-initialization command-hook refinement on
  2026-06-05: `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with all
  existing protected behavior algorithms still blocking and normal traffic
  quiet.
- [x] Extend Java 8/11/17 script-source hooks after the Druid
  CVE-2021-25646 gap: Rhino/Mozilla `Context.evaluateString`,
  `Context.compileString`, and `Context.compileFunction` sources now use the
  same runtime-execution classification as JSR-223/Nashorn script sources, so
  Druid-style request-supplied parser functions are inspected before command
  output can be produced.
- [x] Extend Java 8/11/17 command hooks after the Unomi CVE-2020-13942 gap:
  process sinks reached from MVEL, OGNL, Groovy, Apache Commons JEXL, Spring
  SpEL, or Spring WebFlow expression stacks emit the same
  `javaX_command_execution_exploit_primitive` family, while plain
  `Runtime.exec("touch ...")` outside expression-language stacks remains quiet.
- [x] Extend Java 8/11/17 command hooks after the Nacos CVE-2021-29442 gap:
  process sinks reached from database Java routine stacks such as Derby, H2, or
  HSQLDB emit the same `javaX_command_execution_exploit_primitive` family,
  while plain `Runtime.exec("id")` outside those stacks remains quiet.
- [x] Extend Java 8/11/17 request hooks after the Nacos CVE-2021-29441 gap:
  servlet request classification now reads `User-Agent` and emits
  `javaX_request_internal_identity` when `Nacos-Server` or `Nacos-Server/...`
  reaches sensitive auth, user, admin, management, console, or ops paths.
  Non-control service-discovery paths with the same internal identity and normal
  user agents on sensitive paths remain quiet.
- [x] Re-run the LTS Tomcat compatibility matrix after the Nacos internal
  identity request hook on 2026-06-05: `scripts/acceptance-java17.sh` passed
  Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat
  10.1 -> 9, and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Extend Java 8/11/17 file-write hooks after the Flink CVE-2020-17518 gap:
  `java.io.File.renameTo(File)` and `java.nio.file.Files` path-to-path
  `copy`/`move` now inspect the destination path with the existing
  `javaX_file_script_write` classifier, so multipart upload frameworks that
  first write a temporary file and then move it to an attacker-controlled
  traversal archive/script path are covered without product-specific matching.
- [x] Re-run the LTS Tomcat compatibility matrix after the Flink
  CVE-2020-17518 file-move sink refinement on 2026-06-04:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [x] Re-run the LTS Tomcat compatibility matrix after the Nacos
  CVE-2021-29442 database Java routine command-stack refinement on
  2026-06-04: `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [x] Extend Java 8/11/17 deserialization hooks after the Dubbo
  CVE-2019-17564 gap: Spring HTTP Invoker
  `ConfigurableObjectInputStream` and `CodebaseAwareObjectInputStream`
  `resolveClass`/`resolveProxyClass` methods now feed the same
  `javaX_deserialization_gadget_class` classifier, so Dubbo/Spring remoting
  object streams are inspected before CommonsCollections gadget side effects.
- [x] Make Java 8/11/17 servlet request hooks safe for OSGi servlet-api bundle
  classloaders: Felix, Eclipse OSGi, and Knopflerfish servlet classes now use a
  reflection-only JDK bytecode path with computed stack frames instead of a
  direct constant-pool reference to the agent hook class; the Java 8 agent jar
  declares `Boot-Class-Path` for bootstrap sinks, while Java 11/17 continue to
  append themselves from the system-loaded agent path to avoid premature module
  resolution of optional JDK modules.
- [x] Re-run the LTS Tomcat compatibility matrix after the Unomi
  expression-stack command refinement, OSGi servlet hook compatibility path, and
  Java 11/17 manifest correction on 2026-06-04: `scripts/acceptance-java17.sh`
  passed Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed
  Tomcat 10.1 -> 9, and `scripts/acceptance-java8.sh` passed
  Tomcat 10.0 -> 9 -> 8.5 with baseline/protected checks for every current
  LTS-era behavior algorithm.
- [x] Re-run the LTS Tomcat compatibility matrix after the Dubbo
  CVE-2019-17564 Spring HTTP Invoker deserialization hook extension and
  embedded Tomcat modeler DTD false-positive refinement on 2026-06-04:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [x] Re-run the LTS Tomcat compatibility matrix after the Rhino/Mozilla
  `Context` hook extension on 2026-06-04: `scripts/acceptance-java17.sh`
  passed Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed
  Tomcat 10.1 -> 9, and `scripts/acceptance-java8.sh` passed
  Tomcat 10.0 -> 9 -> 8.5 with baseline/protected checks for every current
  LTS-era behavior algorithm.
- [x] Extend Java 8/11/17 script-source hooks after the H2 CVE-2018-10054
  gap: `ScriptEngine.eval(String...)` and `compile(String...)` sources now use
  the same runtime-execution classification, so compiled Nashorn/H2 trigger
  script sources are inspected before `CompiledScript.eval()`.
- [x] Re-run the LTS Tomcat compatibility matrix after the JMeter
  CVE-2018-1297 BeanShell gadget and RMI `MarshalInputStream`
  deserialization-hook extension on 2026-06-05:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [x] Re-run the Java 8/Tomcat compatibility matrix after the Solr Velocity
  real Java 8 acceptance on 2026-06-04: `scripts/acceptance-java8.sh` passed
  Tomcat 10.0 -> 9 -> 8.5 with baseline/protected checks for every current
  Java 8 behavior algorithm.
- [x] Re-run the LTS Tomcat compatibility matrix after the Solr
  `RunExecutableListener` command-stack refinement on 2026-06-04:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [x] Re-run the LTS Tomcat compatibility matrix after the script
  `compile(String...)` hook extension on 2026-06-04:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [ ] Continue expanding Java 8 Vulhub-era acceptance beyond the current real
  Shiro 1.0.0, Shiro 1.5.1, Fastjson, Log4j/Solr, Log4j 2.8.1
  CVE-2017-5645, JMeter 3.3 CVE-2018-1297, Neo4j 3.4.18
  CVE-2021-34371, Java RMI codebase on `vulhub/j2ee:8u222`, Java RMI Registry
  JRMP bypass on `vulhub/j2ee:8u111`, Solr Velocity,
  Solr RunExecutableListener, Solr XML parser XXE, Solr RemoteStreaming and
  DataImportHandler, H2 Console
  CVE-2022-23221, CVE-2021-42392, and CVE-2018-10054, XStream 1.4.15
  CVE-2021-21351, AJ-Report 1.4.0, Apache Druid 0.20.0, Apache Unomi 1.5.1,
  Spring Cloud Gateway 3.1.0 CVE-2022-22947, Spring Cloud Function 3.2.2
  CVE-2022-22963, Spring Data REST 2.6.6 CVE-2017-8046, Apache Dubbo 2.7.3,
  Spring Data Commons 2.0.5 CVE-2018-1273, Apache CXF 3.2.14, Alibaba Nacos
  1.4.0, RocketMQ 5.1.0, Apache Flink 1.11.2 CVE-2020-17518/CVE-2020-17519,
  Tomcat 8.5.19 CVE-2017-12615, Spark 2.3.1 unauthenticated REST submission,
  Hadoop YARN ResourceManager submission, Jetty 9.4.37 CVE-2021-28164,
  Elasticsearch CVE-2014-3120/CVE-2015-1427/CVE-2015-3337/CVE-2015-5531 and
  WooYun-2015-110216, and XXL-JOB 2.2.0 unauthenticated executor evidence
  before claiming complete Java 8
  vulnerability coverage for the dominant Java 8 Vulhub image group.
- [x] Build and test the dedicated Java 11 era startup-probe agent/testbed:
  `agent-java11`, `playground-java11`, `playground-java11-jakarta`,
  `Dockerfile.java11`, `docker-compose.java11.yml`, and
  `scripts/acceptance-java11.sh` run Java 11-compatible WARs on both
  `tomcat:10.1-jdk11-temurin` and `tomcat:9.0-jdk11-temurin`; the protected
  containers emit `ohmyrasp-java11-agent-start` with
  `instrumentation:"available"` and normal traffic produces no detection.
- [x] Add the first functional Java 11 era behavior hook:
  `ProcessBuilder.start` and `Runtime.exec` are transformed by the dedicated
  Java 11 agent, suspicious command-execution primitives emit
  `java11_command_execution_exploit_primitive` or
  `java11_command_execution_shell_meta`, normal `/bin/true` smoke and Tomcat
  traffic emit no detection, and block mode records `action:"block"` before
  throwing `Java11RaspBlockException` on Temurin 11, Tomcat 10.1/JDK11, and
  Tomcat 9/JDK11.
- [x] Add the second functional Java 11 era behavior hook:
  `InitialContext.lookup` and `lookupLink` are transformed by the dedicated
  Java 11 agent, remote LDAP/RMI/IIOP/CORBA naming URLs emit
  `java11_jndi_remote_lookup`, `java:comp/env` smoke traffic emits no
  detection, and block mode records `action:"block"` before throwing
  `Java11RaspBlockException` on Temurin 11, Tomcat 10.1/JDK11, and Tomcat
  9/JDK11.
- [x] Add the third functional Java 11 era behavior hook:
  `ObjectInputStream.resolveClass` and `resolveProxyClass` are transformed by
  the dedicated Java 11 agent, high-risk gadget or execution primitive classes
  such as `JdbcRowSetImpl`, `TemplatesImpl`, commons-collections transformer
  gadgets, Groovy closure gadgets, Spring factory gadgets, and `ProcessBuilder`
  emit `java11_deserialization_gadget_class`, ordinary string deserialization
  emits no detection, and block mode records `action:"block"` before throwing
  `Java11RaspBlockException` on Temurin 11, Tomcat 10.1/JDK11, and Tomcat
  9/JDK11.
- [x] Add the fourth functional Java 11 era behavior hook:
  `FileInputStream`, `FileOutputStream`, `RandomAccessFile`, and
  `java.nio.file.Files` content read/write and byte-channel open APIs are
  transformed by the dedicated Java 11 agent, sensitive reads emit
  `java11_file_sensitive_read`, webroot or traversal script/executable writes
  emit `java11_file_script_write`, ordinary temporary file access and Tomcat
  `WEB-INF` deployment artifacts emit no detection, and block mode records
  `action:"block"` before throwing `Java11RaspBlockException` on Temurin 11
  smoke, Tomcat 10.1/JDK11, and Tomcat 9/JDK11.
- [x] Add the fifth functional Java 11 era behavior hook: `ZipEntry.getName`
  is transformed by the dedicated Java 11 agent and correlated with subsequent
  Java file-write sinks, archive entry traversal emits
  `java11_archive_entry_traversal_write`, safe archive entry smoke traffic
  emits no detection, and block mode records `action:"block"` before throwing
  `Java11RaspBlockException` on Temurin 11, Tomcat 10.1/JDK11, and
  Tomcat 9/JDK11.
- [x] Add the sixth functional Java 11 era behavior hook:
  `URL.openConnection` and `openStream` are transformed by the dedicated
  Java 11 agent, cloud metadata URLs emit `java11_ssrf_cloud_metadata`,
  loopback administrative URLs emit `java11_ssrf_loopback_admin`, ordinary
  public URL traffic emits no detection, and block mode records
  `action:"block"` before throwing `Java11RaspBlockException` on Temurin 11,
  Tomcat 10.1/JDK11, and Tomcat 9/JDK11.
- [x] Add the seventh functional Java 11 era behavior hook:
  `URLClassLoader` constructors, `URLClassLoader.addURL`, and
  `RMIClassLoader` codebase APIs are transformed by the dedicated Java 11
  agent, remote HTTP(S)/FTP/LDAP/RMI codebases and `jar:`-wrapped remote
  codebases emit `java11_classloader_remote_codebase`, local `file:` classpath
  URLs and Felix/OSGi internal `http://felix.extensions:<port>/`
  extension-bundle codebases emit no detection, and block mode records
  `action:"block"` before throwing `Java11RaspBlockException` on Temurin 11,
  Tomcat 10.1/JDK11, and Tomcat 9/JDK11.
- [x] Add the eighth functional Java 11 era behavior hook:
  `DriverManager.getConnection` and direct H2 `org.h2.jdbc.JdbcConnection`
  constructors are transformed by the dedicated Java 11 agent, H2 `INIT`
  code-execution URLs emit `java11_jdbc_h2_code_execution`, Derby Java
  code-loading JDBC URLs emit `java11_jdbc_derby_code_loading`, MySQL
  `autoDeserialize` interceptor/custom-collation JDBC URLs emit
  `java11_jdbc_mysql_deserialization`, ordinary JDBC URL smoke traffic emits
  no detection, and block mode records `action:"block"` before throwing
  `Java11RaspBlockException` on Temurin 11, Tomcat 10.1/JDK11, and
  Tomcat 9/JDK11.
- [x] Add the ninth Java 11 era runtime primitive hook group:
  `ScriptEngine.eval`, Java source compilation, JAAS configuration entries,
  JMX MBean invocation, XMLDecoder JavaBeans object graphs, and Xerces XML
  entity setup are transformed by the dedicated Java 11 agent. The new
  algorithms are `java11_script_engine_runtime_execution`,
  `java11_java_compile_runtime_execution`, `java11_jaas_jndi_remote_provider`,
  `java11_jmx_remote_config_source`, `java11_jmx_script_file_write`,
  `java11_xml_decoder_runtime_execution`,
  `java11_xml_decoder_script_file_write`, and
  `java11_xxe_external_entity_protocol`. Temurin 11 extended smoke passes with
  ordinary script/compile/JAAS/JMX/XML traffic quiet and block mode recording
  `action:"block"` before throwing `Java11RaspBlockException`; Tomcat
  10.1/JDK11 and Tomcat 9/JDK11 matrix verification passes with
  baseline/protected checks for all eight algorithms.
- [x] Add the Java 11 era request path-confusion hook:
  `javax.servlet.http.HttpServlet.service` and
  `jakarta.servlet.http.HttpServlet.service` are transformed by the dedicated
  Java 11 agent, Shiro-style `/./admin` and `/xxx/..;/admin/` authentication
  bypass paths emit `java11_request_path_confusion`, ordinary direct admin
  paths emit no detection, and block mode records `action:"block"` before
  throwing `Java11RaspBlockException`.
- [x] Re-run the Java 11/Tomcat compatibility matrix after the request hook on
  2026-06-04: `scripts/acceptance-java11.sh` now checks
  `request_hook:"installed"` and passed Tomcat 10.1 -> 9 with all existing
  protected behavior algorithms still blocking and normal traffic quiet.
- [x] Run the first real Java 11 Vulhub application acceptance:
  `scripts/acceptance-vulhub-activemq-java11.sh` starts
  `vulhub/activemq:5.17.3` baseline/protected containers for ActiveMQ
  CVE-2022-41678. The baseline authenticated Jolokia Log4j2 flow invokes
  `org.apache.logging.log4j2:* setConfigText`, writes and executes
  `webapps/admin/shell.jsp`, then the authenticated JFR flow reaches
  `jdk.management.jfr:type=FlightRecorder.copyTo` and writes
  `webapps/admin/shelljfr.jsp`; the protected container starts quietly and
  blocks both webroot write variants with `java11_jmx_script_file_write`.
- [x] Run the first real Java 11 Spring WebMVC Vulhub application acceptance:
  `scripts/acceptance-vulhub-spring-java11.sh` starts
  `vulhub/spring-webmvc:5.3.17` baseline/protected containers for Spring
  Framework CVE-2022-22965. The baseline data-binding request reconfigures
  Tomcat AccessLogValve, writes `webapps/ROOT/tomcatwar.jsp`, and verifies the
  JSP webshell executes `id`; the protected Java 11 agent blocks the same
  AccessLogValve JSP write with `java11_file_script_write`.
- [x] Run the first real Java 11 HertzBeat Vulhub application acceptance:
  `scripts/acceptance-vulhub-hertzbeat-java11.sh` starts
  `vulhub/hertzbeat:1.4.4` baseline/protected containers for HertzBeat
  CVE-2024-42323. The baseline authenticated YAML import constructs
  `org.h2.jdbc.JdbcConnection` and creates `/tmp/ohmyrasp-hertzbeat-success`;
  the protected Java 11 agent blocks the direct H2 constructor URL before H2
  dynamic compilation with `java11_jdbc_h2_code_execution`.
- [x] Run the first real Java 11 HugeGraph Vulhub application acceptance:
  `scripts/acceptance-vulhub-hugegraph-java11.sh` starts
  `vulhub/hugegraph:1.2.0` baseline/protected containers for HugeGraph
  CVE-2024-27348. The baseline unauthenticated Gremlin/Groovy request reflects
  into `ProcessBuilder.start` and creates `/tmp/ohmyrasp-hugegraph-success`;
  the protected Java 11 agent blocks the same process primitive with
  `java11_command_execution_exploit_primitive`.
- [x] Run the real Java 11 HugeGraph default-JWT Vulhub application
  acceptance: `scripts/acceptance-vulhub-hugegraph-43441-java11.sh` starts
  `vulhub/hugegraph:1.3.0` baseline/protected containers for
  CVE-2024-43441. The baseline rejects unauthenticated `/graphs` with 401 but
  returns `{"graphs":["hugegraph"]}` for the README HS256 default-secret JWT;
  the protected Java 11 agent starts through HugeGraph `JAVA_OPTIONS`, keeps
  readiness quiet, and blocks the same Bearer token at the Jersey/Grizzly
  request entry with `java11_request_default_jwt_secret` before graph metadata
  is returned.
- [x] Run the first real Java 11 Metabase Vulhub application acceptance:
  `scripts/acceptance-vulhub-metabase-41277-java11.sh` starts
  `vulhub/metabase:0.40.4` baseline/protected containers for Metabase
  CVE-2021-41277. The baseline `/api/geojson?url=file:////etc/passwd`
  request returns passwd content; the protected Java 11 agent starts quietly
  and blocks the same GeoJSON local file load at `FileInputStream.open` with
  `java11_file_sensitive_read` before passwd content is disclosed.
- [x] Run the first real Java 11 Metabase setup-validation RCE Vulhub
  application acceptance: `scripts/acceptance-vulhub-metabase-38646-java11.sh`
  starts `vulhub/metabase:0.46.6` baseline/protected containers for Metabase
  CVE-2023-38646. Both sides first retrieve the real setup token from
  `/api/session/properties`; the baseline `/api/setup/validate` H2 `init`
  trigger creates `/tmp/ohmyrasp-metabase38646-success`, while the protected
  Java 11 agent blocks the same trigger source at `ScriptEngine.eval` with
  `java11_script_engine_runtime_execution`.
- [x] Refine Java 8/11/17 file-write false-positive handling from the Spring
  WebMVC 5.3.17 protected startup test: Tomcat `ExpandWar` deployment writes
  and Jasper JSP compilation outputs are ignored, while runtime writes to
  `webapps/ROOT/*.jsp` outside those deployment/compilation stacks remain
  covered.
- [x] Refine Java 8/11/17 sensitive file-read false-positive handling from the
  HertzBeat 1.4.4 protected startup test: Netty hosts-file resolver stack reads
  of `/etc/hosts` are ignored, while `/etc/passwd` and other sensitive files
  remain covered even from the same Netty-shaped stack.
- [ ] Continue expanding Java 11 Vulhub-era acceptance beyond the current real
  ActiveMQ 5.17.3, Spring WebMVC 5.3.17, HertzBeat 1.4.4, HugeGraph 1.2.0,
  Metabase 0.40.4, and Metabase 0.46.6 evidence before claiming complete
  Java 11 Vulhub vulnerability coverage.
- [x] Build and test the dedicated Java 17 era startup-probe and first
  behavior-hook agent/testbed: `agent-java17`, `playground-java17`,
  `playground-java17-jakarta`, `Dockerfile.java17`,
  `docker-compose.java17.yml`, and `scripts/acceptance-java17.sh` run
  Java 17-compatible WARs on `tomcat:11.0-jdk17-temurin`,
  `tomcat:10.1-jdk17-temurin`, and `tomcat:9.0-jdk17-temurin`; the protected
  containers emit `ohmyrasp-java17-agent-start` with
  `instrumentation:"available"`, normal traffic produces no detection, and
  protected mode blocks `java17_command_execution_exploit_primitive`,
  `java17_command_execution_shell_meta`, `java17_jndi_remote_lookup`,
  `java17_deserialization_gadget_class`, `java17_file_sensitive_read`, and
  `java17_file_script_write`.
- [x] Add the Java 17 era URL/SSRF behavior hook: `URL.openConnection` and
  `openStream` are transformed by the dedicated Java 17 agent, cloud metadata
  URLs emit `java17_ssrf_cloud_metadata`, loopback administrative URLs emit
  `java17_ssrf_loopback_admin`, ordinary public URL traffic emits no detection,
  and block mode records `action:"block"` before throwing
  `Java17RaspBlockException` on Temurin 17, Tomcat 11/JDK17,
  Tomcat 10.1/JDK17, and Tomcat 9/JDK17.
- [x] Add the Java 17 era archive traversal behavior hook:
  `ZipEntry.getName` is transformed by the dedicated Java 17 agent and
  correlated with subsequent Java file-write sinks, archive entry traversal
  emits `java17_archive_entry_traversal_write`, safe archive entry smoke
  traffic emits no detection, and block mode records `action:"block"` before
  throwing `Java17RaspBlockException` on Temurin 17, Tomcat 11/JDK17,
  Tomcat 10.1/JDK17, and Tomcat 9/JDK17.
- [x] Add the Java 17 era remote classloader codebase behavior hook:
  `URLClassLoader` constructors, `URLClassLoader.addURL`, and
  `RMIClassLoader` codebase APIs are transformed by the dedicated Java 17
  agent, remote HTTP(S)/FTP/LDAP/RMI codebases and `jar:`-wrapped remote
  codebases emit `java17_classloader_remote_codebase`, local `file:` classpath
  URLs and Felix/OSGi internal `http://felix.extensions:<port>/`
  extension-bundle codebases emit no detection, and block mode records
  `action:"block"` before throwing `Java17RaspBlockException` on Temurin 17,
  Tomcat 11/JDK17, Tomcat 10.1/JDK17, and Tomcat 9/JDK17.
- [x] Add the Java 17 era JDBC URL primitive behavior hook:
  `DriverManager.getConnection` and direct H2 `org.h2.jdbc.JdbcConnection`
  constructors are transformed by the dedicated Java 17 agent, H2 `INIT`
  code-execution URLs emit `java17_jdbc_h2_code_execution`, Derby Java
  code-loading JDBC URLs emit `java17_jdbc_derby_code_loading`, MySQL
  `autoDeserialize` interceptor/custom-collation JDBC URLs emit
  `java17_jdbc_mysql_deserialization`, ordinary JDBC URL smoke traffic emits
  no detection, and block mode records `action:"block"` before throwing
  `Java17RaspBlockException` on Temurin 17, Tomcat 11/JDK17,
  Tomcat 10.1/JDK17, and Tomcat 9/JDK17.
- [x] Add the Java 17 era runtime primitive hook group:
  `ScriptEngine.eval`, Java source compilation, JAAS configuration entries,
  JMX MBean invocation, XMLDecoder JavaBeans object graphs, and Xerces XML
  entity setup are transformed by the dedicated Java 17 agent. The new
  algorithms are `java17_script_engine_runtime_execution`,
  `java17_java_compile_runtime_execution`, `java17_jaas_jndi_remote_provider`,
  `java17_jmx_remote_config_source`, `java17_jmx_script_file_write`,
  `java17_xml_decoder_runtime_execution`,
  `java17_xml_decoder_script_file_write`, and
  `java17_xxe_external_entity_protocol`. Temurin 17 extended smoke passes with
  ordinary script/compile/JAAS/JMX/XML traffic quiet, including a Java17-specific
  Xerces fix that extracts `XMLInputSource.getSystemId()` inside the transformed
  `XMLEntityManager`; Tomcat 11/JDK17, Tomcat 10.1/JDK17, and Tomcat 9/JDK17
  matrix verification passes with baseline/protected checks for all eight
  algorithms.
- [x] Extend Java 8/11/17 file sink component coverage to
  `java.nio.file.Files` content read/write and byte-channel open APIs:
  `newInputStream`, `newOutputStream`, `newByteChannel`, `readAllBytes`,
  `readString`, `readAllLines`, `lines`, `copy`, `write`, and `writeString`
  now route through the same sensitive-read and script-write policies as
  `FileInputStream`, `FileOutputStream`, and `RandomAccessFile`; the combined
  `:agent-java8:check :agent-java11:check :agent-java17:check` run passes.
- [x] Re-run the LTS Tomcat compatibility matrix after the NIO file sink
  extension on 2026-06-04: `scripts/acceptance-java17.sh` passed Tomcat
  11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9,
  and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every then-current LTS-era behavior algorithm.
- [x] Add the Java 17 era request path-confusion hook:
  `javax.servlet.http.HttpServlet.service` and
  `jakarta.servlet.http.HttpServlet.service` are transformed by the dedicated
  Java 17 agent, Openfire-style `%u002e%u002e` setup traversal and Jetty
  lenient `%2>` dot decoding emit `java17_request_path_confusion`, ordinary
  direct admin paths emit no detection, and block mode records
  `action:"block"` before throwing `Java17RaspBlockException`.
- [x] Re-run the Java 17/Tomcat compatibility matrix after the request hook on
  2026-06-04: `scripts/acceptance-java17.sh` now checks
  `request_hook:"installed"` and passed Tomcat 11 -> 10.1 -> 9 with all
  existing protected behavior algorithms still blocking and normal traffic
  quiet.
- [x] Run the first real Java 17 Vulhub application acceptance:
  `scripts/acceptance-vulhub-activemq-java17.sh` starts
  `vulhub/activemq:6.1.1` baseline/protected containers for ActiveMQ
  CVE-2024-32114 plus CVE-2026-34197. The baseline unauthenticated Jolokia
  `addNetworkConnector(java.lang.String)` request reaches the vulnerable Broker
  MBean and returns Jolokia `status:200`; the protected container starts
  quietly, with no runtime JSP tag-library DTD XXE false positive, and blocks
  the same request with `java17_jmx_remote_config_source`.
- [x] Extend the real Java 17 ActiveMQ Vulhub application acceptance to
  `vulhub/activemq:6.2.2` for authenticated CVE-2026-34197 coverage:
  unauthenticated Jolokia requests return 401, the baseline `admin:admin`
  `addNetworkConnector(java.lang.String)` request reaches the vulnerable Broker
  MBean and returns Jolokia `status:200`, and the protected Java 17 agent
  blocks the same authenticated JMX remote configuration source with
  `java17_jmx_remote_config_source`.
- [x] Run the first real Java 17 GeoServer Vulhub application acceptance:
  `scripts/acceptance-vulhub-geoserver-java17.sh` starts
  `vulhub/geoserver:2.23.2` baseline/protected containers for CVE-2024-36401.
  The baseline WFS `GetPropertyValue` request with a `valueReference`
  `Runtime.exec('cat /etc/passwd')` expression reaches the vulnerable sink and
  returns the expected `ProcessImpl cannot be cast` error; the protected Java
  17 agent starts without Jetty/Servlet/Spring runtime-DTD XXE false positives
  and blocks the same expression with
  `java17_command_execution_exploit_primitive`.
- [x] Re-run the real Java 17 GeoServer Vulhub application acceptance for
  CVE-2022-41852 family coverage:
  `scripts/acceptance-vulhub-geoserver-java17.sh` starts
  `vulhub/geoserver:2.23.2` baseline/protected containers; the same WFS
  `GetPropertyValue` `valueReference=exec(...)` path proves the shared
  `Runtime.exec` XPath expression class referenced by CVE-2022-41852 and
  CVE-2024-36401. Baseline reaches the vulnerable sink, while protected mode
  blocks `java17_command_execution_exploit_primitive` before command-output
  evidence is returned. Evidence:
  `/tmp/ohmyrasp-geoserver-41852-family-java17-20260610234613.log`.
- [x] Run real Java 17 GeoServer Vulhub application acceptance for
  CVE-2021-40822: `scripts/acceptance-vulhub-geoserver-40822-java17.sh`
  starts `vulhub/geoserver:2.19.1` baseline/protected containers. The baseline
  `/geoserver/TestWfsPost` form post relays a request-parameter-controlled
  `url` to an isolated listener; the protected Java 17 agent keeps startup
  quiet, blocks the same `URL.openConnection` sink with
  `java17_ssrf_request_parameter_url`, and the protected listener receives no
  relay request.
- [x] Extend Java 8/11/17 servlet request hooks with OGC CQL/FILTER SQL
  injection classification: OGC `CQL_FILTER`, `ECQL_FILTER`, and `FILTER`
  parameters carrying nested `SELECT`, `CAST(SELECT ...)`, SQL comments, or
  SQL time-delay primitives now block as
  `javaX_request_ogc_filter_sql_injection` before datastore SQL execution,
  while normal CQL filters remain quiet and event details log only parameter
  name, value length, and `[redacted]`.
- [x] Run real Java 17 GeoServer Vulhub application acceptance for
  CVE-2023-25157/CVE-2023-25158:
  `scripts/acceptance-vulhub-geoserver-25157-java17.sh` starts
  `vulhub/geoserver:2.22.1` plus `postgis/postgis:14-3.3-alpine`
  baseline/protected pairs. The baseline WFS `GetFeature` request with the
  README `CQL_FILTER` payload reaches PostGIS and returns the PostgreSQL cast
  error evidence; the protected Java 17 agent keeps startup and normal CQL
  traffic quiet, blocks the same unauthenticated request with
  `java17_request_ogc_filter_sql_injection`, and does not leak PostgreSQL or
  raw SQL payload details in the response or event log.
- [x] Re-run the full LTS Tomcat matrix after adding the OGC CQL/FILTER SQL
  injection request rule and GeoServer 2.22.1 startup false-positive
  refinement on 2026-06-05: `scripts/acceptance-java17.sh` passed Tomcat 11
  -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Run real DataEase Vulhub application acceptance on an OpenJDK 21 runtime:
  `scripts/acceptance-vulhub-dataease-32966-java21.sh` starts
  `vulhub/dataease:2.10.7` plus `mysql:8.4` baseline/protected pairs for
  CVE-2025-32966. The baseline forged `X-DE-TOKEN`
  `/de2api/datasource/validate` H2 JDBC payload creates
  `/tmp/ohmyrasp-dataease-32966`; the protected Java 17-compatible agent keeps
  DataEase startup quiet and blocks the direct H2 constructor URL with
  `java17_jdbc_h2_code_execution` before the marker is created.
- [x] Run real DataEase CVE-2024-56511 Vulhub application acceptance on an
  OpenJDK 21 runtime: `scripts/acceptance-vulhub-dataease-56511-java21.sh`
  starts `vulhub/dataease:2.10.3` plus `mysql:8.4` baseline/protected pairs.
  The baseline direct `/dataease/de2api/datasource/types` request returns
  `500`, while `--path-as-is /geo/../dataease/de2api/datasource/types`
  returns the datasource type list; the protected Java 17-compatible agent
  keeps startup and the direct unauthenticated API request quiet, then blocks
  the traversal-shaped request with `java17_request_path_confusion`.
- [x] Extend Java 8/11/17 JWT verification-failure hooks after the DataEase
  CVE-2025-49001 gap: auth0 `java-jwt` `JWTVerifier.verify(...)` and
  `algorithms.*Algorithm.verify(DecodedJWT)` are transformed, request-time
  verification exceptions are correlated only with the active request's compact
  JWT token header on API/control paths, and events omit token values.
- [x] Run real DataEase CVE-2025-49001 Vulhub application acceptance on an
  OpenJDK 21 runtime: `scripts/acceptance-vulhub-dataease-49001-java21.sh`
  starts `vulhub/dataease:2.10.7` plus `mysql:8.4` baseline/protected pairs.
  Baseline returns a clean `401` for `/de2api/user/info` without
  `X-DE-TOKEN`, but a valid-format arbitrary-secret admin JWT reaches the
  downstream continuation path and returns `400` with the signature failure in
  `DE-GATEWAY-FLAG`; the protected Java 17-compatible agent keeps startup and
  the no-token rejection quiet, then blocks the auth0 JWT verification failure
  with `java17_request_jwt_verification_failure` without logging the token.
- [x] Re-run the full LTS Tomcat matrix after the auth0 `java-jwt`
  verification-failure hook on 2026-06-05:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Re-run the full LTS Tomcat matrix after adding request-parameter outbound
  URL correlation and servlet request cleanup hooks: `scripts/acceptance-java17.sh`
  passed Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat
  10.1 -> 9, and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Run the first real Java 17 Struts2 Vulhub application acceptance:
  `scripts/acceptance-vulhub-struts2-upload-java17.sh` starts
  `vulhub/struts2:s2-066` and `vulhub/struts2:s2-067` baseline/protected
  containers for S2-066/CVE-2023-50164 and S2-067/CVE-2024-53677. The
  baseline multipart uploads use `fileFileName=../shell.jsp` and
  `top.fileFileName=../shell.jsp` to write and execute `/shell.jsp`; the
  protected Java 17 agent blocks both server-side JSP writes with
  `java17_file_script_write`.
- [x] Run the first real Java 17 JimuReport Vulhub application acceptance:
  `scripts/acceptance-vulhub-jimureport-java17.sh` starts
  `vulhub/jimureport:1.6.0` plus MySQL baseline/protected containers for
  CVE-2023-4450. The baseline FreeMarker SSTI SQL body executes
  `cat /etc/passwd` and returns passwd content; the protected Java 17 agent
  blocks the same FreeMarker `Execute` process sink with
  `java17_command_execution_exploit_primitive`.
- [x] Run the first real Java 17 Spring Boot/Jetty Vulhub application
  acceptance: `scripts/acceptance-vulhub-spring-boot-jetty-java17.sh` starts
  `vulhub/spring-boot-jetty:3.2.4` baseline/protected containers for
  CVE-2025-41242. The baseline raw ghost-bits path traversal request reads
  `/etc/passwd`; the protected Java 17 agent keeps startup quiet and blocks
  the request path confusion before the file read with
  `java17_request_path_confusion`.
- [x] Run the first real Java 17 Openfire Vulhub application acceptance:
  `scripts/acceptance-vulhub-openfire-java17.sh` starts
  `vulhub/openfire:4.7.4` baseline/protected containers for CVE-2023-32315.
  The baseline `%u002e%u002e` setup traversal creates a new administrator in
  `OFUSER` and `admin.authorizedJIDs`; the protected Java 17 request hook keeps
  startup quiet, blocks both `%u002e%u002e` and lenient `%2>` traversal
  variants with `java17_request_path_confusion`, and neither protected user is
  persisted.
- [x] Re-run the real Java 17 Openfire setup traversal acceptance on
  2026-06-10 after the current backport hook changes:
  `scripts/acceptance-vulhub-openfire-java17.sh` passed again
  (`/tmp/ohmyrasp-openfire-2008-family-java17-20260610233858.log`). This
  current evidence is also used for the CVE-2008-6508 predecessor row because
  the Vulhub CVE-2023-32315 README records CVE-2008-6508 as the original setup
  traversal issue and the protected behavior is the same request path-confusion
  block before administrator persistence.
- [x] Refine XXE runtime-DTD false-positive handling from the ActiveMQ 6.1.1
  protected startup test: local `.dtd` resources under trusted runtime homes
  including `java.home`, Tomcat, Jetty, ActiveMQ, and Karaf homes are ignored,
  while external `file:`, `jar:`, HTTP(S), FTP, LDAP/RMI/IIOP/CORBA-style, and
  SMB/UNC entity sources remain covered.
- [x] Refine Java 8/11/17 XXE runtime-DTD false-positive handling from the
  GeoServer 2.23.2 protected startup test: exact Jetty configure,
  Java EE/Servlet deployment descriptor, JSP tag-library, and Spring beans DTD
  URLs used by runtime bootstrapping are ignored, while arbitrary HTTP(S) DTDs
  such as `http://127.0.0.1:9/evil.dtd` remain covered.
- [x] Refine Java 8/11/17 command false-positive handling from the GeoServer
  2.19.1 protected startup test: exact OS/system inventory probes used by
  OSHI during Spring bean initialization, including `getconf CLK_TCK`,
  `getconf PAGE_SIZE`, `getconf PAGESIZE`, `lscpu -p=cpu,node`, and
  `vcgencmd measure_temp`, are ignored while exploit-grade Spring bean-init
  process sinks remain covered.
- [x] Refine Java 8/11/17 command false-positive handling from the GeoServer
  2.22.1 protected startup test: exact Spring bean-initialization inventory
  probes `cat /etc/os-release | grep ^ID`, `/sbin/ldconfig -p`, and
  `uname -o` are ignored while arbitrary shell commands and exploit-grade
  Spring bean-init process sinks remain covered.
- [x] Refine Java 8/11/17 URL false-positive handling from the DataEase 2.10.7
  protected startup test: exact local APISIX admin self-checks on
  `http://127.0.0.1:9180/apisix/admin/...` are ignored only from the DataEase
  `XpackRouteManage` Spring ready-event stack, while the same loopback admin
  URL outside that startup stack still blocks as `javaX_ssrf_loopback_admin`.
- [x] Re-run the full LTS Tomcat matrix after the DataEase APISIX startup URL
  false-positive refinement: `scripts/acceptance-java17.sh` passed Tomcat 11
  -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Refine Java 8/11/17 XXE runtime-DTD false-positive handling from the
  Solr 8.11.0 protected startup test: the exact Jetty
  `http://www.eclipse.org/jetty/configure_9_0.dtd` and HTTPS equivalent used
  by Jetty 9.4 bootstrapping are ignored, while arbitrary HTTP(S) DTDs such as
  `http://127.0.0.1:9/evil.dtd` remain covered.
- [x] Refine Java 8/11/17 XXE runtime-DTD false-positive handling from the
  AJ-Report 1.4.0 protected startup test: exact MyBatis
  `mybatis-3-mapper.dtd` and `mybatis-3-config.dtd` runtime DTD URLs are
  ignored, while arbitrary HTTP(S) DTDs such as
  `http://127.0.0.1:9/evil.dtd` remain covered.
- [x] Refine Java 8/11/17 XXE runtime-DTD false-positive handling from the
  Dubbo 2.7.3 protected startup test: the exact embedded Tomcat modeler
  `jar:file:...!/org/apache/tomcat/util/modeler/mbeans-descriptors.dtd`
  resource inside a local fat JAR is ignored, while arbitrary external JAR,
  file, HTTP(S), FTP, LDAP/RMI/IIOP/CORBA-style, and SMB/UNC entity sources
  remain covered.
- [x] Refine Java 8/11/17 XXE local Struts validation XML false-positive
  handling from the Struts2 S2-009 protected readiness test: trusted local
  Struts/XWork `*-validation.xml` metadata is ignored, while arbitrary
  `file:///tmp/...-validation.xml` and other external entity sources remain
  covered.
- [x] Refine Java 8/11/17 XXE local Struts/XWork include XML false-positive
  handling from the Struts2 S2-005 protected startup test: simple classpath
  XML includes such as `WEB-INF/classes/example.xml` are ignored only while the
  XWork `XmlConfigurationProvider` is loading local app metadata, while direct
  out-of-stack app XML reads, arbitrary `/tmp` XML, and remote external entity
  sources remain covered.
- [x] Extend Java 8/11/17 request hooks for HugeGraph-style default JWT
  authentication bypasses and Jersey/Grizzly request dispatch: the dedicated
  agents now normalize Servlet and Jersey `ContainerRequest` URI/header values,
  verify known weak HMAC bearer JWT signatures without logging token material,
  and emit `java8_request_default_jwt_secret`,
  `java11_request_default_jwt_secret`, or `java17_request_default_jwt_secret`.
- [x] Re-run the full LTS Tomcat matrix after the default-JWT request rule and
  Jersey/Grizzly request-entry hook on 2026-06-05:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  per-version baseline/protected checks for every current playground matrix
  behavior algorithm.
- [x] Extend Java 8/11/17 servlet request hooks to Tomcat
  `org.apache.catalina.core.StandardWrapperValve` and add forged servlet
  include attribute detection: top-level requests carrying
  `javax.servlet.include.*` or `jakarta.servlet.include.*` attributes for
  protected web resources now emit `java8_request_forged_include_attribute`,
  `java11_request_forged_include_attribute`, or
  `java17_request_forged_include_attribute`, while normal
  `RequestDispatcher.include` stacks stay quiet. Real Vulhub evidence is
  `scripts/acceptance-vulhub-tomcat-1938-java8.sh`: Tomcat 9.0.30 on
  OpenJDK 8u242 discloses `WEB-INF/web.xml` through AJP in baseline mode, and
  protected mode blocks before the file is returned.
- [x] Re-run the LTS Tomcat compatibility matrix after the Tomcat
  `StandardWrapperValve` forged-include hook on 2026-06-05:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  per-version baseline/protected checks for every current LTS-era behavior
  algorithm.
- [x] Extend Java 8/11/17 servlet request hooks to Tomcat
  `org.apache.catalina.authenticator.AuthenticatorBase` before session
  swap-in and add filesystem-shaped `JSESSIONID` detection:
  hidden-file, traversal, slash, and encoded-separator session identifiers now
  emit `java8_request_session_file_deserialization`,
  `java11_request_session_file_deserialization`, or
  `java17_request_session_file_deserialization`; ordinary route-suffix session
  ids stay quiet. Real Vulhub evidence is
  `scripts/acceptance-vulhub-tomcat-24813-java8.sh`: Tomcat 9.0.97 on the
  Vulhub CVE-2025-24813 configuration resolves the baseline URLDNS payload
  during `GET /` with `Cookie: JSESSIONID=.deserialize`, and protected mode
  blocks before the DNS lookup.
- [x] Re-run the LTS Tomcat compatibility matrix after the Tomcat
  `AuthenticatorBase` session-file hook on 2026-06-05:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Add real Java 8 Tomcat Tribes CVE-2026-34486 acceptance:
  `scripts/acceptance-vulhub-tomcat-34486-java8.sh` uses the Vulhub
  `tomcat/CVE-2026-34486/poc.py` frame against `vulhub/tomcat:9.0.116`
  on OpenJDK 8u482/Tomcat 9.0.116. Baseline HTTP startup stays healthy and
  the Tribes receiver accepts an unencrypted CommonsCollections6 serialized
  payload after the `EncryptInterceptor` bypass, creating
  `/tmp/ohmyrasp-tomcat-34486-success`; protected mode starts quietly with the
  Java 8 agent, then blocks `ObjectInputStream.resolveClass` with
  `java8_deserialization_gadget_class` on
  `org.apache.commons.collections.functors.ChainedTransformer` before the
  marker is created.
- [x] Re-run the real Java 8 Tomcat Tribes CVE-2026-34486 acceptance on
  2026-06-10 after the current backport hook changes:
  `scripts/acceptance-vulhub-tomcat-34486-java8.sh` passed again
  (`/tmp/ohmyrasp-tomcat-29146-family-java8-20260610233350.log`). This current
  evidence is also used for the CVE-2026-29146 predecessor row because the
  Vulhub CVE-2026-34486 README records CVE-2026-29146 as the
  EncryptInterceptor padding-oracle predecessor and the protected sink is the
  same post-oracle Tribes deserialization path.
- [x] Extend Java 8/11/17 JDBC-era transformers to SkyWalking
  `org.apache.skywalking.oap.server.storage.plugin.jdbc.h2.dao.H2LogQueryDAO`:
  `queryLogs(String, ...)` now checks the GraphQL `metricName` table/metric
  identifier before the H2 SQL string is built, emits
  `java8_sql_identifier_injection`, `java11_sql_identifier_injection`, or
  `java17_sql_identifier_injection` for comment, separator, expression, boolean
  comparison, and keyword-control syntax, ignores ordinary metric names such as
  `service_instance_jvm_memory.max`, and logs only source, parameter, reason,
  and value length. Real Vulhub evidence is
  `scripts/acceptance-vulhub-skywalking-java8.sh`: baseline SkyWalking 8.3.0
  on OpenJDK 8 includes the malicious `metricName` in the H2 `select count(1)
  total from ...` error, while protected mode blocks in the OAP JVM with
  `java8_sql_identifier_injection`.
- [x] Re-run the LTS Tomcat compatibility matrix after the SkyWalking
  `H2LogQueryDAO` SQL identifier hook on 2026-06-05:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Extend Java 8/11/17 JDBC-era transformers to MyBatis
  `org.apache.ibatis.mapping.BoundSql`: constructor-time checks now inspect
  order-by metadata carried by request objects such as `orders[].type`,
  `orders[].name`, and `orders[].prefix`, emit `java8_sql_identifier_injection`,
  `java11_sql_identifier_injection`, or `java17_sql_identifier_injection` for
  SQL control syntax, keep ordinary sort metadata such as `desc` quiet, and
  log only source, parameter, reason, and value length. Real Vulhub evidence is
  `scripts/acceptance-vulhub-metersphere-45788-java8.sh`: baseline
  MeterSphere 1.15.4 on OpenJDK 8 accepts the default login, creates the
  testcase-list context, and delays on the injected sort direction, while
  protected mode blocks at `MyBatis.BoundSql` with
  `java8_sql_identifier_injection` without logging the session id, CSRF token,
  or raw SQL value.
- [x] Re-run the LTS Tomcat compatibility matrix after the MyBatis `BoundSql`
  SQL identifier hook on 2026-06-06: `scripts/acceptance-java17.sh` passed
  Java 17 Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed
  Java 11 Tomcat 10.1 -> 9, and `scripts/acceptance-java8.sh` passed Java 8
  Tomcat 10.0 -> 9 -> 8.5.
- [x] Extend Java 8/11/17 multipart upload filename hooks across Servlet
  `Part`, Tomcat `ApplicationPart`, Undertow `PartImpl`, Commons FileUpload,
  Jetty multipart parts, and Spring `MultipartFile` implementations: Java
  executable archive filenames now emit `fileUpload_java_archive` only when the
  active request context is a plugin, extension, driver, connector, job, JAR,
  or deployment surface. The LTS playground matrices now baseline-test
  `/javaX/plugin/add` multipart `Evil.jar` uploads and protected mode verifies
  `MultipartUpload.filename` block events without accepting the file.
- [x] Add real Java 8 Vulhub MeterSphere plugin RCE acceptance:
  `scripts/acceptance-vulhub-metersphere-plugin-java8.sh` verifies
  `vulhub/metersphere:1.16.3` on OpenJDK 8 exposes `/plugin/list` without
  login, accepts the official Vulhub Backdoor plugin JAR through `/plugin/add`,
  executes `org.vulhub.Evil` through `/plugin/customMethod`, and creates
  `/tmp/ohmyrasp-metersphere-plugin-success`; protected mode starts quietly,
  keeps `/plugin/list` quiet, blocks the same `Evil.jar` upload with
  `fileUpload_java_archive` at `MultipartUpload.filename`, does not write the
  plugin JAR under `/opt/metersphere/data/body/plugin`, and cannot create the
  marker through `customMethod`.
- [x] Re-run the LTS Tomcat compatibility matrix after the multipart Java
  archive upload hook on 2026-06-06: `scripts/acceptance-java17.sh` passed
  Java 17 Tomcat 11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed
  Java 11 Tomcat 10.1 -> 9, and `scripts/acceptance-java8.sh` passed Java 8
  Tomcat 10.0 -> 9 -> 8.5 with the new upload baseline/protected checks.
- [x] Extend Java 8/11/17 servlet request hooks for TeamCity
  CVE-2024-27198 internal-forward authentication bypasses:
  request-controlled `jsp`, `view`, `forward`, and related parameters now
  decode servlet path-parameter JSP suffix confusion such as
  `/app/rest/users;.jsp`, strip path parameters before sensitive-control-path
  matching, and emit `java8_request_internal_forward`,
  `java11_request_internal_forward`, or `java17_request_internal_forward`.
  The same pass refined TeamCity startup false positives for the metadata
  verifier JVM subprocess and bundled plugin resource unpacking. Real Vulhub
  evidence is `scripts/acceptance-vulhub-teamcity-27198-java17.sh`:
  baseline `vulhub/teamcity:2023.11.3` on Java 17 LTS exposes
  unauthenticated users XML and creates a `SYSTEM_ADMIN` user through
  `POST /hax?jsp=/app/rest/users;.jsp`, while protected mode starts quietly
  and blocks both GET and POST with `java17_request_internal_forward`.
- [x] Re-run the LTS Tomcat compatibility matrix after the TeamCity
  CVE-2024-27198 internal-forward hook and TeamCity startup false-positive
  refinements on 2026-06-05: `scripts/acceptance-java17.sh` passed Tomcat
  11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9,
  and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Extend Java 8/11/17 servlet request hooks for TeamCity
  CVE-2023-42793 debug process-launch chains: mutating debug/process control
  requests with executable or command parameters now emit
  `java8_request_debug_process_launch`, `java11_request_debug_process_launch`,
  or `java17_request_debug_process_launch` before TeamCity reaches the later
  process-spawn sink. The same pass refined TeamCity startup false positives
  for the metadata verifier JVM subprocess using `server.jar` and the ordinary
  `/admin/../installLinks.jspf` fragment request. Real Vulhub evidence is
  `scripts/acceptance-vulhub-teamcity-42793-java17.sh`: baseline
  `vulhub/teamcity:2023.05.3` on Java 17 LTS creates the `/RPC2` token, enables
  `rest.debug.processes.enable=true`, and executes `id` through
  `/app/rest/debug/processes?exePath=id`, while protected mode starts quietly
  and blocks the debug process-launch request with
  `java17_request_debug_process_launch` without logging the bearer token or raw
  command value.
- [x] Re-run the LTS Tomcat compatibility matrix after the TeamCity
  CVE-2023-42793 debug process-launch hook and TeamCity startup false-positive
  refinements on 2026-06-06: `scripts/acceptance-java17.sh` passed Tomcat
  11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9,
  and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5.
- [x] Re-run the LTS Tomcat compatibility matrix after the Struts/XWork include
  XML refinement on 2026-06-05: `scripts/acceptance-java17.sh` passed Tomcat
  11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  per-version execution and baseline/protected checks for every current
  LTS-era behavior algorithm.
- [x] Re-run the LTS Tomcat compatibility matrix after the Struts validation XML
  refinement on 2026-06-05: `scripts/acceptance-java17.sh` passed Tomcat
  11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  per-version execution and baseline/protected checks for every current
  LTS-era behavior algorithm.
- [x] Re-run the LTS Tomcat compatibility matrix after the MyBatis runtime-DTD
  refinement on 2026-06-04: `scripts/acceptance-java17.sh` passed Tomcat
  11 -> 10.1 -> 9, `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9,
  and `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [x] Re-run the LTS Tomcat compatibility matrix after the Jetty
  `configure_9_0.dtd` runtime-DTD refinement on 2026-06-04:
  `scripts/acceptance-java17.sh` passed Tomcat 11 -> 10.1 -> 9,
  `scripts/acceptance-java11.sh` passed Tomcat 10.1 -> 9, and
  `scripts/acceptance-java8.sh` passed Tomcat 10.0 -> 9 -> 8.5 with
  baseline/protected checks for every current LTS-era behavior algorithm.
- [ ] Continue expanding Java 17 Vulhub-era acceptance beyond the current real
  ActiveMQ 6.x, GeoServer, Struts2, JimuReport, Spring Boot/Jetty, and
  Openfire evidence before claiming complete Java 17 vulnerability coverage.
- [ ] Decide and document the legacy track for Java 7/Tomcat 6/7 environments
  without weakening the Java 25 production agent for backward compatibility.

## Source Path Coverage Matrix

Every scoped Java/JVM README path below is either covered by a checked target in
this file or explicitly handled as an alias/reference path in the source audit
above.

- [x] `activemq/CVE-2015-5254/README.md`
- [x] `activemq/CVE-2016-3088/README.md`
- [x] `activemq/CVE-2022-41678/README.md`
- [x] `activemq/CVE-2023-46604/README.md`
- [x] `activemq/CVE-2024-32114/README.md`
- [x] `activemq/CVE-2026-34197/README.md`
- [x] `aj-report/CNVD-2024-15077/README.md`
- [x] `apache-cxf/CVE-2024-28752/README.md`
- [x] `apache-druid/CVE-2021-25646/README.md`
- [x] `apereo-cas/4.1-rce/README.md`
- [x] `coldfusion/CVE-2010-2861/README.md`
- [x] `coldfusion/CVE-2017-3066/README.md`
- [x] `coldfusion/CVE-2023-26360/README.md`
- [x] `coldfusion/CVE-2023-29300/README.md`
- [x] `confluence/CVE-2019-3396/README.md`
- [x] `confluence/CVE-2021-26084/README.md`
- [x] `confluence/CVE-2022-26134/README.md`
- [x] `confluence/CVE-2023-22515/README.md`
- [x] `confluence/CVE-2023-22527/README.md`
- [x] `dataease/CVE-2024-56511/README.md`
- [x] `dataease/CVE-2025-32966/README.md`
- [x] `dataease/CVE-2025-49001/README.md`
- [x] `dubbo/CVE-2019-17564/README.md`
- [x] `elasticsearch/CVE-2014-3120/README.md`
- [x] `elasticsearch/CVE-2015-1427/README.md`
- [x] `elasticsearch/CVE-2015-3337/README.md`
- [x] `elasticsearch/CVE-2015-5531/README.md`
- [x] `elasticsearch/WooYun-2015-110216/README.md`
- [x] `fastjson/1.2.24-rce/README.md`
- [x] `fastjson/1.2.47-rce/README.md`
- [x] `fastjson/vuln/README.md`
- [x] `flink/CVE-2020-17518/README.md`
- [x] `flink/CVE-2020-17519/README.md`
- [x] `geoserver/CVE-2021-40822/README.md`
- [x] `geoserver/CVE-2022-24816/README.md`
- [x] `geoserver/CVE-2023-25157/README.md`
- [x] `geoserver/CVE-2024-36401/README.md`
- [x] `glassfish/CVE-2017-1000028/README.md`
- [x] `h2database/CVE-2018-10054/README.md`
- [x] `h2database/CVE-2021-42392/README.md`
- [x] `h2database/CVE-2022-23221/README.md`
- [x] `hadoop/unauthorized-yarn/README.md`
- [x] `hertzbeat/CVE-2024-42323/README.md`
- [x] `hugegraph/CVE-2024-27348/README.md`
- [x] `hugegraph/CVE-2024-43441/README.md`
- [x] `jackson/CVE-2017-7525/README.md`
- [x] `java/rmi-codebase/README.md`
- [x] `java/rmi-registry-bind-deserialization-bypass/README.md`
- [x] `java/rmi-registry-bind-deserialization/README.md`
- [x] `jboss/CVE-2017-12149/README.md`
- [x] `jboss/CVE-2017-7504/README.md`
- [x] `jboss/JMXInvokerServlet-deserialization/README.md`
- [x] `jenkins/CVE-2017-1000353/README.md`
- [x] `jenkins/CVE-2018-1000861/README.md`
- [x] `jenkins/CVE-2024-23897/README.md`
- [x] `jetty/CVE-2021-28164/README.md`
- [x] `jetty/CVE-2021-28169/README.md`
- [x] `jetty/CVE-2021-34429/README.md`
- [x] `jimureport/CVE-2023-4450/README.md`
- [x] `jira/CVE-2019-11581/README.md`
- [x] `jmeter/CVE-2018-1297/README.md`
- [x] `kafka/CVE-2023-25194/README.md`
- [x] `kkfileview/4.3-zipslip-rce/README.md`
- [x] `liferay-portal/CVE-2020-7961/README.md`
- [x] `linkis/CVE-2022-44645/README.md`
- [x] `log4j/CVE-2017-5645/README.md`
- [x] `log4j/CVE-2021-44228/README.md`
- [x] `metabase/CVE-2021-41277/README.md`
- [x] `metabase/CVE-2023-38646/README.md`
- [x] `metersphere/CVE-2021-45788/README.md`
- [x] `metersphere/plugin-rce/README.md`
- [x] `mojarra/jsf-viewstate-deserialization/README.md`
- [x] `nacos/CVE-2021-29441/README.md`
- [x] `nacos/CVE-2021-29442/README.md`
- [x] `neo4j/CVE-2021-34371/README.md`
- [x] `nexus/CVE-2019-7238/README.md`
- [x] `nexus/CVE-2020-10199/README.md`
- [x] `nexus/CVE-2020-10204/README.md`
- [x] `nexus/CVE-2024-4956/README.md`
- [x] `ofbiz/CVE-2020-9496/README.md`
- [x] `ofbiz/CVE-2023-49070/README.md`
- [x] `ofbiz/CVE-2023-51467/README.md`
- [x] `ofbiz/CVE-2024-38856/README.md`
- [x] `ofbiz/CVE-2024-45195/README.md`
- [x] `ofbiz/CVE-2024-45507/README.md`
- [x] `openfire/CVE-2023-32315/README.md`
- [x] `opentsdb/CVE-2020-35476/README.md`
- [x] `opentsdb/CVE-2023-25826/README.md`
- [x] `rocketmq/CVE-2023-33246/README.md`
- [x] `rocketmq/CVE-2023-37582/README.md`
- [x] `shiro/CVE-2010-3863/README.md`
- [x] `shiro/CVE-2016-4437/README.md`
- [x] `shiro/CVE-2020-1957/README.md`
- [x] `skywalking/8.3.0-sqli/README.md`
- [x] `solr/CVE-2017-12629-RCE/README.md`
- [x] `solr/CVE-2017-12629-XXE/README.md`
- [x] `solr/CVE-2019-0193/README.md`
- [x] `solr/CVE-2019-17558/README.md`
- [x] `solr/Remote-Streaming-Fileread/README.md`
- [x] `spark/unacc/README.md`
- [x] `spring/CVE-2016-4977/README.md`
- [x] `spring/CVE-2017-4971/README.md`
- [x] `spring/CVE-2017-8046/README.md`
- [x] `spring/CVE-2018-1270/README.md`
- [x] `spring/CVE-2018-1273/README.md`
- [x] `spring/CVE-2022-22947/README.md`
- [x] `spring/CVE-2022-22963/README.md`
- [x] `spring/CVE-2022-22965/README.md`
- [x] `spring/CVE-2022-22978/README.md`
- [x] `spring/CVE-2025-41242/README.md`
- [x] `struts2/s2-001/README.md`
- [x] `struts2/s2-005/README.md`
- [x] `struts2/s2-007/README.md`
- [x] `struts2/s2-008/README.md`
- [x] `struts2/s2-009/README.md`
- [x] `struts2/s2-012/README.md`
- [x] `struts2/s2-013/README.md`
- [x] `struts2/s2-015/README.md`
- [x] `struts2/s2-016/README.md`
- [x] `struts2/s2-032/README.md`
- [x] `struts2/s2-045/README.md`
- [x] `struts2/s2-046/README.md`
- [x] `struts2/s2-048/README.md`
- [x] `struts2/s2-052/README.md`
- [x] `struts2/s2-053/README.md`
- [x] `struts2/s2-057/README.md`
- [x] `struts2/s2-059/README.md`
- [x] `struts2/s2-061/README.md`
- [x] `struts2/s2-066/README.md`
- [x] `struts2/s2-067/README.md`
- [x] `teamcity/CVE-2023-42793/README.md`
- [x] `teamcity/CVE-2024-27198/README.md`
- [x] `tomcat/CVE-2017-12615/README.md`
- [x] `tomcat/CVE-2020-1938/README.md`
- [x] `tomcat/CVE-2025-24813/README.md`
- [x] `tomcat/CVE-2026-34486/README.md`
- [x] `tomcat/tomcat8/README.md`
- [x] `unomi/CVE-2020-13942/README.md`
- [x] `weblogic/CVE-2017-10271/README.md`
- [x] `weblogic/CVE-2018-2628/README.md`
- [x] `weblogic/CVE-2018-2894/README.md`
- [x] `weblogic/CVE-2020-14882/README.md`
- [x] `weblogic/CVE-2023-21839/README.md`
- [x] `weblogic/ssrf/README.md`
- [x] `weblogic/weak_password/README.md`
- [x] `xstream/CVE-2021-21351/README.md`
- [x] `xstream/CVE-2021-29505/README.md`
- [x] `xxl-job/unacc/README.md`

## Covered Targets

### ActiveMQ

- [x] ActiveMQ - CVE-2015-5254 object message browse deserialization (`deserialization_activemq_cve_2015_5254_object_message_browse`; real Java7 legacy boundary: `scripts/acceptance-vulhub-activemq-5254-java7-legacy.sh`)
- [x] ActiveMQ - CVE-2023-46604 OpenWire protocol class loading (`deserialization_activemq_cve_2023_46604_openwire_protocol_class`; real Java11 acceptance: `scripts/acceptance-vulhub-activemq-46604-java11.sh` blocks `java11_command_execution_exploit_primitive`)
- [x] ActiveMQ - CVE-2016-3088 fileserver PUT/MOVE webroot write (`fileUpload_activemq_fileserver_move`; real Java7 legacy boundary: `scripts/acceptance-vulhub-activemq-3088-java7-legacy.sh`)
- [x] ActiveMQ - CVE-2022-41678 Jolokia Log4j2 `setConfigText` webroot write (`jmx_activemq_jolokia_file_write`; real Java11 acceptance: `scripts/acceptance-vulhub-activemq-java11.sh` blocks `java11_jmx_script_file_write`)
- [x] ActiveMQ - CVE-2022-41678 Jolokia JFR `FlightRecorder.copyTo` webroot write (`jmx_activemq_cve_2022_41678_jfr_copyto_webshell`; real Java11 acceptance: `scripts/acceptance-vulhub-activemq-java11.sh` blocks `java11_jmx_script_file_write`)
- [x] ActiveMQ - CVE-2024-32114 plus CVE-2026-34197 Jolokia `addNetworkConnector` brokerConfig RCE chain (`jmx_activemq_jolokia_broker_config`; real Java17 acceptance: `scripts/acceptance-vulhub-activemq-java17.sh` blocks `java17_jmx_remote_config_source`)

### AJ-Report / JimuReport

- [x] AJ-Report - CNVD-2024-15077 `dataSetParam/verification;swagger-ui` script validation (`request_aj_report_cnvd_2024_15077_validation_rules`; real Java8 acceptance: `scripts/acceptance-vulhub-aj-report-java8.sh` blocks `java8_script_engine_runtime_execution`)
- [x] JimuReport - CVE-2023-4450 FreeMarker SQL template body (`request_jmreport_freemarker_sql`; real Java17 acceptance: `scripts/acceptance-vulhub-jimureport-java17.sh` blocks `java17_command_execution_exploit_primitive`)

### Apache CXF / Druid / Kafka

- [x] Apache CXF - CVE-2024-28752 Aegis XOP `href` file/SSRF reference (`xop_attachment_cxf_cve_2024_28752_aegis_file_read`; real Java8 acceptance: `scripts/acceptance-vulhub-cxf-java8.sh` blocks `java8_file_sensitive_read`)
- [x] Apache Druid - CVE-2021-25646 JavaScript sampler execution (`request_druid_cve_2021_25646_javascript_sampler`; real Java8 acceptance: `scripts/acceptance-vulhub-druid-java8.sh` blocks `java8_script_engine_runtime_execution`)
- [x] Apache Druid / Kafka - CVE-2023-25194 JAAS JNDI sampler config (`jndi_kafka_cve_2023_25194_druid_sampler_jaas`; real Java8 acceptance: `scripts/acceptance-vulhub-druid-25194-java8.sh` blocks `java8_jaas_jndi_remote_provider`)

### Apereo CAS / Java RMI / JMeter / Log4j

- [x] Apereo CAS - 4.1 encrypted WebFlow execution state deserialization (`deserialization_apereo_cas_4_1_webflow_execution_state`; real Java8 acceptance: `scripts/acceptance-vulhub-apereo-cas-415-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] Apache JMeter - CVE-2018-1297 RMI distributed test deserialization (`deserialization_jmeter_cve_2018_1297_rmi_transport`; real Java8 acceptance: `scripts/acceptance-vulhub-jmeter-1297-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] Apache Log4j - CVE-2017-5645 TCP SocketServer deserialization (`deserialization_log4j_cve_2017_5645_socket_server`; real Java8 acceptance: `scripts/acceptance-vulhub-log4j-5645-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] Java RMI - remote RMIClassLoader codebase class loading (`classloader_java_rmi_codebase_remote_classload`; real Java8 acceptance: `scripts/acceptance-vulhub-rmi-codebase-java8.sh` blocks `java8_classloader_remote_codebase`)
- [x] Java RMI Registry - JDK <= 8u111 bind deserialization (`deserialization_java_rmi_registry_bind`; real Java8 acceptance: `scripts/acceptance-vulhub-rmi-registry-direct-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] Java RMI Registry - JDK < 8u232-b09 UnicastRef/JRMP bypass (`deserialization_java_rmi_registry_bind_bypass`; real Java8 acceptance: `scripts/acceptance-vulhub-rmi-registry-bypass-java8.sh` blocks `java8_deserialization_gadget_class`)

### Apache Flink / Hadoop / HertzBeat / Spark

- [x] Apache Flink - CVE-2020-17518 jar upload traversal (`fileUpload_flink_cve_2020_17518_jar_upload`; real Java8 acceptance: `scripts/acceptance-vulhub-flink-java8.sh` blocks `java8_file_script_write`)
- [x] Apache Flink - CVE-2020-17519 JobManager logs traversal (`request_path_confusion`; real Java8 acceptance: `scripts/acceptance-vulhub-flink-17519-java8.sh` blocks `java8_file_sensitive_read` in the Netty REST runtime)
- [x] Apache Hadoop YARN - REST container command submission (`request_hadoop_yarn_command_submission`; real Java8 acceptance: `scripts/acceptance-vulhub-hadoop-yarn-java8.sh` blocks `java8_request_remote_job_submission`)
- [x] Apache HertzBeat - CVE-2024-42323 SnakeYAML H2 import (`request_hertzbeat_cve_2024_42323_yaml_import`; real Java11 acceptance: `scripts/acceptance-vulhub-hertzbeat-java11.sh` blocks `java11_jdbc_h2_code_execution`)
- [x] Apache Spark - unauthenticated REST application submission (`request_spark_unacc_rest_submission`; real Java8 acceptance: `scripts/acceptance-vulhub-spark-java8.sh` blocks `java8_request_remote_job_submission`)

### Apache Shiro / Struts2 / Tomcat

- [x] Apache Shiro - CVE-2010-3863 dot-segment auth bypass shape (`request_shiro_cve_2010_3863_dot_segment_admin`; real Java8 acceptance: `scripts/acceptance-vulhub-shiro-java8.sh` blocks `java8_request_path_confusion`)
- [x] Apache Shiro - CVE-2016-4437 default rememberMe crypto key (`request_shiro_cve_2016_4437_default_rememberme`; real Java8 acceptance: `scripts/acceptance-vulhub-shiro-4437-java8.sh` blocks `java8_request_default_crypto_cookie`)
- [x] Apache Shiro - CVE-2020-1957 semicolon traversal bypass shape (`request_shiro_cve_2020_1957_semicolon_traversal_admin`; real Java8 acceptance: `scripts/acceptance-vulhub-shiro-java8.sh` blocks `java8_request_path_confusion`)
- [x] Apache Struts2 - S2-001/S2-007/S2-008/S2-009/S2-012/S2-013/S2-048/S2-053 OGNL request expressions (`request_expression_parameter`; real Java8 acceptances: S2-001 `scripts/acceptance-vulhub-struts2-s2001-java8.sh`, S2-007 `scripts/acceptance-vulhub-struts2-s2007-java8.sh`, S2-008 `scripts/acceptance-vulhub-struts2-s2008-java8.sh`, S2-009 `scripts/acceptance-vulhub-struts2-s2009-java8.sh`, S2-012 `scripts/acceptance-vulhub-struts2-s2012-java8.sh`, S2-013 `scripts/acceptance-vulhub-struts2-s2013-java8.sh`, S2-048 `scripts/acceptance-vulhub-struts2-s2048-java8.sh`, and S2-053 `scripts/acceptance-vulhub-struts2-s2053-java8.sh` block `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-014 dollar OGNL includeParams bypass (`request_struts2_s2014_dollar_ognl_includeparams`; real Java8 acceptance: `scripts/acceptance-vulhub-struts2-s2013-java8.sh` exercises the local `struts2/s2-013` S2-013/S2-014 build and blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-003 escaped hash parameter-name OGNL origin (`request_struts2_s2003_eval_parameter_name`; current Vulhub snapshot has no `struts2/s2-003` environment, so this remains a source-availability boundary rather than real Vulhub acceptance)
- [x] Apache Struts2 - S2-005/S2-016 parameter-name OGNL (`request_expression_parameter_name`; real Java8 acceptances: S2-005 `scripts/acceptance-vulhub-struts2-s2005-java8.sh` and S2-016 `scripts/acceptance-vulhub-struts2-s2016-java8.sh` block `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-032 / CVE-2016-3081 dynamic method parameter-name OGNL (`request_struts2_cve_2016_3081_s2032_method_parameter_name`; real Java8 acceptance: `scripts/acceptance-vulhub-struts2-s2032-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-015 action path OGNL (`request_struts2_s2015_action_path`; real Java8 acceptance: `scripts/acceptance-vulhub-struts2-s2015-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-045 / CVE-2017-5638 content-type OGNL (`request_struts2_cve_2017_5638_s2045_content_type`; real Java8 acceptance: `scripts/acceptance-vulhub-struts2-s2045-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-046 / CVE-2017-5638 multipart filename OGNL (`fileUpload_struts2_cve_2017_5638_s2046_filename`; real Java8 acceptance: `scripts/acceptance-vulhub-struts2-s2046-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-052 REST XML polymorphic gadget (`request_struts2_s2052_xml_polymorphic_gadget`; real Java8 acceptance: `scripts/acceptance-vulhub-struts2-s2052-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-057 / CVE-2018-11776 namespace path OGNL (`request_struts2_cve_2018_11776_s2057_namespace_path`; real Java8 acceptance: `scripts/acceptance-vulhub-struts2-s2057-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-059 / CVE-2019-0230 forced OGNL request expression (`request_struts2_cve_2019_0230_s2059_forced_ognl`; real Java8 acceptance: `scripts/acceptance-vulhub-struts2-s2059-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-061 / CVE-2020-17530 FreeMarker Execute multipart payload (`request_struts2_cve_2020_17530_s2061_freemarker_execute`; real Java8 acceptance: `scripts/acceptance-vulhub-struts2-s2061-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Struts2 - S2-066 / CVE-2023-50164 upload filename override (`request_struts2_cve_2023_50164_s2066_upload_filename_override`; real Java17 acceptance: `scripts/acceptance-vulhub-struts2-upload-java17.sh` blocks `java17_file_script_write`)
- [x] Apache Struts2 - S2-067 / CVE-2024-53677 upload filename override (`request_struts2_cve_2024_53677_s2067_upload_filename_override`; real Java17 acceptance: `scripts/acceptance-vulhub-struts2-upload-java17.sh` blocks `java17_file_script_write`)
- [x] Apache Tomcat - CVE-2017-12615 DefaultServlet JSP PUT shape (`request_tomcat_cve_2017_12615_server_side_script_put`; real Java8 acceptance: `scripts/acceptance-vulhub-tomcat-12615-java8.sh` blocks `java8_file_script_write`)
- [x] Apache Tomcat - CVE-2020-1938 / CNVD-2020-10487 Ghostcat AJP include replay (`request_tomcat_cnvd_2020_10487_ghostcat_include`; real Java8 acceptance: `scripts/acceptance-vulhub-tomcat-1938-java8.sh` blocks `java8_request_forged_include_attribute`)
- [x] Apache Tomcat - CVE-2025-24813 session file deserialization (`deserialization_tomcat_cve_2025_24813_session_file`; real Java8 acceptance: `scripts/acceptance-vulhub-tomcat-24813-java8.sh` blocks `java8_request_session_file_deserialization`)
- [x] Apache Tomcat Tribes - CVE-2026-29146 EncryptInterceptor padding-oracle predecessor post-oracle deserialization sink (`deserialization_tomcat_cve_2026_29146_tribes_padding_oracle`; covered by the same real Java8 acceptance as CVE-2026-34486 because `scripts/acceptance-vulhub-tomcat-34486-java8.sh` proves the post-oracle Tribes receiver deserializes a CommonsCollections gadget and blocks `java8_deserialization_gadget_class` before marker creation)
- [x] Apache Tomcat Tribes - CVE-2026-34486 EncryptInterceptor bypass cluster message deserialization (`deserialization_tomcat_cve_2026_34486_tribes_encrypt`; real Java8 acceptance: `scripts/acceptance-vulhub-tomcat-34486-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] Apache Tomcat 7+/8 - Manager weak credential backend WAR upload chain (`request_tomcat8_manager_default_credential`; real Java7 legacy boundary: `scripts/acceptance-vulhub-tomcat8-manager-java7-legacy.sh`)

### Atlassian Confluence / Jira

- [x] Confluence - CVE-2019-3396 macro preview template source (`request_confluence_cve_2019_3396_macro_template_source`; real Java8 setup/license boundary: `scripts/acceptance-vulhub-confluence-setup-boundaries.sh`)
- [x] Confluence - CVE-2021-26084 WebWork queryString OGNL (`request_confluence_cve_2021_26084_doenterpagevariables`; real Java11 setup/license boundary: `scripts/acceptance-vulhub-confluence-setup-boundaries.sh`)
- [x] Confluence - CVE-2022-26134 URL path OGNL (`request_confluence_cve_2022_26134_direct_path_ognl`; real Java11 setup/license boundary: `scripts/acceptance-vulhub-confluence-setup-boundaries.sh`)
- [x] Confluence - CVE-2023-22515 setup state reset (`request_confluence_cve_2023_22515_setup_reset`; real Java11 setup/license boundary: `scripts/acceptance-vulhub-confluence-setup-boundaries.sh`)
- [x] Confluence - CVE-2023-22527 text-inline delegated OGNL (`request_confluence_cve_2023_22527_text_inline_delegated_expression`; real Java11 setup/license boundary: `scripts/acceptance-vulhub-confluence-setup-boundaries.sh`)
- [x] Jira - CVE-2019-11581 ContactAdministrators template injection (`request_jira_cve_2019_11581_contact_template`; real Java8 setup/license/SMTP/sample-project boundary: `scripts/acceptance-vulhub-jira-11581-setup-boundary-java8.sh`)

### ColdFusion

- [x] Adobe ColdFusion - CVE-2010-2861 locale traversal source (`request_coldfusion_locale_source_traversal`; real Java6 legacy boundary: `scripts/acceptance-vulhub-coldfusion-2861-java6-legacy.sh` proves baseline `/etc/passwd` disclosure and Java8 agent class-version mismatch on Java 6u04)
- [x] Adobe ColdFusion - CVE-2017-3066 AMF deserialization (`deserialization_coldfusion_amf`; real Java8 acceptance: `scripts/acceptance-vulhub-coldfusion-3066-java8.sh` blocks `java8_command_execution_exploit_primitive` from the AMF Java deserialization stack)
- [x] Adobe ColdFusion - CVE-2023-26360 metadata classname source (`request_coldfusion_iedit_metadata_class_source`; real Java11 acceptance: `scripts/acceptance-vulhub-coldfusion-26360-java11.sh` blocks `java11_file_sensitive_read`)
- [x] Adobe ColdFusion - CVE-2023-29300 WDDX `argumentCollection` typed payload (`request_typed_payload_deserialization`; real Java11 acceptance: `scripts/acceptance-vulhub-coldfusion-29300-java11.sh` blocks `java11_request_typed_payload_deserialization`)

### Elasticsearch / Solr / Log4j

- [x] Elasticsearch - CVE-2014-3120 MVEL `_search` script RCE (`request_elasticsearch_cve_2014_3120_mvel_search_script`; real Java8 acceptance: `scripts/acceptance-vulhub-elasticsearch-3120-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Elasticsearch - CVE-2015-1427 Groovy `_search` script sandbox bypass (`request_elasticsearch_cve_2015_1427_groovy_search_script`; real Java8 acceptance: `scripts/acceptance-vulhub-elasticsearch-1427-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Elasticsearch - CVE-2015-3337 plugin directory traversal (`request_elasticsearch_cve_2015_3337_plugin_traversal`; real Java8 acceptance: `scripts/acceptance-vulhub-elasticsearch-3337-java8.sh` blocks `java8_file_sensitive_read`)
- [x] Elasticsearch - CVE-2015-5531 snapshot directory traversal (`request_elasticsearch_cve_2015_5531_snapshot_traversal`; real Java8 acceptance: `scripts/acceptance-vulhub-elasticsearch-5531-java8.sh` blocks `java8_file_sensitive_read`)
- [x] Elasticsearch - WooYun-2015-110216 snapshot repository webroot write (`request_elasticsearch_wooyun_2015_110216_snapshot_webroot_write`; real Java8 acceptance: `scripts/acceptance-vulhub-elasticsearch-110216-java8.sh` blocks `java8_file_script_write`)
- [x] Apache Log4j - CVE-2021-44228 Solr admin JNDI lookup (`request_log4j_cve_2021_44228_solr_admin_cores`; real Java8 acceptance: `scripts/acceptance-vulhub-log4j-solr-java8.sh` blocks `java8_jndi_remote_lookup`)
- [x] Apache Solr - CVE-2017-12629 RunExecutableListener RCE (`command_solr_cve_2017_12629_runexecutable`; real Java8 acceptance: `scripts/acceptance-vulhub-solr-runexec-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Solr - CVE-2017-12629 XML parser XXE (`request_solr_cve_2017_12629_xmlparser_xxe`; real Java8 acceptance: `scripts/acceptance-vulhub-solr-xxe-java8.sh` blocks `java8_xxe_external_entity_protocol`)
- [x] Apache Solr - CVE-2019-0193 DataImportHandler script config (`request_solr_cve_2019_0193_dataimport_script`; real Java8 acceptance: `scripts/acceptance-vulhub-solr-dataimport-java8.sh` blocks `java8_script_engine_runtime_execution`)
- [x] Apache Solr - CVE-2019-17558 Velocity template payload (`request_solr_cve_2019_17558_velocity_template`; real Java8 acceptance: `scripts/acceptance-vulhub-solr-velocity-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Apache Solr - RemoteStreaming config enable and file read (`request_solr_remotestreaming_file_read`; real Java8 acceptance: `scripts/acceptance-vulhub-solr-remotestreaming-java8.sh` blocks `java8_file_sensitive_read`)

### DataEase / H2 / Metabase

- [x] DataEase - CVE-2024-56511 geo whitelist traversal (`request_dataease_geo_whitelist_traversal`; real OpenJDK21 runtime acceptance: `scripts/acceptance-vulhub-dataease-56511-java21.sh` blocks `java17_request_path_confusion`)
- [x] DataEase - CVE-2025-32966 H2 datasource validation config (`request_dataease_cve_2025_32966_h2_datasource_validate`; real OpenJDK21 runtime acceptance: `scripts/acceptance-vulhub-dataease-32966-java21.sh` blocks `java17_jdbc_h2_code_execution`)
- [x] DataEase - CVE-2025-49001 invalid JWT continuation (`request_dataease_cve_2025_49001_user_info_invalid_jwt`; real OpenJDK21 runtime acceptance: `scripts/acceptance-vulhub-dataease-49001-java21.sh` blocks `java17_request_jwt_verification_failure`)
- [x] H2 Database - CVE-2018-10054 console SQL ALIAS/TRIGGER execution (`sql_h2_console_query`; real Java8 acceptance: `scripts/acceptance-vulhub-h2-10054-java8.sh` blocks `java8_script_engine_runtime_execution`)
- [x] H2 Database - CVE-2021-42392 console JNDI driver URL (`request_h2_cve_2021_42392_console_jndi_driver`; real Java8 acceptance: `scripts/acceptance-vulhub-h2-42392-java8.sh` blocks `java8_jndi_remote_lookup`)
- [x] H2 Database - CVE-2022-23221 console JDBC INIT login URL (`request_h2_console_login_jdbc_init`; real Java8 acceptance: `scripts/acceptance-vulhub-h2-23221-java8.sh` blocks `java8_jdbc_h2_code_execution`)
- [x] Metabase - CVE-2021-41277 GeoJSON local file URL (`readFile_metabase_cve_2021_41277_geojson_file_url`; real Java11 acceptance: `scripts/acceptance-vulhub-metabase-41277-java11.sh` blocks `java11_file_sensitive_read`)
- [x] Metabase - CVE-2023-38646 setup validate H2 INIT (`request_metabase_cve_2023_38646_setup_validate`; real Java11 acceptance: `scripts/acceptance-vulhub-metabase-38646-java11.sh` blocks `java11_script_engine_runtime_execution`)

### Dubbo / JBoss / WebLogic

- [x] Apache Dubbo - CVE-2019-17564 HTTP Invoker deserialization (`deserialization_dubbo_cve_2019_17564_http_invoker`; real Java8 acceptance: `scripts/acceptance-vulhub-dubbo-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] JBoss - CVE-2017-12149 ReadOnlyAccessFilter Java object stream (`deserialization_jboss_cve_2017_12149_readonly`; real Java7 legacy boundary: `scripts/acceptance-vulhub-jboss-12149-java7-legacy.sh`)
- [x] JBoss - JMXInvokerServlet Java object stream (`deserialization_jboss_jmxinvoker`; real Java7 legacy boundary: `scripts/acceptance-vulhub-jboss-jmxinvoker-java7-legacy.sh`)
- [x] JBossMQ - CVE-2017-7504 HTTPServerILServlet Java object stream (`deserialization_jboss_cve_2017_7504_httpil`; real Java7 legacy boundary: `scripts/acceptance-vulhub-jboss-7504-java7-legacy.sh`)
- [x] WebLogic - weak password console login and JSP file read (`request_weblogic_weak_password_console_login`, `readFile_weblogic_weak_password_file_read`; real Java6 legacy boundary: `scripts/acceptance-vulhub-weblogic-weak-password-java6-legacy.sh` proves the Vulhub `/hello/file.jsp?path=/etc/passwd` file-read baseline and Java8 agent class-version mismatch on Java 6u45)
- [x] WebLogic - UDDI Explorer SSRF shape (`ssrf_weblogic_uddi`; real Java6 legacy boundary: `scripts/acceptance-vulhub-weblogic-uddi-ssrf-java6-legacy.sh` proves baseline UDDI `operator=` SSRF to a host listener and Java8 agent class-version mismatch on Java 6u45)
- [x] WebLogic - CVE-2017-10271 WorkContext XMLDecoder (`xml_decoder_runtime_weblogic_workcontext`; real Java6 legacy boundary: `scripts/acceptance-vulhub-weblogic-10271-java6-legacy.sh` proves baseline WorkContext XMLDecoder `ProcessBuilder.start` marker creation and Java8 agent class-version mismatch on Java 6u45)
- [x] WebLogic - CVE-2018-2628 T3 JRMPClient deserialization replay (`deserialization_weblogic_cve_2018_2628_t3_jrmpclient`; real Java6 legacy boundary: `scripts/acceptance-vulhub-weblogic-2628-java6-legacy.sh` proves baseline JRMPClient2 marker creation and Java8 agent class-version mismatch on Java 6u45)
- [x] WebLogic - CVE-2018-2894 WS_UTC Web Service Test Page JSP upload (`fileUpload_weblogic_cve_2018_2894_ws_utc_jsp`; real Java8 acceptance: `scripts/acceptance-vulhub-weblogic-2894-java8.sh` blocks Jersey multipart `ContentDisposition.getFileName` with `fileUpload_multipart_script` before JSP write)
- [x] WebLogic - CVE-2020-14882 / CVE-2020-14883 console ShellSession handle (`request_weblogic_cve_2020_14883_console_shellsession`; real Java8 acceptance: `scripts/acceptance-vulhub-weblogic-14883-java8.sh` blocks `java8_request_path_confusion` before ShellSession execution)
- [x] WebLogic - CVE-2019-2725 console FileSystemXmlApplicationContext handle (`request_weblogic_cve_2019_2725_console_filesystemxml`; current Vulhub snapshot has no `weblogic/CVE-2019-2725` environment, so this remains a source-availability boundary rather than real Vulhub acceptance)
- [x] WebLogic - CVE-2023-21839 IIOP JNDI deserialization replay (`deserialization_weblogic_cve_2023_21839_iiop_jndi`; real Java8 acceptance: `scripts/acceptance-vulhub-weblogic-21839-java8.sh` blocks `java8_jndi_remote_lookup` before the protected WebLogic container connects to the LDAP listener)

### GeoServer / GlassFish / Jetty / Openfire

- [x] GeoServer - CVE-2021-40822 TestWfsPost SSRF (`ssrf_geoserver_cve_2021_40822_testwfspost`; real Java17 acceptance: `scripts/acceptance-vulhub-geoserver-40822-java17.sh` blocks `java17_ssrf_request_parameter_url`)
- [x] GeoServer - CVE-2022-24816 / CVE-2023-35042 Jiffle WPS runtime script (`jiffle_runtime_geoserver_cve_2022_24816_wms`, `jiffle_runtime_geoserver_cve_2023_35042_jai_ext_wms`; real Java17 acceptance: `scripts/acceptance-vulhub-geoserver-24816-java17.sh` blocks `java17_command_execution_exploit_primitive` at `Runtime.exec(String)` from the JAI-EXT Jiffle runtime stack)
- [x] GeoServer - CVE-2022-41852 WFS valueReference XPath reference (`request_geoserver_cve_2022_41852_wfs_valuereference_get`; covered by the same real Java17 acceptance as CVE-2024-36401 because `scripts/acceptance-vulhub-geoserver-java17.sh` proves the shared WFS `GetPropertyValue` `valueReference=exec(...)` XPath expression reaches `Runtime.exec` and blocks `java17_command_execution_exploit_primitive` before command-output evidence is returned)
- [x] GeoServer - CVE-2023-25157 CQL filter SQL injection (`request_geoserver_cve_2023_25157_cql_filter_sqli`; real Java17 acceptance: `scripts/acceptance-vulhub-geoserver-25157-java17.sh` blocks `java17_request_ogc_filter_sql_injection`)
- [x] GeoServer - CVE-2023-25158 CQL filter SQL injection reference (`request_geoserver_cve_2023_25158_cql_filter_sqli`; covered by the same real Java17 acceptance: `scripts/acceptance-vulhub-geoserver-25157-java17.sh`)
- [x] GeoServer - CVE-2024-36401 WFS valueReference XPath (`request_geoserver_cve_2024_36401_wfs_valuereference_get`; real Java17 acceptance: `scripts/acceptance-vulhub-geoserver-java17.sh` blocks `java17_command_execution_exploit_primitive`)
- [x] GlassFish - CVE-2017-1000028 overlong UTF-8 traversal (`request_glassfish_cve_2017_1000028_overlong_traversal`; real Java8 acceptance: `scripts/acceptance-vulhub-glassfish-1000028-java8.sh` blocks `java8_request_path_confusion`)
- [x] Jetty - CVE-2021-28164/CVE-2021-28169/CVE-2021-34429 internal resource decoding (`request_jetty_cve_2021_28164_encoded_dot_webinf`, `request_jetty_cve_2021_28169_concat_double_decode`, `request_jetty_cve_2021_34429_unicode_dot_webinf`, `request_jetty_cve_2021_34429_nul_dot_webinf`, `request_jetty_cve_2021_34429_nul_dotdot_webinf`; real Java8 acceptance: `scripts/acceptance-vulhub-jetty-28164-java8.sh` blocks `java8_request_path_confusion`)
- [x] Openfire - CVE-2008-6508 setup traversal auth bypass shape (`request_openfire_cve_2008_6508_setup_traversal`; covered by the same real Java17 acceptance as CVE-2023-32315 because `openfire/CVE-2023-32315/README.md` identifies CVE-2008-6508 as the original setup traversal predecessor and `scripts/acceptance-vulhub-openfire-java17.sh` proves the current setup traversal family with `%u002e%u002e` and lenient `%2>` variants blocks `java17_request_path_confusion` before administrator persistence)
- [x] Openfire - CVE-2023-32315 setup Unicode traversal (`request_openfire_cve_2023_32315_unicode_setup_traversal`; real Java17 acceptance: `scripts/acceptance-vulhub-openfire-java17.sh` blocks `java17_request_path_confusion`)

### HugeGraph / Liferay / Nacos / Nexus

- [x] Apache HugeGraph - CVE-2024-27348 Gremlin Groovy execution (`request_hugegraph_cve_2024_27348_gremlin_rce`; real Java11 acceptance: `scripts/acceptance-vulhub-hugegraph-java11.sh` blocks `java11_command_execution_exploit_primitive`)
- [x] Apache HugeGraph - CVE-2024-43441 default JWT secret (`request_hugegraph_cve_2024_43441_default_jwt_secret`; real Java11 acceptance: `scripts/acceptance-vulhub-hugegraph-43441-java11.sh` blocks `java11_request_default_jwt_secret`)
- [x] Liferay Portal - CVE-2020-7961 JSONWS typed parameter (`request_liferay_jsonws_typed_parameter`; real Java8 acceptance: `scripts/acceptance-vulhub-liferay-7961-java8.sh` blocks `java8_classloader_remote_codebase`)
- [x] Nacos - CVE-2021-29441 `Nacos-Server` identity bypass (`request_nacos_cve_2021_29441_list_users`, `request_nacos_cve_2021_29441_create_user`; real Java8 acceptance: `scripts/acceptance-vulhub-nacos-29441-java8.sh` blocks `java8_request_internal_identity`)
- [x] Nacos - CVE-2021-29442 Derby ops SQL execution (`sql_nacos_cve_2021_29442_derby_ops_code_execution`; real Java8 acceptance: `scripts/acceptance-vulhub-nacos-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Nexus Repository - CVE-2019-7238 ExtDirect JEXL filter (`request_nexus_cve_2019_7238_extdirect_jexl_filter`; real Java8 acceptance: `scripts/acceptance-vulhub-nexus-7238-java8.sh` blocks `java8_jexl_runtime_execution`)
- [x] Nexus Repository - CVE-2018-16621 ExtDirect role EL predecessor (`request_nexus_cve_2018_16621_extdirect_role_el`; covered by the same real Java8 acceptance as CVE-2020-10204 because `scripts/acceptance-vulhub-nexus-10204-java8.sh` proves the shared ExtDirect `coreui_User` `updateRole` `memberNames` EL payload reaches marker-creating command execution and blocks `java8_el_runtime_execution` before marker creation)
- [x] Nexus Repository - CVE-2020-10199 Go group EL (`request_nexus_cve_2020_10199_go_group_el`; real Java8 acceptance: `scripts/acceptance-vulhub-nexus-10199-java8.sh` blocks `java8_el_runtime_execution`)
- [x] Nexus Repository - CVE-2020-10204 ExtDirect role EL (`request_nexus_cve_2020_10204_extdirect_role_el`; real Java8 acceptance: `scripts/acceptance-vulhub-nexus-10204-java8.sh` blocks `java8_el_runtime_execution`)
- [x] Nexus Repository - CVE-2024-4956 encoded slash traversal (`request_nexus_cve_2024_4956_encoded_slash_traversal`; real Java8 acceptance: `scripts/acceptance-vulhub-nexus-4956-java8.sh` blocks `java8_file_sensitive_read`)

### Jenkins / Mojarra / Neo4j / XXL-JOB

- [x] Jenkins - CVE-2017-1000353 CLI SignedObject deserialization (`deserialization_jenkins_cve_2017_1000353_cli_signed_object`; real Java8 acceptance: `scripts/acceptance-vulhub-jenkins-1000353-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] Jenkins - CVE-2018-1000861 Groovy checkScript validation (`request_jenkins_cve_2018_1000861_checkscript`; real Java8 acceptance: `scripts/acceptance-vulhub-jenkins-1000861-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Jenkins - CVE-2024-23897 CLI argument file expansion (`readFile_jenkins_cve_2024_23897_proc_environ`, `readFile_jenkins_cve_2024_23897_connect_node_passwd`; real Java17 acceptance: `scripts/acceptance-vulhub-jenkins-23897-java17.sh` blocks `java17_file_sensitive_read`)
- [x] Mojarra JSF - ViewState deserialization (`request_mojarra_jsf_viewstate_deserialization`; real Java7 legacy boundary: `scripts/acceptance-vulhub-mojarra-viewstate-java7-legacy.sh`)
- [x] Neo4j Shell - CVE-2021-34371 RMI `setSessionVariable` deserialization (`deserialization_neo4j_cve_2021_34371_shell_rmi`; real Java8 acceptance: `scripts/acceptance-vulhub-neo4j-34371-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] XXL-JOB - unauthenticated executor shell job submission (`request_xxl_job_executor_run_shell`; real Java8 acceptance: `scripts/acceptance-vulhub-xxljob-java8.sh` blocks `java8_command_execution_shell_meta`)
- [x] XXL-JOB - Hessian API type deserialization (`deserialization_xxl_job_hessian_api`; real Java8 Vulhub probe remains a dependency-version boundary because current `vulhub/xxl-job:2.2.0-admin` lacks the old Hessian classes)

### Linkis / kkFileView / TeamCity

- [x] Apache Linkis - CVE-2022-44645 MySQL JDBC `autoDeserialize` datasource test (`jdbc_linkis_cve_2022_44645_mysql_datasource_connect`; real Java8 acceptance: `scripts/acceptance-vulhub-linkis-44645-java8.sh` blocks `java8_jdbc_mysql_deserialization` at `DriverManager.getConnection`)
- [x] Apache Linkis - CVE-2023-27987/CVE-2023-29215/CVE-2023-46801 JDBC blacklist bypass family (`jdbc_linkis_cve_2023_46801_mysql_datasource_connect`; covered by the same real Java8 acceptance as CVE-2022-44645 because `scripts/acceptance-vulhub-linkis-44645-java8.sh` proves the generic MySQL `autoDeserialize` sink blocks with `java8_jdbc_mysql_deserialization` at `DriverManager.getConnection` before any rogue MySQL connection)
- [x] kkFileView - 4.3 ZipSlip preview archive traversal (`archive_kkfileview_zipslip_preview`; real Java8 acceptance: `scripts/acceptance-vulhub-kkfileview-java8.sh` blocks `java8_archive_entry_traversal_write`)
- [x] JetBrains TeamCity - CVE-2023-42793 debug process launch chain (`request_teamcity_cve_2023_42793_debug_process_launch`; real Java17 acceptance: `scripts/acceptance-vulhub-teamcity-42793-java17.sh` blocks `java17_request_debug_process_launch`)
- [x] JetBrains TeamCity - CVE-2024-27198 JSP internal forward auth bypass (`request_teamcity_cve_2024_27198_internal_forward`; real Java17 acceptance: `scripts/acceptance-vulhub-teamcity-27198-java17.sh` blocks `java17_request_internal_forward`)

### MeterSphere / OFBiz / OpenTSDB / RocketMQ

- [x] MeterSphere - CVE-2021-45788 case-list sort SQL injection (`request_metersphere_cve_2021_45788_case_sort_sqli`; real Java8 acceptance: `scripts/acceptance-vulhub-metersphere-45788-java8.sh` blocks `java8_sql_identifier_injection` at MyBatis `BoundSql`)
- [x] MeterSphere - plugin add Java archive upload (`fileUpload_metersphere_plugin_add_jar_upload`; real Java8 acceptance: `scripts/acceptance-vulhub-metersphere-plugin-java8.sh` blocks `fileUpload_java_archive` at `MultipartUpload.filename` before the plugin JAR is written or loaded)
- [x] OFBiz - CVE-2020-9496 XML-RPC serialized payload (`deserialization_ofbiz_cve_2020_9496_xmlrpc_serialized`; real Java8 acceptance: `scripts/acceptance-vulhub-ofbiz-9496-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] OFBiz - CVE-2023-49070 XML-RPC serialized payload (`deserialization_ofbiz_cve_2023_49070_xmlrpc_serialized`; real Java8 acceptance: `scripts/acceptance-vulhub-ofbiz-49070-java8.sh` blocks `java8_deserialization_gadget_class`)
- [x] OFBiz - CVE-2023-51467 ProgramExport Groovy expression (`request_ofbiz_cve_2023_51467_programexport`; real Java8 acceptance: `scripts/acceptance-vulhub-ofbiz-51467-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] OFBiz - CVE-2024-32113 controller-view state desync predecessor (`request_ofbiz_cve_2024_32113_viewdatafile_remote_import`; covered by the same real Java8 acceptance as CVE-2024-45195 because `scripts/acceptance-vulhub-ofbiz-45195-java8.sh` proves the shared unauthenticated controller/view state desync reaches `viewdatafile` remote JSP import and blocks `java8_file_script_write` before webroot replacement)
- [x] OFBiz - CVE-2024-36104 controller-view state desync predecessor (`request_ofbiz_cve_2024_36104_viewdatafile_remote_import`; covered by the same real Java8 acceptance as CVE-2024-45195 because `scripts/acceptance-vulhub-ofbiz-45195-java8.sh` proves the shared unauthenticated controller/view state desync reaches `viewdatafile` remote JSP import and blocks `java8_file_script_write` before webroot replacement)
- [x] OFBiz - CVE-2024-38856 ProgramExport multipart Groovy expression (`request_ofbiz_cve_2024_38856_programexport`; real Java8 acceptance: `scripts/acceptance-vulhub-ofbiz-38856-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] OFBiz - CVE-2024-45195 viewdatafile remote import JSP write (`request_ofbiz_cve_2024_45195_viewdatafile_remote_import`; real Java8 acceptance: `scripts/acceptance-vulhub-ofbiz-45195-java8.sh` blocks `java8_file_script_write`)
- [x] OFBiz - CVE-2024-45507 remote decorator template source (`request_ofbiz_cve_2024_45507_remote_decorator_source`; real Java8 acceptance: `scripts/acceptance-vulhub-ofbiz-45507-java8.sh` blocks `java8_request_template_source`)
- [x] OpenTSDB - CVE-2020-35476 generated yrange script (`writeFile_opentsdb_cve_2020_35476_generated_yrange_script`, `request_opentsdb_cve_2020_35476_yrange_plot_command`; real Java8 acceptance: `scripts/acceptance-vulhub-opentsdb-java8.sh` blocks `java8_file_generated_plot_script_command`)
- [x] OpenTSDB - CVE-2023-25826 generated key script (`writeFile_opentsdb_cve_2023_25826_generated_key_script`, `request_opentsdb_cve_2023_25826_key_plot_command`; real Java8 acceptance: `scripts/acceptance-vulhub-opentsdb-java8.sh` blocks `java8_file_generated_plot_script_command`)
- [x] RocketMQ - CVE-2023-33246 filterserver command config (`command_rocketmq_cve_2023_33246_filterserver`; real Java8 acceptance: `scripts/acceptance-vulhub-rocketmq-java8.sh` blocks `java8_command_execution_shell_meta`)
- [x] RocketMQ - CVE-2023-37582 nameserver config path write (`writeFile_rocketmq_cve_2023_37582_namesrv_config_path`; real Java8 acceptance: `scripts/acceptance-vulhub-rocketmq-37582-java8.sh` blocks `java8_file_script_write`)

### Spring / SkyWalking / Unomi

- [x] Spring Security OAuth - CVE-2016-4977 response_type SpEL (`request_spring_cve_2016_4977_oauth_response_type_spel`; real Java8 acceptance: `scripts/acceptance-vulhub-spring-security-oauth-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Spring WebFlow - CVE-2017-4971 binding SpEL (`request_spring_cve_2017_4971_webflow_binding_spel`; real Java7 legacy boundary: `scripts/acceptance-vulhub-spring-webflow-java7-legacy.sh`)
- [x] Spring Data REST - CVE-2017-8046 JSON Patch SpEL (`request_spring_cve_2017_8046_json_patch_spel`; real Java8 acceptance: `scripts/acceptance-vulhub-spring-data-rest-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Spring Messaging - CVE-2018-1270 STOMP selector SpEL (`request_spring_cve_2018_1270_stomp_selector`; real Java8 acceptance: `scripts/acceptance-vulhub-spring-messaging-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Spring Framework - CVE-2018-1271 path normalization reference (`request_spring_cve_2018_1271_path_normalization_reference`; covered by the same real Java8 acceptance as Nexus CVE-2024-4956 because `scripts/acceptance-vulhub-nexus-4956-java8.sh` proves the repeated-encoded-slash canonicalization bypass discloses `/etc/passwd` and blocks `java8_file_sensitive_read` before passwd content is returned)
- [x] Spring Data Commons - CVE-2018-1273 binder SpEL (`request_spring_cve_2018_1273_data_commons_binding_spel`; real Java8 acceptance: `scripts/acceptance-vulhub-spring-data-commons-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Spring Cloud Gateway - CVE-2022-22947 route SpEL (`request_spring_cve_2022_22947_gateway_route_spel`; real Java8 acceptance: `scripts/acceptance-vulhub-spring-gateway-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Spring Cloud Function - CVE-2022-22963 routing-expression SpEL (`request_spring_cve_2022_22963_functionrouter_spel`; real Java8 acceptance: `scripts/acceptance-vulhub-spring-function-java8.sh` blocks `java8_command_execution_exploit_primitive`)
- [x] Spring Framework - CVE-2022-22965 Tomcat access-log JSP write (`request_spring_cve_2022_22965_tomcatwar_accesslog_jsp`; real Java11 acceptance: `scripts/acceptance-vulhub-spring-java11.sh` blocks `java11_file_script_write`)
- [x] Spring Security - CVE-2022-22978 RegexRequestMatcher LF/CR bypass (`request_spring_cve_2022_22978_regex_requestmatcher_lf`, `request_spring_cve_2022_22978_regex_requestmatcher_cr`; real Java8 acceptance: `scripts/acceptance-vulhub-spring-security-22978-java8.sh` blocks `java8_request_path_confusion`)
- [x] Spring Framework - CVE-2025-41242 ghost-bits path traversal (`request_spring_cve_2025_41242_ghostbits_path_traversal`; real Java17 acceptance: `scripts/acceptance-vulhub-spring-boot-jetty-java17.sh` blocks `java17_request_path_confusion`)
- [x] SkyWalking 8.3.0 - GraphQL metricName SQL identifier injection (`request_skywalking_8_3_0_graphql_metricname_sqli`; real Java8 acceptance: `scripts/acceptance-vulhub-skywalking-java8.sh` blocks `java8_sql_identifier_injection` at SkyWalking `H2LogQueryDAO.queryLogs`)
- [x] Apache Unomi - CVE-2020-13942 MVEL context expression (`request_unomi_cve_2020_13942_context_mvel`; real Java8 acceptance: `scripts/acceptance-vulhub-unomi-java8.sh` blocks `java8_command_execution_exploit_primitive`)

### Serialization Frameworks

- [x] Fastjson - 1.2.24 / CVE-2017-18349 autoType `JdbcRowSetImpl` (`deserialization_fastjson_cve_2017_18349_1224_autotype`; real Java8 acceptance: `scripts/acceptance-vulhub-fastjson-java8.sh` blocks `java8_jndi_remote_lookup`)
- [x] Fastjson - 1.2.47 autoType bypass (`deserialization_fastjson_1247_autotype_bypass`; real Java8 acceptance: `scripts/acceptance-vulhub-fastjson-java8.sh` blocks `java8_jndi_remote_lookup`)
- [x] Jackson - CVE-2017-7525 `TemplatesImpl` polymorphic JSON (`deserialization_jackson_cve_2017_7525_templatesimpl`; real Java7 legacy boundary: `scripts/acceptance-vulhub-jackson-java7-legacy.sh`)
- [x] Jackson - CVE-2017-17485 Spring XML polymorphic JSON bypass (`deserialization_jackson_cve_2017_17485_spring_xml`; real Java7 legacy boundary: `scripts/acceptance-vulhub-jackson-java7-legacy.sh`)
- [x] SnakeYAML - H2 `JdbcConnection` type (`deserialization_snakeyaml_h2_type`; real Java11 acceptance: `scripts/acceptance-vulhub-hertzbeat-java11.sh` blocks `java11_jdbc_h2_code_execution`)
- [x] XStream - CVE-2021-21351 `JdbcRowSetImpl` JNDI XML gadget (`request_xstream_cve_2021_21351_jdbcrowset_jndi_xml_gadget`; real Java8 acceptance: `scripts/acceptance-vulhub-xstream-21351-java8.sh` blocks `java8_jndi_remote_lookup`)
- [x] XStream - CVE-2021-29505 `RegistryImpl_Stub` RMI XML gadget (`request_xstream_cve_2021_29505_registryimpl_rmi_xml_gadget`; real Java8 acceptance: `scripts/acceptance-vulhub-xstream-29505-java8.sh` blocks `java8_deserialization_gadget_class`)

## Candidates
- [ ] _Add the next Java Vulhub candidate here before probing it._
