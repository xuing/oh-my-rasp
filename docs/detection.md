# Detection Engineering

OhMyRASP intercepts dangerous JDK operations inside the running JVM rather than inspecting traffic at a network boundary. This document describes the five-stage detection pipeline, active detection techniques, false-positive evaluation, and deployment limits.

## Rule scope

Classify the decision by the evidence it needs. Request input contributing control syntax to a shell program can be recognized in different applications. A decision that depends on how a particular product launches that process belongs with that product. A library-specific hook can still provide evidence for a general decision at a standard runtime boundary.

For new shared decision code, place cross-product predicates in [general rules](../java-agent/shared/src/main/java/io/ohmyrasp/agent/rules/general/) and implementation-specific predicates under [product rules](../java-agent/shared/src/main/java/io/ohmyrasp/agent/rules/product/). Keep hook wiring with the runtime subsystem. When two branches share a policy ID, record each basis in the appropriate catalog. Scope and blocking confidence are independent. See the [rule scope tables](../java-agent/docs/DETECTION-COVERAGE.md#rule-scope).

## Primary-agent detector layout

Hooks call the public [DetectorEngine facade](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/DetectorEngine.java). Put the decision beside the evidence it consumes. The facade keeps the HTTP first-match order visible, including credential and serialized client-state checks. The [policy evaluator](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/policy/AgentPolicy.java) applies operator selection and actions after classification.

| Evidence at the decision point | Implementation |
|---|---|
| HTTP configuration and naming lookups | [RequestConfigurationDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/RequestConfigurationDetector.java) |
| Template loading and expression-bearing request fields | [RequestTemplateDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/RequestTemplateDetector.java) and [RequestExpressionDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/RequestExpressionDetector.java) |
| XML entities and polymorphic binding in request data | [RequestPayloadDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/RequestPayloadDetector.java) |
| Remote sources and filesystem targets in a request | [RequestResourceDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/RequestResourceDetector.java) |
| JDBC statement, connection options, or database error | [JdbcDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/JdbcDetector.java) |
| SQL-like fields in a request, selected by policy | [SqlRequestIndicators](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/SqlRequestIndicators.java) |
| Host write targets, archive extraction, generated content and deletion | [HostFileMutationDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/HostFileMutationDetector.java) |
| Process arguments and caller stack | [ProcessDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/ProcessDetector.java) |
| Deserialization transport and resolved type | [DeserializationDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/DeserializationDetector.java) and [DeserializationTypes](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/DeserializationTypes.java) |
| Resource selected through class loading, JNDI, JAAS, or Spring configuration | [RemoteResourceDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/RemoteResourceDetector.java) |
| Credentials or serialized state observed in a request | [CredentialDetector](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/CredentialDetector.java) and [SerializedRequestState](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/SerializedRequestState.java) |

Each domain owns its matching constants, event construction and redaction. Shared request parsing stays in the primary agent. The Java 8-compatible shared source tree provides runtime observations and portable predicates to all agent tracks. The general and product catalogs describe rule applicability independently of these Java boundaries.

## Detection pipeline

Every detection decision passes through the same pipeline:

```
ASM hook at sink
  └─ ThreadLocal<RequestContext> parameter correlation
       └─ StackWalker call-stack analysis
            └─ algorithm classification
                 └─ policy decision (off / monitor / block)
                      ├─ daemon mode: async NDJSON spool -> Rust daemon -> Go control plane
                      └─ standalone locked mode: structured JSON -> stderr
```

**Stage 1: ASM hook at sink.** `OhMyRaspTransformer` and `HookRegistry` rewrite JVM bytecode at class-load or retransform time to insert advice immediately before dangerous JDK and framework call sites. Representative hook points include `ProcessBuilder.start`, `Runtime.exec`, `InitialContext.lookup`, `ObjectInputStream.resolveClass`, `FileInputStream`/`FileOutputStream`, `DriverManager.getConnection`, `ZipEntry.getName`, `ScriptEngine.eval`, and `Base64$Decoder.decode0`. In `agent-jdk25`, `HookRegistry.defaults()` registers the hook modules; the `agent-java8`, `agent-java11`, and `agent-java17` backport tracks each register their own ASM transformers. See [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md) for the complete module table. Application source code is never modified.

**Stage 2: RequestContext parameter correlation.** A `ThreadLocal<RequestContext>` is populated at HTTP request entry across both `javax.servlet` and `jakarta.servlet` namespaces. At sink invocation, detectors call `RequestContext.hasParameterIn(value)` to check whether the sink argument contains a substring from a request parameter value (or a bounded request body) before raising a request-correlated finding. This is **request-parameter substring correlation**, not bytecode dataflow taint tracking. SQL injection and OS command injection require confirmed parameter correlation (or a structural signature) before escalating to severity 95.

**Stage 3: StackWalker call-stack analysis.** `OhMyRaspHooks` captures a live `StackWalker` trace (`RETAIN_CLASS_REFERENCE`, `SHOW_REFLECT_FRAMES`) at sink invocation. `detectCommand` inspects the trace for expression-engine frames (OGNL, MVEL, SpEL, Groovy, JEXL, Nashorn, Velocity, Jiffle, XStream), executable-listener frames (Solr `RunExecutableListener`), config-launcher frames, and reflective deserialization stacks. The presence of these frames changes both the algorithm label and the confidence score, classifying `ProcessBuilder.start` differently depending on whether it originates from Struts2/OGNL, an XStream unmarshaller, or ordinary application code.

**Stage 4: Algorithm classification and policy decision.** The detector returns a named algorithm signature (such as `java8_jndi_remote_lookup` or `java17_request_path_confusion`) with a confidence score and recommended action. `AgentRuntime` applies the active mode (`off`, `monitor`, or `block`) and per-algorithm switches:

- **Daemon-managed or local-control mode:** `AgentRuntime` polls a JSON control file (default `/tmp/ohmyrasp-control.json`) updated by the Rust host daemon or operator, applying mode, per-algorithm switches, and distributed policies without a JVM restart.
- **Standalone locked mode (`META-INF/ohmyrasp-shirudo.properties`):** Shirudo Java upatch JARs bake in `standalone=true`, `lock_config=true`, `mode=block` (or `monitor` when built with `--mode monitor`), and `control=none`. Configuration is fixed at build time, ignores `/tmp/ohmyrasp-control.json` and runtime mode overrides, and starts zero control-poller threads.

**Stage 5: Reporting.** Accepted findings are emitted as structured JSON:

- **Daemon-managed mode:** `JsonEventLogger` queues findings asynchronously on a background daemon writer thread to a local NDJSON spool file (default `/tmp/ohmyrasp-events.jsonl`). The Rust host daemon tails the spool and forwards events to the Go control plane, keeping detection latency independent of network reachability.
- **Standalone locked mode:** `log=stderr` and `latency_sample=0` write detection JSON lines directly to `stderr` with zero file-writer threads, no spool file, and no periodic `hook_latency` telemetry lines.

The primary agent records `log` when a managed block rule matches outside its enforcement scope in block mode. In monitor mode, it records a would-be block as `monitor`.

On the primary agent a block decision at servlet entry stops dispatch before application code runs, including when the response cannot redirect. A successful redirect returns directly from the servlet entry point so the container can deliver the 302 response. Identical request observations from the generic and typed service overloads share one event. Each new generic dispatch can report its own observation, including nested dispatches on the same request. All Java agent tracks read servlet admission metadata through the public servlet API so that container-owned wrappers can supply the URI, parameters, headers and include attributes. Scanner-like User-Agent metadata requires a policy selecting `request_scanner`. [Servlet admission check](../java-agent/scripts/fp-harness/ServletAdmissionCheck.java)

## Coverage numbers

Hook-family, detector-capability, asserted-signature, and acceptance-scenario counts, the per-JDK scenario distribution, and the tested vulnerability matrix are generated from the agent source and acceptance suite by [`gen-detection-coverage.py`](../java-agent/scripts/gen-detection-coverage.py) into [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md). Vulhub component roots and CVE tracking live in [`vulhub-coverage.md`](development/vulhub-coverage.md). This page does not restate those numbers.

The signature inventory counts literal algorithm IDs in the acceptance scripts. The [Vulhub coverage ledger](development/vulhub-coverage.md) records application outcomes and the boundaries of historical evidence.

## Detection techniques

### Spark REST submission authorization

Set `-Dohmyrasp.spark.submitRole=submitter` on the Spark REST server JVM to
require the deployment's `submitter` servlet role for job creation. Use a role
mapped by that deployment's servlet container. At the call to `handleSubmit`,
the agent checks the actual creation message and calls `isUserInRole` on the
submitting request. A false decision emits `required_submit_role_denied`.
Block mode stops the handoff. Monitor mode records the denial and allows the
handler to proceed. Local and remote artifacts use the same authorization check.

An unset or blank role, servlet wildcards, and an unavailable role service
leave this rule silent. On an unprotected cluster the operator must declare the
required role to enforce this boundary. Events omit the submitted descriptor,
artifact location and caller identity. In the primary agent, a descriptor-only
artifact finding from the synthetic policy API requires explicit selection.
[Spark submission servlet](https://github.com/apache/spark/blob/v2.3.1/core/src/main/scala/org/apache/spark/deploy/rest/RestSubmissionServer.scala)

### Hadoop YARN REST submission authorization

Set `-Dohmyrasp.yarn.submitRole=submitter` on the ResourceManager JVM to require
a deployment-mapped servlet role for REST application submission. Hadoop first
checks the caller and converts the application context. Once the internal
`SubmitApplicationRequest` has been prepared, the agent checks `isUserInRole`
on the submitting HTTP request. A false result records `required_submit_role_denied`.
Block mode stops the request before the client service receives it. Monitor mode
logs the denial and allows Hadoop to continue its own admission checks.

This setting uses the servlet container’s role mapping. Hadoop retains its own
queue ACLs and scheduler decisions. An unset, blank or wildcard role, or an
unavailable role lookup, leaves this rule silent. The event omits commands and
caller names. In the primary agent the synthetic YARN command-descriptor finding
requires an explicit policy selection. [ResourceManager REST service](https://github.com/apache/hadoop/blob/rel/release-2.8.1/hadoop-yarn-project/hadoop-yarn/hadoop-yarn-server/hadoop-yarn-server-resourcemanager/src/main/java/org/apache/hadoop/yarn/server/resourcemanager/webapp/RMWebServices.java)

### Java archive upload authorization

The filename hook can enforce an application-declared role when application code or
its multipart framework reads the submitted name of a JAR, WAR, EAR or class file.
Declare the operation in the web application's `WEB-INF/web.xml`. For example, a
deployment endpoint can require the servlet role assigned to release engineers.

```xml
<context-param>
  <param-name>ohmyrasp.archiveUpload.POST/releases/import</param-name>
  <param-value>role:release-engineer</param-value>
</context-param>
```

The key uses the HTTP method followed by the servlet path and path info, relative
to the current application. Matching is exact. The agent calls the current
request's `isUserInRole` at the filename hook. A false result produces
`required_role_denied`. Use the role that the deployment actually defines for
that operation. The value `deny` declares a freeze on Java archive uploads to
the operation. Its decision basis is `archive_upload_denied`. Monitor mode
records either finding. Block mode can enforce it.

Without a declaration, the local role check stays quiet. Includes and unavailable
role information supply no role denial. On the primary agent a distributed rule
can still explicitly select `fileUpload_java_archive` by algorithm name or an
equality condition to observe or prohibit archive submissions on deployment
surfaces. Its decision basis is `deployment_context`. A filename or route gives
no evidence of a failed authorization check. Applications using an object-level
ACL or a custom uploader still need their own operation-level access checks.

For additional Servlet Part and Spring MultipartFile implementations the archive
check follows a part returned by the current request. Single-item lookup, indexing
a returned list, and consuming a returned collection's iterator are observed at
their actual handoffs. The agent does not enumerate the collection or ask the part
for its filename again. A matching method name on an unrelated object does not
establish an upload. A later request needs its own part lookup. Custom bulk access
through unobserved helpers, streams or maps can lack this evidence.

A declared-policy denial records the SHA-256 of the exact context parameter key,
a zero byte and the trimmed configured value, encoded in UTF-8. An observed
request lookup is identified in the event when available. The digest lets an
operator compare a retained deployment declaration without recording principal
or role names. A historical filename event alone cannot reconstruct authorization.

### Request-parameter substring correlation

If a servlet container rejects parameter-map access, the primary agent can still inspect the request URI, headers and decoded URL query values. For example, an upload limit can make form fields unavailable while a header policy still applies. The application retains its own upload error handling.

Request parameter values (and bounded request bodies up to 8192 characters) are captured into `ThreadLocal<RequestContext>` at HTTP entry. `RequestContext.hasParameterIn(value)` checks whether a dangerous sink argument contains a parameter value of at least 2 characters, a parameter name of at least 8 characters with non-alphanumeric delimiters, or matches within the request body for sink values of at least 8 characters. This is value-level substring correlation, not bytecode dataflow taint tracking: if an application transforms a parameter string before reaching the sink in a way that breaks substring matching, correlation will not trigger, while structural and call-stack rules still evaluate the sink.

Applications that call `ProcessBuilder` with purely internal arguments do not trigger the parameter-correlated path. The call-stack analysis layer fires only if an expression-engine or gadget-chain frame is present.

### Call-stack structural analysis

Expression-engine and RCE-gadget-chain stacks appear consistently across framework exploits. `detectCommand` inspects `StackWalker` frames for:

- **Expression engines:** OGNL (Struts2), MVEL (Druid, OFBiz, Unomi), SpEL (Spring), Groovy, JEXL, Nashorn, Velocity, Jiffle (GeoServer), XStream
- **Executable listeners:** Solr `RunExecutableListener`
- **Config launchers:** RocketMQ filter-server process launches
- **Deep reflective stacks:** gadget-chain indicators from deserialization (`ObjectInputStream`, Axis2, AMF)

A novel Struts2 bypass that passes through OGNL evaluation is caught at the process sink without requiring an OGNL-specific HTTP signature. The same applies to Spring SpEL injections reaching a process or file sink.

### Spring process initialization

The Spring rule observes the HTTP(S) stream that `UrlResource` supplies to the XML reader. It associates the initializer setting with the definition that the parser assigns to that resource and follows the setting into a merged definition. At startup, the guard requires Spring to reflectively dispatch `ProcessBuilder.start()` on the same builder that reaches the JVM process handoff. Replacing the initializer locally clears the original attribution. A URL in definition metadata alone does not establish this origin.

An ordinary Bean can launch a local helper during startup. The process still passes through the regular command policies. Deployments that intentionally use HTTP-backed XML to select the process launcher itself as an initializer are subject to this rule. The event records a launch attempt and can occur outside an HTTP request. [Packaged Spring check](../java-agent/scripts/fp-harness/SpringProcessCheck.java)

### SQL syntax-aware detection

`detectSql` combines parameter correlation with structural SQL analysis across partitioned rule sets:

- The shared SQL lexer correlates a request value with its location in executable SQL. Literals and ordinary comments keep their boundaries. PostgreSQL dollar-quote tags and H2 block-comment nesting are interpreted using driver evidence. At an unidentified pool or proxy, ambiguous text can be rechecked at the concrete driver.
- Template preparation includes callable statements and JDBC options for generated keys, result-set behavior and holdability. Binding a value supplies data to the prepared template. The primary call-site hook preserves the option arguments and inspects the receiver and SQL template. A preparation finding records a submission to the driver. Evidence of execution requires a later observation.
- Independent structural checks cover a constant disjunction, a truncated literal and configured file or timing operations. The primary H2 classifier checks the command and its source operand in one declaration. Derby routine signatures require executable clauses in the same statement.
- **H2 code execution:** `CREATE ALIAS` and `CREATE TRIGGER` with `AS $$` Java inline blocks (covering CVE-2022-23221 and variants), plus H2 `INIT` URL checks in `detectJdbcUrl`.
- **Derby code execution:** `SQLJ.INSTALL_JAR` and `LANGUAGE JAVA EXTERNAL NAME` procedure patterns.
- **`detectSqlRegex`:** GeoServer OGC filter CQL injection (`strConcat`, Jiffle script fragments).

Zero false positives on the benign SQL corpus (see [False-positive methodology](#false-positive-methodology)).

At JDBC handoff, the lexer recognizes square-bracket identifiers for SQLite and SQL Server. SQLite ends the name at the first closing bracket. SQL Server permits a doubled closing bracket inside the name. The concrete PostgreSQL driver retains array-expression semantics. When a pool has no driver identity, bracket-dependent findings can be deferred to the driver. [SQLite identifier tokens](https://www.sqlite.org/draft/tokenreq.html) · [SQL Server delimited identifiers](https://learn.microsoft.com/en-us/sql/t-sql/functions/quotename-transact-sql)

For MySQL-family JDBC statements the lexer treats a hash outside quotes as a line comment and recognizes the whitespace or control character required after a double dash. A lone carriage return remains in the comment until the line feed. A request tag that also occurs in a report annotation supplies no independent evidence of SQL control. At a mapper handoff the agent can use the recorded substitution offsets to check whether a supplied marker consumed a fixed delimiter. [MariaDB comment syntax](https://mariadb.com/docs/server/reference/sql-statements/comment-syntax) · [MySQL lexer](https://github.com/mysql/mysql-server/blob/8.4/sql/sql_lex.cc)

### MyBatis dynamic SQL

The mapper hook observes raw property substitutions as MyBatis appends them. It
propagates their character offsets through token parsing, bound placeholders,
dynamic SQL assembly, trim nodes, whitespace compaction and observed PageHelper
SQL builder copies. The parameter
object stays in the application. At JDBC, the agent checks whether the final
template contains executable syntax introduced by a marked range. Findings
record the reason and the decision basis `mapper_substitution_at_jdbc`.

An unchanged copy returned by the same `BoundSql` can be checked during its
statement handler's JDBC call. A replacement SQL string with different text
needs its own source evidence. JDBC's general SQL checks still apply.
Computed OGNL expressions, custom language drivers and arbitrary third-party
rewrites can lack origin information. Raw substitution identifies a source of
SQL text; application authorization is a separate question. [MyBatis mapper reference](https://mybatis.org/mybatis-3/sqlmap-xml.html#String_Substitution)

The primary agent makes the JSON-only observations `request_sql_sort_injection`
and `request_sql_identifier_injection` available to distributed policies that
explicitly select them. Use a log action to observe those fields. The default
mapper decision waits for JDBC.

### Deserialization defenses

Multiple hook modules and detectors cover Java deserialization surfaces:

- **`detectDeserialization`:** checks the resolved class at the primary JDK stream’s `ObjectInputStream.filterCheck` callback. The agent evaluates its class policy alongside the filter selected by the application’s factory. The JDK handles rejection, application callbacks and stream metadata at the same check. Array descriptors and lengths remain available to the application filter. The agent applies the listed-type rule when the JDK checks an object element. Applications retain their global and per-stream registration APIs. [JDK serial filter configuration](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/io/ObjectInputFilter.Config.html)
- The backports observe the class returned by the stream’s virtual resolver before the JDK consumes it. Proxy resolution checks the interfaces of the selected proxy class and records a separate hook label. For native Java serialization the BeanShell rule checks interpreter types and syntax-tree ancestry on the resolved type. A serialized scalar can be read normally. [Packaged resolution check](../java-agent/scripts/fp-harness/check-stream-resolution.py)
- Commons Collections 3 and 4 use the upstream unsafe functor list for native object streams. Equality predicates, constant transformers and chains composed of ordinary steps can be read normally. The stream checks the resolved types of the components and their nested values. [Apache security changes](https://commons.apache.org/proper/commons-collections/release_3_2_2.html) · [Stream check](../java-agent/scripts/fp-harness/StreamResolutionCheck.java)
- Native streams can restore JMX attribute exceptions with normal string or null values. In block mode, if the JDK reader would call application `toString()` to populate the exception’s display field, the agent supplies an identity string at that call. Boxed primitive values retain their display. Monitor and off modes retain the original receiver. The repair addresses the native reader only. [OpenJDK reader](https://github.com/openjdk/jdk/blob/master/src/java.management/share/classes/javax/management/BadAttributeValueExpException.java) · [JMX check](../java-agent/scripts/fp-harness/check-jmx-dispatch.py)
- The primary JDK stream filter checks resolved c3p0 types that expose JDBC data sources or JNDI references and factories. Plain credential records and connection testers can round-trip, subject to any application filter. Intentional deserialization of a listed data source can still be blocked. Parsers that supply only a type name continue to use the name policy. [Stream filter check](../java-agent/scripts/fp-harness/check-serial-filter.py)
- The Groovy serialization type policy covers the listed method and interface closure adapters. Ordinary interpolated strings and numeric sort comparators can round-trip through the JDK stream filter. [Shared type policy](../java-agent/shared/src/main/java/io/ohmyrasp/agent/serialization/StreamTypeNames.java)
- **`detectFastjsonClassResource`:** blocks URL-shaped class-resource lookups in Fastjson 1.2.83 immediately before `ParserConfig.checkAutoType` invokes the `ClassLoader`. Block mode enforces this decision on background threads as well as HTTP request threads. Local classpath resource names are allowed. [Resource policy](../java-agent/shared/src/main/java/io/ohmyrasp/agent/rules/product/fastjson/FastjsonClassResource.java)
- **`detectPolymorphicType`:** inspects `@type`, `javaClass`, and `class` JSON keys (Fastjson, Jackson) and YAML `!!` tags.
- **`detectHessianType`** checks the class a built-in Caucho Hessian or relocated Hessian Lite decoder is about to allocate. Events identify the selected class and whether the decoder used a reflective constructor, `Class.newInstance` or `Unsafe.allocateInstance`. Factory lookups, application-selected type substitutions and empty arrays can complete without allocating the advertised element type. The guard enforces the listed allocation policy even for intentional uses of those types. Custom decoders with independent allocation code are outside this hook. [Type policy](../java-agent/shared/src/main/java/io/ohmyrasp/agent/rules/product/hessian/HessianAllocationTypes.java) · [Local codec check](../java-agent/scripts/fp-harness/HessianAllocationCheck.java)
- Spring HTTP Invoker can restore ordinary RPC arguments under the default class policy. On the primary track, explicitly selecting `deserialization_http_invoker` governs the exporter's object read. Explicitly selecting `deserialization_http_object_stream` governs object reads on a stream constructed directly over a servlet input stream during request processing. Local cache streams can be read on the same request thread. The JDK's resolved-type checks apply independently to nested arguments. [Packaged RPC check](../java-agent/scripts/fp-harness/HttpInvokerReadCheck.java)
- Apache XML-RPC applies the JDK class policy to the object stream selected by its serialized-value parser. This includes worker threads without an HTTP request. Normal values can be read under the default policy. To forbid the extension altogether on the primary agent, select `deserialization_xmlrpc_serialized` explicitly in a managed policy. It takes effect at `ObjectInputStream.readObject`, after the JDK accepts the stream header. [Packaged XML-RPC check](../java-agent/scripts/fp-harness/XmlRpcReadCheck.java)
- **`detectProtocolClassInstantiation`** checks that the constructor selected by the OpenWire exception marshaller belongs to a `Throwable` subtype. The guard runs before reflective invocation, including outside HTTP requests. Legitimate application exceptions keep their message. If the library rejects a type first, its rejection is preserved. OpenWire can convert a rejected operation to a fallback exception; the relevant outcome is whether the constructor ran. [Local contract check](../java-agent/scripts/fp-harness/OpenWireThrowableCheck.java) · [Apache advisory](https://activemq.apache.org/news/cve-2023-46604)
- **`detectRmiRegistryBind`:** covers RMI Registry gadget delivery.
- **`detectSessionDeserialization`:** covers serialized session-file deserialization paths.

Fastjson CVE-2017-18349 and the 1.2.47 `@type` bypass, XStream CVE-2021-21351 and CVE-2021-29505, and WebLogic XMLDecoder CVE-2017-10271 all have verified Java 8 acceptance runs.

### JMX invocation arguments

The agent inspects the arguments forwarded by the JDK management server to a resolved `DynamicMBean`. Lookup failures retain their JMX exceptions. The argument check uses supplied strings and string arrays. Calling application display methods or iterating application objects during dispatch could consume them before the managed operation runs.

The remote configuration check considers complete URI expressions, including a URI supplied as a property value. This dispatch event describes the configuration argument.

The JMX file rule correlates text supplied to the innermost synchronous invocation with the path at a writable host-file open. The path must match an argument or a complete quoted value within it. The operation name can be arbitrary. The agent observes output-stream and writable random-access opens, plus supported Unix NIO channel opens. A blocking decision precedes the open. A monitoring event records an attempt. Changes of thread, rewrites of the supplied filename, and directory-descriptor-relative opens without an absolute operand can lose the correlation. Other file policies may act earlier in the call.

### Packaged XML catalogs

When a parser remaps an external DTD identifier to a local archive, the agent checks the parser's selected input and the archive's origin. It can establish the origin from a URL class loader or from the code source of a class actually defined by the built-in system loader. The check also recognizes a relative DTD in the same archive as a root document opened by the parser. Applications that supply a document reader and set a base URI do not establish that archive origin.

### Multi-form path-confusion decoding

`request_path_confusion` decodes every incoming URI in six forms simultaneously:

1. Raw (as received)
2. URL-decoded (one pass)
3. Double-decoded (two passes)
4. Low-byte Unicode normalization
5. Overlong UTF-8 decoding (for example, `%c0%ae` -> `.`)
6. Lenient percent-decode

Percent decoding preserves valid UTF-8 scalars. The control-character check uses the decoded text before low-byte projection, so a non-ASCII report name can pass through ordinary servlet routing.

Comparing all six representations catches path-semantic mismatches (such as traversal sequences appearing only after decoding) without product-specific path signatures. Verified scenarios include Shiro semicolon traversal (CVE-2010-3863, CVE-2020-1957), Nexus repeated encoded-slash, GlassFish overlong UTF-8 (CVE-2010-1000028), Openfire `%u002e%u002e` encoding (CVE-2023-32315), Spring high-Unicode normalization, Flink double-percent encoding, and Jetty `ConcatServlet` `%2e/WEB-INF` traversal.

### Cryptographic default-secret verification

- **JWT default HMAC secrets:** The primary agent tests incoming Bearer JWTs against known default HMAC secrets (such as HugeGraph's published default). A valid HMAC under a default secret fires at severity 95.
- **Apache Shiro default rememberMe key:** encrypted `rememberMe` cookies are decrypted under Shiro's default AES key; if decryption yields a Java object-stream magic header, the detector fires (verified in the CVE-2016-4437 Java 8 acceptance run).

### RMI codebase selection

RMI may resolve a class or proxy locally even when its annotation contains a remote URL. On runtimes with a codebase-loader branch, the agent checks the parsed URL array when the JDK enters `sun.rmi.server.LoaderHandler.lookupLoader`. Local resolutions retain their original result or exception. Custom RMI providers have their own resolution logic.

For `URLClassLoader`, the class-origin rule runs immediately before the JVM receives class bytes for definition. For a directory resource it uses the JDK connection that supplied the stream. For an archive it checks the selected archive origin, including when the JAR is already cached. Ordinary resource reads, classpath registration and parent-loader hits can complete without a class-origin event. Bytes may already have been fetched when a definition is blocked. Applications that intentionally define classes from a covered remote source are subject to this policy. [Packaged class-definition check](../java-agent/scripts/fp-harness/ClassDefinitionCheck.java)

Opening an HTTP-backed JAR wrapper is a protocol policy decision on the primary agent only when a managed policy explicitly selects `ssrf_protocol`. The HTTP transport separately checks the backing destination, including when a request supplied the URL of a member inside that archive.

### JAAS directory lookups

During JAAS login the agent attributes URL selection to the JDK's `JndiLoginModule` when its own directory lookup reaches the naming router. Applications can construct or inspect JAAS entries, including entries for remote directories, without activating the policy. If a context factory builder handles the lookup locally, the JAAS rule stays silent. Block mode applies the configured naming policy before the URL provider receives the lookup. [Packaged login and directory check](../java-agent/scripts/fp-harness/JaasDirectoryCheck.java)

### Elasticsearch LZ4 transport block isolation (CVE-2026-82303)

In block mode the Java agents, including the standalone Shirudo packages, repair
the legacy array decoder call in `Lz4TransportDecompressor.decodeBlock` on each
instrumented node. If the input resides in a larger buffer, the guard copies
only the declared compressed block before invoking Elasticsearch's selected decoder.
An exact standalone block can be used in place. The decoder must report consuming
exactly the declared length before Elasticsearch can publish output pages. An invalid
extent or consumption mismatch fails the transport read with an I/O error.

Monitor and off modes keep the original decoder behavior. Deploy the agent in
block mode on each affected JVM for this mitigation. The upstream fixed
ByteBuffer call site is outside the rewrite. This is a transport repair that
works without an HTTP request. The copy adds allocation and bandwidth cost for
shared buffers. Upgrading to a vendor-fixed release provides the permanent fix.
[Elastic security advisory](https://discuss.elastic.co/t/391840) · [Upstream transport fix](https://github.com/elastic/elasticsearch/pull/161345)

### Base64 AVX-512 tail-underflow guard (CVE-2026-114938)

[`Base64HookModule`](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/asm/Base64HookModule.java) (and `Java{8,11,17}Base64Transformer` across the backport agents) instruments `java.util.Base64$Decoder.decode0([BII[B)I` across JDK 8, 11, 17, 21, and 25. Before the native x86-64 AVX-512 stub can underflow the tail buffer and write past the destination array, `DetectorEngine.isBase64TailUnderflowCandidate` performs a zero-allocation check for non-MIME inputs of length `>= 65` with `1 <= (length & 63) <= 3`, `1 <= padding <= 2` (`padding <= remainder`), and valid Base64 alphabet bytes (`+`/`/` for standard, `-`/`_` for URL-safe). Matching inputs are blocked (even outside an HTTP request context) and logged using length, padding, remainder, and alphabet metadata only; raw input bytes are never recorded.

### JWT rejection and filter dispatch

The DataEase community authentication filter can catch a signature or algorithm
rejection and still pass its request to the downstream servlet chain. The product
rule records the credential selected by the filter and the result of verifying
that string or its decoded object. It checks the original request and chain at
the dispatch call. A successful retry with that credential clears the pending
rejection. Each invocation owns its state and the event omits credential values.
[DataEase filter source](https://github.com/dataease/dataease/blob/v2.10.7/sdk/common/src/main/java/io/dataease/auth/filter/CommunityTokenFilter.java)

### Process launches

On the supported OpenJDK launch path the agent checks the argument array at
`ProcessImpl.start`. At this point the process builder has taken its snapshot.
The policy check runs before the platform starts that stage or opens its redirect
files. It does not read the application's mutable command list a second time.
Each pipeline stage is checked separately; earlier stages may already have started.
JDKs without the recognized handoff retain the public-API hooks.

Process events at the handoff identify the public API and argument count. Display
text alone does not recover the argument vector, and a recorded decision reason
does not recover a call stack. The primary agent treats direct reflective dispatch
alone as an explicitly selected `command_reflect` policy. An ordinary report job
invoked by a reflective framework has its own caller at the process API.
[JDK process builder](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html)

For common process indicators the agent distinguishes direct tool operands from
inline shell source. A fixed POSIX shell program can take report text in a
positional parameter. The command indicator check reads the program argument and
keeps those later arguments out of its source scan. For noninteractive `sh`, `dash`
and `bash` invocations with a confirmed `noexec` option, syntax checking does
not activate the inline-execution rules. For a single literal command
in a plain `sh -c`, `dash -c` or `bash -c` invocation, the common indicator rule
recognizes quoted words, escapes and comments. It treats literal `echo` operands
and string-format `printf` operands as output. For supported readers with literal
absolute file operands it compares complete path arguments. Compound programs,
expansions and other command modes continue through the source indicator check.

For cmd and PowerShell, the agent first identifies an inline command operand.
A native program can receive punctuation in an ordinary argument. PowerShell
script-file arguments and the positional arguments after a `-CommandWithArgs`
program can carry the same text. For supported inline invocations, request
matching uses separator positions in the program and excludes literal and
comment text. An event describes the launch arguments observed by the JDK.
[cmd command modes](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd) · [PowerShell command modes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh)

For a direct network tool launch, the primary agent checks recognized destination
operands against its callback-domain policy. The event carries the normalized host.
This evidence describes the requested destination at process start. Network delivery
and the purpose of the transfer require separate evidence.

For untyped temporary output the generated-script rule checks whether request input
supplies an operation in code position or its complete operand. Quoted report fields
and comments are ordinary data. The JDK write hooks use the encoded handoff and the
lines consumed by the writer. A denied streamed line can follow earlier lines already
written to the file. Counting the denied write does not establish execution of a script.

### Plot output streams

The Java backports associate a plot filename with the actual output stream after its file open succeeds. Byte-array slices and single-byte writes are checked at the JDK's native write call. This association follows the stream when another thread uses it. Each successful write can supply bounded context for the next write. A rejected write contributes no bytes. An I/O exception invalidates the prefix because a partial write may have occurred.

The content rule looks for lowercase plot directives outside ordinary quoted labels and comments. Overlapping writes, a stream opened for append, or access through a channel or file descriptor can make the preceding line uncertain. The detector resumes matching at an observed line boundary in those cases. This check does not cover arbitrary channel writers or establish that a plot interpreter ran. [Gnuplot quoting](https://gnuplot.info/docs_6.1/loc4437.html)

### Host file reads

On supported OpenJDK Unix builds, the file-read hook checks the path and the read-access
flag selected by the channel factory before the operating-system open. This includes
synchronous and asynchronous file channels. Reading attributes, reading a symbolic
link's target string and reading an entry inside a ZIP filesystem do not open the
corresponding host path for content. Ordinary NIO content operations retain a fallback
until the native hook has run. Relative opens through a directory descriptor carry
no absolute path at this hook and need separate evidence.

For a request-selected host path, the open hook can resolve symbolic links and check
the observed destination against the protected-file rules. The check runs on the
path being opened. NIO's final-link policy is respected, and creating a new file
cannot consume pre-existing content. Input streams and random-access files are checked
at their validated path open. Link resolution is a point-in-time observation and does
not track every hard link or subsequent filesystem mutation.

On the primary agent an exact `readFile_userinput` rule can select ordinary reads
by supplied absolute path. An application's use of a supplied path to select an
ordinary report produces no default finding solely because of its filename extension.
The primary agent can apply an explicit `readFile_outsideWebroot` policy to otherwise
uncorrelated reads under system directories. The request-controlled and sensitive-file
checks continue independently. Backport agents correlate reads of the system hosts file
with the captured request path. They use the same check for libraries and application
code. When removing a parent component could change a protected target, the
location check compares file identity at the operation. A later replacement of
the file falls outside that observation. [JDK file channel access modes](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/channels/FileChannel.html)

For CXF Aegis package reads, a local reference is associated with the specific Javax
or Jakarta Activation data source constructed for that reference. The local-file
decision is made when that data source actually opens the matching host file. A MIME
part selected by content ID can be backed by an ordinary file. On the primary agent
a deferred read retains the originating request for policy evaluation. [XOP package references](https://www.w3.org/TR/xop10/#xop_href)

### Windows file streams

At a writable Windows file open, the primary agent applies the ordinary file policy to the base file of an explicitly named default data stream. Named data streams can contain legitimate metadata. An explicit `writeFile_NTFS` selector can monitor or block attempts to open a named data stream for writing. Its event records the requested stream name and base path. Select action `log` to observe normal usage. The hooks cover the JDK output stream, writable random-access file and Windows NIO dispatcher. An upload filename alone does not establish the destination filesystem. [Windows file streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)

### Host writes and archive entries

Host-file and generated-script write checks use the destination filesystem. A virtual archive member can have the same spelling as a host path. Writing that member consumes the pending archive name and does not apply host-file policy to its contents. A provider can still perform independently observable host operations.

On the primary agent, a ZIP input stream supplies the stored member name. A `ZipFile` lookup supplies a name only when the JDK returns an input stream. Collecting that metadata leaves application overrides of `getName()` alone. Closing the reader expires its pending observation, including when an outer servlet dispatch is suspended. The backports observe returned entry-name strings and have less information about the reader.

With a pending archive name, the Unix channel hook checks the JDK's validated write flag and the host operand before opening the file. For a relative open against a directory descriptor on Linux it resolves the directory held by that descriptor. When the directory cannot be identified the agent skips that correlation. The evidence records the opening attempt, not a completed extraction. It does not recover names rewritten by an application or passed between threads.

### Host file deletion

An operator can confine request-selected file deletion to a directory by passing `-Dohmyrasp.file.delete_root=/absolute/allowed/directory` at JVM startup. Choose the enclosing directory within which requests may move between subdirectories. The rule checks operations originating under this root. Jobs using independent directories keep their existing behavior. Without a configured root, relative names containing parent segments alone produce no delete finding.

On Linux, NIO deletion is checked at the provider's remove operation. The agent correlates the request path with the actual operand and resolves the entry's parent, preserving a final symbolic link. For a relative deletion against an open directory it uses the directory descriptor. An in-root sibling is allowed. A request-selected entry whose parent resolves outside the configured root can be blocked, including through an intermediate symbolic link. Advance normalization, an unavailable descriptor or missing request data can prevent correlation. A filesystem rename between the check and the native removal is outside this check's guarantees.

On the primary agent an exact absolute path in a request can also be monitored with an explicit `deleteFile_userinput` rule using action `log`. Legitimate cleanup can contain the same path. A `delete_on_exit_registration` event describes the scheduling operation. Whether the file was removed depends on JVM shutdown.

### Host directory listings

The `File` hook checks a successful listing before names reach the caller or its
filename filter. On supported OpenJDK providers the NIO hook checks the opened
directory stream before it reaches the application. A denied stream is closed.
The default rule requires both a request-selected directory (or traversal root)
and an observed protected host directory. ZIP entries remain in the archive namespace.

On Unix, a secure stream's directory identity can be compared with the current
protected directories through its attribute view, including for operations relative
to an open directory descriptor. A non-secure listing uses the selected pathname
and has a time interval between enumeration and path inspection. A lazy tree walk
retains its originating request; the decision applies when a directory is actually
enumerated. Parent entries already returned by an earlier step can remain visible.
The primary agent supports explicit policies for ordinary requested paths, location
alone, and reflective dispatch. [JDK directory streams](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/SecureDirectoryStream.html)

### HTTP transport evidence

The JDK URLConnection hooks check the selected HTTP or HTTPS target after response-cache
selection and again before writing a request. This covers requests on a reused connection.
Creating or configuring a connection object leaves the HTTP rules quiet. The JDK HttpClient
hooks follow the submission through asynchronous work and subsequent exchanges. Actual
transport events record the phase and omit the outbound query string, user-info and fragment.
Managed policy evaluation still sees the comparison inputs. [Java URL connection semantics](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/URL.html#openConnection())

The default request-correlated rule checks a supplied destination against an internal
address. It can use a direct socket address already resolved by the JDK or the selected
direct route for an HTTP client connection. IPv6 destination comparisons use the address
bytes and preserve the zone identifier, which can name a local network interface. The agent performs no extra DNS lookup.
A supplied administrative path can also select a protected local route. A fixed local
self-check and a supplied hostname with no internal route evidence stay quiet under
this rule. The primary agent supports an explicitly selected `ssrf_userinput` policy
for those broader destinations. The separate cloud metadata and callback rules still apply.

Automatic changes of destination are checked in the originating HTTP operation.
An explicit proxy's address belongs to the proxy. Custom transports, proxy-side DNS
and third-party HTTP stacks can require additional evidence. The JDK HTTP/2 pool
check uses the selected connection's direct address before reserving a stream. A block records a denied
attempt at the indicated phase. The remote application's outcome needs separate evidence.

### SSRF heuristics

`detectUrl` and `detectXmlAttachmentReference` check:

- **Cloud metadata endpoints** use the shared address classification in [NetworkHost](../java-agent/shared/src/main/java/io/ohmyrasp/agent/net/NetworkHost.java). A fixed DNS resolver address is handled as an ordinary destination.
- **Dangerous protocols:** `ldap`, `rmi`, `file`, `jar`, `dict`, `gopher`, `sftp`, `tftp`
- **Internal RFC-1918 address space:** `10.x`, `172.16-31.x`, `192.168.x`
- **Known DNS callback domains:** `ceye.io`, `dnslog.cn`, `burpcollaborator.net`, and other well-known out-of-band callback domains (see the shared primary-agent domain policy in [CallbackDomain.java](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/CallbackDomain.java))
- **IP obfuscation forms:** decimal (`2130706433`), hex (`0x7f000001`), and octal (`0177.0.0.1`) encodings of loopback and RFC-1918 addresses

### Response-side data-leak detection

`detectResponseDataLeak` inspects outbound response bodies (HTML, JSON, XML) for:

- **Chinese national ID cards:** 18-digit format with checksum verification
- **Mobile phone numbers:** validated against Chinese carrier prefix tables
- **Payment card numbers:** Luhn-validated (card brand not distinguished)

`detectXssEcho` checks whether an XSS-like input payload is reflected verbatim in the response body.

> **Wiring status: not yet active on live traffic.** Both `detectResponseDataLeak` and `detectXssEcho` are implemented and exposed via `OhMyRaspHooks.beforeResponseDataLeak` and `OhMyRaspHooks.beforeXssEcho`, but **no ASM hook module currently instruments a servlet response-output sink** (`HttpServletResponse.getWriter()` / `ServletOutputStream`). Today they execute only when called directly by the playground probes (`response` and `xss-echo` actions in [`VulnerableServlet.java`](../java-agent/playground/src/main/java/io/ohmyrasp/playground/VulnerableServlet.java)). Wiring response-body scanning onto the hot response path is deferred to avoid adding outbound-body scanning overhead on every request.

### Payload redaction before logging

Before writing events to the NDJSON spool or `stderr`, detectors and `JsonEventLogger` redact sensitive fields:

- `JsonEventLogger` masks sensitive HTTP headers (`authorization`, `cookie`, `set-cookie`, `x-api-key`, `api-key`, `x-auth-token`, `access-token`, `refresh-token`, `id-token`), sensitive parameters (`password`, `token`, `secret`, `apikey`, `credential`, and variants), and executable-source parameters (`script`, `source`, `command`, `cmd`, `payload`, `template`, `expression`, and variants).
- Expression payloads in multipart upload filenames record `length=N` and `engine=X` metadata only.

## Validated against real exploits

### JDK and Tomcat compatibility matrix

Each JDK track produces a self-contained agent JAR with ASM relocated to `io.ohmyrasp.agent.shaded.asm` so it does not collide with application-bundled ASM (for example, Struts2 bundling ASM 3.3). The servlet hooks instrument both `javax.servlet` and `jakarta.servlet` namespaces, so one binary covers Tomcat 9 through 11 without recompilation. See [`agent.md`](agent.md) for artifact paths and build commands.

| Agent track | Target JDK | Tomcat versions |
|---|---|---|
| `agent-jdk25` (primary) | Java 21 and 25 (`--release 21`) | Tomcat 11, 10, 9 |
| `agent-java17` | Java 17 (and 21) | Tomcat 11, 10.1, 9 |
| `agent-java11` | Java 11 | Tomcat 10.1, 9 |
| `agent-java8` | Java 8 | Tomcat 10.0, 9, 8.5 |

Per-JDK acceptance scenario counts are in the generated matrix in [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md).

Java 25 is the primary development target and is not an LTS release. Production deployments on Java 17 or Java 21 LTS should use `agent-java17`.

### Notable CVE acceptance runs

The table below highlights representative Vulhub scenarios verified end-to-end against real Docker containers (see [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md) and [`vulhub-coverage.md`](development/vulhub-coverage.md) for the complete scenario list):

| CVE / Advisory | Application | JDK tested |
|---|---|---|
| CVE-2021-44228 (Log4Shell) | Solr JNDI lookup | Java 8 |
| CVE-2017-18349, 1.2.47 bypass | Fastjson `@type` | Java 8 |
| CVE-2016-4437 (Shiro default key) | Apache Shiro | Java 8 |
| CVE-2010-3863, CVE-2020-1957 (path traversal) | Apache Shiro | Java 8 |
| Struts2 OGNL advisories (S2-001 and later) | Apache Struts2 | Java 8 / 17 |
| CVE-2022-22965 (Spring4Shell) | Spring MVC / Tomcat | Java 8 |
| CVE-2022-22947 | Spring Cloud Gateway SpEL | Java 8 |
| CVE-2020-1938 (Ghostcat) | Tomcat AJP | Java 8 |
| CVE-2023-46604 | Apache ActiveMQ OpenWire | Java 11 |
| CVE-2021-21351, CVE-2021-29505 | XStream gadget | Java 8 |
| CVE-2020-14882/14883, CVE-2017-10271 | Oracle WebLogic | Java 8 / Java 6 legacy |
| CVE-2022-24816, CVE-2023-25157, CVE-2024-36401 | GeoServer | Java 17 |
| CVE-2024-56511, CVE-2025-32966, CVE-2025-49001 | DataEase | Java 21 |
| CVE-2019-3396, CVE-2021-26084, CVE-2022-26134, CVE-2023-22515, CVE-2023-22527 | Atlassian Confluence | boundary script (`unknown`) |

## False-positive methodology

A curated corpus of benign inputs across the detector categories (SQL queries, OS commands, outbound URLs, file reads and writes, deserialization classes, expressions, OGNL expressions, JNDI names, DNS lookups, upload filenames, JDBC URLs, request parameters, and Base64 decoding) is evaluated against the live `DetectorEngine` with a `RequestContext` carrying user-supplied values in request parameters. The report is generated by [`FpReport.java`](../java-agent/scripts/fp-harness/FpReport.java) against the real engine, including `detectRequest` on benign HTML parameter values. Per-category input counts and results are in the generated [`FALSE-POSITIVE-REPORT.md`](../java-agent/docs/FALSE-POSITIVE-REPORT.md); the current result is zero false positives.

For `InitialContext.lookup` and `lookupLink`, the agent checks the name component that the JDK uses to select a URL scheme. A local binding can have a URL-like display name without triggering the rule. When an installed context factory builder handles the name directly, the JDK skips URL selection. Calls directly into the JDK URL context are checked where the provider requests its root context. The event records which of these two operations occurred. In block mode the remote-scheme policy also applies to intentional LDAP directory lookups. A routing event alone cannot establish a network connection or an unauthorized lookup.



**Framing:** This is a detector-precision regression check on hand-curated benign inputs, not a production false-positive rate measurement. Production traffic introduces context that this corpus does not model, such as framework middleware wrappers, custom parameter encoding, and ORM-generated SQL.

## Known limitations

- **Java 25 build toolchain:** `agent-jdk25` builds with `JavaLanguageVersion.of(25)` and `options.release.set(25)`. Production Java 17 or Java 21 LTS deployments must use `agent-java17`.
- **Java 6 and 7 JVMs are outside agent support:** Agent classfiles target Java 8 (`<= 52`) or newer and cannot load on Java 6 or 7 JVMs. The `java6-legacy` and `java7-legacy` entries in the acceptance matrix document exploit baselines on those runtimes; they do not demonstrate agent blocking.
- **Confluence setup boundary:** Confluence requires an interactive license-setup step that prevents unattended container startup. `acceptance-vulhub-confluence-setup-boundaries.sh` probes expected setup boundaries rather than completing full agent-injection and block assertions.
- **Curated false-positive corpus:** The zero-false-positive result measures regression precision on curated inputs and must not be extrapolated directly to production FP rates.
- **Vulhub scope:** Acceptance breadth covers the Java/JVM Vulhub roots listed in [`vulhub-coverage.md`](development/vulhub-coverage.md). Middleware patterns outside that corpus may exercise uninstrumented sinks.
- **Regional PII scope:** `detectResponseDataLeak` covers Chinese national IDs, Chinese mobile prefixes, and Luhn payment cards (and is not yet wired to a servlet response hook). US SSNs, EU identifiers, and other regional formats are out of scope.

## Coverage ledgers

Detailed tables of hooks, detectors, algorithm signatures, and acceptance scenarios are maintained in:

- [`java-agent/docs/DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md): generated hook families, detector capabilities, asserted algorithm signatures, and acceptance matrix
- [`java-agent/docs/FALSE-POSITIVE-REPORT.md`](../java-agent/docs/FALSE-POSITIVE-REPORT.md): generated per-category false-positive report from `FpReport.java`
- [`docs/development/algorithm-coverage.md`](development/algorithm-coverage.md): algorithm-level narrative and per-scenario notes
- [`docs/development/vulhub-coverage.md`](development/vulhub-coverage.md): Vulhub CVE tracking checklist with boundary classifications
- [`deploy/shirudo/README.md`](../deploy/shirudo/README.md): standalone Shirudo Java upatch packaging and security boundary
