# Detection Engineering

OhMyRASP intercepts dangerous JDK operations inside the running JVM rather than inspecting traffic at a network boundary. This document describes the five-stage detection pipeline, active detection techniques, false-positive evaluation, and deployment limits.

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

**Stage 3: StackWalker call-stack analysis.** `OhMyRaspHooks` captures a live `StackWalker` trace (`RETAIN_CLASS_REFERENCE`, `SHOW_REFLECT_FRAMES`) at sink invocation. `detectCommand` inspects the trace for expression-engine frames (OGNL, MVEL, SpEL, Groovy, JEXL, Nashorn, Velocity, Jiffle, XStream), executable-listener frames (Solr `RunExecutableListener`), config-launcher frames, and reflective deserialization stacks. The presence of these frames changes both the algorithm label and the confidence score, classifying `ProcessBuilder.start` differently depending on whether it originates from Struts2/OGNL, a Spring bean-init chain, an XStream unmarshaller, or ordinary application code.

**Stage 4: Algorithm classification and policy decision.** The detector returns a named algorithm signature (such as `java8_jndi_remote_lookup` or `java17_request_path_confusion`) with a confidence score and recommended action. `AgentRuntime` applies the active mode (`off`, `monitor`, or `block`) and per-algorithm switches:

- **Daemon-managed or local-control mode:** `AgentRuntime` polls a JSON control file (default `/tmp/ohmyrasp-control.json`) updated by the Rust host daemon or operator, applying mode, per-algorithm switches, and distributed policies without a JVM restart.
- **Standalone locked mode (`META-INF/ohmyrasp-shirudo.properties`):** Shirudo Java upatch JARs bake in `standalone=true`, `lock_config=true`, `mode=block` (or `monitor` when built with `--mode monitor`), and `control=none`. Configuration is fixed at build time, ignores `/tmp/ohmyrasp-control.json` and runtime mode overrides, and starts zero control-poller threads.

**Stage 5: Reporting.** Accepted findings are emitted as structured JSON:

- **Daemon-managed mode:** `JsonEventLogger` queues findings asynchronously on a background daemon writer thread to a local NDJSON spool file (default `/tmp/ohmyrasp-events.jsonl`). The Rust host daemon tails the spool and forwards events to the Go control plane, keeping detection latency independent of network reachability.
- **Standalone locked mode:** `log=stderr` and `latency_sample=0` write detection JSON lines directly to `stderr` with zero file-writer threads, no spool file, and no periodic `hook_latency` telemetry lines.

## Coverage numbers

Hook-family, detector-capability, verified-signature, and acceptance-scenario counts, the per-JDK scenario distribution, and the tested vulnerability matrix are generated from the agent source and acceptance suite by [`gen-detection-coverage.py`](../java-agent/scripts/gen-detection-coverage.py) into [`DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md). Vulhub component roots and CVE tracking live in [`vulhub-coverage.md`](development/vulhub-coverage.md). This page does not restate those numbers.

A "verified algorithm signature" means an end-to-end acceptance test launched a real vulnerable application inside a Docker container under the agent, sent an exploit payload, and asserted that the named algorithm was detected and blocked. Signatures implemented in `DetectorEngine` without an end-to-end acceptance assertion are not included in the verified-signature count.

## Detection techniques

### Request-parameter substring correlation

Request parameter values (and bounded request bodies up to 8192 characters) are captured into `ThreadLocal<RequestContext>` at HTTP entry. `RequestContext.hasParameterIn(value)` checks whether a dangerous sink argument contains a parameter value of at least 2 characters, a parameter name of at least 8 characters with non-alphanumeric delimiters, or matches within the request body for sink values of at least 8 characters. This is value-level substring correlation, not bytecode dataflow taint tracking: if an application transforms a parameter string before reaching the sink in a way that breaks substring matching, correlation will not trigger, while structural and call-stack rules still evaluate the sink.

Applications that call `ProcessBuilder` with purely internal arguments do not trigger the parameter-correlated path. The call-stack analysis layer fires only if an expression-engine or gadget-chain frame is present.

### Call-stack structural analysis

Expression-engine and RCE-gadget-chain stacks appear consistently across framework exploits. `detectCommand` inspects `StackWalker` frames for:

- **Expression engines:** OGNL (Struts2), MVEL (Druid, OFBiz, Unomi), SpEL (Spring), Groovy, JEXL, Nashorn, Velocity, Jiffle (GeoServer), XStream
- **Executable listeners:** Solr `RunExecutableListener`
- **Config launchers:** Spring `ProcessBuilderFactoryBean` and bean-initialization patterns
- **Deep reflective stacks:** gadget-chain indicators from deserialization (`ObjectInputStream`, Axis2, AMF)

A novel Struts2 bypass that passes through OGNL evaluation is caught at the process sink without requiring an OGNL-specific HTTP signature. The same applies to Spring SpEL injections reaching a process or file sink.

### SQL syntax-aware detection

`detectSql` combines parameter correlation with structural SQL analysis across partitioned rule sets:

- **`SQLI_USER_INPUT`:** injection structures correlated with request parameters (`OR`/`AND` tautologies, `UNION SELECT`, comment prefixes `--`, `#`, `/*`).
- **`SQLI_STRUCTURAL`:** standalone structural injection signatures (quote-terminated comments `['"]\s*--`, quote-terminated `OR`/`AND` tautologies, and unquoted `OR <id>=<id>` tautologies) enforced across driver-wide JDBC `Statement` sinks even outside an active HTTP `RequestContext`, while leaving benign `WHERE 1=1 AND ...` query-builder prefixes quiet.
- **`SQL_POLICY`:** schema enumeration (`information_schema`) and file-export keywords (`INTO OUTFILE`, `LOAD_FILE`).
- **H2 code execution:** `CREATE ALIAS` and `CREATE TRIGGER` with `AS $$` Java inline blocks (covering CVE-2022-23221 and variants), plus H2 `INIT` URL checks in `detectJdbcUrl`.
- **Derby code execution:** `SQLJ.INSTALL_JAR` and `LANGUAGE JAVA EXTERNAL NAME` procedure patterns.
- **`detectSqlRegex`:** GeoServer OGC filter CQL injection (`strConcat`, Jiffle script fragments).

Zero false positives on the benign SQL corpus (see [False-positive methodology](#false-positive-methodology)).

### Deserialization defenses

Multiple hook modules and detectors cover Java deserialization surfaces:

- **`detectDeserialization`:** hooks `ObjectInputStream.resolveClass` and checks class names against a known-dangerous gadget blocklist (Commons Collections, BeanShell, Groovy, and related gadgets) via `DeserializationGuard`.
- **`detectFastjsonClassResource`:** blocks URL-shaped class-resource lookups in Fastjson 1.2.83 immediately before `ParserConfig.checkAutoType` invokes the `ClassLoader`.
- **`detectPolymorphicType`:** inspects `@type`, `javaClass`, and `class` JSON keys (Fastjson, Jackson) and YAML `!!` tags.
- **`detectHessianType`:** covers Hessian type-loading gadget chains (active with or without an HTTP `RequestContext`).
- **`detectHttpInvokerDeserialization` and `detectHttpObjectStreamDeserialization`:** cover Spring HTTP Invoker.
- **`detectProtocolClassInstantiation`:** covers ActiveMQ OpenWire class instantiation (CVE-2023-46604, active with or without an HTTP `RequestContext`).
- **`detectRmiRegistryBind`:** covers RMI Registry gadget delivery.
- **`detectSessionDeserialization`:** covers serialized session-file deserialization paths.

Fastjson CVE-2017-18349 and the 1.2.47 `@type` bypass, XStream CVE-2021-21351 and CVE-2021-29505, and WebLogic XMLDecoder CVE-2017-10271 all have verified Java 8 acceptance runs.

### Multi-form path-confusion decoding

`request_path_confusion` decodes every incoming URI in six forms simultaneously:

1. Raw (as received)
2. URL-decoded (one pass)
3. Double-decoded (two passes)
4. Low-byte Unicode normalization
5. Overlong UTF-8 decoding (for example, `%c0%ae` -> `.`)
6. Lenient percent-decode

Comparing all six representations catches path-semantic mismatches (such as traversal sequences appearing only after decoding) without product-specific path signatures. Verified scenarios include Shiro semicolon traversal (CVE-2010-3863, CVE-2020-1957), Nexus repeated encoded-slash, GlassFish overlong UTF-8 (CVE-2010-1000028), Openfire `%u002e%u002e` encoding (CVE-2023-32315), Spring high-Unicode normalization, Flink double-percent encoding, and Jetty `ConcatServlet` `%2e/WEB-INF` traversal.

### Cryptographic default-secret verification

- **JWT default HMAC secrets:** `detectJwtVerificationFailure` tests incoming Bearer JWTs against known default HMAC secrets (such as HugeGraph's published default). A valid HMAC under a default secret fires at severity 95.
- **Apache Shiro default rememberMe key:** encrypted `rememberMe` cookies are decrypted under Shiro's default AES key; if decryption yields a Java object-stream magic header, the detector fires (verified in the CVE-2016-4437 Java 8 acceptance run).

### Base64 AVX-512 tail-underflow guard (CVE-2026-114938)

[`Base64HookModule`](../java-agent/agent-jdk25/src/main/java/io/ohmyrasp/agent/asm/Base64HookModule.java) (and `Java{8,11,17}Base64Transformer` across the backport agents) instruments `java.util.Base64$Decoder.decode0([BII[B)I` across JDK 8, 11, 17, 21, and 25. Before the native x86-64 AVX-512 stub can underflow the tail buffer and write past the destination array, `DetectorEngine.isBase64TailUnderflowCandidate` performs a zero-allocation check for non-MIME inputs of length `>= 65` with `1 <= (length & 63) <= 3`, `1 <= padding <= 2` (`padding <= remainder`), and valid Base64 alphabet bytes (`+`/`/` for standard, `-`/`_` for URL-safe). Matching inputs are blocked (even outside an HTTP request context) and logged using length, padding, remainder, and alphabet metadata only; raw input bytes are never recorded.

### SSRF heuristics

`detectUrl` and `detectXmlAttachmentReference` check:

- **Cloud metadata endpoints:** `169.254.169.254`, `/latest/meta-data`
- **Dangerous protocols:** `ldap`, `rmi`, `file`, `jar`, `dict`, `gopher`, `sftp`, `tftp`
- **Internal RFC-1918 address space:** `10.x`, `172.16-31.x`, `192.168.x`
- **Known DNS callback domains:** `ceye.io`, `dnslog.cn`, `burpcollaborator.net`, and other well-known out-of-band callback domains (see the DNS patterns in `DetectorEngine`)
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

`detectJndi` is scheme-aware across all four tracks: it fires only when the lookup name resolves through a remote naming provider (`ldap`, `ldaps`, `rmi`, `iiop`, `corbaname`, `corbaloc`) and ignores local `java:` JNDI names (`java:comp/env/jdbc/AppDataSource`, `java:global/...`) and bare relative names.

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

- [`java-agent/docs/DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md): generated hook families, detector capabilities, verified algorithm signatures, and acceptance matrix
- [`java-agent/docs/FALSE-POSITIVE-REPORT.md`](../java-agent/docs/FALSE-POSITIVE-REPORT.md): generated per-category false-positive report from `FpReport.java`
- [`docs/development/algorithm-coverage.md`](development/algorithm-coverage.md): algorithm-level narrative and per-scenario notes
- [`docs/development/vulhub-coverage.md`](development/vulhub-coverage.md): Vulhub CVE tracking checklist with boundary classifications
- [`deploy/shirudo/README.md`](../deploy/shirudo/README.md): standalone Shirudo Java upatch packaging and security boundary
