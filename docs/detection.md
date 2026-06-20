# Detection Engineering

OhMyRASP is a Java RASP (Runtime Application Self-Protection) agent that
intercepts dangerous JDK operations inside the running JVM rather than
inspecting traffic at a network boundary. This document explains how the
detection pipeline is designed, what techniques it uses, what it has been
validated against, and where its current limits are.

---

## Detection pipeline

Every detection decision passes through the same five-stage pipeline:

```
ASM hook at sink
  └─ ThreadLocal RequestContext taint correlation
       └─ StackWalker call-stack analysis
            └─ algorithm classification
                 └─ policy decision (off / monitor / block)
                      └─ async NDJSON spool → Rust daemon → Go control plane
```

**Stage 1 — ASM hook at sink.** `OhMyRaspTransformer` and `HookRegistry`
rewrite JVM bytecode at class-load time to insert advice immediately before
dangerous JDK call sites: `ProcessBuilder.start`, `Runtime.exec`,
`InitialContext.lookup`, `ObjectInputStream.resolveClass`,
`FileInputStream`/`FileOutputStream`, `DriverManager.getConnection`,
`ZipEntry.getName`, `ScriptEngine.eval`, and 23 more families (27 hook
families total). The application source code is never touched.

**Stage 2 — RequestContext taint correlation.** A `ThreadLocal<RequestContext>`
is populated at every HTTP request entry, covering both the `javax.servlet`
and `jakarta.servlet` API namespaces. At sink invocation, detectors call
`request.hasParameterIn(value)` to check whether the suspect value derives
from a user-controlled request parameter before raising a taint-positive
finding. SQL injection and OS command injection require confirmed taint before
escalating to severity 95.

**Stage 3 — StackWalker call-stack analysis.** `OhMyRaspHooks` captures a
live `StackWalker` trace (`RETAIN_CLASS_REFERENCE`, `SHOW_REFLECT_FRAMES`) at
sink invocation. `detectCommand` inspects the trace for expression-engine
frames (OGNL, MVEL, SpEL, Groovy, JEXL, Nashorn, Velocity, Jiffle, XStream),
executable-listener frames (Solr `RunExecutableListener`),
config-launcher frames, and reflective stacks. The presence of these frames
changes both the algorithm label and the confidence score. The same
`ProcessBuilder.start` call is therefore classified differently depending on
whether it originates from Struts2/OGNL, a Spring bean-init chain, an XStream
unmarshaller, or normal application code.

**Stage 4 — Algorithm classification and policy decision.** The detector
returns a named algorithm signature (e.g. `java8_jndi_remote_lookup`,
`java17_request_path_confusion`) with a severity score and a recommended
action. The active policy — `off`, `monitor`, or `block` — is read from a
polled JSON control file updated by the Rust daemon. Mode changes reach the
agent without a JVM restart.

**Stage 5 — Async NDJSON spool reporting.** Accepted findings are written
asynchronously to a local NDJSON spool file. The Rust host daemon tails the
spool and forwards events to the Go control plane. The agent never opens
outbound network connections at detection time, so detection latency is
independent of network reachability.

---

## Coverage numbers

These counts are generated from the agent source and acceptance suite by
`scripts/gen-detection-coverage.py` and checked by CI.

| Metric | Count |
|--------|------:|
| Hook families (ASM instrumentation points) | 27 |
| Detector capabilities (engine entry points) | 52 |
| Verified algorithm signatures (asserted by tests) | 43 |
| End-to-end vulnerability acceptance scenarios | 136 |
| JDK lines exercised in acceptance matrix | 6 |
| Vulhub component roots in scope | 53 |
| Unique Vulhub CVE tokens tracked | 130 |

A "verified algorithm signature" means an end-to-end acceptance test
launched a real vulnerable application inside a Docker container under the
agent, sent a real exploit payload, and asserted the named algorithm was
detected and blocked. Signatures that are implemented but not yet covered by
acceptance tests are not counted here.

Acceptance scenario distribution by JDK line:

| JDK line | Scenarios | Notes |
|----------|----------:|-------|
| Java 8 | 96 | Primary coverage baseline; most Vulhub images |
| Java 17 | 12 | Tomcat 11, 10.1, 9; GeoServer, Struts2 upload |
| Java 11 | 10 | Tomcat 10.1, 9; ActiveMQ, HertzBeat |
| Java 21 | 3 | DataEase CVEs; agent-java17 binary on OpenJDK 21 JVM |
| Java 7 legacy | 9 | Boundary scenarios only — agent injection not possible |
| Java 6 legacy | 5 | Boundary scenarios only — agent injection not possible |

---

## Detection techniques

### Taint correlation

Request parameter values are tracked from HTTP entry through the
`ThreadLocal<RequestContext>`. A detection is taint-positive only when the
value at the dangerous sink contains a substring drawn from a request
parameter. This is why `sql_userinput` and `command_userinput` carry the
highest severity: they prove that untrusted input reached a dangerous
operation, not merely that a dangerous operation occurred.

Applications that call `ProcessBuilder` with purely internal arguments (e.g.
a scheduled task with no user-controlled components) do not trip the
taint-correlated path. The stack-analysis layer may still fire a lower-severity
structural alert if an expression-engine frame is present.

### Call-stack structural analysis

Expression-engine and RCE-gadget-chain stacks have a recognizable structure
that appears in every framework-level exploit. `detectCommand` identifies:

- **Expression engines**: OGNL (Struts2), MVEL (Druid, OFBiz), SpEL (Spring),
  Groovy, JEXL, Nashorn, Velocity, Jiffle (GeoServer), XStream
- **Executable listeners**: Solr `RunExecutableListener`
- **Config launchers**: Spring `ProcessBuilderFactoryBean` patterns
- **Deep reflective stacks**: gadget-chain indicators from deserialization

This means a novel Struts2 bypass that still passes through OGNL evaluation
is caught at the process sink without requiring an OGNL-specific request
pattern. The same applies to Spring SpEL injections arriving through any
entry point that eventually invokes a JDK process or file sink.

### SQL syntax-aware detection

`detectSql` combines taint correlation with structural SQL pattern analysis.
It does not rely on a single regex. The patterns are partitioned by intent:

- **`SQLI_USER_INPUT`** — classic injection structures: OR/AND tautologies,
  `UNION SELECT`, comment prefixes (`--`, `#`, `/*`)
- **`SQL_POLICY`** — schema enumeration (`information_schema`), file-export
  keywords (`INTO OUTFILE`, `LOAD_FILE`)
- **H2 code execution** — `CREATE ALIAS`, `CREATE TRIGGER` with `AS $$`
  Java inline blocks; catches CVE-2022-23221 and variants
- **Derby code execution** — `SQLJ.INSTALL_JAR`,
  `LANGUAGE JAVA EXTERNAL NAME` procedure patterns
- **`detectSqlRegex`** — GeoServer OGC filter CQL injection; GIS-specific
  constructs (`strConcat`, Jiffle script fragments)

False-positive rate on the 10-query benign SQL corpus: **0/10** (see
false-positive methodology below).

### Deserialization defenses

Multiple layers address the Java deserialization attack surface:

- **`detectDeserialization`** hooks `ObjectInputStream.resolveClass` and
  matches class names against a known-dangerous gadget blocklist (Commons
  Collections, BeanShell, Groovy, etc.) via `DeserializationGuard`.
- **`detectPolymorphicType`** covers polymorphic-type deserialization:
  `@type`, `javaClass`, and `class` JSON keys (Fastjson, Jackson);
  YAML `!!` tags.
- **`detectHessianType`** covers Hessian type-loading gadget chains.
- **`detectHttpInvokerDeserialization`** and
  **`detectHttpObjectStreamDeserialization`** cover Spring HTTP Invoker.
- **`detectProtocolClassInstantiation`** covers ActiveMQ OpenWire
  class-instantiation (CVE-2023-46604).
- **`detectRmiRegistryBind`** covers RMI Registry gadget delivery.
- **`detectSessionDeserialization`** covers serialized session-file
  deserialization paths.

Fastjson CVE-2017-18349 and the 1.2.47 `@type` bypass, XStream
CVE-2021-21351 and CVE-2021-29505, and WebLogic XMLDecoder CVE-2017-10271
all have verified Java 8 acceptance runs.

### Multi-form path-confusion decoding

`request_path_confusion` decodes every incoming URI in six forms
simultaneously:

1. Raw (as received)
2. URL-decoded (one pass)
3. Double-decoded (two passes)
4. Low-byte Unicode normalization
5. Overlong UTF-8 decoding (e.g., `%c0%ae` → `.`)
6. Lenient percent-decode

All six representations are compared. A mismatch that changes path semantics
(e.g., a traversal sequence appearing only in one decoded form) fires the
detector. This single generic detector catches:

- Shiro semicolon traversal (CVE-2010-3863, CVE-2020-1957)
- Nexus repeated encoded-slash
- GlassFish overlong UTF-8 (CVE-2010-1000028)
- Openfire `%u002e%u002e` encoding (CVE-2023-32315)
- Spring high-Unicode ghost-bit collapse
- Flink double-percent encoding
- Jetty ConcatServlet `%2e/WEB-INF` traversal

No product-specific path signatures are required.

### Cryptographic default-secret verification

These detectors perform actual cryptographic operations rather than
pattern-matching on token shapes:

- **JWT default HMAC secrets.** `detectJwtVerificationFailure` inspects JWT
  Bearer tokens against a table of known default HMAC secrets (e.g.,
  HugeGraph's published default). The token HMAC is verified under each
  candidate key. A valid HMAC fires at severity 95. This catches active
  exploitation of default-key deployments, not just the presence of a JWT.
- **Apache Shiro default rememberMe key.** The encrypted cookie is decrypted
  under the Shiro default AES key; if decryption yields a Java
  object-stream magic header, the detector fires. CVE-2016-4437 has a
  verified Java 8 acceptance run.

### SSRF heuristics

`detectUrl` and `detectXmlAttachmentReference` combine multiple heuristics:

- **Cloud metadata endpoints**: `169.254.169.254`, `/latest/meta-data`
- **Dangerous protocols**: `ldap`, `rmi`, `file`, `jar`, `dict`, `gopher`,
  `sftp`, `tftp`
- **Internal RFC-1918 address space**: 10.x, 172.16–31.x, 192.168.x
- **Known DNS callback domains**: `ceye.io`, `dnslog.cn`,
  `burpcollaborator.net`, and 12 others
- **IP obfuscation forms**: decimal (`2130706433`), hex (`0x7f000001`),
  octal (`0177.0.0.1`) encodings of loopback and RFC-1918 addresses

### Response-side data-leak detection

`detectResponseDataLeak` inspects outbound response bodies (HTML, JSON, XML)
for:

- **Chinese national ID cards** — 18-digit format with checksum verification
- **Mobile phone numbers** — validated against Chinese carrier prefix tables
- **Payment card numbers** — Luhn-validated; card brand not distinguished

`detectXssEcho` confirms whether an XSS-like input payload is reflected
verbatim in the response body, converting a one-sided injection alert into
a confirmed reflection finding.

Note: PII detection is oriented toward Chinese formats. International PII
formats (US SSN, EU national identifiers) are not currently in scope.

### Payload redaction before logging

Before writing events to the NDJSON spool, detectors call `redact*Request`
helpers. Expression payloads in file-upload filenames are recorded as
`length=N engine=X` only, never echoed. Serialized client-state headers,
expression-injection headers, and credential fields are stripped or
truncated. Sensitive input never reaches log storage in plaintext.

---

## Validated against real exploits

### JDK and Tomcat compatibility matrix

Each JDK era has a dedicated agent fat-jar with ASM dependencies relocated
to avoid colliding with application-bundled ASM (Struts2 ships ASM 3.3;
OhMyRASP ships a current version). The servlet hook instruments both
`javax.servlet` and `jakarta.servlet` namespaces, so one binary covers
Tomcat 9 through 11 without recompilation.

| Agent artifact | Target JDK | Tomcat versions | Acceptance scenarios |
|----------------|-----------|-----------------|---------------------:|
| `agent-jdk25` (primary) | Java 25 | Tomcat 11, 10, 9 | (JDK 25 build) |
| `agent-java17` | Java 17 | Tomcat 11, 10.1, 9 | 12 |
| `agent-java11` | Java 11 | Tomcat 10.1, 9 | 10 |
| `agent-java8` | Java 8 | Tomcat 10.0, 9, 8.5 | 96 |

`agent-java17` has also been verified on an OpenJDK 21 JVM (3 DataEase
acceptance scenarios). Java 25 is the primary development target and is not
yet an LTS release; production deployments on Java 17 LTS should use
`agent-java17`.

### Notable CVE acceptance runs

The following vulnerabilities have end-to-end acceptance tests that launch
the real Vulhub container, inject the agent, send a real exploit, and assert
detection and block. This is not an exhaustive list; it is the set of
well-known CVEs in the acceptance matrix.

| CVE / Advisory | Application | JDK tested |
|----------------|-------------|-----------|
| CVE-2021-44228 (Log4Shell) | Solr JNDI lookup | Java 8 |
| CVE-2017-18349, 1.2.47 bypass (Fastjson) | Fastjson `@type` | Java 8 |
| CVE-2016-4437 (Shiro default key) | Apache Shiro | Java 8 |
| CVE-2010-3863, CVE-2020-1957 (Shiro auth bypass) | Apache Shiro | Java 8 |
| S2-001 through S2-067 (19 Struts2 scenarios) | Apache Struts2 | Java 8 / 17 |
| CVE-2022-22965 (Spring4Shell) | Spring MVC / Tomcat | Java 8 |
| CVE-2022-22947 (Spring Cloud Gateway) | Spring Gateway SpEL | Java 8 |
| CVE-2020-1938 (Ghostcat) | Tomcat AJP | Java 8 |
| CVE-2023-46604 (ActiveMQ OpenWire) | Apache ActiveMQ | Java 11 |
| CVE-2021-21351, CVE-2021-29505 (XStream) | XStream gadget | Java 8 |
| CVE-2020-14882/14883, CVE-2017-10271 (WebLogic) | Oracle WebLogic | Java 8 |
| CVE-2022-24816, CVE-2023-25157, CVE-2024-36401 (GeoServer) | GeoServer | Java 17 |
| CVE-2024-56511, CVE-2025-32966, CVE-2025-49001 (DataEase) | DataEase | Java 21 |
| CVE-2019-3396, CVE-2021-26084, CVE-2022-26134, | Confluence | boundary |
| CVE-2023-22515, CVE-2023-22527 | | script |

Top application families by scenario count: Struts2 (19), Spring (10),
WebLogic (7), OFBiz (6), ActiveMQ (5), Elasticsearch (5), Solr (5).

---

## False-positive methodology

A curated corpus of 51 benign-but-realistic inputs across 9 detector
categories is run against the live `DetectorEngine` with a realistic
`RequestContext` (user-supplied values placed in request parameters). The
report is generated by `scripts/fp-harness/FpReport.java` against the real
engine, not a mock.

| Category | Benign inputs | False positives | FP rate |
|----------|---:|---:|---:|
| SQL queries | 10 | 0 | 0.0% |
| OS commands | 8 | 0 | 0.0% |
| Outbound URLs | 6 | 0 | 0.0% |
| File reads | 5 | 0 | 0.0% |
| File writes | 4 | 0 | 0.0% |
| Deserialization classes | 6 | 0 | 0.0% |
| Expressions | 5 | 0 | 0.0% |
| JNDI names | 3 | 0 | 0.0% |
| DNS lookups | 4 | 0 | 0.0% |
| **Overall** | **51** | **0** | **0.0%** |

The corpus is clean. The previous JNDI precision gap — legitimate Java EE
names (`java:comp/env/jdbc/AppDataSource`,
`java:comp/env/jms/QueueConnectionFactory`, `java:global/AppEjb/UserService`)
tripping `jndi_disable_all` — was closed by making `detectJndi` scheme-aware:
the detector now fires only when the lookup name resolves through a *remote*
naming provider (`ldap`, `ldaps`, `rmi`, `iiop`, `corbaname`, `corbaloc`) — the
JNDI-injection vector — and ignores the local `java:` namespace and bare
relative names. This matches the scheme set the `agent-java8/11/17` backports
already enforced, restoring cross-agent parity.

**Framing.** This is a detector-precision measurement on 51 hand-curated
benign strings. It is not a production false-positive rate measurement.
Production traffic contains context that the corpus cannot reproduce: unusual
framework middleware, custom parameter encoding, ORM-generated SQL. The
corpus is useful for regression testing detector changes, not for quoting a
deployment-level FP rate.

---

## Known limitations

The following limitations are stated plainly because they affect deployment
decisions.

**Java 25 primary agent requires a Java 25 toolchain to build.** The primary
`agent-jdk25` artifact compiles with `JavaLanguageVersion.of(25)` and a
GraalVM/Temurin 25 toolchain. Java 25 is not yet an LTS release. Operators
running Java 17 LTS production environments must use the `agent-java17`
artifact, which has 12 verified acceptance scenarios.

**Java 6 and 7 environments cannot be protected by the agent.** The agent
classfile (Java 8, major version 52) is rejected by Java 6 and 7 JVMs. The
14 legacy-boundary scenarios in the acceptance matrix document real Vulhub
exploits running against those runtimes but do not demonstrate agent-side
blocking. They are recorded as "legacy runtime boundary" to be honest about
the baseline.

**Confluence acceptance coverage is a boundary script, not a full injection
run.** Confluence requires an interactive license-setup step that prevents
automated container starts. The acceptance script probes expected payloads
against the setup boundary; it does not complete a full agent-injection and
block cycle.

**The false-positive corpus is 51 curated inputs, not production traffic.**
The overall FP rate on this corpus is 0.0%, but a clean curated corpus should
not be extrapolated to a production deployment rate.

**Acceptance breadth is bounded by the 53 Vulhub roots in scope.** 136
scenarios against real Docker containers is strong coverage for the
frameworks tested, but enterprise middleware not represented in Vulhub may
have unexercised attack surfaces.

**Response data-leak detection covers Chinese PII formats only.** National
ID card (format + checksum), mobile number (carrier prefix tables), and
payment card (Luhn) are detected. US SSN, EU national identifiers, and other
regional formats are not in scope.

---

## Coverage ledgers

Detailed tables of hooks, detectors, algorithm signatures, and acceptance
scenarios are maintained as generated artifacts and checked by CI:

- [`java-agent/docs/DETECTION-COVERAGE.md`](../java-agent/docs/DETECTION-COVERAGE.md)
  — hook families, detector capabilities, verified algorithm signatures,
  acceptance matrix
- [`java-agent/docs/FALSE-POSITIVE-REPORT.md`](../java-agent/docs/FALSE-POSITIVE-REPORT.md)
  — per-category false-positive measurements regenerated by
  `scripts/fp-harness/FpReport.java`
- [`docs/development/algorithm-coverage.md`](development/algorithm-coverage.md)
  — algorithm-level narrative and per-scenario notes
- [`docs/development/vulhub-coverage.md`](development/vulhub-coverage.md)
  — Vulhub CVE tracking checklist with boundary classifications
