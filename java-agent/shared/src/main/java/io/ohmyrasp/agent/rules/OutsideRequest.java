package io.ohmyrasp.agent.rules;

import java.util.Locale;

/**
 * Whether a finding blocks when nothing ties it to an HTTP request, the same on every agent line.
 *
 * <p><b>Inside a request.</b> A finding is inside a request when it carries request evidence: the thread serves an
 * HTTP request, or the hook carries the request that started the operation onto the thread doing it (an HTTP client
 * exchange submitted during a request, a directory walk a request selected, an XML attachment read for a request),
 * or the hook holds the HTTP request itself (the Spark and YARN submission checks, the DataEase filter). Both engines
 * decide with that one definition: a finding with request evidence blocks in block mode wherever it runs.
 *
 * <p><b>Outside a request</b> a finding falls in one of three classes, by what shows the attack ({@link #scope}):
 *
 * <ul>
 *   <li>{@link #INTRINSIC}: the argument is the exploit itself (a listed gadget class in a stream, a JNDI name with a
 *       remote URL, the Base64 tail-underflow shape, shell syntax of an exploit primitive, a product exploit chain).
 *       It blocks in block mode whatever {@code outside_request} says.
 *   <li>{@link #OPERATION}: the only evidence is that an operation of some kind happened (a destination such as the
 *       cloud metadata address, a protocol, a configured remote resource, an evaluator on the stack). Software does
 *       these on purpose at start-up and in scheduled jobs, so it logs outside a request whatever the setting says.
 *   <li>{@link #CONTEXT}: a sensitive operation whose meaning depends on who asked (a protected host file read, a
 *       script written into a web root, a compiled source that runs a process). It follows {@code outside_request}:
 *       block by default, {@code log} when the operator says so.
 * </ul>
 *
 * <p>The setting is the control document's top-level {@value #CONTROL_KEY} member (the host's), the policy's
 * {@code config.hardening.outside_request} (the cloud's), or for a standalone agent the agent argument
 * {@value #CONTROL_KEY}, the system property {@value #PROPERTY}, the environment variable {@value #ENVIRONMENT} or
 * the baked {@value #CONTROL_KEY} of {@code META-INF/ohmyrasp-shirudo.properties}, resolved like {@code mode}.
 * docs/detection.md has the table of every family this classifies, with the reason for each.
 *
 * <p>Java 8 source with no lambdas: the backport lines read it from their hooks.
 */
public final class OutsideRequest {
  /** The member of the control document, the policy's hardening section, the agent argument and the baked property. */
  public static final String CONTROL_KEY = "outside_request";
  /** The system property. */
  public static final String PROPERTY = "ohmyrasp.outside_request";
  /** The environment variable. */
  public static final String ENVIRONMENT = "OHMYRASP_OUTSIDE_REQUEST";
  /** Without a setting a context-dependent finding outside a request blocks. */
  public static final boolean DEFAULT_BLOCKS = true;

  /** Follows {@code outside_request} outside a request. */
  public static final int CONTEXT = 0;
  /** Blocks outside a request whatever {@code outside_request} says. */
  public static final int INTRINSIC = 1;
  /** Logs outside a request whatever {@code outside_request} says. */
  public static final int OPERATION = 2;

  /**
   * Rule ids (primary) and families (backport, without the line prefix) whose every finding is intrinsic. Each is
   * an exploit primitive by its shape, or a product exploit chain the engine recognises by its own frames.
   */
  private static final String[] INTRINSIC_RULES = {
    "base64_avx512_tail_underflow",
    // A JNDI lookup whose name is a remote naming URL: the URL context resolves a remote reference and its factory.
    "jndi_disable_all",
    "jndi_jaas_config",
    "jndi_remote_lookup",
    "jaas_jndi_remote_provider",
    // Spring dispatched an initializer from HTTP-backed XML to ProcessBuilder.start.
    "command_spring_remote_init",
    // A process argument in the shape of an exploit: a reverse shell, a download piped to a shell, cat /etc/passwd.
    "command_common",
    // DataEase continued the request after rejecting its credential (the hook holds the request too).
    "request_jwt_verification_failure",
  };

  /** Rule id or family prefixes whose every finding is intrinsic: a listed type chosen by a decoder. */
  private static final String[] INTRINSIC_PREFIXES = {"deserialization_"};

  /** Rule ids and families whose every finding is operation-only. */
  private static final String[] OPERATION_RULES = {
    // A destination: the cloud metadata address. Cloud SDKs read it at start-up.
    "ssrf_aws",
    "ssrf_cloud_metadata",
    // A protocol, or a URL java.net.URI cannot parse (a file or JAR location with a space).
    "ssrf_protocol",
    "ssrf_obfuscate",
    // Outside a request this rule fires only on a managed policy's destination-only candidate.
    "ssrf_userinput",
    // A remote external entity: a scheduled import fetches the DTD it is configured to fetch.
    "xxe_protocol",
    "xxe_external_entity_protocol",
    // A class or a Spring configuration loaded from a remote location the deployment configured.
    "classloader_remote",
    "classloader_remote_codebase",
    "spring_remote_config",
  };

  /**
   * Decision bases that set the class whatever the rule: {basis, class}. The basis says what the evidence is when
   * one rule id carries several kinds of it.
   */
  private static final Object[][] BASES = {
    // An XML attachment reference (CXF XOP) that opened a host file: no MTOM document names a file.
    {"attachment_file_open", Integer.valueOf(INTRINSIC)},
    // A process started under a deserializer: the gadget chain ran.
    {"object_deserialization", Integer.valueOf(INTRINSIC)},
    {"xml_deserialization", Integer.valueOf(INTRINSIC)},
    // Spring's initializer on the backports' command family.
    {"remote_bean_init_dispatch", Integer.valueOf(INTRINSIC)},
    // Exploit-shaped process arguments on the backports' command family.
    {"command_arguments", Integer.valueOf(INTRINSIC)},
    // Shell operators in the program RocketMQ's filter-server manager launches (CVE-2023-33246).
    {"configuration_launcher", Integer.valueOf(INTRINSIC)},
    // A process started under an expression or script evaluator, or a database Java routine: the frame says who
    // started it, not what it runs. Groovy jobs, build scripts and stored routines start processes on purpose.
    {"expression_evaluation", Integer.valueOf(OPERATION)},
    {"database_stack", Integer.valueOf(OPERATION)},
    // A shell script an XXL-JOB executor runs: the job type the scheduler was configured with.
    {"scheduled_script", Integer.valueOf(OPERATION)},
    // A managed policy's destination-only egress candidate.
    {"destination_only", Integer.valueOf(OPERATION)},
  };

  private OutsideRequest() {}

  /**
   * The class of a finding of {@code rule} (a primary rule id, or a backport family without the line prefix) made on
   * {@code basis} (its {@code decision_basis}, or null): {@link #CONTEXT}, {@link #INTRINSIC} or {@link #OPERATION}.
   */
  public static int scope(String rule, String basis) {
    if (basis != null) {
      for (int i = 0; i < BASES.length; i++) {
        if (BASES[i][0].equals(basis)) {
          return ((Integer) BASES[i][1]).intValue();
        }
      }
    }
    if (rule == null) {
      return CONTEXT;
    }
    if (contains(INTRINSIC_RULES, rule)) {
      return INTRINSIC;
    }
    for (int i = 0; i < INTRINSIC_PREFIXES.length; i++) {
      if (rule.startsWith(INTRINSIC_PREFIXES[i])) {
        return INTRINSIC;
      }
    }
    if (contains(OPERATION_RULES, rule)) {
      return OPERATION;
    }
    return CONTEXT;
  }

  /**
   * Whether a finding of class {@code scope} may block: always with request evidence; outside a request, an intrinsic
   * finding always, an operation-only finding never, a context-dependent one when {@code outsideRequestBlocks}.
   */
  public static boolean mayBlock(int scope, boolean requestEvidence, boolean outsideRequestBlocks) {
    if (requestEvidence || scope == INTRINSIC) {
      return true;
    }
    return scope == CONTEXT && outsideRequestBlocks;
  }

  /** {@code rule} without a backport line prefix ({@code java8_}, {@code java11_}, {@code java17_}). */
  public static String family(String rule) {
    if (rule == null || !rule.startsWith("java")) {
      return rule;
    }
    int underscore = rule.indexOf('_');
    if (underscore < 5) {
      return rule;
    }
    for (int i = 4; i < underscore; i++) {
      char ch = rule.charAt(i);
      if (ch < '0' || ch > '9') {
        return rule;
      }
    }
    return rule.substring(underscore + 1);
  }

  /**
   * {@code TRUE} for {@code block}, {@code FALSE} for {@code log}, null for anything else. Letter case is ignored,
   * and so are characters up to U+0020 around the word, as for {@code mode}.
   */
  public static Boolean parse(String token) {
    if (token == null) {
      return null;
    }
    String value = token.trim().toLowerCase(Locale.ROOT);
    if (value.equals("block")) {
      return Boolean.TRUE;
    }
    if (value.equals("log")) {
      return Boolean.FALSE;
    }
    return null;
  }

  private static final String[] POLICY_PATH = {"config", "hardening", CONTROL_KEY};

  /**
   * Whether the cloud's policy permits blocking outside a request: false when its {@code config.hardening} sets
   * {@value #CONTROL_KEY} to {@code log}, true otherwise (absent, null, {@code block}, a value nobody accepts, a
   * policy that is not a JSON object, or no policy). Blocking outside a request needs both this and the host's
   * setting, as blocking a hardening finding needs both the top-level {@code mode} and the policy's
   * {@code hardening.mode}: withdrawing the policy withdraws its setting with it.
   */
  public static boolean policyPermitsBlocking(String policy) {
    if (policy == null) {
      return true;
    }
    try {
      Object value = io.ohmyrasp.agent.util.ControlDocument.valueAt(policy, POLICY_PATH);
      return !(value instanceof String) || !Boolean.FALSE.equals(parse((String) value));
    } catch (IllegalArgumentException malformed) {
      return true;
    }
  }

  private static boolean contains(String[] values, String value) {
    for (int i = 0; i < values.length; i++) {
      if (values[i].equals(value)) {
        return true;
      }
    }
    return false;
  }
}
