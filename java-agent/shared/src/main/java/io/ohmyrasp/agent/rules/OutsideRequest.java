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
 * <p><b>Outside a request</b> a finding falls in one of these classes, by what shows the attack ({@link #scope}):
 *
 * <ul>
 *   <li>{@link #INTRINSIC}: the argument is the exploit itself (a listed gadget class in a stream, a JNDI name with a
 *       remote URL, the Base64 tail-underflow shape, shell syntax of an exploit primitive, an expression language
 *       reaching the process API, a product exploit chain).
 *       It blocks in block mode whatever {@code outside_request} says.
 *   <li>{@link #CONTEXT}: a sensitive operation whose meaning depends on who asked (a protected host file read, a
 *       script written into a web root, a class or Spring configuration loaded from a remote URL, a remote DTD or
 *       entity, a connection to the cloud metadata address). It follows {@code outside_request}: block by default,
 *       {@code log} when the operator says so.
 *   <li>{@link #REQUEST_ONLY}: blocks only with request evidence and logs outside a request whatever the setting says.
 *       Two kinds: the primary's {@code ssrf_protocol}, {@code ssrf_obfuscate} and {@code ssrf_userinput}, rules
 *       defined against a request that the backports do not have and that only logged outside one before this
 *       setting existed ({@code ssrf_obfuscate} reports any URL {@code java.net.URI} cannot parse, a JAR path with a
 *       space included); and a connection to the cloud metadata address made by a cloud provider's own credential or
 *       metadata client ({@link #scopeHere}).
 * </ul>
 *
 * <p><b>Trust boundary of the cloud client allowance.</b> The client is recognised by a frame of a listed class on
 * the thread's stack, by name. An application that ships a class with one of those names can make its own metadata
 * access outside a request log instead of block; telling the SDK's class from an impostor's is not cheap on a hook's
 * path. It cannot do so for a finding with request evidence: that blocks whatever the stack holds.
 *
 * <p>The setting is the control document's top-level {@value #CONTROL_KEY} member (the host's), the policy's
 * {@code config.hardening.outside_request} (the cloud's), and at start-up the system property {@value #PROPERTY}, the
 * environment variable {@value #ENVIRONMENT} or the baked {@value #CONTROL_KEY} of
 * {@code META-INF/ohmyrasp-shirudo.properties}, resolved like {@code mode}; the primary line (Java 21 and 25) also reads
 * the agent argument {@value #CONTROL_KEY} first, the backport lines read no agent argument.
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
  /** Blocks only with request evidence: logs outside a request whatever {@code outside_request} says. */
  public static final int REQUEST_ONLY = 2;

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

  /**
   * Primary rule ids whose every finding is request-only: defined against a request, with no backport counterpart,
   * and logged outside a request before {@code outside_request} existed.
   */
  private static final String[] REQUEST_ONLY_RULES = {
    // A protocol (ftp:, ldap:, gopher:...) or a URL java.net.URI cannot parse (a file or JAR location with a space,
    // which class loading opens at start-up).
    "ssrf_protocol",
    "ssrf_obfuscate",
    // Request input selecting an internal destination; outside a request only a redirect or a managed policy's
    // destination-only candidate reaches it.
    "ssrf_userinput",
  };

  /** Rule ids and families whose finding is a connection to the cloud metadata address. */
  private static final String[] CLOUD_METADATA_RULES = {"ssrf_aws", "ssrf_cloud_metadata"};

  /**
   * Classes of cloud providers' own credential and metadata clients, each checked in a released SDK JAR from Maven
   * Central: AWS SDK for Java 1.x ({@code aws-java-sdk-core} 1.12.797), AWS SDK for Java 2.x ({@code auth},
   * {@code regions}, {@code imds} 2.59.10), Google ({@code google-auth-library-oauth2-http} 1.58.0,
   * {@code google-cloud-core} 2.81.0), Azure ({@code azure-identity} 1.19.0, {@code msal4j} 1.23.1), Alibaba Cloud
   * ({@code credentials-java} 1.0.8, {@code aliyun-java-sdk-core} 4.7.10), Tencent Cloud
   * ({@code tencentcloud-sdk-java-common} 3.2.65) and Huawei Cloud ({@code huaweicloud-sdk-core} 3.1.225). A frame
   * of one of them, or of a class nested in one, counts.
   */
  private static final String[] CLOUD_METADATA_CLIENTS = {
    "com.amazonaws.auth.InstanceProfileCredentialsProvider",
    "com.amazonaws.auth.InstanceMetadataServiceCredentialsFetcher",
    "com.amazonaws.auth.ContainerCredentialsProvider",
    "com.amazonaws.auth.ContainerCredentialsFetcher",
    "com.amazonaws.internal.EC2ResourceFetcher",
    "com.amazonaws.internal.InstanceMetadataServiceResourceFetcher",
    "com.amazonaws.internal.EC2MetadataClient",
    "com.amazonaws.util.EC2MetadataUtils",
    "com.amazonaws.regions.InstanceMetadataRegionProvider",
    "software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider",
    "software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider",
    "software.amazon.awssdk.regions.internal.util.EC2MetadataUtils",
    "software.amazon.awssdk.regions.providers.InstanceProfileRegionProvider",
    "com.google.auth.oauth2.ComputeEngineCredentials",
    "com.google.cloud.MetadataConfig",
    "com.azure.identity.ManagedIdentityCredential",
    "com.azure.identity.ManagedIdentityMsalCredential",
    "com.azure.identity.VirtualMachineMsiCredential",
    "com.azure.identity.implementation.IdentityClient",
    "com.azure.identity.implementation.IdentitySyncClient",
    "com.microsoft.aad.msal4j.IMDSManagedIdentitySource",
    "com.microsoft.aad.msal4j.ManagedIdentityClient",
    "com.aliyun.credentials.provider.EcsRamRoleCredentialProvider",
    "com.aliyun.credentials.provider.ECSMetadataServiceCredentialsFetcher",
    "com.aliyuncs.auth.InstanceProfileCredentialsProvider",
    "com.aliyuncs.auth.ECSMetadataServiceCredentialsFetcher",
    "com.tencentcloudapi.common.provider.CvmRoleCredential",
    "com.huaweicloud.sdk.core.auth.MetadataAccessor",
    "com.huaweicloud.sdk.core.auth.MetadataCredentialProvider",
    "com.huaweicloud.sdk.core.auth.MetadataBasicCredentialProvider",
    "com.huaweicloud.sdk.core.auth.MetadataGlobalCredentialProvider",
  };

  /** Packages whose every class is a cloud metadata client: the AWS SDK 2.x instance metadata client. */
  private static final String[] CLOUD_METADATA_CLIENT_PACKAGES = {"software.amazon.awssdk.imds."};

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
    // A process started under an expression language (OGNL, SpEL, MVEL, JEXL, EL, a template engine, XPath, Jiffle):
    // expression injection reaching the process API. It often runs where no servlet request is tracked (a Struts
    // filter, WebFlux, Netty), so it blocks there too. A general-purpose script engine (Groovy, JavaScript,
    // javax.script: script_evaluation), a database Java routine (database_stack) and an XXL-JOB executor's shell job
    // (scheduled_script) start processes on purpose as well: those follow the setting.
    {"expression_evaluation", Integer.valueOf(INTRINSIC)},
    // A managed policy's destination-only egress candidate.
    {"destination_only", Integer.valueOf(REQUEST_ONLY)},
  };

  private OutsideRequest() {}

  /**
   * The class of a finding of {@code rule} (a primary rule id, or a backport family without the line prefix) made on
   * {@code basis} (its {@code decision_basis}, or null): {@link #CONTEXT}, {@link #INTRINSIC} or {@link #REQUEST_ONLY}.
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
    if (contains(REQUEST_ONLY_RULES, rule)) {
      return REQUEST_ONLY;
    }
    return CONTEXT;
  }

  /**
   * {@link #scope} of a finding made on this thread: a connection to the cloud metadata address with no request
   * evidence, made by a cloud provider's own credential or metadata client ({@link #cloudMetadataClient} of this
   * thread's stack), is {@link #REQUEST_ONLY}. The stack is read only for such a finding.
   */
  public static int scopeHere(String rule, String basis, boolean requestEvidence) {
    int scope = scope(rule, basis);
    if (scope == CONTEXT && !requestEvidence && contains(CLOUD_METADATA_RULES, rule)
        && cloudMetadataClient(Thread.currentThread().getStackTrace()) != null) {
      return REQUEST_ONLY;
    }
    return scope;
  }

  /** The first frame's class on {@code stack} that is a listed cloud metadata client, or null. */
  public static String cloudMetadataClient(StackTraceElement[] stack) {
    if (stack == null) {
      return null;
    }
    for (int i = 0; i < stack.length; i++) {
      String name = stack[i] == null ? null : stack[i].getClassName();
      if (name == null) {
        continue;
      }
      for (int j = 0; j < CLOUD_METADATA_CLIENTS.length; j++) {
        String client = CLOUD_METADATA_CLIENTS[j];
        if (name.startsWith(client)
            && (name.length() == client.length() || name.charAt(client.length()) == '$')) {
          return client;
        }
      }
      for (int j = 0; j < CLOUD_METADATA_CLIENT_PACKAGES.length; j++) {
        if (name.startsWith(CLOUD_METADATA_CLIENT_PACKAGES[j])) {
          return name;
        }
      }
    }
    return null;
  }

  /**
   * Whether a finding of class {@code scope} may block: always with request evidence; outside a request, an intrinsic
   * finding always, a request-only finding never, a context-dependent one when {@code outsideRequestBlocks}.
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
