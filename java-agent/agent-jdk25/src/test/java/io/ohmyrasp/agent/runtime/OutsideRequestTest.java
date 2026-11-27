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
 * blocks wherever it runs; outside a request an intrinsic finding blocks whatever {@code outside_request} says, an
 * operation-only finding logs whatever it says, and a context-dependent one follows it (block by default).
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
   * A cloud SDK reads instance metadata at start-up, a job fetches an ftp: URL: outside a request these log whatever
   * the setting says; inside one they block.
   */
  @Test
  void anOperationOnlyFindingLogsOutsideARequestAndBlocksInsideOne() throws Exception {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\"}"));

    assertDoesNotThrow(() -> OhMyRaspHooks.beforeUrlOpen(URI.create("ftp://127.0.0.1:1/report.csv").toURL()));
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeUrlOpen(URI.create(METADATA).toURL()));
    OhMyRaspHooks.enterHttpRequest(new ReportRequest(), new Object());
    try {
      assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeUrlOpen(URI.create(METADATA).toURL()));
    } finally {
      OhMyRaspHooks.exitHttpRequest();
    }
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
