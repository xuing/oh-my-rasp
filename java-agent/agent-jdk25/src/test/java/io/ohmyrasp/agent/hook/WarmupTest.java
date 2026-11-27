package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import io.ohmyrasp.agent.policy.AgentPolicy;
import io.ohmyrasp.agent.runtime.AgentRuntime;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The start-up warm-up runs the entries the transformers inject on harmless input and leaves no trace: no event, no
 * telemetry, no error report, no stderr line, no file, no request state on the starting thread; and it does the same
 * with detection off and under a managed policy.
 */
final class WarmupTest {
  @AfterEach
  void reset() throws Exception {
    OhMyRaspHooks.reportTo(null);
    OhMyRaspHooks.installPolicy(AgentPolicy.absent(), "");
    System.clearProperty("ohmyrasp.block");
    System.clearProperty("ohmyrasp.debug");
    restoreStartUpSettings();
  }

  @Test
  void theWarmUpRunsEveryStepAndWritesNoEventAndLeavesNoFileEvenWhenBlocking(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = logger(log);
    OhMyRaspHooks.reportTo(logger);
    // Blocking on, so a detection on any warm-up input would be written and thrown, not only logged.
    System.setProperty("ohmyrasp.block", "true");
    System.setProperty("ohmyrasp.debug", "true");

    // The control: the same logger and the same setting do write an event for a real detection, so an empty
    // log after the warm-up means the warm-up detected nothing and not that nothing could be written. It is made
    // outside a request, where a metadata destination alone is an operation-only finding: logged, not blocked.
    URL metadata = new URL("http://169.254.169.254/latest/meta-data/");
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeUrlOpen(metadata));
    assertTrue(Files.size(log) > 0, "the control detection was not written");
    Files.delete(log);

    String stderr = stderrOf(() -> assertEquals(Warmup.STEPS, Warmup.run(), "a warm-up step failed"));

    assertEquals("", stderr, "the warm-up printed to stderr");
    assertFalse(Files.exists(log), "the warm-up wrote to the event log");
    try (Stream<Path> files = Files.list(dir)) {
      assertEquals(List.of(), files.toList(), "the warm-up left a file behind");
    }
    assertFalse(OhMyRaspHooks.currentRequest().active(), "the warm-up left a request open on this thread");
    assertSame(logger, OhMyRaspHooks.reportingTo(), "the warm-up did not give the hooks their logger back");
  }

  @Test
  void withDetectionOffTheWarmUpDoesNothingAndSucceeds(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));
    apply("{\"mode\":\"off\"}");

    assertEquals(Warmup.STEPS, Warmup.run());

    assertFalse(Files.exists(log), "the warm-up wrote to the event log with detection off");
  }

  @Test
  void underAManagedPolicyTheWarmUpWritesNothing(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));
    apply("{\"mode\":\"block\"}");
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("""
        {"rules":[{"algorithm":"xss_userinput","action":"block"},{"algorithm":"request_scanner","action":"block"},
                  {"algorithm":"sql_userinput","action":"block"},{"algorithm":"sql_identifier_injection","action":"block"}]}
        """), "agent-one");

    assertEquals(Warmup.STEPS, Warmup.run());

    assertFalse(Files.exists(log), "the warm-up wrote to the event log under a policy");
  }

  @Test
  void theWarmUpRunsTwiceWithTheSameResult() {
    assertEquals(Warmup.STEPS, Warmup.run());
    assertEquals(Warmup.STEPS, Warmup.run());
  }

  /** The warm-up acts with the hooks off, as a start runs it before it commits, and leaves them off. */
  @Test
  void theWarmUpActsBeforeTheStartCommitsAndLeavesTheHooksOff() {
    HookActivation.deactivate();
    try {
      assertEquals(Warmup.STEPS, Warmup.run());
      assertTrue(HookActivation.inactive(), "the warm-up turned the hooks on");
    } finally {
      HookActivation.activate();
    }
  }

  private static JsonEventLogger logger(Path log) {
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    return JsonEventLogger.newForTesting(null, log.toString(), 0, true, console, console);
  }

  private static String stderrOf(Runnable body) {
    PrintStream original = System.err;
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
    try {
      body.run();
    } finally {
      System.setErr(original);
    }
    return captured.toString(StandardCharsets.UTF_8);
  }

  private static void apply(String control) throws Exception {
    Method apply = AgentRuntime.class.getDeclaredMethod("apply", String.class);
    apply.setAccessible(true);
    assertTrue((Boolean) apply.invoke(AgentRuntime.get(), control));
  }

  private static void restoreStartUpSettings() throws Exception {
    Method restore = AgentRuntime.class.getDeclaredMethod("restoreStartUpSettings");
    restore.setAccessible(true);
    restore.invoke(AgentRuntime.get());
  }
}
