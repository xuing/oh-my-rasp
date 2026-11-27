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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
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

  /**
   * Nothing process-wide is swapped for the run: a live reporter that other threads use stays the reporter while
   * the warm-up runs, and only the warm-up's own thread reports to the logger that writes nothing.
   */
  @Test
  void aLiveReporterStaysLiveForOtherThreadsWhileTheWarmUpRuns(@TempDir Path dir) throws Exception {
    JsonEventLogger live = logger(dir.resolve("events.jsonl"));
    OhMyRaspHooks.reportTo(live);
    CountDownLatch inStep = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    AtomicReference<JsonEventLogger> onWorker = new AtomicReference<>();
    ExecutorService starter = Executors.newSingleThreadExecutor();
    try {
      Future<Integer> run = starter.submit(() -> Warmup.run(10_000, step -> {
        if (step == 0) {
          onWorker.set(OhMyRaspHooks.events());
          inStep.countDown();
          release.await();
        }
      }));
      assertTrue(inStep.await(10, TimeUnit.SECONDS), "the warm-up never reached its first step");
      assertSame(live, OhMyRaspHooks.events(), "another thread's reports went to the warm-up's logger");
      assertSame(live, OhMyRaspHooks.reportingTo(), "the warm-up swapped the reporter");
      assertTrue(onWorker.get().discards(), "the warm-up thread reported to a logger that writes");
      release.countDown();
      assertEquals(Warmup.STEPS, run.get(10, TimeUnit.SECONDS));
    } finally {
      release.countDown();
      starter.shutdownNow();
    }
    assertSame(live, OhMyRaspHooks.events());
  }

  /**
   * A step that stalls past the wait: the start goes on, the worker's activation exception ends, it reports nowhere
   * (a hook failure it hits after the start went on is not written to stderr or sent to the live reporter), it runs
   * no further step, and it has none of the starter's inheritable thread-locals.
   */
  @Test
  void aStalledStepIsCancelledAndItsWorkerStaysSilentAndStops(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));
    System.setProperty("ohmyrasp.debug", "true");
    InheritableThreadLocal<String> application = new InheritableThreadLocal<>();
    application.set("the application's");
    List<Integer> ran = new CopyOnWriteArrayList<>();
    AtomicReference<Thread> worker = new AtomicReference<>();
    AtomicReference<String> inherited = new AtomicReference<>("unset");
    AtomicReference<Boolean> inactiveWhileRunning = new AtomicReference<>();
    AtomicReference<Boolean> inactiveAfterCancel = new AtomicReference<>();
    AtomicReference<Boolean> discardsAfterCancel = new AtomicReference<>();
    CountDownLatch stalled = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    HookActivation.deactivate();
    try {
      String stderr = stderrOf(() -> {
        int completed = Warmup.run(2000, step -> {
          ran.add(step);
          if (step == 0) {
            worker.set(Thread.currentThread());
            inherited.set(application.get());
            inactiveWhileRunning.set(HookActivation.inactive());
          }
          if (step == 1) {
            stalled.countDown();
            release.await();
            // The start went on while this step stalled; a hook it was inside now fails.
            inactiveAfterCancel.set(HookActivation.inactive());
            discardsAfterCancel.set(OhMyRaspHooks.events().discards());
            OhMyRaspHooks.quiet("warm-up", new IllegalStateException("a hook failed after the start went on"));
          }
        });
        assertEquals(0, completed, "a warm-up that did not finish reported steps");
        assertEquals(0, stalled.getCount(), "the step had not stalled when the wait ended");
        release.countDown();
        try {
          worker.get().join(10_000);
        } catch (InterruptedException e) {
          throw new AssertionError(e);
        }
      });
      assertFalse(worker.get().isAlive(), "the cancelled worker did not stop");
      assertEquals(List.of(0, 1), ran, "the worker ran a step after it was cancelled");
      assertEquals("", stderr, "the worker printed after the start went on");
      assertFalse(Files.exists(log), "the worker wrote to the live reporter");
      assertEquals(Boolean.FALSE, inactiveWhileRunning.get(), "the worker did not act before the start committed");
      assertEquals(Boolean.TRUE, inactiveAfterCancel.get(), "the worker's activation exception outlived the wait");
      assertEquals(Boolean.TRUE, discardsAfterCancel.get(), "the cancelled worker reached the live reporter");
      assertEquals(null, inherited.get(), "the worker inherited a thread-local of the thread that started it");
    } finally {
      release.countDown();
      HookActivation.activate();
      application.remove();
    }
  }

  /** The wait is interrupted: the flag is kept, the worker is cancelled and stops after the step it is in. */
  @Test
  void anInterruptedWaitCancelsTheWorkerAndKeepsTheInterrupt() throws Exception {
    List<Integer> ran = new CopyOnWriteArrayList<>();
    AtomicReference<Thread> worker = new AtomicReference<>();
    AtomicReference<Boolean> inactiveAfterCancel = new AtomicReference<>();
    CountDownLatch inStep = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    AtomicReference<Integer> completed = new AtomicReference<>();
    AtomicReference<Boolean> interruptKept = new AtomicReference<>();
    HookActivation.deactivate();
    try {
      Thread starter = new Thread(() -> {
        completed.set(Warmup.run(10_000, step -> {
          ran.add(step);
          worker.set(Thread.currentThread());
          inStep.countDown();
          release.await();
          inactiveAfterCancel.set(HookActivation.inactive());
        }));
        interruptKept.set(Thread.currentThread().isInterrupted());
      }, "test-starter");
      starter.start();
      assertTrue(inStep.await(10, TimeUnit.SECONDS), "the warm-up never reached its first step");
      starter.interrupt();
      starter.join(10_000);
      assertFalse(starter.isAlive(), "the interrupted wait did not end");
      assertEquals(0, completed.get());
      assertEquals(Boolean.TRUE, interruptKept.get(), "the warm-up swallowed the interrupt");
      release.countDown();
      worker.get().join(10_000);
      assertFalse(worker.get().isAlive(), "the cancelled worker did not stop");
      assertEquals(List.of(0), ran, "the worker ran a step after the interrupted wait cancelled it");
      assertEquals(Boolean.TRUE, inactiveAfterCancel.get(), "the worker kept its activation exception");
    } finally {
      release.countDown();
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
