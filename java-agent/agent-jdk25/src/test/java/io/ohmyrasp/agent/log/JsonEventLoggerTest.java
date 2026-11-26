package io.ohmyrasp.agent.log;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Settings and writer lifecycle of the event logger. */
final class JsonEventLoggerTest {
  private static final long BOUND_SECONDS = 20;

  @Test
  void invalidSyncPropertyDoesNotHideAValidEnvironmentValue() {
    assertTrue(JsonEventLogger.flagValue("maybe", "true"), "an invalid ohmyrasp.log.sync property");
    assertFalse(JsonEventLogger.flagValue("false", "true"), "a valid false still wins");
    assertTrue(JsonEventLogger.flagValue(null, "on"));
    assertFalse(JsonEventLogger.flagValue("maybe", "perhaps"));
    assertFalse(JsonEventLogger.flagValue(null, null));
  }

  /**
   * The writer takes the first event, then waits inside its own serialisation on a latch the test
   * holds, so its progress is controlled. Every wait is bounded; none decides the outcome by timing.
   */
  @Test
  void shutdownWaitsForTheBatchTheWriterHoldsAndThenFlushesTheRestOnce(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    CountDownLatch taken = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    JsonEventLogger logger =
        JsonEventLogger.newForTesting(
            null, log.toString(), 0, false, new PrintStream(new ByteArrayOutputStream()),
            new PrintStream(new ByteArrayOutputStream()));

    logger.log(detection("spool-first", new GatedDetails(taken, release)));
    assertTrue(taken.await(BOUND_SECONDS, TimeUnit.SECONDS), "the writer took the first event");
    logger.log(detection("spool-second", Map.of()));

    // A budget far above the test's own waits, so the stopper cannot give up on the writer.
    Thread stopper = new Thread(() -> logger.shutdown(TimeUnit.SECONDS.toMillis(60)), "ohmyrasp-test-stopper");
    stopper.start();
    awaitJoiningOrDone(stopper);
    release.countDown();
    stopper.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    assertFalse(stopper.isAlive(), "shutdown returned");
    waitForLines(log, 2);

    List<String> messages = new ArrayList<>();
    for (String line : Files.readAllLines(log)) {
      messages.add(line.contains("spool-first") ? "spool-first" : line.contains("spool-second") ? "spool-second" : line);
    }
    assertEquals(List.of("spool-first", "spool-second"), messages, "each event once, in order");
  }

  private static Detection detection(String message, Map<String, String> details) {
    return new Detection(Instant.now(), "test", "test_algorithm", "log", 50, message, RequestContext.empty(), details);
  }

  /** The writer of the old code may still be appending after shutdown returns; wait for it, bounded. */
  private static void waitForLines(Path log, int count) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
    while (System.nanoTime() < deadline && (!Files.exists(log) || Files.readAllLines(log).size() < count)) {
      Thread.sleep(1);
    }
  }

  /**
   * Waits until {@code stopper} has finished or is waiting in Thread.join for the writer. Either
   * state is final for this test: the writer cannot finish while the test holds its latch. The
   * loop only observes; it is bounded and its sleep decides nothing.
   */
  private static void awaitJoiningOrDone(Thread stopper) throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
    while (System.nanoTime() < deadline) {
      Thread.State state = stopper.getState();
      if (state == Thread.State.TERMINATED) {
        return;
      }
      if (state == Thread.State.WAITING || state == Thread.State.TIMED_WAITING) {
        for (StackTraceElement frame : stopper.getStackTrace()) {
          if ("java.lang.Thread".equals(frame.getClassName()) && "join".equals(frame.getMethodName())) {
            return;
          }
        }
      }
      Thread.sleep(1);
    }
    fail("the stopper neither finished nor waited for the writer");
  }

  /** Details whose first serialisation signals {@code taken} and then waits for {@code release}. */
  private static final class GatedDetails extends AbstractMap<String, String> {
    private final CountDownLatch taken;
    private final CountDownLatch release;

    GatedDetails(CountDownLatch taken, CountDownLatch release) {
      this.taken = taken;
      this.release = release;
    }

    @Override
    public Set<Map.Entry<String, String>> entrySet() {
      if (taken.getCount() > 0) {
        taken.countDown();
        try {
          release.await(BOUND_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      return Set.of(Map.entry("gate", "released"));
    }
  }
}
