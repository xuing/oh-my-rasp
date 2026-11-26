package io.ohmyrasp.agent.log;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Settings and writer lifecycle of the event logger. */
final class JsonEventLoggerTest {
  private static final long BOUND_SECONDS = 5;

  @Test
  void invalidSyncPropertyDoesNotHideAValidEnvironmentValue() {
    assertTrue(JsonEventLogger.flagValue("maybe", "true"), "an invalid ohmyrasp.log.sync property");
    assertFalse(JsonEventLogger.flagValue("false", "true"), "a valid false still wins");
    assertTrue(JsonEventLogger.flagValue(null, "on"));
    assertFalse(JsonEventLogger.flagValue("maybe", "perhaps"));
    assertFalse(JsonEventLogger.flagValue(null, null));
  }

  @Test
  void invalidIntegerPropertyDoesNotHideAValidEnvironmentValue() {
    // ohmyrasp.latency_sample / OHMYRASP_LATENCY_SAMPLE and ohmyrasp.log.queue / OHMYRASP_LOG_QUEUE.
    assertEquals(25, JsonEventLogger.intValue("often", "25", 10), "an invalid property");
    assertEquals(4096, JsonEventLogger.intValue(" ", "4096", 8192), "a blank property");
    assertEquals(0, JsonEventLogger.intValue("0", "25", 10), "a valid property still wins");
    assertEquals(10, JsonEventLogger.intValue("often", "sometimes", 10));
    assertEquals(10, JsonEventLogger.intValue(null, null, 10));
  }

  /**
   * The writer takes the first event and waits for the production write lock, which the test
   * holds, so it holds an undelivered batch. Shutdown must not return before that batch is on disk.
   */
  @Test
  void shutdownWaitsForTheBatchTheWriterHoldsAndThenFlushesTheRestOnce(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());
    Thread stopper;
    logger.writeLock.lock();
    try {
      logger.log(detection("spool-first"));
      awaitQueuedOn(logger.writeLock);
      logger.log(detection("spool-second"));
      stopper = daemon("ohmyrasp-test-stopper", () -> logger.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS)));
      awaitJoiningOrDone(stopper);
      assertTrue(stopper.isAlive(), "shutdown returned while the writer held an undelivered batch");
    } finally {
      logger.writeLock.unlock();
    }
    stopper.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    assertFalse(stopper.isAlive(), "shutdown returned");
    // No waiting: once shutdown has returned, everything it accepted is on disk.
    assertEquals(List.of("spool-first", "spool-second"), messages(log), "each event once, in order");
  }

  /**
   * The writer stalls inside a console print while it holds the write lock. Shutdown waits for it
   * only up to its bound and then gives up on the lock: it returns, and the event still queued is
   * the one loss it allows.
   */
  @Test
  void shutdownReturnsInBoundedTimeWhenTheWriterStallsHoldingTheLock(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    StalledOutput console = new StalledOutput();
    JsonEventLogger logger =
        JsonEventLogger.newForTesting(null, log.toString(), 0, false, new PrintStream(console), quiet());
    try {
      logger.log(detection("spool-first"));
      assertTrue(console.entered.await(BOUND_SECONDS, TimeUnit.SECONDS), "the writer stalled printing");
      logger.log(detection("spool-second"));
      Thread stopper = daemon("ohmyrasp-test-stopper", () -> logger.shutdown(200));
      stopper.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      assertFalse(stopper.isAlive(), "shutdown waited without bound for the lock a stalled writer holds");
      assertEquals(List.of("spool-first"), messages(log));
    } finally {
      // Only the test ends the stall, after its assertions, so no timing can change the outcome.
      console.release.countDown();
    }
    assertTrue(console.left.await(BOUND_SECONDS, TimeUnit.SECONDS), "the writer left the stalled print");
  }

  @Test
  void anEventAfterShutdownIsWrittenOnTheCallersThread(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());
    logger.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    logger.log(detection("after-shutdown"));
    assertEquals(List.of("after-shutdown"), messages(log), "the late event is on disk when log returns");
  }

  /** The query keeps its shape; only the values of the parameters {@code parameters} redacts change. */
  @Test
  void theQueryRedactsTheValuesOfSensitiveParametersAndKeepsItsShape() {
    assertEquals("id=1&password=[redacted]&x=2", JsonEventLogger.redactedQuery("id=1&password=hunter2&x=2"));
    assertEquals("folder=reports&password=[redacted]", JsonEventLogger.redactedQuery("folder=reports&password=hunter2"));
    // The same name rule as parameters: case, '_' and '-' do not matter, and neither does encoding.
    assertEquals("API_KEY=[redacted]&a=b", JsonEventLogger.redactedQuery("API_KEY=k3y&a=b"));
    assertEquals("access-token=[redacted]", JsonEventLogger.redactedQuery("access-token=abc"));
    assertEquals("%70assword=[redacted]&q=1", JsonEventLogger.redactedQuery("%70assword=hunter2&q=1"));
    assertEquals("pass%2Dword=[redacted]", JsonEventLogger.redactedQuery("pass%2Dword=hunter2"));
    // Executable-source names are redacted in parameters, so they are here.
    assertEquals("script=[redacted]&a=1", JsonEventLogger.redactedQuery("script=Runtime.exec&a=1"));
    // Repeated names, empty values, a trailing separator and flags are kept as they are.
    assertEquals("token=[redacted]&token=[redacted]&u=", JsonEventLogger.redactedQuery("token=a&token=b&u="));
    assertEquals("password=&a=1&", JsonEventLogger.redactedQuery("password=&a=1&"));
    assertEquals("a=1&flag&b=2", JsonEventLogger.redactedQuery("a=1&flag&b=2"));
    assertEquals("a=1&&b=2", JsonEventLogger.redactedQuery("a=1&&b=2"));
    // Nothing to redact: the same string comes back.
    String plain = "id=1&name=a%20b&q=password+policy";
    assertTrue(plain == JsonEventLogger.redactedQuery(plain));
    assertEquals("", JsonEventLogger.redactedQuery(""));
  }

  @Test
  void theQueryRedactsAssignmentsHiddenInsideValuesAndUnsplittableText() {
    assertEquals("next=[redacted]&a=1", JsonEventLogger.redactedQuery("next=%2Fcb%3Ftoken%3Dabc&a=1"));
    assertEquals("next=[redacted]", JsonEventLogger.redactedQuery("next=%252Fcb%253Fpassword%253Dabc"));
    assertEquals("a=[redacted]", JsonEventLogger.redactedQuery("a=1;password=hunter2"));
    // A piece that is not name=value but names a sensitive parameter.
    assertEquals("a=1&[redacted]", JsonEventLogger.redactedQuery("a=1&password%3Dhunter2"));
    assertEquals("a=1&[redacted]", JsonEventLogger.redactedQuery("a=1&{\"password\":\"hunter2\"}"));
    // A query with no '=' at all is kept unless it names a sensitive parameter.
    assertEquals("flag&other", JsonEventLogger.redactedQuery("flag&other"));
    assertEquals("[redacted]", JsonEventLogger.redactedQuery("password:hunter2"));
    assertEquals("[redacted]", JsonEventLogger.redactedQuery("%7B%22password%22%3A%22hunter2%22%7D"));
    // A malformed escape is not an error and not a match.
    assertEquals("a=%zz&b=%4", JsonEventLogger.redactedQuery("a=%zz&b=%4"));
    // Multi-byte UTF-8 in a name decodes the way the container decodes it.
    assertEquals("to%E2%84%AAen=[redacted]", JsonEventLogger.redactedQuery("to%E2%84%AAen=abc"));
  }

  /** The line the daemon uploads from: no secret from the query reaches it, the other members do. */
  @Test
  void anEventLineCarriesTheRedactedQuery(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());
    var request =
        new RequestContext(
            "GET",
            "/app/login",
            "password=hunter2&id=1",
            Map.of("password", List.of("hunter2"), "id", List.of("1")),
            Map.of());
    logger.log(new Detection(Instant.now(), "test", "test_algorithm", "log", 50, "m", request, Map.of()));
    logger.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    String line = Files.readString(log);
    assertTrue(line.contains("\"query\":\"password=[redacted]&id=1\""), line);
    assertFalse(line.contains("hunter2"), line);
  }

  private static Detection detection(String message) {
    return new Detection(Instant.now(), "test", "test_algorithm", "log", 50, message, RequestContext.empty(), Map.of());
  }

  private static PrintStream quiet() {
    return new PrintStream(new ByteArrayOutputStream());
  }

  /** The test messages in the log, in order; empty when there is no log. */
  private static List<String> messages(Path log) throws Exception {
    List<String> messages = new ArrayList<>();
    if (!Files.exists(log)) {
      return messages;
    }
    for (String line : Files.readAllLines(log)) {
      int start = line.indexOf("\"message\":\"") + "\"message\":\"".length();
      messages.add(line.substring(start, line.indexOf('"', start)));
    }
    return messages;
  }

  private static Thread daemon(String name, Runnable body) {
    Thread thread = new Thread(body, name);
    thread.setDaemon(true);
    thread.start();
    return thread;
  }

  /** Waits, bounded, until a thread waits for {@code lock}. The loop only observes. */
  private static void awaitQueuedOn(ReentrantLock lock) throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
    while (!lock.hasQueuedThreads()) {
      if (System.nanoTime() > deadline) {
        fail("the writer never waited for the write lock");
      }
      Thread.sleep(1);
    }
  }

  /**
   * Waits until {@code stopper} has finished or is waiting in Thread.join for the writer. Either
   * state is final for this test: the writer cannot finish while the test holds the lock. The
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

  /**
   * An output stream whose writes signal {@code entered} and then wait until the test counts down
   * {@code release}; nothing else ends the wait. {@code left} is counted down once a write returns.
   */
  private static final class StalledOutput extends OutputStream {
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    final CountDownLatch left = new CountDownLatch(1);

    @Override
    public void write(int b) {
      stall();
    }

    @Override
    public void write(byte[] bytes, int offset, int length) {
      stall();
    }

    private void stall() {
      entered.countDown();
      try {
        release.await();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      } finally {
        left.countDown();
      }
    }
  }
}
