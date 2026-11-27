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
import org.junit.jupiter.api.Assumptions;
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

  /**
   * A start that fails cancels the logger it started. The writer is stuck mirroring an event to a console that
   * never returns, holding the write lock, and ignores interrupts, as a write to a full pipe does: cancel returns
   * in bounded time anyway, without the lock, and nothing queued or submitted from then on is written.
   */
  @Test
  void cancelReturnsInBoundedTimeAndWritesNothingMoreWhileTheSinkIsStuck(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    StuckOutput console = new StuckOutput();
    JsonEventLogger logger =
        JsonEventLogger.newForTesting(null, log.toString(), 0, false, new PrintStream(console), quiet());
    try {
      logger.log(detection("before-cancel"));
      assertTrue(console.entered.await(BOUND_SECONDS, TimeUnit.SECONDS), "the writer is stuck printing");
      logger.log(detection("queued-at-cancel"));
      long began = System.nanoTime();
      Thread canceller = daemon("ohmyrasp-test-canceller", logger::cancel);
      canceller.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      assertFalse(canceller.isAlive(), "cancel waited for a sink that does not return");
      assertTrue(System.nanoTime() - began < TimeUnit.SECONDS.toNanos(3), "cancel waited longer than its bound");
      logger.log(detection("after-cancel"));
      assertEquals(List.of("before-cancel"), messages(log), "cancel wrote, or let the caller write, an event");
    } finally {
      console.release.countDown();
    }
    Thread writer = logger.writerThread();
    writer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    assertFalse(writer.isAlive(), "the writer did not end once its output call returned");
    assertEquals(List.of("before-cancel"), messages(log), "the writer wrote what was queued when cancel ran");
  }

  /** Creating the logger starts nothing; start starts the writer once; a cancelled logger does not start again. */
  @Test
  void constructionStartsNoThreadAndStartStartsTheWriterOnce(@TempDir Path dir) throws Exception {
    JsonEventLogger logger = JsonEventLogger.unstartedForTesting(dir.resolve("events.jsonl").toString(), quiet(), quiet());
    assertEquals(null, logger.writerThread(), "creating the logger started its writer");
    logger.start();
    Thread writer = logger.writerThread();
    assertTrue(writer != null && writer.isAlive(), "start did not start the writer");
    logger.start();
    assertTrue(writer == logger.writerThread(), "a second start started another writer");
    logger.cancel();
    writer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    assertFalse(writer.isAlive(), "cancel left the writer running");
    logger.start();
    assertTrue(writer == logger.writerThread(), "a cancelled logger started again");
  }

  /**
   * After the JVM's exit began, an event for the queue is dropped and counted: the shutdown hook writes nothing, and an
   * application thread does not take over the writer's output either. (Until this round it was written on the
   * caller's thread.) Sync mode still writes on the caller's thread.
   */
  @Test
  void anEventAfterShutdownIsDroppedAndCounted(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());
    logger.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    logger.log(detection("after-shutdown"));
    assertEquals(List.of(), messages(log));
    assertEquals(1, logger.droppedCount());

    Path syncLog = dir.resolve("sync.jsonl");
    JsonEventLogger sync = JsonEventLogger.newForTesting(null, syncLog.toString(), 0, true, quiet(), quiet());
    sync.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    sync.log(detection("sync-after-shutdown"));
    assertEquals(List.of("sync-after-shutdown"), messages(syncLog));
  }

  /**
   * The JVM exit hook with a spool that blocks forever: a FIFO nobody reads, whose open never returns. Events are
   * queued that no writer holds (a logger whose writer is not running), so only the hook could write them. The hook
   * returns within its bounded waits, writes nothing and counts them as dropped. (Until this round it wrote the queue
   * itself after its wait, and hung in the open.)
   */
  @Test
  void theExitHookReturnsAndWritesNothingWhenTheSpoolBlocksForever(@TempDir Path dir) throws Exception {
    Path fifo = dir.resolve("events.fifo");
    Assumptions.assumeTrue(new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor() == 0, "no mkfifo");
    JsonEventLogger logger = JsonEventLogger.unstartedForTesting(fifo.toString(), quiet(), quiet());
    logger.log(detection("queued-1"));
    logger.log(detection("queued-2"));
    Thread hook = daemon("ohmyrasp-test-exit-hook", logger::shutdownForExit);
    try {
      hook.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      assertFalse(hook.isAlive(), "the exit hook is stuck in the spool's output");
      assertEquals(2, logger.droppedCount());
    } finally {
      // Opened read-write, the FIFO never blocks this open, and it lets a stuck open finish.
      try (var reader = new java.io.RandomAccessFile(fifo.toFile(), "rw")) {
        hook.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      }
    }
  }

  /**
   * The same with a running writer stuck in that open: the exit hook waits for it at most its bound, writes nothing,
   * and drops what the writer had not taken.
   */
  @Test
  void theExitHookReturnsWithinItsBoundWhileTheWriterIsStuckInTheSpool(@TempDir Path dir) throws Exception {
    Path fifo = dir.resolve("events.fifo");
    Assumptions.assumeTrue(new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor() == 0, "no mkfifo");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, fifo.toString(), 0, false, quiet(), quiet());
    Thread writer = logger.writerThread();
    try {
      logger.log(detection("taken-by-the-writer"));
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
      while (logger.writeLock.isLocked() == false && System.nanoTime() < deadline) {
        Thread.sleep(5);
      }
      logger.log(detection("queued"));
      long began = System.nanoTime();
      Thread hook = daemon("ohmyrasp-test-exit-hook", logger::shutdownForExit);
      hook.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      assertFalse(hook.isAlive(), "the exit hook waited without bound for a writer stuck in its output");
      assertTrue(System.nanoTime() - began < TimeUnit.SECONDS.toNanos(4), "the exit hook waited longer than its bound");
      assertEquals(1, logger.droppedCount(), "the event the writer had not taken is dropped and counted");
    } finally {
      try (var reader = new java.io.RandomAccessFile(fifo.toFile(), "rw")) {
        writer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      }
    }
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
    String plain = "id=1&x=2&name=a%20b&passwordless=1&bypass=1&tokens=3";
    assertTrue(plain == JsonEventLogger.redactedQuery(plain));
    assertEquals("", JsonEventLogger.redactedQuery(""));
  }

  @Test
  void theQueryRedactsAssignmentsHiddenInsideValuesAndUnsplittableText() {
    assertEquals("next=[redacted]&a=1", JsonEventLogger.redactedQuery("next=%2Fcb%3Ftoken%3Dabc&a=1"));
    assertEquals("next=[redacted]", JsonEventLogger.redactedQuery("next=%252Fcb%253Fpassword%253Dabc"));
    // A ';' is part of its piece (Tomcat reads it as part of the value), so the piece is redacted
    // whole; the name `a` stays and its value goes.
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

  /** The shapes a review got through the exact-key match: HTML-escaped separators, double encoding, JSON. */
  @Test
  void theQueryRedactsTheShapesThatSlippedPastExactKeys() {
    // The piece is `amp;password=example`: its key holds a ';', so the whole piece goes.
    assertEquals("id=1&[redacted]", JsonEventLogger.redactedQuery("id=1&amp;password=example"));
    assertEquals("%2570assword=[redacted]", JsonEventLogger.redactedQuery("%2570assword=example"));
    assertEquals("%252570assword=[redacted]", JsonEventLogger.redactedQuery("%252570assword=example"));
    assertEquals("cfg=[redacted]", JsonEventLogger.redactedQuery("cfg=%7B%22password%22%3A%22hunter4%22%7D"));
    assertEquals("cfg=[redacted]", JsonEventLogger.redactedQuery("cfg={\"password\":\"x\"}"));
    assertEquals("user[password]=[redacted]", JsonEventLogger.redactedQuery("user[password]=x"));
    assertEquals("next=[redacted]", JsonEventLogger.redactedQuery("next=/cb?token=abc"));
    assertEquals("x-api-key=[redacted]", JsonEventLogger.redactedQuery("x-api-key=k"));
    // A secret that follows an '=' inside the JSON does not survive as the kept key text.
    String json = JsonEventLogger.redactedQuery("{\"password\":\"a=b\"}&id=1");
    assertEquals("[redacted]&id=1", json);
    // Unicode case folding: Kelvin sign and dotted capital I read as k and i.
    assertEquals("to%E2%84%AAen=[redacted]", JsonEventLogger.redactedQuery("to%E2%84%AAen=abc"));
    assertEquals("author%C4%B0zation=[redacted]", JsonEventLogger.redactedQuery("author%C4%B0zation=abc"));
  }

  /** Accepted over-redaction: the rule reads tokens, not intent, so a search for the word goes too. */
  @Test
  void aSearchForTheWordPasswordIsRedactedAsAcceptedOverRedaction() {
    assertEquals("q=[redacted]", JsonEventLogger.redactedQuery("q=password+policy"));
  }

  /** Tomcat reads everything up to the next '&' as the value, a ';' included. */
  @Test
  void aSemicolonDoesNotEndTheValueOfASensitiveParameter() {
    assertEquals("password=[redacted]", JsonEventLogger.redactedQuery("password=alpha;omega"));
    assertEquals(
        "password=[redacted]&id=1", JsonEventLogger.redactedQuery("password=alpha;omega&id=1"));
    assertEquals("id=1;x=2&b=3", JsonEventLogger.redactedQuery("id=1;x=2&b=3"));
  }

  @Test
  void aSensitiveNameBehindFourToSevenEncodingLayersIsFoundAndLongerChainsAreRedacted() {
    // "%" + "25" * (n - 1) + "70assword" is `password` with its first letter encoded n times.
    for (int layers = 1; layers <= 7; layers++) {
      String query = "id=1&%" + "25".repeat(layers - 1) + "70assword=hunter5";
      String key = query.substring(5, query.lastIndexOf('='));
      assertEquals("id=1&" + key + "=[redacted]", JsonEventLogger.redactedQuery(query), "layers " + layers);
    }
    assertEquals(
        "%25252570assword=[redacted]", JsonEventLogger.redactedQuery("%25252570assword=hunter5"));
    // Past the bound the text is still changing, which is treated as sensitive.
    String deep = "x=%" + "25".repeat(12) + "41";
    assertEquals("x=[redacted]", JsonEventLogger.redactedQuery(deep));
    // Text that stops changing within the bound and holds no name is left alone.
    assertTrue(JsonEventLogger.redactedQuery("x=%2541") == "x=%2541");
  }

  @Test
  void theQueryKeepsBenignShapes() {
    for (String benign :
        new String[] {"id=1&x=2", "passwordless=1", "a=1;b=2", "flag&other", "bypass=1&compass=n", "name=a%20b"}) {
      assertTrue(benign == JsonEventLogger.redactedQuery(benign), benign);
    }
    assertEquals("a=1&password=&b=2", JsonEventLogger.redactedQuery("a=1&password=&b=2"));
  }

  @Test
  void aQueryOverTheBoundIsNotScannedAndBecomesTheMarker() {
    String atBound = "a=" + "x".repeat(8190);
    assertEquals(8192, atBound.length());
    assertTrue(atBound == JsonEventLogger.redactedQuery(atBound), "a query of exactly the bound is scanned");
    assertEquals("[redacted]", JsonEventLogger.redactedQuery(atBound + "y"));
    // The secret is not in the output, nor is anything else of the query.
    assertEquals("[redacted]", JsonEventLogger.redactedQuery("id=1&" + "x".repeat(9000) + "&password=hunter2"));
  }

  @Test
  void aQueryOfManyFlagsThenOneAssignmentIsScannedInLinearTime() {
    // Under the bound: thousands of flags, then the assignment, the shape that made the old scan quadratic.
    String flags = "f&".repeat(4000);
    long started = System.nanoTime();
    String result = JsonEventLogger.redactedQuery(flags + "password=hunter2");
    long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
    assertTrue(result.endsWith("password=[redacted]"), result);
    assertTrue(millis < 1000, "took " + millis + " ms");
    // Over the bound: 20,000 flags are not scanned at all.
    started = System.nanoTime();
    result = JsonEventLogger.redactedQuery("f&".repeat(20_000) + "x=1");
    millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
    assertEquals("[redacted]", result);
    assertTrue(millis < 1000, "took " + millis + " ms");
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
  /** An output whose writes do not return until released, whatever interrupts the writing thread. */
  private static final class StuckOutput extends OutputStream {
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);

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
      boolean interrupted = false;
      while (release.getCount() > 0) {
        try {
          release.await();
        } catch (InterruptedException e) {
          interrupted = true;
        }
      }
      if (interrupted) {
        Thread.currentThread().interrupt();
      }
    }
  }

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
