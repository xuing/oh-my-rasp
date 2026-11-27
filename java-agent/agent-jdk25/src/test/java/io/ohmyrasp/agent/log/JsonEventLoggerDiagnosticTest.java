package io.ohmyrasp.agent.log;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The agent's diagnostic lines (the hook-miss report's) have a path of their own in the event logger that shares
 * nothing a detection waits for: they never take a slot of the detection queue, never share a batch with detections,
 * never take the detections' lock, never go to the console the detections are printed to, and are dropped, and
 * counted, when they cannot be written. A diagnostic stalled in its own output call holds up no detection.
 */
final class JsonEventLoggerDiagnosticTest {
  private static final long BOUND_SECONDS = 5;
  private static final String FIELDS = "\"unit\":\"U\",\"class\":\"a.B\",\"reason\":\"no_agent_call\"";

  @Test
  void aDiagnosticIsWrittenAsOneLineOfItsOwn(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());

    logger.log(detection("before"));
    logger.recordDiagnostic("hook_miss", FIELDS);
    logger.log(detection("after"));
    logger.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));

    List<String> lines = Files.readAllLines(log);
    assertEquals(3, lines.size(), lines.toString());
    long diagnostics = lines.stream().filter(line -> line.contains("\"kind\":\"diagnostic\",\"diagnostic\":\"hook_miss\"," + FIELDS)).count();
    assertEquals(1, diagnostics, lines.toString());
    assertEquals(0, logger.diagnosticsDroppedCount());
  }

  /**
   * A diagnostic that holds an unpaired surrogate (the cut of a text on a code unit boundary used to leave one) is
   * made valid before it is written, and what it holds cannot make a batch with detections fail to encode.
   */
  @Test
  void aDiagnosticWithAnUnpairedSurrogateCannotCostADetection(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());

    logger.log(detection("first"));
    logger.recordDiagnostic("hook_miss", "\"unit\":\"U" + '\uD83D' + "\",\"class\":\"x" + '\uD83D' + "y\",\"half\":\"" + '\uDE00' + "\"");
    logger.log(detection("second"));
    logger.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertFalse(text.contains("�") && text.contains("\uD83D"), "decoded as UTF-8 without a lone surrogate");
    assertTrue(StandardCharsets.UTF_8.newEncoder().canEncode(text), "every line encodes");
    assertTrue(text.contains("\"message\":\"first\"") && text.contains("\"message\":\"second\""), text);
    assertTrue(text.contains("\"diagnostic\":\"hook_miss\""), text);
    assertEquals(0, logger.droppedCount());
  }

  @Test
  void unpairedSurrogatesAreReplacedAndPairsKept() {
    String pair = new String(Character.toChars(0x1F600));
    assertEquals("a�b�c" + pair + "d�", JsonEventLogger.withoutUnpairedSurrogates("a\uD83Db\uDE00c" + pair + "d\uD83D"));
    String clean = "plain " + pair;
    assertTrue(clean == JsonEventLogger.withoutUnpairedSurrogates(clean), "text that needs no change is returned as it is");
  }

  /**
   * The detection lock is held, as by a writer stalled in a file call. A diagnostic does not wait for it: it is
   * written at once, takes no slot of the detection queue, and the detections that were waiting are written when the
   * lock is released.
   */
  @Test
  void aDiagnosticIsWrittenWhileADetectionWriterHoldsItsLockAndTakesNoDetectionSlot(@TempDir Path dir)
      throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());
    logger.writeLock.lock();
    try {
      logger.log(detection("held-by-the-writer"));
      awaitQueuedOn(logger.writeLock);
      for (int i = 0; i < 100; i++) {
        logger.log(detection("queued-" + i));
      }

      Thread worker = new Thread(() -> logger.recordDiagnostic("hook_miss", FIELDS), "ohmyrasp-test-hook-miss");
      worker.setDaemon(true);
      worker.start();
      worker.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      assertFalse(worker.isAlive(), "the diagnostic waited for the detections' lock");
      assertTrue(Files.readString(log).contains("\"diagnostic\":\"hook_miss\""), "written while the lock is held");
      assertEquals(0, logger.diagnosticsDroppedCount());
      assertEquals(0, logger.droppedCount(), "no detection was dropped, and the diagnostic took no slot of their queue");
    } finally {
      logger.writeLock.unlock();
    }
    logger.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    List<String> lines = Files.readAllLines(log);
    assertEquals(102, lines.size(), "every detection reached the spool, and the diagnostic once");
  }

  /**
   * A diagnostic stalled for good in its own output call, with a detection behind it on each path: written inline (sync
   * mode) and through the writer thread. Both are written at once, and the JVM exit hook's part still returns within
   * its wait.
   */
  @Test
  void detectionsBehindADiagnosticStalledInItsOutputAreWritten(@TempDir Path dir) throws Exception {
    for (boolean sync : new boolean[] {true, false}) {
      Path log = dir.resolve("events-" + sync + ".jsonl");
      JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, sync, quiet(), quiet());
      CountDownLatch entered = new CountDownLatch(1);
      CountDownLatch never = new CountDownLatch(1);
      logger.diagnosticOutput = (path, line) -> {
        entered.countDown();
        try {
          never.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      };
      Thread worker = new Thread(() -> logger.recordDiagnostic("hook_miss", FIELDS), "ohmyrasp-test-hook-miss");
      worker.setDaemon(true);
      worker.start();
      try {
        assertTrue(entered.await(BOUND_SECONDS, TimeUnit.SECONDS), "the diagnostic never reached its output");
        logger.log(detection("behind-" + sync));
        long started = System.nanoTime();
        logger.shutdown(500);
        long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
        assertTrue(millis < 2000, "shutdown took " + millis + " ms with a diagnostic stalled");
        assertTrue(Files.readString(log).contains("behind-" + sync), "sync=" + sync + ": the detection was not written");
        assertEquals(0, logger.droppedCount());
      } finally {
        never.countDown();
        worker.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      }
    }
  }

  /**
   * The real output, stalled: the spool is a FIFO nobody reads, so opening it for writing blocks. While a diagnostic
   * is stuck there, the detections' lock is free (until this round the diagnostic held it across the open).
   */
  @Test
  void aDiagnosticStuckOpeningTheSpoolHoldsNoDetectionLock(@TempDir Path dir) throws Exception {
    Path fifo = dir.resolve("events.fifo");
    Assumptions.assumeTrue(new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor() == 0, "no mkfifo");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, fifo.toString(), 0, true, quiet(), quiet());
    Thread worker = new Thread(() -> logger.recordDiagnostic("hook_miss", FIELDS), "ohmyrasp-test-hook-miss");
    worker.setDaemon(true);
    worker.start();
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
      while (!inOpen(worker) && System.nanoTime() < deadline) {
        Thread.sleep(5);
      }
      assertTrue(inOpen(worker), "the diagnostic never reached the open of the FIFO");
      assertFalse(logger.writeLock.isLocked(), "a diagnostic stalled in its output holds the detections' lock");
    } finally {
      // Opened read-write, the FIFO never blocks this open, and it lets the diagnostic's open finish.
      try (var reader = new java.io.RandomAccessFile(fifo.toFile(), "rw")) {
        worker.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      }
    }
  }

  private static boolean inOpen(Thread thread) {
    for (StackTraceElement frame : thread.getStackTrace()) {
      if (frame.getMethodName().startsWith("open") && (frame.getClassName().startsWith("sun.nio.")
          || frame.getClassName().startsWith("java.nio.") || frame.getClassName().startsWith("java.io."))) {
        return true;
      }
    }
    return false;
  }

  @Test
  void aDiagnosticAfterTheLoggerShutDownIsDroppedNotWritten(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());

    logger.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    logger.recordDiagnostic("hook_miss", FIELDS);

    assertEquals(1, logger.diagnosticsDroppedCount());
    assertFalse(Files.exists(log) && Files.readString(log).contains("diagnostic"), "nothing written");
  }

  /** A start that failed cancels the logger: a diagnostic after that is dropped and counted, on every target. */
  @Test
  void aDiagnosticAfterTheLoggerWasCancelledIsDroppedNotWritten(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger file = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    JsonEventLogger console = JsonEventLogger.newForTesting(null, "stderr", 0, true, quiet(), new PrintStream(err));

    file.cancel();
    console.cancel();
    file.recordDiagnostic("hook_miss", FIELDS);
    console.recordDiagnostic("hook_miss", FIELDS);

    assertEquals(1, file.diagnosticsDroppedCount());
    assertEquals(1, console.diagnosticsDroppedCount());
    assertFalse(Files.exists(log), "nothing written to the spool");
    assertEquals("", err.toString(StandardCharsets.UTF_8), "nothing printed");
  }

  /**
   * Before {@link JsonEventLogger#start} nothing is written: the primary starts the logger before its commit, and a
   * logger nobody started (a start that failed before it, or one that never ran) writes no diagnostic either.
   */
  @Test
  void aDiagnosticBeforeTheLoggerStartedIsDroppedNotWritten(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger file = JsonEventLogger.unstartedForTesting(log.toString(), quiet(), quiet());
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    JsonEventLogger console = JsonEventLogger.unstartedForTesting("stderr", quiet(), new PrintStream(err));

    file.recordDiagnostic("hook_miss", FIELDS);
    console.recordDiagnostic("hook_miss", FIELDS);

    assertEquals(1, file.diagnosticsDroppedCount());
    assertEquals(1, console.diagnosticsDroppedCount());
    assertFalse(Files.exists(log), "nothing written to the spool");
    assertEquals("", err.toString(StandardCharsets.UTF_8), "nothing printed");

    file.start();
    file.recordDiagnostic("hook_miss", FIELDS);
    assertTrue(Files.readString(log).contains("\"kind\":\"diagnostic\""), "written once started");
    assertEquals(1, file.diagnosticsDroppedCount());
    file.cancel();
  }

  /**
   * A cancel (the undo of a failed start) that comes while the writer's batch waits for the write lock: the batch is
   * not written when the lock comes free. The writer checks the cancellation again once it holds the lock.
   */
  @Test
  void aCancelWhileADetectionBatchWaitsForTheLockWritesNothing(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());
    Thread writer = logger.writerThread();
    logger.writeLock.lock();
    try {
      logger.log(detection("waiting-for-the-lock"));
      awaitQueuedOn(logger.writeLock);
      logger.cancel();
    } finally {
      logger.writeLock.unlock();
    }
    writer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));

    assertFalse(writer.isAlive());
    assertFalse(Files.exists(log), "a cancelled logger wrote the batch that waited for the lock");
  }

  /** A file target mirrors detections to the console; a diagnostic, which names source paths, stays in the spool. */
  @Test
  void aDiagnosticIsNotMirroredToTheConsoleOfAFileTarget(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    ByteArrayOutputStream console = new ByteArrayOutputStream();
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, true, new PrintStream(console), quiet());

    logger.log(detection("mirrored"));
    logger.recordDiagnostic("hook_miss", FIELDS);

    String shown = console.toString(StandardCharsets.UTF_8);
    assertTrue(shown.contains("mirrored"), shown);
    assertFalse(shown.contains("diagnostic"), shown);
    assertTrue(Files.readString(log).contains("\"diagnostic\":\"hook_miss\""));
  }

  /**
   * On a console target a diagnostic is dropped and counted: it would share the stream the detections are printed to,
   * and a diagnostic stalled there would hold them up.
   */
  @Test
  void aConsoleTargetDropsTheDiagnostic() throws Exception {
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, "stderr", 0, true, quiet(), new PrintStream(err));

    logger.recordDiagnostic("hook_miss", FIELDS);
    logger.log(detection("printed"));

    String shown = err.toString(StandardCharsets.UTF_8);
    assertFalse(shown.contains("\"kind\":\"diagnostic\""), shown);
    assertTrue(shown.contains("printed"), shown);
    assertEquals(1, logger.diagnosticsDroppedCount());
  }

  @Test
  void aNoneTargetDropsTheDiagnostic() {
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, "none", 0, true, quiet(), quiet());

    logger.recordDiagnostic("hook_miss", FIELDS);

    assertEquals(1, logger.diagnosticsDroppedCount());
  }

  private static Detection detection(String message) {
    return new Detection(Instant.now(), "test", "test_algorithm", "log", 50, message, RequestContext.empty(), Map.of());
  }

  private static PrintStream quiet() {
    return new PrintStream(new ByteArrayOutputStream());
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
}
