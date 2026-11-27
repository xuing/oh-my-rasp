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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The agent's diagnostic lines (the hook-miss report's) have a path of their own in the event logger: they never
 * take a slot of the detection queue, never share a batch with detections, never wait for the detections' lock
 * longer than a short bound, and are dropped, and counted, when they cannot be written.
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
   * The detection lock is held, as by a writer stalled in a file call. A diagnostic does not wait behind it for
   * more than a short bound, is dropped and counted, takes no slot of the detection queue, and the detections that
   * were waiting are written when the lock is released.
   */
  @Test
  void aDiagnosticNeverWaitsBehindAStalledDetectionWriterAndTakesNoDetectionSlot(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, false, quiet(), quiet());
    logger.writeLock.lock();
    try {
      logger.log(detection("held-by-the-writer"));
      awaitQueuedOn(logger.writeLock);
      for (int i = 0; i < 100; i++) {
        logger.log(detection("queued-" + i));
      }

      // From another thread: the lock is reentrant, and the report's worker is never the writer.
      Thread worker = new Thread(() -> logger.recordDiagnostic("hook_miss", FIELDS), "ohmyrasp-test-hook-miss");
      worker.setDaemon(true);
      long started = System.nanoTime();
      worker.start();
      worker.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
      assertFalse(worker.isAlive(), "the diagnostic never returned");

      assertTrue(millis < 2000, "a diagnostic waited " + millis + " ms behind the detections' lock");
      assertEquals(1, logger.diagnosticsDroppedCount(), "dropped, and counted apart from detections");
      assertEquals(0, logger.droppedCount(), "no detection was dropped, and the diagnostic took no slot of their queue");
    } finally {
      logger.writeLock.unlock();
    }
    logger.shutdown(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
    assertEquals(101, Files.readAllLines(log).size(), "every detection reached the spool, and no diagnostic");
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

    console.start();
    console.recordDiagnostic("hook_miss", FIELDS);
    assertTrue(err.toString(StandardCharsets.UTF_8).contains("\"kind\":\"diagnostic\""), "written once started");
    assertEquals(1, console.diagnosticsDroppedCount());
  }

  /** A cancel that comes while the line waits for the write lock still leaves the spool without it. */
  @Test
  void aCancelWhileTheDiagnosticWaitsForTheLockWritesNothing(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 0, true, quiet(), quiet());
    Thread worker;
    logger.writeLock.lock();
    try {
      worker = new Thread(() -> logger.recordDiagnostic("hook_miss", FIELDS), "ohmyrasp-test-hook-miss");
      worker.start();
      awaitQueuedOn(logger.writeLock);
      logger.cancel();
    } finally {
      logger.writeLock.unlock();
    }
    worker.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));

    assertFalse(worker.isAlive());
    assertEquals(1, logger.diagnosticsDroppedCount());
    assertFalse(Files.exists(log) && Files.readString(log).contains("diagnostic"), "nothing written");
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

  /** On a console target the line is printed under a lock of its own, so the detections' lock does not hold it up. */
  @Test
  void aConsoleTargetPrintsTheDiagnosticWhileTheDetectionLockIsHeld() throws Exception {
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, "stderr", 0, true, quiet(), new PrintStream(err));
    logger.writeLock.lock();
    try {
      Thread worker = new Thread(() -> logger.recordDiagnostic("hook_miss", FIELDS), "ohmyrasp-test-hook-miss");
      worker.start();
      worker.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      assertFalse(worker.isAlive(), "the diagnostic waited for the detections' lock");
    } finally {
      logger.writeLock.unlock();
    }

    String shown = err.toString(StandardCharsets.UTF_8);
    assertTrue(shown.startsWith("[OHMYRASP] {") && shown.contains("\"kind\":\"diagnostic\""), shown);
    assertEquals(0, logger.diagnosticsDroppedCount());
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
