package io.ohmyrasp.agent.backport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The backport lines' diagnostic lines (the hook-miss report's) are written by {@code RaspRuntime.writeDiagnostic},
 * a path of its own that shares nothing a detection waits for: never the detections' queue, never their write lock,
 * never the console stream they are printed to; valid UTF-8 whatever the default charset. A diagnostic stalled in its
 * own output call holds up no detection.
 */
final class Java8DiagnosticWriteTest {
  @TempDir Path dir;

  @AfterEach
  void clear() {
    System.clearProperty("ohmyrasp.java8.log");
    RaspRuntime.diagnosticOutput = RaspRuntime.FILE_APPEND;
  }

  @Test
  void aDiagnosticIsAppendedAsOneUtf8Line() throws Exception {
    Path log = dir.resolve("events.jsonl");
    System.setProperty("ohmyrasp.java8.log", log.toString());

    RaspRuntime.writeDiagnostic(RaspRuntime.resolveLogPath(), "{\"event\":\"ohmyrasp-hook-miss\",\"code_source_path\":\"/opt/é/x.jar\"}");
    RaspRuntime.writeDiagnostic(RaspRuntime.resolveLogPath(), "{\"event\":\"ohmyrasp-hook-miss\",\"n\":2}");

    // Strict: the bytes must decode as UTF-8 whatever the JVM's default charset is.
    String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(Files.readAllBytes(log))).toString();
    assertTrue(text.contains("/opt/é/x.jar"), text);
    assertEquals(2, text.split(System.lineSeparator()).length, text);
  }

  /** A thread that holds the write lock, as a detection writer stalled in a file call does: a diagnostic does not wait. */
  @Test
  void aDiagnosticIsWrittenWhileTheDetectionWriteLockIsHeld() throws Exception {
    Path log = dir.resolve("events.jsonl");
    System.setProperty("ohmyrasp.java8.log", log.toString());
    final CountDownLatch locked = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    Thread holder = new Thread(new Runnable() {
      @Override public void run() {
        RaspRuntime.WRITE_LOCK.lock();
        try {
          locked.countDown();
          release.await();
        } catch (InterruptedException ignored) {
          // ends
        } finally {
          RaspRuntime.WRITE_LOCK.unlock();
        }
      }
    }, "test-stalled-writer");
    holder.setDaemon(true);
    holder.start();
    assertTrue(locked.await(5, TimeUnit.SECONDS));
    try {
      RaspRuntime.writeDiagnostic(RaspRuntime.resolveLogPath(), "{\"event\":\"ohmyrasp-hook-miss\"}");
      assertTrue(Files.exists(log), "the diagnostic waited for the detections' lock");
    } finally {
      release.countDown();
      holder.join(5000);
    }
  }

  /**
   * A diagnostic stalled for good in its own output call, and a detection behind it: the detection is written at once.
   * The diagnostic's output never holds anything the detections' path needs.
   */
  @Test
  void aDetectionBehindADiagnosticStalledInItsOutputIsWritten() throws Exception {
    final Path log = dir.resolve("events.jsonl");
    System.setProperty("ohmyrasp.java8.log", log.toString());
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch never = new CountDownLatch(1);
    RaspRuntime.diagnosticOutput = new RaspRuntime.DiagnosticOutput() {
      @Override public void append(java.io.File target, byte[] line) {
        entered.countDown();
        try {
          never.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
    };
    Thread diagnostic = new Thread(new Runnable() {
      @Override public void run() {
        RaspRuntime.writeDiagnostic(log.toString(), "{\"event\":\"ohmyrasp-hook-miss\"}");
      }
    }, "test-hook-miss-worker");
    diagnostic.setDaemon(true);
    diagnostic.start();
    try {
      assertTrue(entered.await(5, TimeUnit.SECONDS), "the diagnostic never reached its output");
      long started = System.nanoTime();
      RaspRuntime.writeEvent(log.toString(), "{\"kind\":\"detection\",\"message\":\"behind\"}");
      long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
      assertTrue(millis < 2000, "the detection waited " + millis + " ms behind a stalled diagnostic");
      String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
      assertTrue(text.contains("\"message\":\"behind\""), text);
    } finally {
      never.countDown();
      diagnostic.join(5000);
    }
  }

  /**
   * The real output, stalled: the spool is a FIFO nobody reads, so opening it for writing blocks. While a diagnostic
   * is stuck there, the detections' write lock is free (until this round the diagnostic held it across the open).
   */
  @Test
  void aDiagnosticStuckOpeningTheSpoolHoldsNoDetectionLock() throws Exception {
    final Path fifo = dir.resolve("events.fifo");
    Process mkfifo = new ProcessBuilder("mkfifo", fifo.toString()).start();
    org.junit.jupiter.api.Assumptions.assumeTrue(mkfifo.waitFor() == 0, "mkfifo is not available");
    Thread diagnostic = new Thread(new Runnable() {
      @Override public void run() {
        RaspRuntime.writeDiagnostic(fifo.toString(), "{\"event\":\"ohmyrasp-hook-miss\"}");
      }
    }, "test-hook-miss-worker");
    diagnostic.setDaemon(true);
    diagnostic.start();
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (!inOpen(diagnostic) && System.nanoTime() < deadline) {
        Thread.sleep(5);
      }
      assertTrue(inOpen(diagnostic), "the diagnostic never reached the open of the FIFO");
      assertFalse(RaspRuntime.WRITE_LOCK.isLocked(), "a diagnostic stalled in its output holds the detections' lock");
    } finally {
      // A reader lets the open, and so the diagnostic, finish. Opened read-write, the FIFO never blocks this open.
      java.io.RandomAccessFile reader = new java.io.RandomAccessFile(fifo.toFile(), "rw");
      try {
        diagnostic.join(5000);
      } finally {
        reader.close();
      }
    }
  }

  private static boolean inOpen(Thread thread) {
    for (StackTraceElement frame : thread.getStackTrace()) {
      if (frame.getClassName().equals("java.io.FileOutputStream") && frame.getMethodName().startsWith("open")) {
        return true;
      }
    }
    return false;
  }

  /** On a console target a diagnostic is dropped and counted: it would share the detections' stream. */
  @Test
  void aConsoleTargetDropsTheDiagnostic() {
    long before = RaspRuntime.diagnosticsDropped();
    java.io.PrintStream console = System.err;
    java.io.ByteArrayOutputStream captured = new java.io.ByteArrayOutputStream();
    System.setErr(new java.io.PrintStream(captured, true));
    try {
      RaspRuntime.writeDiagnostic("stderr", "{\"event\":\"ohmyrasp-hook-miss\"}");
    } finally {
      System.setErr(console);
    }
    assertEquals(0, captured.size(), "a diagnostic was printed to the detections' console");
    assertEquals(before + 1, RaspRuntime.diagnosticsDropped());
  }

  @Test
  void aConsoleOrNoneTargetNeedsNoSpool() {
    System.setProperty("ohmyrasp.java8.log", "none");
    RaspRuntime.writeDiagnostic(RaspRuntime.resolveLogPath(), "{\"event\":\"ohmyrasp-hook-miss\"}");
    assertFalse(Files.exists(dir.resolve("none")));
  }
}
