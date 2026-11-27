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
 * a path of its own: never the detections' queue, valid UTF-8 whatever the default charset, and no waiting behind
 * the detections' write lock for more than a short bound.
 */
final class Java8DiagnosticWriteTest {
  @TempDir Path dir;

  @AfterEach
  void clear() {
    System.clearProperty("ohmyrasp.java8.log");
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

  /** A thread that holds the write lock, as a detection writer stalled in a file call does. */
  @Test
  void aDiagnosticDoesNotWaitBehindTheDetectionWriteLock() throws Exception {
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
      long started = System.nanoTime();
      RaspRuntime.writeDiagnostic(RaspRuntime.resolveLogPath(), "{\"event\":\"ohmyrasp-hook-miss\"}");
      long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);

      assertTrue(millis < 2000, "a diagnostic waited " + millis + " ms behind the detections' lock");
      assertFalse(Files.exists(log), "dropped, not written");
    } finally {
      release.countDown();
      holder.join(5000);
    }

    RaspRuntime.writeDiagnostic(RaspRuntime.resolveLogPath(), "{\"event\":\"ohmyrasp-hook-miss\"}");
    assertTrue(Files.exists(log), "written once the lock is free");
  }

  @Test
  void aConsoleOrNoneTargetNeedsNoSpool() {
    System.setProperty("ohmyrasp.java8.log", "none");
    RaspRuntime.writeDiagnostic(RaspRuntime.resolveLogPath(), "{\"event\":\"ohmyrasp-hook-miss\"}");
    assertFalse(Files.exists(dir.resolve("none")));
  }
}
