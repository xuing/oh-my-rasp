package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The start-up warm-up runs the hooks on harmless input and leaves no trace: no event, no file, no request state. */
final class WarmupTest {
  @AfterEach
  void reset() {
    OhMyRaspHooks.reportTo(null);
    System.clearProperty("ohmyrasp.block");
  }

  @Test
  void theWarmUpWritesNoEventAndLeavesNoFileEvenWhenBlocking(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));
    // Blocking on, so a detection on any warm-up input would be written and thrown, not only logged.
    System.setProperty("ohmyrasp.block", "true");

    // The control: the same logger and the same setting do write an event for a real detection, so an empty
    // log after the warm-up means the warm-up detected nothing and not that nothing could be written.
    OhMyRaspHooks.beforeUrlOpen(new URL("http://169.254.169.254/latest/meta-data/"));
    assertTrue(Files.size(log) > 0, "the control detection was not written");
    Files.delete(log);

    Warmup.run();

    assertFalse(Files.exists(log), "the warm-up wrote to the event log");
    try (Stream<Path> files = Files.list(dir)) {
      assertEquals(List.of(), files.toList(), "the warm-up left a file behind");
    }
    assertFalse(OhMyRaspHooks.currentRequest().active(), "the warm-up left a request open on this thread");
  }

  @Test
  void theWarmUpRunsTwiceWithTheSameResult() {
    Warmup.run();
    Warmup.run();
  }

  private static JsonEventLogger logger(Path log) {
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    return JsonEventLogger.newForTesting(null, log.toString(), 0, true, console, console);
  }
}
