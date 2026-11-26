package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The contract tests must not hand a writer a newline or a timestamp it did not write. */
final class Java8ContractFilesTest {
  private static Path file(Path dir, String content) throws Exception {
    Path file = dir.resolve("events.jsonl");
    Files.write(file, content.getBytes(StandardCharsets.UTF_8));
    return file;
  }

  @Test
  void aLineEndedByOneNewlineIsReturnedWithoutIt(@TempDir Path dir) throws Exception {
    assertEquals("{\"a\":1}", Java8ContractFiles.onlyLine(file(dir, "{\"a\":1}\n")));
  }

  @Test
  void aWriterThatDoesNotTerminateTheLineFails(@TempDir Path dir) throws Exception {
    final Path unterminated = file(dir, "{\"a\":1}");
    assertThrows(AssertionError.class, () -> Java8ContractFiles.onlyLine(unterminated));
    assertThrows(AssertionError.class, () -> Java8ContractFiles.onlyLine(file(dir, "{\"a\":1}\n\n")));
    assertThrows(AssertionError.class, () -> Java8ContractFiles.onlyLine(file(dir, "{\"a\":1}\r\n")));
  }

  @Test
  void aTimestampMustBeThirteenDigitEpochMillisecondsInAPlausibleWindow() {
    Java8ContractFiles.normalizeEvent("{\"event\":\"x\",\"timestamp\":1767225600000,\"hook\":\"h\"}", false);
    // Seconds, which the daemon would read as a day in January 1970.
    assertThrows(AssertionError.class,
        () -> Java8ContractFiles.normalizeEvent("{\"event\":\"x\",\"timestamp\":1767225600,\"hook\":\"h\"}", false));
    // Thirteen digits, but before 2020 and after 2100.
    assertThrows(AssertionError.class,
        () -> Java8ContractFiles.normalizeEvent("{\"timestamp\":1000000000000}", false));
    assertThrows(AssertionError.class,
        () -> Java8ContractFiles.normalizeEvent("{\"timestamp\":9999999999999}", false));
    // A string timestamp is not what a backport writes.
    assertThrows(AssertionError.class,
        () -> Java8ContractFiles.normalizeEvent("{\"timestamp\":\"2026-01-01T00:00:00Z\"}", false));
    // A start line has none.
    Java8ContractFiles.normalizeEvent("{\"event\":\"ohmyrasp-java8-agent-start\"}", false);
  }
}
