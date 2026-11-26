package io.ohmyrasp.agent.contract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The contract tests must not hand a writer a newline it did not write. */
final class ContractFilesTest {
  private static Path file(Path dir, String content) throws Exception {
    Path file = dir.resolve("events.jsonl");
    Files.write(file, content.getBytes(StandardCharsets.UTF_8));
    return file;
  }

  @Test
  void aLineEndedByOneNewlineIsReturnedWithoutIt(@TempDir Path dir) throws Exception {
    assertEquals("{\"a\":1}", ContractFiles.onlyLine(file(dir, "{\"a\":1}\n")));
  }

  @Test
  void aWriterThatDoesNotTerminateTheLineFails(@TempDir Path dir) throws Exception {
    assertThrows(AssertionError.class, () -> ContractFiles.onlyLine(file(dir, "{\"a\":1}")));
  }

  @Test
  void moreThanOneLineOrAnotherTerminatorFails(@TempDir Path dir) throws Exception {
    assertThrows(AssertionError.class, () -> ContractFiles.onlyLine(file(dir, "{\"a\":1}\n\n")));
    assertThrows(AssertionError.class, () -> ContractFiles.onlyLine(file(dir, "{\"a\":1}\n{\"b\":2}\n")));
    assertThrows(AssertionError.class, () -> ContractFiles.onlyLine(file(dir, "{\"a\":1}\r\n")));
    assertThrows(AssertionError.class, () -> ContractFiles.onlyLine(file(dir, "\n")));
  }
}
