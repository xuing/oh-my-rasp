package io.ohmyrasp.agent.file;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HostReadPathTest {
  @Test
  void matchingLexicalNamesDoesNotJoinRequestsAcrossDifferentFiles(@TempDir Path root) throws Exception {
    assumeTrue(File.separatorChar == '/');
    Path display = Files.createDirectory(root.resolve("reports"));
    Path storage = Files.createDirectory(root.resolve("storage"));
    Path branch = Files.createDirectory(storage.resolve("branch"));
    Path supplied = Files.writeString(display.resolve("weekly.csv"), "public");
    Path actual = Files.writeString(storage.resolve("weekly.csv"), "separate");
    Path link = Files.createSymbolicLink(display.resolve("catalog"), branch);
    Path opened = link.resolve("../weekly.csv");

    assertTrue(opened.normalize().equals(supplied));
    assertTrue(Files.isSameFile(opened, actual));
    assertFalse(HostReadPath.selected(opened.toString(), List.of(supplied.toString())));
    assertTrue(HostReadPath.selected(opened.toString(), List.of(opened.toString())));
  }
}
