package io.ohmyrasp.agent.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** What a line's start accepts as its preload list, before it loads anything. */
final class PreloadTest {
  @TempDir Path work;

  @Test
  void aListWhoseClassFilesAreThereIsReturnedInOrder() throws Exception {
    File jar = jar("a.B\na.C\n", "a/B.class", "a/C.class");
    assertEquals(Arrays.asList("a.B", "a.C"), Preload.verified(jar, "m"));
  }

  @Test
  void anEmptyListIsRejected() throws Exception {
    File jar = jar("\n");
    IllegalStateException failure = assertThrows(IllegalStateException.class, () -> Preload.verified(jar, "m"));
    assertTrue(failure.getMessage().contains("has an empty META-INF/ohmyrasp/preload/m.txt"), failure.getMessage());
  }

  @Test
  void aDirectoryEntryNamedLikeAClassFileIsNotOne() throws Exception {
    File jar = jar("a.B\n", "a/B.class/");
    IllegalStateException failure = assertThrows(IllegalStateException.class, () -> Preload.verified(jar, "m"));
    assertTrue(failure.getMessage().contains("holds no a/B.class"), failure.getMessage());
  }

  private File jar(String list, String... entries) throws IOException {
    File file = work.resolve("agent" + System.nanoTime() + ".jar").toFile();
    JarOutputStream out = new JarOutputStream(new FileOutputStream(file));
    try {
      out.putNextEntry(new JarEntry(Preload.INDEX + "m.txt"));
      out.write(list.getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
      for (String entry : entries) {
        out.putNextEntry(new JarEntry(entry));
        if (!entry.endsWith("/")) {
          out.write(new byte[] {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE});
        }
        out.closeEntry();
      }
    } finally {
      out.close();
    }
    return file;
  }
}
