package io.ohmyrasp.agent.hookmiss;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the agent accepts as its expectation table: a complete, well formed table of the family asked for, read
 * from the agent's own JAR; anything else leaves the report off.
 */
final class HookExpectationsTest {
  private static final String ROW = "SqlHookModule a/B report m(I)V=hook,other n()Ljava/lang/String;=hook\n";

  /** The text of a generated table of {@code family} with these rows. */
  private static String generated(String family, String rows) {
    String body = "# comment\n#! family " + family + "\n" + rows;
    int count = rows.isEmpty() ? 0 : rows.split("\n").length;
    return body + "#! end rows=" + count + " sha256=" + HookExpectations.sha256(body.getBytes(StandardCharsets.UTF_8)) + "\n";
  }

  @Test
  void aGeneratedTableIsReadWithItsCallees() {
    HookExpectations table = HookExpectations.parseVerified(generated("primary", ROW), "primary");

    HookExpectation pair = table.forUnit("SqlHookModule").get("a/B");
    assertArrayEquals(new String[] {"m(I)V", "n()Ljava/lang/String;"}, pair.methods);
    assertArrayEquals(new String[] {"hook", "other"}, pair.callees[0]);
    assertArrayEquals(new String[] {"hook"}, pair.callees[1]);
    assertEquals(1, table.size());
  }

  @Test
  void aTableCutAtARowBoundaryOrChangedAfterItWasGeneratedIsRejected() {
    String two = ROW + "FileHookModule c/D report read()I=beforeRead\n";
    String whole = generated("primary", two);
    String cut = whole.substring(0, whole.indexOf("FileHookModule"));

    assertThrows(IllegalArgumentException.class, () -> HookExpectations.parseVerified(cut, "primary"), "no trailer");
    assertThrows(IllegalArgumentException.class, () -> HookExpectations.parseVerified(cut + whole.substring(whole.indexOf("#! end")), "primary"),
        "a trailer that no longer matches what precedes it");
    assertThrows(IllegalArgumentException.class,
        () -> HookExpectations.parseVerified(whole.replace("beforeRead", "beforeWrite"), "primary"), "an edited row");
    assertThrows(IllegalArgumentException.class, () -> HookExpectations.parseVerified("", "primary"), "empty input");
    assertThrows(IllegalArgumentException.class, () -> HookExpectations.parseVerified("# only a comment\n", "primary"));
    assertThrows(IllegalArgumentException.class,
        () -> HookExpectations.parseVerified(whole.replace("rows=2", "rows=3"), "primary"), "a wrong row count");
  }

  @Test
  void aTableOfAnotherFamilyOrWithAUnitOfAnotherFamilyIsRejected() {
    assertThrows(IllegalArgumentException.class, () -> HookExpectations.parseVerified(generated("backport", ROW), "primary"),
        "the backport table where the primary's was asked for");
    assertThrows(IllegalArgumentException.class,
        () -> HookExpectations.parseVerified(generated("primary", "Java{N}JdbcTransformer a/B report m()V=hook\n"), "primary"),
        "a backport unit in the primary table");
    assertThrows(IllegalArgumentException.class,
        () -> HookExpectations.parseVerified(generated("backport", ROW), "backport"), "a primary unit in the backport table");
    assertThrows(IllegalArgumentException.class,
        () -> HookExpectations.parseVerified("SqlHookModule a/B report m()V=hook\n#! family primary\n#! end rows=1 sha256=x\n", "primary"));
  }

  @Test
  void aGeneratedMethodWithNoCalleeIsRejectedButAHandWrittenOneIsNot() {
    assertThrows(IllegalArgumentException.class,
        () -> HookExpectations.parseVerified(generated("primary", "SqlHookModule a/B report m()V\n"), "primary"));
    assertEquals(1, HookExpectations.parse("SqlHookModule a/B report m()V\n").size());
  }

  @Test
  void aTableWithAnIncompleteDescriptorOrADuplicateIsRejected() {
    for (String method : Arrays.asList("m(", "m(I", "m(I)", "m(Lfoo)V", "m(Lfoo;V", "m(I)Lfoo", "m(X)V", "m(I)VV", "m()", "m(I)V)", "(I)V",
        "m(I)[", "m(Ljava.lang.String;)V", "m(I)V=", "m(I)V=a,,b", "m(I)V=1a")) {
      assertThrows(IllegalArgumentException.class, () -> HookExpectations.parse("U a/B report " + method + "\n"), method);
    }
    for (String method : Arrays.asList("m()V", "m(I[J)V", "<init>(Ljava/lang/String;[[I)V", "m(IJ)Ljava/util/List;", "m()[Ljava/lang/Object;")) {
      assertEquals(1, HookExpectations.parse("U a/B report " + method + "\n").size(), method);
    }
    assertThrows(IllegalArgumentException.class, () -> HookExpectations.parse("U a/B report m()V\nU a/B absent n()V\n"), "a pair twice");
    assertThrows(IllegalArgumentException.class, () -> HookExpectations.parse("U a/B report m()V m()V\n"), "a method twice");
    assertThrows(IllegalArgumentException.class, () -> HookExpectations.parse("U a.B report m()V\n"), "a dotted class");
  }

  @Test
  void theShippedTablesAreCompleteForTheirFamilies() throws Exception {
    for (String family : Arrays.asList("primary", "backport")) {
      HookExpectations table = HookExpectations.load(family);
      assertTrue(table.size() > 100, family);
    }
  }

  @Test
  void theTableIsReadFromTheAgentJarItselfAndASizeLimitHolds(@TempDir Path dir) throws Exception {
    Path jar = dir.resolve("agent.jar");
    writeJar(jar, HookExpectations.RESOURCE_DIRECTORY + "primary.txt", generated("primary", ROW));
    assertEquals(1, HookExpectations.load("primary", jar.toFile()).size());

    assertThrows(IOException.class, () -> HookExpectations.load("backport", jar.toFile()), "the JAR holds no table of that family");

    Path wrongFamily = dir.resolve("wrong.jar");
    writeJar(wrongFamily, HookExpectations.RESOURCE_DIRECTORY + "primary.txt", generated("backport", ROW));
    assertThrows(IllegalArgumentException.class, () -> HookExpectations.load("primary", wrongFamily.toFile()));

    Path large = dir.resolve("large.jar");
    writeJar(large, HookExpectations.RESOURCE_DIRECTORY + "primary.txt",
        hashes(HookExpectations.MAX_BYTES) + "\n" + generated("primary", ROW));
    assertThrows(IOException.class, () -> HookExpectations.load("primary", large.toFile()), "larger than the limit");
  }

  private static String hashes(int count) {
    StringBuilder out = new StringBuilder(count);
    for (int i = 0; i < count; i++) {
      out.append('#');
    }
    return out.toString();
  }

  private static void writeJar(Path jar, String entry, String text) throws IOException {
    try (OutputStream out = Files.newOutputStream(jar); ZipOutputStream zip = new ZipOutputStream(out)) {
      zip.putNextEntry(new ZipEntry(entry));
      zip.write(text.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
  }
}
