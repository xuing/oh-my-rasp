package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Locates and compares the agent-daemon contract fixtures, {@code contracts/agent-daemon/} under
 * {@code java-agent/}. The rules for normalising volatile fields live in that directory's README.
 * The three backport lines run this one copy.
 */
final class Java8ContractFiles {
  private static final String UPDATE_HINT =
      "If the format change is intended, regenerate with -Pcontracts.update=true (see "
          + "contracts/agent-daemon/README.md), review the diff, and run the daemon tests too.";

  /** The timestamp, in epoch milliseconds, that every normalised backport event carries. */
  static final String FIXED_TIMESTAMP_MILLIS = "1767225600000";

  /** The latency that every normalised event carries. */
  static final String FIXED_LATENCY_US = "1234";

  /** What the line's own token (the last segment of its package) becomes in a golden file shared by the lines. */
  static final String LINE_PLACEHOLDER = "javaN";

  private Java8ContractFiles() {}

  static Path dir() {
    String property = System.getProperty("ohmyrasp.contracts");
    assertTrue(property != null && Files.isDirectory(Paths.get(property)),
        "the ohmyrasp.contracts system property must name contracts/agent-daemon (set by build.gradle.kts): " + property);
    return Paths.get(property);
  }

  static boolean updating() {
    return Boolean.parseBoolean(System.getProperty("ohmyrasp.contracts.update", "false"));
  }

  /** This line's token: the last segment of its package, for example {@code java11}. */
  static String lineToken() {
    String name = Java8RaspHooks.class.getPackage().getName();
    return name.substring(name.lastIndexOf('.') + 1);
  }

  static String read(String relative) {
    try {
      return new String(Files.readAllBytes(dir().resolve(relative)), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new UncheckedIOException(relative, e);
    }
  }

  /** The files directly in {@code relative}, sorted by name. */
  static List<Path> files(String relative) {
    List<Path> found = new ArrayList<Path>();
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir().resolve(relative))) {
      for (Path path : stream) {
        if (Files.isRegularFile(path)) {
          found.add(path);
        }
      }
    } catch (IOException e) {
      throw new UncheckedIOException(relative, e);
    }
    Collections.sort(found);
    return found;
  }

  /** Compares {@code actual} with the golden file, or rewrites the file when updating. */
  static void assertGolden(String relative, String actual) {
    Path file = dir().resolve(relative);
    String expected = actual.endsWith("\n") ? actual : actual + "\n";
    if (updating()) {
      try {
        Files.createDirectories(file.getParent());
        Files.write(file, expected.getBytes(StandardCharsets.UTF_8));
      } catch (IOException e) {
        throw new UncheckedIOException(relative, e);
      }
      return;
    }
    assertEquals(read(relative), expected, relative + " no longer matches what the agent writes. " + UPDATE_HINT);
  }

  /**
   * A backport event line with its volatile parts fixed: the timestamp (epoch milliseconds), the
   * latency, and the Java version and vendor of a start line. With {@code sharedAcrossLines} the
   * line's own token, which names it in rule ids and in message text ("Java 11 ..."), becomes a
   * placeholder, so one golden file serves the three lines.
   */
  static String normalizeEvent(String line, boolean sharedAcrossLines) {
    String fixed = line;
    if (sharedAcrossLines) {
      String token = lineToken();
      fixed = fixed
          .replace("\"" + token + "_", "\"" + LINE_PLACEHOLDER + "_")
          .replace("Java " + token.substring("java".length()) + " ", "Java N ");
    }
    // A start line has no timestamp.
    fixed = replaceOnce(fixed, "\"timestamp\":\\d+", "\"timestamp\":" + FIXED_TIMESTAMP_MILLIS, false);
    fixed = replaceOnce(fixed, "\"latency_us\":\\d+", "\"latency_us\":" + FIXED_LATENCY_US, false);
    fixed = replaceOnce(fixed, "\"java_version\":\"[^\"]*\"", "\"java_version\":\"1.8.0_402\"", false);
    fixed = replaceOnce(fixed, "\"java_vendor\":\"[^\"]*\"", "\"java_vendor\":\"Example Vendor\"", false);
    return fixed;
  }

  private static String replaceOnce(String line, String regex, String replacement, boolean required) {
    java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(regex).matcher(line);
    if (!matcher.find()) {
      assertTrue(!required, "expected " + regex + " in " + line);
      return line;
    }
    return matcher.replaceFirst(java.util.regex.Matcher.quoteReplacement(replacement));
  }
}
