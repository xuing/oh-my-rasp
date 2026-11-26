package io.ohmyrasp.agent.contract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Locates and compares the agent-daemon contract fixtures, {@code contracts/agent-daemon/} under
 * {@code java-agent/}. The rules for normalising volatile fields live in that directory's README.
 */
public final class ContractFiles {
  private static final String UPDATE_HINT =
      "If the format change is intended, regenerate with -Pcontracts.update=true (see "
          + "contracts/agent-daemon/README.md), review the diff, and run the daemon tests too.";
  private static final Pattern TIMESTAMP = Pattern.compile("\"timestamp\":\"(\\d{4}-\\d\\d-\\d\\dT[0-9:.]+Z)\"");
  private static final Pattern LATENCY = Pattern.compile("\"latency_us\":(\\d+)");

  /** The timestamp every normalised event carries. */
  public static final String FIXED_TIMESTAMP = "2026-01-01T00:00:00Z";

  /** The latency every normalised event carries. */
  public static final long FIXED_LATENCY_US = 1234;

  private ContractFiles() {}

  public static Path dir() {
    String property = System.getProperty("ohmyrasp.contracts");
    assertTrue(property != null && Files.isDirectory(Path.of(property)),
        "the ohmyrasp.contracts system property must name contracts/agent-daemon (set by build.gradle.kts): " + property);
    return Path.of(property);
  }

  public static boolean updating() {
    return Boolean.parseBoolean(System.getProperty("ohmyrasp.contracts.update", "false"));
  }

  public static String read(String relative) {
    try {
      return Files.readString(dir().resolve(relative), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new UncheckedIOException(relative, e);
    }
  }

  /** The files directly in {@code relative}, sorted by name. */
  public static List<Path> files(String relative) {
    try (Stream<Path> stream = Files.list(dir().resolve(relative))) {
      List<Path> found = new ArrayList<>(stream.filter(Files::isRegularFile).toList());
      found.sort(Path::compareTo);
      return found;
    } catch (IOException e) {
      throw new UncheckedIOException(relative, e);
    }
  }

  /** Compares {@code actual} with the golden file, or rewrites the file when updating. */
  public static void assertGolden(String relative, String actual) {
    Path file = dir().resolve(relative);
    String expected = actual.endsWith("\n") ? actual : actual + "\n";
    if (updating()) {
      try {
        Files.createDirectories(file.getParent());
        Files.writeString(file, expected, StandardCharsets.UTF_8);
      } catch (IOException e) {
        throw new UncheckedIOException(relative, e);
      }
      return;
    }
    assertEquals(read(relative), expected, relative + " no longer matches what the agent writes. " + UPDATE_HINT);
  }

  /**
   * The primary agent's event line with its volatile parts fixed: the timestamp (an ISO-8601
   * instant), the in-hook latency, and the member order of the {@code headers} and {@code details}
   * objects, which the agent emits in hash order.
   */
  public static String normalizeEvent(String line) {
    Matcher timestamp = TIMESTAMP.matcher(line);
    assertTrue(timestamp.find(), "an event line carries an ISO-8601 timestamp string: " + line);
    String fixed = timestamp.replaceFirst("\"timestamp\":\"" + FIXED_TIMESTAMP + "\"");
    fixed = LATENCY.matcher(fixed).replaceFirst("\"latency_us\":" + FIXED_LATENCY_US);
    for (String member : List.of("headers", "details")) {
      fixed = sortMembers(fixed, member);
    }
    return fixed;
  }

  /** Sorts the members of the object that is the value of {@code "name":} by key. */
  static String sortMembers(String line, String name) {
    String marker = "\"" + name + "\":{";
    int start = line.indexOf(marker);
    if (start < 0) {
      return line;
    }
    int open = start + marker.length() - 1;
    List<String> members = new ArrayList<>();
    int depth = 0;
    int memberStart = open + 1;
    boolean inString = false;
    for (int i = open; i < line.length(); i++) {
      char ch = line.charAt(i);
      if (inString) {
        if (ch == '\\') {
          i++;
        } else if (ch == '"') {
          inString = false;
        }
        continue;
      }
      if (ch == '"') {
        inString = true;
      } else if (ch == '{' || ch == '[') {
        depth++;
      } else if (ch == '}' || ch == ']') {
        depth--;
        if (depth == 0) {
          if (i > memberStart) {
            members.add(line.substring(memberStart, i));
          }
          members.sort(String::compareTo);
          return line.substring(0, open + 1) + String.join(",", members) + line.substring(i);
        }
      } else if (ch == ',' && depth == 1) {
        members.add(line.substring(memberStart, i));
        memberStart = i + 1;
      }
    }
    throw new IllegalArgumentException("unterminated " + name + " object: " + line);
  }
}
