package io.ohmyrasp.agent.process;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class PosixShellCommandTest {
  private static List<String> literalWords(String source) {
    LiteralShellCommand parsed = LiteralShellCommand.parse(source);
    return parsed == null ? null : parsed.words;
  }

  @Test
  void extractsExecutionOnlyWhenNonInteractiveNoexecIsOff() {
    String source = "printf weekly; printf ready";
    assertNull(PosixShellCommand.from(List.of("dash", "-nc", source)));
    assertNull(PosixShellCommand.from(List.of("bash", "-o", "noexec", "-c", source)));
    assertEquals(source, PosixShellCommand.from(List.of("bash", "-n", "+o", "noexec", "-c", source)).source());
    assertEquals(source, PosixShellCommand.from(List.of("bash", "-in", "-c", source)).source());
  }

  @Test
  void runtimeStringHasJdkTokenBoundaries() {
    assertArrayEquals(new String[]{"printf", "%s", "'first", "last'"},
        PosixShellCommand.runtimeArguments("printf\t%s  'first last'"));
    assertEquals(0, PosixShellCommand.runtimeArguments("  \r\n").length);
  }

  @Test
  void separatesShellOptionsAndDataFromTheProgram() {
    String program = "printf '%s' \"$1\"";
    assertEquals(program, PosixShellCommand.from(
        List.of("/usr/bin/env", "LC_ALL=C", "/bin/bash", "-o", "pipefail", "-lc", "--", program, "_", "|")).source());
    assertNull(PosixShellCommand.from(List.of("sh", "report.sh", "-c", "data")));
    assertNull(PosixShellCommand.from(List.of("printf", "sh", "-c", "data")));
    assertNull(PosixShellCommand.from(List.of("sh", "-c")));
  }

  @Test
  void literalWordsPreserveQuotedDataAndEmptyArguments() {
    assertEquals(List.of(), literalWords("  # first\n# second"));
    assertEquals(List.of("printf", "%s", "", "quarter two", "x#y"), literalWords(
        "# report\nprintf '%s' '' quarter\\ two x#y ; # comment\n"));
    assertEquals(List.of("cat", "/reports/weekly"), literalWords("cat /reports/'week'\"ly\""));
    assertEquals(List.of("printf", "%s", "pre\\fix"), literalWords("printf %s \"pre\\fix\""));
    assertEquals(List.of("echo", "weekly"), literalWords("echo week\\\nly"));
  }

  @Test
  void complexShellProgramsRemainAvailableForTheSourceRules() {
    for (String program : List.of("printf %s \"$1\"", "printf x | cat", "printf x\ncat /etc/passwd",
        "echo value > report", "echo *.txt", "printf 'unfinished", "echo `date`", "echo $'text'")) {
      assertNull(literalWords(program), program);
    }
    assertNull(PosixShellCommand.from(List.of("bash", "-lc", "echo report")).literalCommand());
  }

  @Test
  void treatsOnlyActivePunctuationAndWholeCommandWordsAsControlEvidence() {
    var script = PosixShellCommand.from(List.of("sh", "-c", "printf 'R&D' # order | cat\nprintf ok; date"));
    assertFalse(script.containsControlFrom("R&D"));
    assertFalse(script.containsControlFrom("order | cat"));
    assertFalse(script.containsControlFrom("dat"));
    assertTrue(script.containsControlFrom("ok; date"));
    assertTrue(script.containsControlFrom("date"));
    assertTrue(PosixShellCommand.from(List.of("sh", "-c", "printf 'unfinished")).hasUnclosedQuote());
    assertFalse(PosixShellCommand.from(List.of("sh", "-c", "printf \"O'Brien\"")).hasUnclosedQuote());
  }
}
