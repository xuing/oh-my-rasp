package io.ohmyrasp.agent.process;

import java.util.BitSet;
import java.util.List;
import java.util.StringTokenizer;

/** The inline program of a POSIX shell invocation. Positional arguments remain separate. */
public final class PosixShellCommand {
  private final String source;
  private final boolean plainInline;
  private final BitSet operators = new BitSet();
  private final BitSet commandWords = new BitSet();
  private final boolean unclosedQuote;

  /** Runtime.exec(String) uses the default StringTokenizer delimiters and keeps quote characters. */
  public static String[] runtimeArguments(String line) {
    StringTokenizer tokens = new StringTokenizer(line == null ? "" : line);
    String[] result = new String[tokens.countTokens()];
    for (int i = 0; i < result.length; i++) {
      result[i] = tokens.nextToken();
    }
    return result;
  }

  static String basename(String name) {
    return name == null ? "" : name.substring(name.lastIndexOf('/') + 1);
  }

  public static boolean isShell(String executable) {
    switch (basename(executable)) {
      case "sh": case "bash": case "dash": case "ash": case "ksh": case "zsh":
        return true;
      default:
        return false;
    }
  }

  static int executableIndex(List<String> argv) {
    if (argv == null || argv.isEmpty()) return 0;
    int i = 0;
    if ("env".equals(basename(argv.get(i)))) {
      i++;
      while (i < argv.size()) {
        String option = argv.get(i);
        if ("--".equals(option)) {
          i++;
          break;
        }
        if ("-i".equals(option) || "--ignore-environment".equals(option)
            || (option != null && option.indexOf('=') > 0 && !option.startsWith("-"))) {
          i++;
        } else {
          break;
        }
      }
    }
    return i;
  }

  public static PosixShellCommand from(List<String> argv) {
    if (argv == null || argv.isEmpty()) {
      return null;
    }
    int i = executableIndex(argv);
    if (i >= argv.size()) {
      return null;
    }
    String name = basename(argv.get(i++));
    if (!isShell(name)) {
      return null;
    }
    int firstOption = i;
    boolean inline = false;
    while (i < argv.size()) {
      String option = argv.get(i);
      if ("--".equals(option)) {
        i++;
        break;
      }
      if (option == null || option.length() < 2 || (option.charAt(0) != '-' && option.charAt(0) != '+')) {
        break;
      }
      i++;
      if ("-o".equals(option) || "+o".equals(option) || "-O".equals(option) || "+O".equals(option)
          || "--rcfile".equals(option) || "--init-file".equals(option)) {
        i++;
      } else if (!option.startsWith("--") && option.charAt(0) == '-' && option.indexOf('c') > 0) {
        inline = true;
      }
    }
    if (!inline || i >= argv.size() || argv.get(i) == null) return null;
    boolean plain = i == firstOption + 1 && "-c".equals(argv.get(firstOption))
        && ("sh".equals(name) || "dash".equals(name) || "bash".equals(name));
    return new PosixShellCommand(argv.get(i), plain);
  }

  private PosixShellCommand(String program, boolean plainInline) {
    this.plainInline = plainInline;
    source = program;
    char quote = 0;
    boolean backtick = false;
    boolean wordStart = true;
    boolean commandStart = true;
    for (int i = 0; i < program.length(); i++) {
      char c = program.charAt(i);
      if (quote == 0 && wordStart && c == '#') {
        i = program.indexOf('\n', i);
        if (i < 0) {
          break;
        }
        c = '\n';
      }
      if (quote != '\'' && c == '\\' && i + 1 < program.length() && program.charAt(i + 1) == '\n') {
        i++;
        continue;
      }
      if (quote == 0 && (c == ' ' || c == '\t' || c == '\n')) {
        wordStart = true;
        if (c == '\n') commandStart = true;
        continue;
      }
      if (commandStart) {
        commandWords.set(i);
        commandStart = false;
      }
      wordStart = false;
      if (c == '\\' && quote != '\'' && i + 1 < program.length()) {
        char next = program.charAt(i + 1);
        if (quote == 0 || "\\`$\"\n".indexOf(next) >= 0) {
          i++;
          continue;
        }
      }
      if (c == '\'' || c == '"') {
        if (quote == 0) quote = c;
        else if (quote == c) quote = 0;
        continue;
      }
      if (quote != '\'' && c == '`') {
        operators.set(i);
        backtick = !backtick;
      } else if (quote != '\'' && c == '$' && (program.startsWith("$(", i)
          || program.startsWith("${IFS}", i) || isIfsExpansion(program, i))) {
        operators.set(i);
      } else if (quote == 0 && ";&|<>".indexOf(c) >= 0) {
        operators.set(i);
        wordStart = true;
        commandStart = ";&|".indexOf(c) >= 0;
      }
    }
    unclosedQuote = quote != 0 || backtick;
  }

  private static boolean isIfsExpansion(String program, int i) {
    if (!program.startsWith("$IFS", i)) {
      return false;
    }
    int end = i + 4;
    return end == program.length() || !(Character.isLetterOrDigit(program.charAt(end)) || program.charAt(end) == '_');
  }

  LiteralShellCommand literalCommand() { return plainInline ? LiteralShellCommand.parse(source) : null; }

  public String source() { return source; }
  public boolean hasOperator() { return !operators.isEmpty(); }
  public boolean hasUnclosedQuote() { return unclosedQuote; }

  /** Associate request text with an active operator or the command it selects. */
  public boolean containsControlFrom(String input) {
    if (!hasOperator() || input == null || input.length() < 2) {
      return false;
    }
    int start = source.indexOf(input);
    int operator = operators.nextSetBit(0);
    while (start >= 0) {
      int end = start + input.length();
      if (operator >= 0 && operator < start) {
        operator = operators.nextSetBit(start);
      }
      if (operator >= 0 && operator < end) {
        return true;
      }
      if (commandWords.get(start)
          && (end == source.length() || Character.isWhitespace(source.charAt(end)) || operators.get(end))) {
        return true;
      }
      start = source.indexOf(input, start + 1);
    }
    return false;
  }
}
