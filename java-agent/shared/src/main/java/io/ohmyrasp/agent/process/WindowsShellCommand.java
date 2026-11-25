package io.ohmyrasp.agent.process;

import java.io.File;
import java.util.BitSet;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Inline command operands selected by cmd or PowerShell. Script-file and positional arguments are data. */
public final class WindowsShellCommand {
  private final String source;
  private final BitSet operators = new BitSet();
  private final BitSet commands = new BitSet();
  private final String active;

  public static WindowsShellCommand from(List<String> argv) {
    if (argv == null || argv.isEmpty()) return null;
    int i = PosixShellCommand.executableIndex(argv);
    if (i >= argv.size() || argv.get(i) == null) return null;
    String exe = new File(argv.get(i++)).getName().toLowerCase(Locale.ROOT);
    if (exe.endsWith(".exe")) exe = exe.substring(0, exe.length() - 4);
    boolean cmd = "cmd".equals(exe);
    if (!cmd && !"pwsh".equals(exe) && !"powershell".equals(exe)) return null;
    while (i < argv.size()) {
      String flag = argv.get(i++);
      if (flag == null) return null;
      flag = flag.toLowerCase(Locale.ROOT);
      boolean withArgs = "pwsh".equals(exe) && ("-commandwithargs".equals(flag) || "-cwa".equals(flag));
      if (withArgs || (cmd ? "/c".equals(flag) || "/k".equals(flag) : "-command".equals(flag) || "-c".equals(flag))) {
        if (i == argv.size() || argv.get(i) == null || (!cmd && "-".equals(argv.get(i)))) return null;
        // cmd consumes a command line. Java may insert quotes around individual trailing
        // arguments. Do not invent operator positions when that serialization is ambiguous.
        if (cmd && argv.size() > i + 1) {
          for (int j = i; j < argv.size(); j++) {
            String part = argv.get(j);
            if (part == null || part.isEmpty() || part.indexOf('"') >= 0 || part.indexOf(' ') >= 0
                || part.indexOf('\t') >= 0 || part.indexOf('<') >= 0 || part.indexOf('>') >= 0) return null;
          }
        }
        String text = withArgs ? argv.get(i) : String.join(" ", argv.subList(i, argv.size()));
        return new WindowsShellCommand(text, cmd);
      }
      if (cmd) {
        if (!("/d".equals(flag) || "/s".equals(flag) || "/q".equals(flag) || "/a".equals(flag) || "/u".equals(flag)
            || "/v:on".equals(flag) || "/v:off".equals(flag) || "/e:on".equals(flag) || "/e:off".equals(flag)
            || "/f:on".equals(flag) || "/f:off".equals(flag))) return null;
      } else {
        switch (flag) {
          case "-noprofile": case "-nop": case "-nologo": case "-noninteractive": case "-noni":
          case "-noexit": case "-sta": case "-mta": break;
          case "-executionpolicy": case "-ep": case "-inputformat": case "-outputformat":
          case "-workingdirectory": case "-windowstyle": i++; break;
          default: return null;
        }
      }
    }
    return null;
  }

  private WindowsShellCommand(String text, boolean cmd) {
    source = text;
    StringBuilder visible = new StringBuilder(text);
    boolean start = true;
    char quote = 0;
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (!cmd) {
        c = powerShellQuote(c);
        if (quote == 0) {
          int end = literalEnd(text, i);
          if (end > i) {
            for (int j = i; j < end; j++) visible.setCharAt(j, ' ');
            if (c == '@') start = false;
            i = end - 1;
            continue;
          }
        }
      }
      if ((cmd && quote == 0 && c == '^') || (!cmd && quote != '\'' && c == '`')) {
        visible.setCharAt(i, ' ');
        if (i + 1 < text.length()) visible.setCharAt(++i, ' ');
        start = false;
        continue;
      }
      if (quote != 0 || c == '"' || (!cmd && c == '\'')) {
        visible.setCharAt(i, ' ');
        if (c == quote) quote = 0;
        else if (quote == 0) quote = c;
        start = false;
        continue;
      }
      if ("&|".indexOf(c) >= 0 || (!cmd && c == ';') || c == '\n') {
        operators.set(i);
        start = true;
      } else if (!Character.isWhitespace(c)) {
        if (start) commands.set(i);
        start = false;
      }
    }
    active = visible.toString();
  }

  private static char powerShellQuote(char c) {
    switch (c) {
      case '\u2018': case '\u2019': case '\u201a': case '\u201b': return '\'';
      case '\u201c': case '\u201d': case '\u201e': return '"';
      default: return c;
    }
  }

  private static int literalEnd(String text, int i) {
    if (text.startsWith("<#", i)) {
      int nesting = 1;
      for (int j = i + 2; j < text.length() - 1; j++) {
        if (text.startsWith("<#", j)) { nesting++; j++; }
        else if (text.startsWith("#>", j)) {
          if (--nesting == 0) return j + 2;
          j++;
        }
      }
      return text.length();
    }
    char c = text.charAt(i);
    if (c == '#') {
      int end = text.indexOf('\n', i);
      return end < 0 ? text.length() : end;
    }
    if (text.startsWith("--%", i)) {
      int end = i + 3;
      while (end < text.length() && text.charAt(end) != '\n' && text.charAt(end) != '|') end++;
      return end;
    }
    if (c == '@' && i + 1 < text.length()) {
      char delimiter = powerShellQuote(text.charAt(i + 1));
      if (delimiter == '\'' || delimiter == '"') {
        for (int line = text.indexOf('\n', i + 2); line >= 0; line = text.indexOf('\n', line + 1)) {
          if (line + 2 < text.length() && powerShellQuote(text.charAt(line + 1)) == delimiter
              && text.charAt(line + 2) == '@') return line + 3;
        }
        return text.length();
      }
    }
    return i;
  }

  public String source() { return source; }
  public boolean hasControl() { return !operators.isEmpty(); }

  public boolean controlsFrom(Iterable<String> values) {
    if (!hasControl() || values == null) return false;
    for (String value : values) {
      if (value == null || value.length() < 2) continue;
      for (int i = source.indexOf(value); i >= 0; i = source.indexOf(value, i + 1)) {
        int op = operators.nextSetBit(i);
        if (op >= 0 && op < i + value.length()) return true;
      }
    }
    return false;
  }

  boolean matchesIndicator(Pattern pattern) {
    Matcher matcher = pattern.matcher(active);
    for (int i = commands.nextSetBit(0); i >= 0; i = commands.nextSetBit(i + 1)) {
      if (matcher.region(i, active.length()).lookingAt()) return true;
    }
    return false;
  }
}
