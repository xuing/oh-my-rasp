package io.ohmyrasp.agent.process;

import java.io.File;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Inspect the program passed to a shell, or the operands of a supported direct command. */
public final class ProcessLaunchIndicators {
  private static final Pattern STRING_CONVERSION = Pattern.compile("%(?:%|-?[0-9]*(?:\\.[0-9]+)?s)");
  private ProcessLaunchIndicators() {}

  public static boolean matches(List<String> argv, PosixShellCommand shell, WindowsShellCommand windows, Pattern programIndicator,
      Collection<String> fileReaders, Collection<String> sensitivePaths) {
    int exe = PosixShellCommand.executableIndex(argv);
    if (exe >= argv.size() || argv.get(exe) == null) return false;
    String name = new File(argv.get(exe)).getName();
    int first = exe + 1;
    if ("bash".equals(name) && first < argv.size() && "-i".equals(argv.get(first))) return true;
    if (shell != null) {
      LiteralShellCommand literal = shell.literalCommand();
      if (literal == null) return programIndicator.matcher(shell.source()).find();
      if (literal.words.isEmpty()) return false;
      String tool = literal.words.get(0);
      if (tool.indexOf('=') < 0) {
        if ("echo".equals(tool) || stringPrintf(tool, literal.words)) return false;
        // For shell programs, only settle a read on literal absolute paths (with an optional --).
        // Other reader modes may interpret an operand as another program.
        if (fileReaders.contains(PosixShellCommand.basename(tool))) {
          Boolean read = literalFileRead(literal.words, sensitivePaths);
          if (read != null) return read;
        }
      }
      return literal.matchesSource(programIndicator);
    }
    if (windows != null) return windows.matchesIndicator(programIndicator);
    if (fileReaders.contains(name)) {
      // After -- every following argument is a file operand. Before it, unknown
      // switches may consume an argument or request help instead of opening files.
      boolean options = true;
      boolean sensitive = false;
      for (int i = first; i < argv.size(); i++) {
        String arg = argv.get(i);
        if (arg == null) return false;
        if (options && "--".equals(arg)) options = false;
        else if (options && arg.startsWith("-") && !"-".equals(arg)) return false;
        else if (sensitivePaths.contains(arg)) sensitive = true;
      }
      return sensitive;
    }
    if ("nc".equals(name)) {
      for (int i = first; i + 1 < argv.size(); i++) {
        if ("--".equals(argv.get(i))) break;
        if ("-e".equals(argv.get(i))) return "/bin/sh".equals(argv.get(i + 1)) || "/bin/bash".equals(argv.get(i + 1));
      }
    }
    return false;
  }

  // Only a literal string format has output-only operands. Other formats and
  // builtin options may interpret an operand as a number or a variable name.
  private static boolean stringPrintf(String tool, List<String> words) {
    if (!"printf".equals(tool) || words.size() < 2) return false;
    String format = words.get(1);
    if (format.startsWith("-")) return false;
    Matcher conversion = STRING_CONVERSION.matcher(format);
    for (int i = format.indexOf('%'); i >= 0; i = format.indexOf('%', conversion.end())) {
      if (!conversion.region(i, format.length()).lookingAt()) return false;
    }
    return true;
  }

  private static Boolean literalFileRead(List<String> words, Collection<String> sensitivePaths) {
    int first = words.size() > 1 && "--".equals(words.get(1)) ? 2 : 1;
    boolean sensitive = false;
    for (int i = first; i < words.size(); i++) {
      String path = words.get(i);
      if (!path.startsWith("/")) return null;
      if (sensitivePaths.contains(path)) sensitive = true;
    }
    return first < words.size() ? sensitive : null;
  }
}
