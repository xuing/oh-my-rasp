import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Local launch receipts and policy decisions over a fixed, side-effect-free shell program. */
public class ProcessLaunchCheck {
  private static final String PROGRAM = "true|true";
  private static final String[] CONTROL = {"/bin/sh", "-c", PROGRAM};
  interface Action { void run() throws Exception; }

  static void exited(Process p, String expected) throws Exception {
    try (InputStream in = p.getInputStream(); ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
      byte[] chunk = new byte[1024];
      for (int n; (n = in.read(chunk)) >= 0;) bytes.write(chunk, 0, n);
      if (p.waitFor() != 0 || !expected.equals(bytes.toString("UTF-8"))) throw new AssertionError("child receipt");
    } finally { p.destroy(); }
  }

  public static void ordinary() throws Exception {
    exited(new ProcessBuilder("/usr/bin/printf", "%s", "weekly report").start(), "weekly report");
  }

  static final class SpellingReport {
    static void format() throws Exception { ordinary(); }
  }

  static final class CountingArgs extends AbstractList<String> {
    final String[] values = {"/usr/bin/printf", "%s", "quarter two"};
    int reads;
    @Override public int size() { return values.length; }
    @Override public String get(int index) { reads++; return values[index]; }
  }

  private static int runCounted() throws Exception {
    CountingArgs list = new CountingArgs();
    exited(new ProcessBuilder(list).start(), "quarter two");
    return list.reads;
  }

  static boolean check(String track, String mode, String label, String source, boolean policy, Action action) throws Exception {
    boolean denied = false;
    try (HttpTransportCheck.Scope ignored = track.equals("off") ? null : new HttpTransportCheck.Scope(track, source)) {
      action.run();
    } catch (Exception failure) {
      if (!HttpTransportCheck.blocked(failure)) throw failure;
      denied = true;
    }
    System.out.println("row," + label + "," + policy + "," + denied);
    if (!mode.equals("observe") && denied != (mode.equals("block") && policy)) throw new AssertionError(label);
    return denied;
  }

  public static void main(String[] args) throws Exception {
    if (args[0].equals("list-baseline")) {
      System.out.println(runCounted());
      return;
    }
    String track = args[0], mode = args[1];
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    Path dir = Files.createTempDirectory("launch-receipts");
    try {
      // Record only the operand of the literal file-reader case, without opening the named file.
      Path recorder = dir.resolve("cat");
      Files.write(recorder, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n".getBytes(StandardCharsets.US_ASCII));
      if (!recorder.toFile().setExecutable(true, true)) throw new IOException("operand recorder is not executable");
      for (int n = 0; n < rounds; n++) {
        check(track, mode, "ordinary", "weekly", false, ProcessLaunchCheck::ordinary);
        String example = "example: cat /etc/passwd";
        check(track, mode, "print-command-text", "weekly", false,
            () -> exited(new ProcessBuilder("/usr/bin/printf", "%s", example).start(), example));
        check(track, mode, "print-positional-data", "weekly", false, () -> exited(
            new ProcessBuilder("/bin/sh", "-c", "printf '%s' \"$1\"", "report", example).start(), example));
        check(track, mode, "quoted-shell-report", "weekly", false, () -> exited(
            new ProcessBuilder("/bin/sh", "-c", "printf '%s' 'example: cat /etc/passwd'").start(), example));
        check(track, mode, "shell-comment", "weekly", false, () -> exited(
            new ProcessBuilder("/bin/sh", "-c", "printf '%s' weekly # example: cat /etc/passwd").start(), "weekly"));
        check(track, mode, "comment-next-to-command", "weekly", false, () -> exited(
            new ProcessBuilder("/bin/sh", "-c", "# example: cat /etc/passwd\n/bin/true # cat /etc/passwd").start(), ""));
        check(track, mode, "comment-only", "weekly", false, () -> exited(
            new ProcessBuilder("/bin/sh", "-c", "# example: cat /etc/passwd").start(), ""));
        check(track, mode, "shell-other-file", "weekly", false, () -> {
          ProcessBuilder reader = new ProcessBuilder("/bin/sh", "-c", "cat /etc/passwd.example");
          reader.environment().put("PATH", dir.toString());
          exited(reader.start(), "/etc/passwd.example\n");
        });
        check(track, mode, "shell-file-operand", "weekly", true, () -> {
          ProcessBuilder reader = new ProcessBuilder("/bin/sh", "-c", "cat '/etc/passwd'");
          reader.environment().put("PATH", dir.toString());
          exited(reader.start(), "/etc/passwd\n");
        });
        check(track, mode, "spelling-report", "weekly", false, SpellingReport::format);
        check(track, mode, "empty-runtime", PROGRAM, false, () -> {
          try {
            Runtime.getRuntime().exec("");
            throw new AssertionError("empty command accepted");
          } catch (IllegalArgumentException expected) { }
        });
        check(track, mode, "reflective-caller", "weekly", false, () -> ProcessLaunchCheck.class.getMethod("ordinary").invoke(null));
        check(track, mode, "reflective-api", "weekly", false, () -> {
          ProcessBuilder b = new ProcessBuilder("/usr/bin/printf", "%s", "weekly");
          exited((Process) ProcessBuilder.class.getMethod("start").invoke(b), "weekly");
        });
        check(track, mode, "argument-boundaries", "weekly", false, () -> {
          exited(new ProcessBuilder("/usr/bin/printf", "[%s]", "alpha beta", "gamma").start(), "[alpha beta][gamma]");
          exited(new ProcessBuilder("/usr/bin/printf", "[%s]", "alpha", "beta gamma").start(), "[alpha][beta gamma]");
        });
        check(track, mode, "fixed-program", "weekly", false, () -> exited(new ProcessBuilder(CONTROL).start(), ""));
        String reportProgram = "printf weekly; printf ready";
        check(track, mode, "syntax-check", reportProgram, false, () -> exited(
            new ProcessBuilder("/bin/sh", "-n", "-c", reportProgram).start(), ""));
        check(track, mode, "execution-restored", reportProgram, true, () -> exited(
            new ProcessBuilder("/bin/sh", "-n", "+n", "-c", reportProgram).start(), "weeklyready"));
        check(track, mode, "runtime-string", PROGRAM, true,
            () -> exited(Runtime.getRuntime().exec("/bin/sh -c " + PROGRAM), ""));
        check(track, mode, "runtime-array", PROGRAM, true, () -> exited(Runtime.getRuntime().exec(CONTROL), ""));
        check(track, mode, "builder", PROGRAM, true, () -> exited(new ProcessBuilder(CONTROL).start(), ""));
        check(track, mode, "mutable-list", "weekly", false, () -> System.out.println("reads," + runCounted()));
        check(track, mode, "invalid-argument", PROGRAM, false, () -> {
          try {
            new ProcessBuilder(CONTROL[0], CONTROL[1], PROGRAM, "invalid\u0000arg").start();
            throw new AssertionError("invalid argument accepted");
          } catch (IOException invalid) { if (HttpTransportCheck.blocked(invalid)) throw invalid; }
        });
        Path output = dir.resolve("existing-report");
        Files.write(output, "previous".getBytes(StandardCharsets.UTF_8));
        boolean blocked = check(track, mode, "redirect", PROGRAM, true, () -> exited(new ProcessBuilder(CONTROL).redirectOutput(output.toFile()).start(), ""));
        String receipt = new String(Files.readAllBytes(output), StandardCharsets.UTF_8);
        System.out.println("redirect," + receipt.equals("previous"));
        if (receipt.equals("previous") != blocked) throw new AssertionError("redirect changed");
      }
    } finally {
      Files.deleteIfExists(dir.resolve("cat"));
      Files.deleteIfExists(dir.resolve("existing-report"));
      Files.delete(dir);
    }
  }
}
