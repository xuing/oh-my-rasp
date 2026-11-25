import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Run fixed, local report workloads and compare the child's output with the servlet input. */
public class WindowsProcessCheck {
  private static void check(String track, String mode, String label, String input, boolean policy,
                            String expected, String... command) throws Exception {
    boolean blocked = false;
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(track, input)) {
      Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
      try (Scanner stdout = new Scanner(p.getInputStream(), "UTF-8")) {
        String text = stdout.useDelimiter("\\A").hasNext() ? stdout.next().replace("\r\n", "\n").trim() : "";
        if (p.waitFor() != 0 || !text.equals(expected)) throw new AssertionError(label + ": " + text);
      } finally {
        p.destroy();
      }
    } catch (RuntimeException e) {
      if (!HttpTransportCheck.blocked(e)) throw e;
      blocked = true;
    }
    if (blocked != (policy && mode.equals("block"))) throw new AssertionError(label + ": blocked=" + blocked);
  }

  public static void main(String[] args) throws Exception {
    if ("print".equals(args[0])) { System.out.print(args[1]); return; }
    for (int i = 0; i < Integer.parseInt(args[3]); i++) run(args[0], args[1], args[2]);
  }

  private static void run(String track, String mode, String pwsh) throws Exception {
    String cmd = System.getenv("ComSpec");
    String label = "O'Brien & Sons";
    String java = Paths.get(System.getProperty("java.home"), "bin", "java.exe").toString();
    check(track, mode, "native argv", label, false, label, java, "-cp", System.getProperty("java.class.path"),
        "WindowsProcessCheck", "print", label);
    Path script = Files.createTempFile("weekly-report", ".ps1");
    try {
      Files.write(script, "param([string]$label)\nWrite-Output $label\n".getBytes(StandardCharsets.US_ASCII));
      check(track, mode, "file argument", label, false, label, pwsh, "-NoProfile", "-File", script.toString(), label);
      check(track, mode, "positional argument", label, false, label, pwsh, "-NoProfile", "-CommandWithArgs",
          "Write-Output $args[0]", label);
    } finally { Files.delete(script); }
    check(track, mode, "quoted data", "Sales & Reports", false, "Sales & Reports",
        pwsh, "-NoProfile", "-Command", "Write-Output 'Sales & Reports'");
    check(track, mode, "escaped data", "Sales^&Reports", false, "Sales&Reports",
        cmd, "/d", "/c", "echo Sales^&Reports");
    String ps = "Write-Output weekly; Write-Output ready";
    check(track, mode, "fixed program", "weekly", false, "weekly\nready", pwsh, "-NoProfile", "-Command", ps);
    check(track, mode, "selected PowerShell program", ps, true, "weekly\nready",
        pwsh, "-NoProfile", "-NonInteractive", "-Command", ps);
    String builtIn = "echo weekly&echo ready";
    check(track, mode, "selected cmd program", builtIn, true, "weekly\nready", cmd, "/d", "/c", builtIn);
  }
}
