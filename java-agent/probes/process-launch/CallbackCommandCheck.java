import java.util.Map;

/** Process receipts from a fixed report printer and a transfer to a loopback HTTP proxy. */
public class CallbackCommandCheck {
  public static void main(String[] args) throws Exception {
    for (int n = 0; n < Integer.parseInt(args[2]); n++) run(args[0], args[1]);
  }

  private static void run(String mode, String curl) throws Exception {
    String example = "curl http://probe.dnslog.cn/a";
    ProcessLaunchCheck.check("main", mode, "print-example", "weekly", false,
        () -> ProcessLaunchCheck.exited(new ProcessBuilder("/usr/bin/printf", "%s", example).start(), example));
    try (HttpTransportCheck.Fixture proxy = new HttpTransportCheck.Fixture()) {
      transfer(mode, curl, proxy, "lookalike", "http://notdnslog.cn/report", false);
      transfer(mode, curl, proxy, "path-text", "http://reports.invalid/guide/dnslog.cn/a", false);
      transfer(mode, curl, proxy, "callback", "http://probe.dnslog.cn/report", true);
      transfer(mode, curl, proxy, "absolute-name", "http://probe.dnslog.cn./report", true);
    }
  }

  private static void transfer(String mode, String curl, HttpTransportCheck.Fixture proxy,
      String label, String url, boolean policy) throws Exception {
    int before = proxy.receipts.get();
    boolean denied = ProcessLaunchCheck.check("main", mode, label, "weekly", policy, () -> {
      ProcessBuilder builder = new ProcessBuilder(curl, "-q", url);
      Map<String, String> env = builder.environment();
      env.clear();
      env.put("http_proxy", proxy.root);
      ProcessLaunchCheck.exited(builder.start(), "weekly");
    });
    if (proxy.receipts.get() != before + (denied ? 0 : 1)) throw new AssertionError(label);
  }
}
