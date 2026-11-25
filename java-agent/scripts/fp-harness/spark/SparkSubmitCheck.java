import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.http.HttpServletRequest;
import org.apache.spark.deploy.rest.SubmitRequestServlet;

public final class SparkSubmitCheck {
  private static final String REMOTE = "{\"action\":\"CreateSubmissionRequest\",\"appResource\":"
      + "\"https://artifacts.example.invalid/weekly.jar\",\"mainClass\":\"reports.Weekly\"}";
  private static final String ROLE = "submitter";

  private static long findings() {
    java.nio.file.Path path = java.nio.file.Paths.get(System.getProperty("ohmyrasp.log"));
    if (!java.nio.file.Files.exists(path)) return 0;
    try (java.util.stream.Stream<String> lines = java.nio.file.Files.lines(path)) {
      return lines.filter(line -> line.contains("request_remote_job_submission")).count();
    } catch (java.io.IOException e) { throw new AssertionError(e); }
  }

  private static void check(String mode, String label, String role, boolean member, boolean available,
      boolean creation, boolean valid, String descriptor, boolean denial) {
    if (role == null) System.clearProperty("ohmyrasp.spark.submitRole");
    else System.setProperty("ohmyrasp.spark.submitRole", role);
    AtomicInteger decisions = new AtomicInteger();
    HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(SparkSubmitCheck.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class}, (proxy, method, args) -> {
          if (method.getName().equals("getRequestURI")) return "/reports/" + label;
          if (method.getName().equals("isUserInRole")) {
            if (!ROLE.equals(args[0])) throw new AssertionError("incorrect role");
            decisions.incrementAndGet();
            if (!available) throw new IllegalStateException("role service unavailable");
            return member;
          }
          return null;
        });
    SubmitRequestServlet servlet = new SubmitRequestServlet();
    servlet.descriptor = descriptor;
    servlet.creation = creation;
    servlet.valid = valid;
    long before = findings();
    boolean blocked = false;
    try { servlet.doPost(request, null); }
    catch (RuntimeException e) {
      if (!e.getClass().getSimpleName().endsWith("RaspBlockException")) throw e;
      blocked = true;
    }
    System.out.println(label + "=" + (blocked ? "blocked" : servlet.receipts));
    if (mode.equals("observe")) return;
    boolean expected = denial && mode.equals("block");
    int checks = creation && valid && ROLE.equals(role) ? 1 : 0;
    if (findings() - before != (denial ? 1 : 0)) throw new AssertionError("finding: " + label);
    if (blocked != expected || servlet.receipts != (valid && !expected ? 1 : 0) || decisions.get() != checks)
      throw new AssertionError(label);
  }

  public static void main(String[] args) {
    String mode = args[0];
    check(mode, "unconfigured", null, false, true, true, true, REMOTE, false);
    check(mode, "authorized", ROLE, true, true, true, true, REMOTE, false);
    check(mode, "denied", ROLE, false, true, true, true, REMOTE, true);
    check(mode, "local-denied", ROLE, false, true, true, true, REMOTE.replace("https:", "file:"), true);
    check(mode, "other-message", ROLE, false, true, false, true, REMOTE, false);
    check(mode, "invalid", ROLE, false, true, true, false, REMOTE, false);
    check(mode, "unavailable", ROLE, false, false, true, true, REMOTE, false);
    check(mode, "wildcard", "*", false, true, true, true, REMOTE, false);
  }
}
