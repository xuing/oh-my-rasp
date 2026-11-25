import java.io.File;
import java.lang.reflect.Method;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.spi.FileSystemProvider;

/** Checks the explicit primary-agent policies under a global force-block setting. */
public class DirectoryPolicyCheck {
  private static void install(String rule) throws Exception {
    Class<?> policy = Class.forName("io.ohmyrasp.agent.policy.AgentPolicy");
    Object parsed = policy.getMethod("parse", String.class).invoke(null, "{\"rules\":[" + rule + "]}");
    Class.forName("io.ohmyrasp.agent.hook.OhMyRaspHooks").getMethod("installPolicy", policy, String.class)
        .invoke(null, parsed, "directory-check");
  }

  public static void main(String[] ignored) throws Exception {
    Path reports = Files.createTempDirectory("catalogue");
    try {
      install("{\"hook\":\"directory\",\"action\":\"block\"}");
      try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope("main", reports.toString())) {
        if (reports.toFile().list() == null || new File("/etc").list() == null) throw new AssertionError();
      }
      install("{\"algorithm\":\"directory_unwanted\",\"action\":\"log\"}");
      try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope("main", "weekly")) {
        if (new File("/etc").list() == null) throw new AssertionError();
      }
      install("{\"algorithm\":\"directory_userinput\",\"action\":\"log\"}");
      try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope("main", reports.toString())) {
        if (reports.toFile().list() == null) throw new AssertionError();
      }
      install("{\"algorithm\":\"directory_reflect\",\"action\":\"block\"}");
      Method open = FileSystemProvider.class.getMethod("newDirectoryStream", Path.class, DirectoryStream.Filter.class);
      try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope("main", "weekly")) {
        try (DirectoryStream<?> stream = (DirectoryStream<?>) open.invoke(reports.getFileSystem().provider(), reports,
            (DirectoryStream.Filter<Path>) entry -> true)) {
          throw new AssertionError("explicit directory dispatch policy did not block");
        } catch (Exception expected) {
          if (!HttpTransportCheck.blocked(expected)) throw expected;
        }
      }
    } finally {
      Files.delete(reports);
    }
  }
}
