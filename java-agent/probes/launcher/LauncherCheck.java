import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * An application for the launcher probe: {@code LauncherCheck TRACK|none [attach AGENT-JAR]}. It always
 * prints that it ran. With "attach" it loads AGENT-JAR into its own JVM (agentmain). Given a track
 * ("8", "11", "17" or "main"), it then opens the system hosts file inside a request that names that
 * file, which every line blocks in block mode (the file-read probe's "file-channel" case), and prints
 * whether it was.
 */
public class LauncherCheck {
  public static void main(String[] args) throws Exception {
    System.out.println("launcher-check: application ran");
    if (args.length > 2 && args[1].equals("attach")) {
      attach(args[2]);
    }
    if (args.length == 0 || args[0].equals("none")) {
      return;
    }
    boolean blocked = false;
    HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(args[0], "/etc/hosts");
    try {
      FileChannel channel = FileChannel.open(Paths.get("/etc/hosts"), StandardOpenOption.READ);
      channel.close();
    } catch (Exception e) {
      if (!HttpTransportCheck.blocked(e)) {
        throw e;
      }
      blocked = true;
    } finally {
      scope.close();
    }
    System.out.println("launcher-check: blocked=" + blocked);
  }

  /** Self-attach through the attach API, by reflection so the fixture compiles on every JDK. */
  private static void attach(String agentJar) throws Exception {
    String name = ManagementFactory.getRuntimeMXBean().getName();
    Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
    Object vm = vmClass.getMethod("attach", String.class).invoke(null, name.substring(0, name.indexOf('@')));
    try {
      Method load = vmClass.getMethod("loadAgent", String.class);
      load.invoke(vm, agentJar);
    } finally {
      vmClass.getMethod("detach").invoke(vm);
    }
    System.out.println("launcher-check: attached");
  }
}
