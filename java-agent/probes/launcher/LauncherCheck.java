import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * An application for the launcher probe: {@code LauncherCheck TRACK|none [attach AGENT-JAR...]}. It always
 * prints that it ran. With "attach" it loads each AGENT-JAR into its own JVM (agentmain), all at once from
 * one thread each. It prints the
 * published ohmyrasp.agent.line property. Given a track
 * ("8", "11", "17" or "main"), it then opens the system hosts file inside a request that names that
 * file, which every line blocks in block mode (the file-read probe's "file-channel" case), and prints
 * whether it was.
 */
public class LauncherCheck {
  public static void main(String[] args) throws Exception {
    System.out.println("launcher-check: application ran");
    if (args.length > 2 && args[1].equals("attach")) {
      attachAll(java.util.Arrays.copyOfRange(args, 2, args.length));
    }
    System.out.println("launcher-check: published line=" + System.getProperty("ohmyrasp.agent.line"));
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

  /** Attaches every JAR from its own thread, released together, and waits for all of them. */
  private static void attachAll(final String[] agentJars) throws Exception {
    final java.util.concurrent.CountDownLatch ready = new java.util.concurrent.CountDownLatch(agentJars.length);
    final Exception[] failures = new Exception[agentJars.length];
    Thread[] threads = new Thread[agentJars.length];
    for (int i = 0; i < agentJars.length; i++) {
      final int index = i;
      threads[i] = new Thread(new Runnable() {
        @Override
        public void run() {
          try {
            ready.countDown();
            ready.await();
            attach(agentJars[index]);
          } catch (Exception e) {
            failures[index] = e;
          }
        }
      });
      threads[i].start();
    }
    for (int i = 0; i < threads.length; i++) {
      threads[i].join();
      if (failures[i] != null) {
        throw failures[i];
      }
    }
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
