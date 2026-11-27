import java.io.File;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.jar.JarFile;

/**
 * A probe agent ({@code -javaagent:flaky.jar=AGENT-JAR}) that starts AGENT-JAR's launcher entry with the JVM's
 * Instrumentation, except that the fifth addTransformer throws: a failure after the line has started. The start
 * must undo itself. It prints how many transformers were added and removed, the agent threads left, and whether
 * the bootstrap-defined backport runtime counts as started.
 */
public class FlakyInstrumentationAgent {
  public static void premain(String agentJar, final Instrumentation real) throws Exception {
    final int[] counts = new int[2];
    Instrumentation flaky = (Instrumentation) Proxy.newProxyInstance(FlakyInstrumentationAgent.class.getClassLoader(),
        new Class<?>[] {Instrumentation.class}, new InvocationHandler() {
          public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getName().equals("addTransformer") && ++counts[0] == 5) {
              counts[0]--;
              throw new IllegalStateException("the fifth transformer is refused by the probe");
            }
            if (method.getName().equals("removeTransformer")) {
              counts[1]++;
            }
            try {
              return method.invoke(real, args);
            } catch (InvocationTargetException e) {
              throw e.getCause();
            }
          }
        });
    String entry;
    JarFile jar = new JarFile(new File(agentJar));
    try {
      entry = jar.getManifest().getMainAttributes().getValue("Premain-Class");
    } finally {
      jar.close();
    }
    // AGENT-JAR is on the class path: its entry, like a -javaagent entry, comes from the system class loader.
    Class.forName(entry, true, ClassLoader.getSystemClassLoader()).getMethod("premain", String.class, Instrumentation.class)
        .invoke(null, "", flaky);
    int threads = 0;
    for (Thread thread : Thread.getAllStackTraces().keySet()) {
      if (thread.getName().startsWith("ohmyrasp-") && thread.isAlive()) {
        threads++;
      }
    }
    Object started;
    try {
      Method isStarted = Class.forName("io.ohmyrasp.agent.backport.RaspRuntime", false, null).getDeclaredMethod("isStarted");
      isStarted.setAccessible(true);
      started = isStarted.invoke(null);
    } catch (ClassNotFoundException primary) {
      started = "n/a";
    }
    System.out.println("flaky: added=" + counts[0] + " removed=" + counts[1] + " threads=" + threads
        + " runtime started=" + started);
  }
}
