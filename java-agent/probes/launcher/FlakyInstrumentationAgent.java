import java.io.File;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.jar.JarFile;

/**
 * A probe agent ({@code -javaagent:flaky.jar=AGENT-JAR}) that starts AGENT-JAR's launcher entry with the JVM's
 * Instrumentation, except that the fifth addTransformer throws: a failure after the line has started. The start
 * must undo itself. It prints how many transformers were added and how many of them are still registered, the agent
 * threads left, whether the bootstrap-defined backport runtime still runs and whether the hooks are on. (The undo
 * also removes the refused one, which it recorded before it asked to add it: a no-op, not counted here.)
 */
public class FlakyInstrumentationAgent {
  public static void premain(String agentJar, final Instrumentation real) throws Exception {
    final int[] added = new int[1];
    final Set<Object> registered = Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
    Instrumentation flaky = (Instrumentation) Proxy.newProxyInstance(FlakyInstrumentationAgent.class.getClassLoader(),
        new Class<?>[] {Instrumentation.class}, new InvocationHandler() {
          public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getName().equals("addTransformer") && added[0] == 4) {
              throw new IllegalStateException("the fifth transformer is refused by the probe");
            }
            Object result;
            try {
              result = method.invoke(real, args);
            } catch (InvocationTargetException e) {
              throw e.getCause();
            }
            if (method.getName().equals("addTransformer")) {
              added[0]++;
              registered.add(args[0]);
            } else if (method.getName().equals("removeTransformer")) {
              registered.remove(args[0]);
            }
            return result;
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
    Object running;
    Object active;
    try {
      Method isRunning = Class.forName("io.ohmyrasp.agent.backport.RaspRuntime", false, null).getDeclaredMethod("isRunning");
      isRunning.setAccessible(true);
      running = isRunning.invoke(null);
      active = Class.forName("io.ohmyrasp.agent.hook.HookActivation", false, null).getMethod("active").invoke(null);
    } catch (ClassNotFoundException primary) {
      running = "n/a";
      active = "n/a";
    }
    System.out.println("flaky: added=" + added[0] + " left=" + registered.size() + " threads=" + threads
        + " runtime running=" + running + " hooks active=" + active);
  }
}
