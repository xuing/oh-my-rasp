package io.ohmyrasp.agent;

import io.ohmyrasp.agent.hook.HookActivation;
import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/**
 * Starts the primary line in a JVM of its own with the JVM's real Instrumentation (this class is also the
 * {@code Premain-Class} of a JAR that holds no class, so the JVM hands it over), with every class of the agent on the
 * bootstrap search as the entry's append puts them. Prints one RESULT line on the real standard output: how the
 * start ended, what a JNDI lookup of a remote name did after it, the threads of ours still alive, whether the hooks
 * are on, and whether {@code javax.naming.InitialContext} was loaded before the transformer could rewrite it on load.
 * Arguments: the scenario, the agent JAR to start from.
 *
 * <ul>
 *   <li>{@code starts}: while the start prints its banner (after the transformer is registered and the loaded
 *       targets retransformed), the application thread runs a JNDI lookup, which loads the JNDI classes and so gets
 *       them rewritten on load. The start then commits; the lookup after it is blocked.
 *   <li>{@code fails-after-rewrite}: the same, and the application's standard output then refuses the banner, so the
 *       start fails after those classes were rewritten. The lookup after it reaches the rewritten code and must do
 *       what it does without the agent: the JDK's own naming failure (nothing listens on the port).
 *   <li>{@code during-shutdown}: the start runs from a shutdown hook, while the JVM exits. It must fail and leave
 *       nothing running, and the event logger must still be usable.
 *   <li>{@code hosts-file-after-start}: after a start that preloaded {@code NetworkHost}, the application points
 *       {@code jdk.net.hosts.file} at a file of its own and resolves a name only that file holds; the lookup field
 *       is the address it got. The JDK reads the property when {@code InetAddress} initialises, so this shows
 *       whether the start initialised it.
 * </ul>
 */
public final class RealJvmStartMain {
  private static volatile Instrumentation real;
  private static final String REMOTE = "ldap://127.0.0.1:1/Exploit";
  private static final PrintStream OUT = System.out;

  private RealJvmStartMain() {}

  public static void premain(String arguments, Instrumentation instrumentation) {
    real = instrumentation;
  }

  public static void main(String[] args) throws Exception {
    String scenario = args[0];
    File jar = new File(args[1]);
    List<ClassFileTransformer> registered = new ArrayList<>();
    Instrumentation counted = counting(real, registered);
    if (scenario.equals("during-shutdown")) {
      Thread hook = new Thread(() -> {
        String ended = start(counted, jar);
        String loggerStart;
        try {
          JsonEventLogger.get().start();
          loggerStart = "started";
        } catch (Throwable refused) {
          loggerStart = "refused " + refused.getClass().getSimpleName();
        }
        report(ended + " | logger " + loggerStart, "-", registered, "-");
      }, "test-start-during-shutdown");
      Runtime.getRuntime().addShutdownHook(hook);
      return;
    }
    if (scenario.equals("hosts-file-after-start")) {
      String ended = start(counted, jar);
      java.nio.file.Path hosts = java.nio.file.Files.createTempFile("hosts", ".txt");
      java.nio.file.Files.writeString(hosts, "10.11.12.13 rasp-hosts-file-probe.example\n");
      System.setProperty("jdk.net.hosts.file", hosts.toString());
      String resolved;
      try {
        resolved = java.net.InetAddress.getByName("rasp-hosts-file-probe.example").getHostAddress();
      } catch (java.io.IOException unresolved) {
        resolved = "unresolved " + unresolved.getClass().getSimpleName();
      }
      report(ended, resolved, registered, "-");
      OUT.flush();
      Runtime.getRuntime().halt(0);
    }
    boolean fail = scenario.equals("fails-after-rewrite");
    String[] loadedBefore = {"-"};
    System.setOut(new PrintStream(new ByteArrayOutputStream()) {
      @Override
      public void println(String line) {
        if (line != null && line.startsWith("[OHMYRASP] agent started")) {
          loadedBefore[0] = Boolean.toString(loaded("javax.naming.InitialContext"));
          lookup();
          if (fail) {
            throw new IllegalStateException("the application's standard output refuses the banner");
          }
        }
        super.println(line);
      }
    });
    String ended;
    try {
      ended = start(counted, jar);
    } finally {
      System.setOut(OUT);
    }
    report(ended, lookup(), registered, loadedBefore[0]);
    OUT.flush();
    Runtime.getRuntime().halt(0);
  }

  private static String start(Instrumentation instrumentation, File jar) {
    try {
      BootstrapAgent.start("", instrumentation, jar);
      return "started";
    } catch (Throwable failure) {
      return "threw " + failure.getClass().getSimpleName() + ": " + failure.getMessage();
    }
  }

  /** What a JNDI lookup of a remote name does: blocked by the agent, or the JDK's own outcome. */
  private static String lookup() {
    try {
      new javax.naming.InitialContext().lookup(REMOTE);
      return "returned";
    } catch (Throwable outcome) {
      String name = outcome.getClass().getName();
      if (name.endsWith("OhMyRaspBlockException")) {
        return "blocked";
      }
      return (outcome instanceof javax.naming.NamingException ? "naming " : "other ") + name;
    }
  }

  private static boolean loaded(String name) {
    for (Class<?> type : real.getAllLoadedClasses()) {
      if (type.getName().equals(name)) {
        return true;
      }
    }
    return false;
  }

  private static void report(String ended, String lookup, List<ClassFileTransformer> registered, String loadedBefore) {
    long deadline = System.nanoTime() + 5_000_000_000L;
    TreeSet<String> threads = ourThreads();
    while (!threads.isEmpty() && !ended.equals("started") && System.nanoTime() < deadline) {
      try {
        Thread.sleep(50);
      } catch (InterruptedException e) {
        break;
      }
      threads = ourThreads();
    }
    OUT.println("RESULT\t" + ended.replace('\n', ' ') + "\t" + lookup + "\t" + String.join(",", threads) + "\t"
        + HookActivation.active() + "\t" + registered.size() + "\t" + loadedBefore);
    OUT.flush();
  }

  /** The JVM's Instrumentation, keeping count of the transformers the start registers and removes. */
  private static Instrumentation counting(Instrumentation delegate, List<ClassFileTransformer> registered) {
    return (Instrumentation) Proxy.newProxyInstance(RealJvmStartMain.class.getClassLoader(),
        new Class<?>[] {Instrumentation.class}, new InvocationHandler() {
          @Override
          public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
            if (method.getName().equals("addTransformer")) {
              registered.add((ClassFileTransformer) arguments[0]);
            } else if (method.getName().equals("removeTransformer")) {
              registered.remove((ClassFileTransformer) arguments[0]);
            }
            try {
              return method.invoke(delegate, arguments);
            } catch (java.lang.reflect.InvocationTargetException e) {
              throw e.getCause();
            }
          }
        });
  }

  private static TreeSet<String> ourThreads() {
    TreeSet<String> names = new TreeSet<>();
    for (Thread thread : Thread.getAllStackTraces().keySet()) {
      if (thread.isAlive() && thread.getName().startsWith("ohmyrasp-")) {
        names.add(thread.getName());
      }
    }
    return names;
  }
}
