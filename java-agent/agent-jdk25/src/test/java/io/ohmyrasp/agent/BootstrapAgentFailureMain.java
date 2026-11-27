package io.ohmyrasp.agent;

import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/**
 * Runs {@link BootstrapAgent#start} once in a JVM of its own, against an Instrumentation that records what the start
 * registers and removes, and prints one RESULT line: how the start ended, the transformers still registered and the
 * threads of ours still alive. A JVM of its own because the runtime and the event logger are singletons: a second
 * start in a shared test JVM would find them started and not start (or stop) anything.
 * Arguments: the scenario, the agent JAR to start from.
 */
public final class BootstrapAgentFailureMain {
  /** A listed class whose initialiser fails. */
  public static final class ExplodingInit {
    static {
      if (System.nanoTime() != 0) {
        throw new IllegalStateException("this class cannot initialise");
      }
    }
  }

  private BootstrapAgentFailureMain() {}

  public static void main(String[] args) throws Exception {
    String scenario = args[0];
    File jar = new File(args[1]);
    final List<ClassFileTransformer> registered = new ArrayList<>();
    final boolean enumerationFails = scenario.equals("fails-after-transformer");
    Instrumentation instrumentation =
        (Instrumentation) Proxy.newProxyInstance(
            BootstrapAgentFailureMain.class.getClassLoader(),
            new Class<?>[] {Instrumentation.class},
            new InvocationHandler() {
              @Override
              public Object invoke(Object proxy, Method method, Object[] arguments) {
                switch (method.getName()) {
                  case "addTransformer" -> registered.add((ClassFileTransformer) arguments[0]);
                  case "removeTransformer" -> {
                    return registered.remove((ClassFileTransformer) arguments[0]);
                  }
                  case "getAllLoadedClasses" -> {
                    if (enumerationFails) {
                      throw new UnsupportedOperationException("the JVM refuses to list its classes");
                    }
                    return new Class<?>[0];
                  }
                  case "isRetransformClassesSupported" -> {
                    return Boolean.TRUE;
                  }
                  default -> {}
                }
                return method.getReturnType() == boolean.class ? Boolean.FALSE : null;
              }
            });
    String ended = "started";
    try {
      BootstrapAgent.start("", instrumentation, scenario.equals("no-jar") ? null : jar);
    } catch (Throwable failure) {
      Throwable root = failure;
      while (root.getCause() != null) {
        root = root.getCause();
      }
      ended = "threw " + failure.getClass().getSimpleName() + ": " + failure.getMessage() + " | root " + root;
    }
    // A thread told to stop needs a moment to notice.
    long deadline = System.nanoTime() + 5_000_000_000L;
    TreeSet<String> threads = ourThreads();
    while (!threads.isEmpty() && !scenario.equals("started") && System.nanoTime() < deadline) {
      Thread.sleep(50);
      threads = ourThreads();
    }
    System.out.println("RESULT\t" + ended.replace('\n', ' ') + "\t" + registered.size() + "\t" + String.join(",", threads));
    System.out.flush();
    Runtime.getRuntime().halt(0);
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
