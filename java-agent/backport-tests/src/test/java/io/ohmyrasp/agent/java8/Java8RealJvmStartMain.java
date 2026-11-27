package io.ohmyrasp.agent.java8;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Starts the line in a JVM of its own, with the JVM's real Instrumentation, from the line's packaged agent JAR (this
 * class is also the {@code Premain-Class} of a JAR that holds no class, so the JVM hands the Instrumentation over).
 * Only the agent JAR and the test classes are on the class path, so the entry class appends the JAR to the bootstrap
 * search and the hooks it injects resolve there, as in a real attach. Prints one RESULT line; see
 * {@link Java8RealJvmStartTest}. Arguments: the scenario.
 *
 * <ul>
 *   <li>{@code commits}: while the start writes its start line (every transformer registered, the process classes
 *       already retransformed, the start not yet committed), an application thread starts a process the command rule
 *       detects ({@code cat /etc/shadow}, logged, not blocked, outside a request). The log target is standard error,
 *       which this class replaces: a detection that agent code prints there pauses that thread, so a hook that acts is
 *       held inside the hook. The start then commits; the same command after it is detected.
 *   <li>{@code fails-during-start}: the same, and the application's standard error then refuses the start line, so the
 *       start fails and is undone while that thread would be paused inside the hook. The thread is released after the
 *       undo and must end as it would without the agent.
 *   <li>{@code second-entry}: the entry is called twice; the second call must change nothing.
 *   <li>{@code spool-charset}: with a default charset that is not UTF-8, the runtime writes a start line, a
 *       detection (through its writer thread) and a diagnostic line to one file; the JVM then exits normally.
 * </ul>
 */
public final class Java8RealJvmStartMain {
  private static volatile Instrumentation real;
  private static final PrintStream ERR = System.err;
  private static final PrintStream OUT = System.out;
  private static final long BOUND_SECONDS = 20;

  private Java8RealJvmStartMain() {}

  public static void premain(String arguments, Instrumentation instrumentation) {
    real = instrumentation;
  }

  public static void main(String[] args) throws Exception {
    String scenario = args[0];
    if (scenario.equals("spool-charset")) {
      spoolCharset(args[1]);
      return;
    }
    final List<ClassFileTransformer> registered = new ArrayList<ClassFileTransformer>();
    Instrumentation counted = counting(real, registered);
    final boolean fail = scenario.equals("fails-during-start");
    final Probe duringStart = new Probe(true);
    final Probe after = new Probe(false);
    final String[] during = {"-"};
    System.setErr(new PrintStream(new ByteArrayOutputStream(), true) {
      @Override
      public void println(String line) {
        if (line != null && line.contains("-agent-start\"")) {
          during[0] = duringStart.startAndWait();
          if (fail) {
            throw new IllegalStateException("the application's standard error refuses the start line");
          }
        } else if (line != null && line.contains("ohmyrasp-detection") && fromAgent()) {
          (Thread.currentThread() == duringStart.thread ? duringStart : after).read();
        }
        ERR.println(line);
      }
    });
    String ended = start(counted);
    int transformers = registered.size();
    String second = "-";
    if (scenario.equals("second-entry")) {
      second = start(counted) + " | transformers " + transformers + " -> " + registered.size();
    }
    String released = duringStart.releaseAndJoin();
    String afterOutcome = after.runHere();
    System.setErr(ERR);
    OUT.println("RESULT\t" + ended.replace('\n', ' ') + "\t" + during[0] + "\t" + released + "\t"
        + after.readByAgent + "/" + afterOutcome + "\t" + ourThreads(!ended.equals("started")) + "\t" + hooksActive()
        + "\t" + registered.size() + "\t" + second.replace('\n', ' '));
    OUT.flush();
    Runtime.getRuntime().halt(0);
  }

  private static String start(Instrumentation instrumentation) {
    try {
      OhMyRaspJava8Agent.premain("", instrumentation);
      return "started";
    } catch (Throwable failure) {
      return "threw " + failure.getClass().getSimpleName() + ": " + failure.getMessage();
    }
  }

  /**
   * A process start the command rule detects. The first detection agent code prints for it pauses its thread, until
   * released, when the probe pauses: a hook that acts is then held inside the hook.
   */
  private static final class Probe {
    final boolean pausing;
    final CountDownLatch paused = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    volatile boolean readByAgent;
    volatile String outcome;
    Thread thread;

    Probe(boolean pausing) {
      this.pausing = pausing;
    }

    /** Starts the process on a thread of its own and waits until it ended or paused inside a hook. */
    String startAndWait() {
      final CountDownLatch done = new CountDownLatch(1);
      thread = new Thread(new Runnable() {
        @Override
        public void run() {
          outcome = runHere();
          done.countDown();
        }
      }, "test-application-thread");
      thread.setDaemon(true);
      thread.start();
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
      while (System.nanoTime() < deadline) {
        try {
          if (done.await(10, TimeUnit.MILLISECONDS)) {
            return outcome;
          }
          if (paused.await(10, TimeUnit.MILLISECONDS)) {
            return "paused in the hook";
          }
        } catch (InterruptedException e) {
          return "interrupted";
        }
      }
      return "neither ended nor paused";
    }

    String releaseAndJoin() {
      if (thread == null) {
        return "-";
      }
      release.countDown();
      try {
        thread.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
      } catch (InterruptedException e) {
        return "interrupted";
      }
      return thread.isAlive() ? "still running" : outcome;
    }

    String runHere() {
      try {
        Process process = new ProcessBuilder("sh", "-c", "cat /etc/shadow").start();
        process.getOutputStream().close();
        process.waitFor();
        return "returned";
      } catch (Throwable thrown) {
        return "threw " + thrown.getClass().getName();
      }
    }

    void read() {
      readByAgent = true;
      if (pausing && paused.getCount() > 0) {
        paused.countDown();
        try {
          release.await(BOUND_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
    }
  }

  /** Whether code of the agent, not of this test, is on the stack. */
  private static boolean fromAgent() {
    for (StackTraceElement frame : new Throwable().getStackTrace()) {
      String name = frame.getClassName();
      if (name.startsWith("io.ohmyrasp.agent.") && !name.startsWith(Java8RealJvmStartMain.class.getName())) {
        return true;
      }
    }
    return false;
  }

  private static void spoolCharset(String log) throws Exception {
    // The classes come from the class path here: the runtime is used directly, without an Instrumentation.
    Java8RaspLine.start();
    Class.forName("io.ohmyrasp.agent.hook.HookActivation").getMethod("activate").invoke(null);
    Class<?> runtime = Class.forName("io.ohmyrasp.agent.backport.RaspRuntime");
    String target = (String) runtime.getMethod("resolveLogPath").invoke(null);
    runtime.getMethod("writeStartupLine", String.class, String.class)
        .invoke(null, target, "{\"event\":\"ohmyrasp-java8-agent-start\",\"agent_args\":\"café\"}");
    runtime.getMethod("writeEvent", String.class, String.class)
        .invoke(null, target, "{\"kind\":\"detection\",\"message\":\"café\"}");
    runtime.getMethod("writeDiagnostic", String.class, String.class)
        .invoke(null, target, "{\"event\":\"ohmyrasp-hook-miss\",\"code_source_path\":\"/opt/café.jar\"}");
    OUT.println("RESULT\t" + Charset.defaultCharset().name() + "\t" + new File(log).getName());
    OUT.flush();
    // A normal exit: the detection is still queued for the writer thread, which the shutdown hook lets drain.
  }

  private static String hooksActive() {
    try {
      return String.valueOf(Class.forName("io.ohmyrasp.agent.hook.HookActivation").getMethod("active").invoke(null));
    } catch (Throwable failure) {
      return "unknown " + failure;
    }
  }

  /** The JVM's Instrumentation, keeping count of the transformers the start registers and removes. */
  private static Instrumentation counting(final Instrumentation delegate, final List<ClassFileTransformer> registered) {
    return (Instrumentation) Proxy.newProxyInstance(Java8RealJvmStartMain.class.getClassLoader(),
        new Class<?>[] {Instrumentation.class}, new InvocationHandler() {
          @Override
          public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
            if (method.getName().equals("addTransformer")) {
              registered.add((ClassFileTransformer) arguments[0]);
            } else if (method.getName().equals("removeTransformer")) {
              registered.remove(arguments[0]);
            }
            try {
              return method.invoke(delegate, arguments);
            } catch (InvocationTargetException e) {
              throw e.getCause();
            }
          }
        });
  }

  /** The line's threads still alive; after a failed start, waited for (bounded) to end. */
  private static String ourThreads(boolean waitForNone) {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    TreeSet<String> names = threads();
    while (waitForNone && !names.isEmpty() && System.nanoTime() < deadline) {
      try {
        Thread.sleep(50);
      } catch (InterruptedException e) {
        break;
      }
      names = threads();
    }
    StringBuilder out = new StringBuilder();
    for (String name : names) {
      out.append(out.length() == 0 ? "" : ",").append(name);
    }
    return out.toString();
  }

  private static TreeSet<String> threads() {
    TreeSet<String> names = new TreeSet<String>();
    for (Thread thread : Thread.getAllStackTraces().keySet()) {
      if (thread.isAlive() && thread.getName().startsWith("ohmyrasp-")) {
        names.add(thread.getName());
      }
    }
    return names;
  }
}
