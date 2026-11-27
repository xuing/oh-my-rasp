package io.ohmyrasp.agent;

import io.ohmyrasp.agent.hookmiss.HookMisses;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Runs {@link BootstrapAgent#start} once in a JVM of its own, against an Instrumentation that records what the start
 * registers and removes, and prints one RESULT line: how the start ended, the transformers still registered and the
 * threads of ours still alive, whether a hook-miss line reached the event log, and whether the hook-miss report is
 * still on. A JVM of its own because the runtime and the event logger are singletons: a second start in a shared
 * test JVM would find them started and not start (or stop) anything.
 * Arguments: the scenario, the agent JAR to start from.
 *
 * <p>In the {@code miss-} scenarios a class that the shipped hook-expectation table expects SqlHookModule to hook,
 * with the hooked method's signature changed, is loaded through the registered transformer while the start runs (as
 * another thread could load it), so the hook-miss report has a line to write.
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

  /** A MyBatis class whose {@code prepare} no recorded version has: SqlHookModule adds no call, a hook miss. */
  static final String HANDLER = "org/apache/ibatis/executor/statement/BaseStatementHandler";

  private BootstrapAgentFailureMain() {}

  static byte[] changedHandler() {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, HANDLER, null, "java/lang/Object", null);
    MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "prepare",
        "(Ljava/sql/Connection;Ljava/time/Duration;)Ljava/sql/Statement;", null, null);
    method.visitCode();
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitInsn(Opcodes.ARETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  public static void main(String[] args) throws Exception {
    String scenario = args[0];
    File jar = new File(args[1]);
    final List<ClassFileTransformer> registered = new ArrayList<>();
    final boolean enumerationFails = scenario.equals("fails-after-transformer") || scenario.equals("miss-then-fails");
    final boolean loadsAMiss = scenario.startsWith("miss-");
    final ClassLoader application = new ClassLoader(null) {};
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
                    if (loadsAMiss) {
                      for (ClassFileTransformer transformer : List.copyOf(registered)) {
                        try {
                          transformer.transform(null, application, HANDLER, null, null, changedHandler());
                        } catch (Exception e) {
                          throw new IllegalStateException(e);
                        }
                      }
                    }
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
    String ended;
    if (scenario.equals("concurrent")) {
      // Two starts that bypass the launcher, released together: one starts, the other is refused and touches nothing.
      java.util.concurrent.CountDownLatch ready = new java.util.concurrent.CountDownLatch(2);
      String[] outcomes = new String[2];
      Thread[] starts = new Thread[2];
      for (int i = 0; i < 2; i++) {
        final int index = i;
        starts[i] = new Thread(() -> {
          ready.countDown();
          try {
            ready.await();
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
          outcomes[index] = start(instrumentation, jar);
        }, "test-start-" + i);
        starts[i].start();
      }
      for (Thread start : starts) {
        start.join();
      }
      java.util.Arrays.sort(outcomes);
      ended = outcomes[0] + " + " + outcomes[1];
    } else if (scenario.equals("again-after-failure")) {
      // The first start fails (its JAR has no list); a second, with a good JAR, is refused: one start per JVM.
      String first = start(instrumentation, new File(args[2]));
      ended = first.startsWith("threw ") ? start(instrumentation, jar) : "the first start did not fail: " + first;
    } else {
      ended = start(instrumentation, scenario.equals("no-jar") ? null : jar);
    }
    // A thread told to stop needs a moment to notice.
    long deadline = System.nanoTime() + 5_000_000_000L;
    boolean succeeded = ended.equals("started") || ended.startsWith("started + ");
    TreeSet<String> threads = ourThreads();
    while (!threads.isEmpty() && !succeeded && System.nanoTime() < deadline) {
      Thread.sleep(50);
      threads = ourThreads();
    }
    // A started agent writes a queued hook-miss line on its own threads: give it the time it needs.
    Path log = Path.of(System.getProperty("ohmyrasp.log"));
    boolean hookMissWritten = hookMissIn(log);
    while (succeeded && loadsAMiss && !hookMissWritten && System.nanoTime() < deadline + 5_000_000_000L) {
      Thread.sleep(50);
      hookMissWritten = hookMissIn(log);
    }
    System.out.println("RESULT\t" + ended.replace('\n', ' ') + "\t" + registered.size() + "\t" + String.join(",", threads)
        + "\t" + hookMissWritten + "\t" + (HookMisses.table() != null));
    System.out.flush();
    Runtime.getRuntime().halt(0);
  }

  private static String start(Instrumentation instrumentation, File jar) {
    try {
      BootstrapAgent.start("", instrumentation, jar);
      return "started";
    } catch (Throwable failure) {
      Throwable root = failure;
      while (root.getCause() != null) {
        root = root.getCause();
      }
      return "threw " + failure.getClass().getSimpleName() + ": " + failure.getMessage() + " | root " + root;
    }
  }

  private static boolean hookMissIn(Path log) {
    try {
      return Files.isRegularFile(log) && Files.readString(log, StandardCharsets.UTF_8).contains("\"diagnostic\":\"hook_miss\"");
    } catch (java.io.IOException unreadable) {
      return false;
    }
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
