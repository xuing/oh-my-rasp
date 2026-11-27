package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.hookmiss.AgentCalls;
import io.ohmyrasp.agent.hookmiss.HookExpectations;
import io.ohmyrasp.agent.hookmiss.HookMissSink;
import io.ohmyrasp.agent.hookmiss.HookMisses;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * The hook-miss report of the primary transformer, on synthetic classes that a real module claims by name: one
 * line for a class whose hooked method changed its signature, none when it matches, none for a class no module
 * expects, at most {@link HookMisses#LIMIT} lines and then one suppressed line, and a transform that succeeds
 * whatever the report throws.
 */
final class HookMissReportTest {
  static final String HANDLER = "org/apache/ibatis/executor/statement/BaseStatementHandler";
  static final String RECORDED = "prepare(Ljava/sql/Connection;Ljava/lang/Integer;)Ljava/sql/Statement;";
  static final String CHANGED = "prepare(Ljava/sql/Connection;Ljava/time/Duration;)Ljava/sql/Statement;";
  static final String TABLE = "# test table\nSqlHookModule " + HANDLER + " report " + RECORDED + "\n";
  static final ClassLoader APPLICATION = new ClassLoader(null) {};

  final List<String[]> lines = Collections.synchronizedList(new ArrayList<>());

  @AfterEach
  void stop() {
    HookMisses.stop();
  }

  @Test
  void aChangedSignatureIsReportedOnceWithWhatTheHookLookedForAndWhatTheClassHas() {
    start(TABLE);

    byte[] out = transform(HANDLER, classWith(HANDLER, CHANGED, "toString()Ljava/lang/String;"), null);
    transform(HANDLER, classWith(HANDLER, CHANGED), null);

    assertNotNull(out, "the class is still transformed");
    assertEquals(1, lines.size(), "one line per module and class in a JVM");
    assertEquals("hook_miss", lines.get(0)[0]);
    String fields = lines.get(0)[1];
    assertTrue(fields.startsWith("\"unit\":\"SqlHookModule\",\"class\":\"org.apache.ibatis.executor.statement.BaseStatementHandler\""
        + ",\"reason\":\"no_agent_call\",\"looked_for\":[\"" + RECORDED + "\"],\"found\":[\"" + CHANGED + "\"]"), fields);
    assertTrue(fields.contains("\"message\":\"Hook SqlHookModule did not apply to "), fields);
  }

  @Test
  void theRecordedSignatureIsInstrumentedAndNotReported() {
    start(TABLE);

    byte[] out = transform(HANDLER, classWith(HANDLER, RECORDED), null);

    var calls = AgentCalls.inMethods(out, HookExpectations.parse(TABLE).forClass(HANDLER));
    assertTrue(calls.get(RECORDED) != null && !calls.get(RECORDED).isEmpty(), "the module instrumented prepare: " + calls);
    assertEquals(List.of(), lines);
  }

  /** The table says which agent methods the module calls from the method: the ones it calls there are no miss. */
  @Test
  void theModulesOwnCalleeIsWhatCountsNotAnyCallIntoTheAgent() {
    start("SqlHookModule " + HANDLER + " report " + RECORDED + "=enterStatement,exitStatement\n");
    transform(HANDLER, classWith(HANDLER, RECORDED), null);
    assertEquals(List.of(), lines, "MyBatisSqlTrace.enterStatement is the recorded callee");

    HookMisses.forget();
    start("SqlHookModule " + HANDLER + " report " + RECORDED + "=somethingTheModuleNeverCalls\n");
    transform(HANDLER, classWith(HANDLER, RECORDED), null);
    assertEquals(1, lines.size(), "the method was instrumented, but not as the recorded maps show");
  }

  /** A call into the agent in another method, which the net count of the whole class used to take as success. */
  @Test
  void aCallInAnotherMethodOfTheClassDoesNotHideTheMiss() {
    start(TABLE);
    byte[] input = classWithAgentCallIn(HANDLER, "unrelated()V", CHANGED);

    transform(HANDLER, input, null);

    assertEquals(1, lines.size(), "prepare has another descriptor, whatever else the class calls");
  }

  /** A class that already carries the module's hook (an earlier pass of this agent) is not a miss. */
  @Test
  void aHookThatIsAlreadyThereIsNoMiss() {
    start(TABLE);
    byte[] once = transform(HANDLER, classWith(HANDLER, RECORDED), null);

    transform(HANDLER, once, null);

    assertEquals(List.of(), lines);
  }

  /** The request-body module takes its streams by superclass; the table names them, so a changed superclass is reported. */
  @Test
  void aServletStreamTheTableNamesIsCheckedByNameWhateverItsSuperclass() {
    String stream = "org/springframework/web/util/ContentCachingRequestWrapper$ContentCachingInputStream";
    start("RequestBodyHookModule " + stream + " report read()I\n");

    transform(stream, classWith(stream, "read()I"), null); // a superclass that is no servlet stream
    assertEquals(1, lines.size(), "the module does not select it any more, which is the loss of the hook");

    HookMisses.forget();
    lines.clear();
    byte[] hooked = transformWithSuper(stream, "javax/servlet/ServletInputStream", "read()I");
    assertEquals(List.of(), lines, "selected by its superclass and instrumented: " + hooked.length);
  }

  /** A class whose loader cannot see the agent is left alone on purpose, so it is no miss. */
  @Test
  void aLoaderThatCannotSeeTheAgentIsNotReportedForTheBodyModule() {
    String stream = "org/springframework/web/util/ContentCachingRequestWrapper$ContentCachingInputStream";
    start("RequestBodyHookModule " + stream + " report read()I\n");

    new OhMyRaspTransformer(HookRegistry.defaults()).transform(null, null, stream, null, null,
        classWithSuper(stream, "javax/servlet/ServletInputStream", "read()I"));

    assertEquals(List.of(), lines);
  }

  /** A module the report asks about, whose answer is a fault; it instruments nothing. */
  static final class FaultyModule implements HookModule {
    static volatile Throwable fault;

    @Override public boolean matchesClass(String className) {
      return false;
    }

    @Override public boolean expectedFor(String className) {
      throw sneaky(fault);
    }

    @Override public org.objectweb.asm.MethodVisitor visitMethod(String className, org.objectweb.asm.MethodVisitor visitor,
        int access, String name, String descriptor) {
      return visitor;
    }
  }

  /**
   * A fault anywhere in the report, while the check is built and while it runs, leaves the result of the transform
   * exactly as it is with the report off: the report is not in the production visitor chain.
   */
  @Test
  void aFaultInTheCheckNeverChangesWhatTheTransformReturns() {
    byte[] input = classWith(HANDLER, RECORDED, "toString()Ljava/lang/String;");
    HookRegistry registry = HookRegistry.of(List.of(new FaultyModule(), new SqlHookModule()));
    HookMisses.stop();
    byte[] off = transformWith(registry, input);
    assertNotNull(off);
    assertTrue(AgentCalls.inMethods(off, HookExpectations.parse(TABLE).forClass(HANDLER)).containsKey(RECORDED), "the module instrumented it");

    // Construction: the check asks the module, which throws.
    for (Throwable fault : List.of(new NoClassDefFoundError("probe"), new StackOverflowError("probe"), new IllegalStateException("probe"))) {
      FaultyModule.fault = fault;
      start("FaultyModule " + HANDLER + " report " + RECORDED + "\nSqlHookModule " + HANDLER + " report " + RECORDED + "\n");
      assertArrayEquals(off, transformWith(registry, input), "construction fault: " + fault);
    }

    // Execution: the check runs on the transform's own thread and its writer throws, for a class it reports.
    byte[] changed = classWith(HANDLER, CHANGED);
    HookMisses.stop();
    byte[] baseline = transformWith(registry, changed);
    for (Throwable fault : List.of(new NoClassDefFoundError("sink"), new StackOverflowError("sink"), new OutOfMemoryError("sink"))) {
      HookMisses.start(HookExpectations.parse(TABLE), new HookMissSink() {
        @Override public void write(String diagnostic, String fields) {
          throw sneaky(fault);
        }

        @Override public boolean enterOwnIo() {
          return false;
        }

        @Override public void exitOwnIo(boolean entered) {}
      }, true);
      assertArrayEquals(baseline, transformWith(registry, changed), "execution fault: " + fault);
    }
    FaultyModule.fault = null;
  }

  @SuppressWarnings("unchecked")
  private static <T extends Throwable> RuntimeException sneaky(Throwable failure) throws T {
    throw (T) failure;
  }

  private static byte[] transformWith(HookRegistry registry, byte[] input) {
    return new OhMyRaspTransformer(registry).transform(null, APPLICATION, HANDLER, null, null, input);
  }

  private static byte[] transformWithSuper(String name, String superName, String... methods) {
    return new OhMyRaspTransformer(HookRegistry.defaults()).transform(null, APPLICATION, name, null, null,
        classWithSuper(name, superName, methods));
  }

  /** A public class extending {@code superName}, with each method returning its zero value. */
  static byte[] classWithSuper(String name, String superName, String... methods) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, superName, null);
    MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    init.visitCode();
    init.visitVarInsn(Opcodes.ALOAD, 0);
    init.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false);
    init.visitInsn(Opcodes.RETURN);
    init.visitMaxs(0, 0);
    init.visitEnd();
    for (String method : methods) {
      int open = method.indexOf('(');
      MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC, method.substring(0, open), method.substring(open), null, null);
      mv.visitCode();
      mv.visitInsn(Opcodes.ICONST_0);
      mv.visitInsn(Opcodes.IRETURN);
      mv.visitMaxs(0, 0);
      mv.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** {@link #classWith} plus a method {@code extra} that calls into the agent. */
  static byte[] classWithAgentCallIn(String name, String extra, String... methods) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, "java/lang/Object", null);
    int open = extra.indexOf('(');
    MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, extra.substring(0, open), extra.substring(open), null, null);
    mv.visitCode();
    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "io/ohmyrasp/agent/hook/OhMyRaspHooks", "somethingElse", "()V", false);
    mv.visitInsn(Opcodes.RETURN);
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    for (String method : methods) {
      int paren = method.indexOf('(');
      MethodVisitor each = writer.visitMethod(Opcodes.ACC_PUBLIC, method.substring(0, paren), method.substring(paren), null, null);
      each.visitCode();
      each.visitInsn(Opcodes.ACONST_NULL);
      each.visitInsn(Opcodes.ARETURN);
      each.visitMaxs(0, 0);
      each.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }

  @Test
  void aClassNoModuleExpectsIsNotChecked() {
    start(TABLE);

    transform("org/example/Unrelated", classWith("org/example/Unrelated", CHANGED), null);

    assertEquals(List.of(), lines);
  }

  /** The JDBC hook also takes a class by the interface it implements; that choice is by content, not by name. */
  @Test
  void aClassTheModuleTakesByWhatItImplementsIsNotChecked() {
    String statement = "org/example/AppStatement";
    start("SqlHookModule " + statement + " report execute(Ljava/lang/String;)Z\n");

    byte[] out = transform(statement, classWith(statement, new String[] {"java/sql/Statement"}, "close()V"), null);

    assertNotNull(out);
    assertEquals(List.of(), lines, "SqlHookModule.matchesClass does not claim it");
  }

  @Test
  void theReportStopsAtTheLimitWithOneSuppressedLine() {
    StringBuilder table = new StringBuilder();
    for (int i = 0; i < HookMisses.LIMIT + 8; i++) {
      table.append("SqlHookModule org/h2/jdbc/Missing").append(i).append(" report execute(Ljava/lang/String;)Z\n");
    }
    start(table.toString());

    for (int i = 0; i < HookMisses.LIMIT + 8; i++) {
      String name = "org/h2/jdbc/Missing" + i;
      assertNotNull(transform(name, classWith(name, "close()V"), null));
    }

    assertEquals(HookMisses.LIMIT + 1, lines.size());
    for (int i = 0; i < HookMisses.LIMIT; i++) {
      assertEquals("hook_miss", lines.get(i)[0]);
    }
    assertEquals("hook_miss_suppressed", lines.get(HookMisses.LIMIT)[0]);
    assertTrue(lines.get(HookMisses.LIMIT)[1].startsWith("\"limit\":" + HookMisses.LIMIT + ","));
  }

  @Test
  void aWriterThatThrowsNeverFailsTheTransform() {
    byte[] input = classWith(HANDLER, CHANGED);
    byte[] unwatched = transform(HANDLER, input, null);
    for (Throwable failure : List.of(new IllegalStateException("writer"), new StackOverflowError("writer"))) {
      HookMisses.start(HookExpectations.parse(TABLE), new HookMissSink() {
        @Override public void write(String diagnostic, String fields) {
          if (failure instanceof Error) {
            throw (Error) failure;
          }
          throw (RuntimeException) failure;
        }

        @Override public boolean enterOwnIo() {
          return false;
        }

        @Override public void exitOwnIo(boolean entered) {}
      }, true);

      assertArrayEquals(unwatched, transform(HANDLER, input, null), "the same class as with the report off: " + failure);
    }
  }

  @Test
  void aClassTheTransformCannotReadIsAFailedTransform() {
    start(TABLE);
    byte[] future = classWith(HANDLER, RECORDED);
    future[6] = (byte) 0x7f; // a major version no ASM reads

    assertNull(transform(HANDLER, future, null), "the JVM loads it unchanged, as before");

    assertEquals(1, lines.size());
    String fields = lines.get(0)[1];
    assertTrue(fields.contains("\"reason\":\"transform_failed\",\"exception\":\"java.lang.IllegalArgumentException\""), fields);
    assertTrue(fields.contains("\"found\":[]"), fields);
  }

  @Test
  void anAbsentMethodIsAVersionGapWhenTheTableSaysSoButANewDescriptorIsNot() {
    start("SqlHookModule " + HANDLER + " absent " + RECORDED + "\n");

    transform(HANDLER, classWith(HANDLER, "toString()Ljava/lang/String;"), null);
    assertEquals(List.of(), lines, "an older release, before the hooked method existed");

    transform(HANDLER, classWith(HANDLER, CHANGED), null);
    assertEquals(1, lines.size(), "the method is there with another signature, and the exempt version above did not use the pair up");
  }

  @Test
  void theLineNamesTheJarAndItsImplementationVersion(@TempDir Path dir) throws Exception {
    start(TABLE);
    Path jar = jar(dir.resolve("mybatis-9.9.9.jar"), "9.9.9");

    transform(HANDLER, classWith(HANDLER, CHANGED), domain(jar.toUri().toURL()));

    String fields = lines.get(0)[1];
    assertTrue(fields.contains("\"code_source\":\"mybatis-9.9.9.jar\",\"code_source_path\":" + quoted(jar.toString())
        + ",\"implementation_version\":\"9.9.9\","), fields);
  }

  @Test
  void aNestedJarIsNamedByItsFileAndHasNoVersion() throws Exception {
    start(TABLE);

    transform(HANDLER, classWith(HANDLER, CHANGED), domain(new URL("jar:file:/app/app.jar!/BOOT-INF/lib/mybatis-9.9.9.jar!/")));

    String fields = lines.get(0)[1];
    assertTrue(fields.contains("\"code_source\":\"mybatis-9.9.9.jar\",\"code_source_path\":\"jar:file:/app/app.jar!/BOOT-INF/lib/mybatis-9.9.9.jar!/\",\"message\""), fields);
  }

  @Test
  void theWorkerThreadWritesTheLineNotTheLoadingThread() throws Exception {
    List<String> threads = Collections.synchronizedList(new ArrayList<>());
    HookMisses.start(HookExpectations.parse(TABLE), new HookMissSink() {
      @Override public void write(String diagnostic, String fields) {
        threads.add(Thread.currentThread().getName());
      }

      @Override public boolean enterOwnIo() {
        return false;
      }

      @Override public void exitOwnIo(boolean entered) {}
    });

    transform(HANDLER, classWith(HANDLER, CHANGED), null);

    long deadline = System.nanoTime() + 10_000_000_000L;
    while (threads.isEmpty() && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    assertEquals(List.of("ohmyrasp-hook-miss"), threads);
    assertNotEquals("ohmyrasp-hook-miss", Thread.currentThread().getName());
  }

  // ---- helpers ------------------------------------------------------------------------------------------

  void start(String table) {
    HookMisses.start(HookExpectations.parse(table), new HookMissSink() {
      @Override public void write(String diagnostic, String fields) {
        lines.add(new String[] {diagnostic, fields});
      }

      @Override public boolean enterOwnIo() {
        return false;
      }

      @Override public void exitOwnIo(boolean entered) {}
    }, true);
  }

  static byte[] transform(String name, byte[] bytes, ProtectionDomain domain) {
    return new OhMyRaspTransformer(HookRegistry.defaults()).transform(null, APPLICATION, name, null, domain, bytes);
  }

  static ProtectionDomain domain(URL location) {
    return new ProtectionDomain(new CodeSource(location, (Certificate[]) null), null);
  }

  static Path jar(Path file, String version) throws Exception {
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().put(Attributes.Name.IMPLEMENTATION_VERSION, version);
    try (OutputStream out = Files.newOutputStream(file); JarOutputStream jar = new JarOutputStream(out, manifest)) {
      jar.flush();
    }
    return file;
  }

  static String quoted(String text) {
    return "\"" + text.replace("\\", "\\\\") + "\"";
  }

  static byte[] classWith(String name, String... methods) {
    return classWith(name, null, methods);
  }

  /** A public class with a constructor and each method (name followed by descriptor) returning its zero value. */
  static byte[] classWith(String name, String[] interfaces, String... methods) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, "java/lang/Object", interfaces);
    MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    init.visitCode();
    init.visitVarInsn(Opcodes.ALOAD, 0);
    init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    init.visitInsn(Opcodes.RETURN);
    init.visitMaxs(0, 0);
    init.visitEnd();
    for (String method : methods) {
      int open = method.indexOf('(');
      String descriptor = method.substring(open);
      MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC, method.substring(0, open), descriptor, null, null);
      mv.visitCode();
      Type returns = Type.getReturnType(descriptor);
      switch (returns.getSort()) {
        case Type.VOID -> mv.visitInsn(Opcodes.RETURN);
        case Type.OBJECT, Type.ARRAY -> {
          mv.visitInsn(Opcodes.ACONST_NULL);
          mv.visitInsn(Opcodes.ARETURN);
        }
        default -> {
          mv.visitInsn(Opcodes.ICONST_0);
          mv.visitInsn(Opcodes.IRETURN);
        }
      }
      mv.visitMaxs(0, 0);
      mv.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }
}
