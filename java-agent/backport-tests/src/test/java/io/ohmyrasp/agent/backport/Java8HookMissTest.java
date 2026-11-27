package io.ohmyrasp.agent.backport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.hookmiss.AgentCalls;
import io.ohmyrasp.agent.hookmiss.HookExpectations;
import io.ohmyrasp.agent.hookmiss.HookMissSink;
import io.ohmyrasp.agent.hookmiss.HookMissWatch;
import io.ohmyrasp.agent.hookmiss.HookMisses;
import io.ohmyrasp.agent.java8.Java8Base64Transformer;
import io.ohmyrasp.agent.java8.Java8JdbcTransformer;
import io.ohmyrasp.agent.java8.Java8MultipartUploadTransformer;
import java.lang.instrument.ClassFileTransformer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * The hook-miss report of a backport line: a real transformer, wrapped as the line's entry registers it, over
 * synthetic classes that it selects by name. One line for a class whose hooked method changed its signature, none
 * when it matches, none for a class the table does not expect or the transformer takes by content, at most
 * {@link HookMisses#LIMIT} lines and then one suppressed line, and the transformer's result unchanged whatever the
 * report throws.
 */
final class Java8HookMissTest {
  static final String HANDLER = "org/apache/ibatis/executor/statement/BaseStatementHandler";
  static final String RECORDED = "prepare(Ljava/sql/Connection;Ljava/lang/Integer;)Ljava/sql/Statement;";
  static final String CHANGED = "prepare(Ljava/sql/Connection;Ljava/time/Duration;)Ljava/sql/Statement;";
  static final String TABLE = "Java{N}JdbcTransformer " + HANDLER + " report " + RECORDED + "\n";
  static final ClassLoader APPLICATION = new ClassLoader(null) {};

  private final List<String[]> lines = Collections.synchronizedList(new ArrayList<String[]>());

  @AfterEach
  void stop() {
    HookMisses.stop();
  }

  @Test
  void aChangedSignatureIsReportedOnceWithWhatTheTransformerLookedForAndWhatTheClassHas() throws Exception {
    ClassFileTransformer jdbc = watched(TABLE, new Java8JdbcTransformer());

    byte[] out = jdbc.transform(APPLICATION, HANDLER, null, null, classWith(HANDLER, CHANGED));
    jdbc.transform(APPLICATION, HANDLER, null, null, classWith(HANDLER, CHANGED));

    assertNotNull(out, "the class is still transformed");
    assertEquals(1, lines.size(), "one line per transformer and class in a JVM");
    assertEquals("hook_miss", lines.get(0)[0]);
    String fields = lines.get(0)[1];
    assertTrue(fields.startsWith("\"unit\":\"Java8JdbcTransformer\",\"class\":\"org.apache.ibatis.executor.statement.BaseStatementHandler\""
        + ",\"reason\":\"no_agent_call\",\"looked_for\":[\"" + RECORDED + "\"],\"found\":[\"" + CHANGED + "\"]"), fields);
  }

  @Test
  void theRecordedSignatureIsInstrumentedAndNotReported() throws Exception {
    ClassFileTransformer jdbc = watched(TABLE, new Java8JdbcTransformer());

    byte[] out = jdbc.transform(APPLICATION, HANDLER, null, null, classWith(HANDLER, RECORDED));

    java.util.Map<String, java.util.Set<String>> calls = AgentCalls.inMethods(out, HookExpectations.parse(TABLE).forClass(HANDLER));
    assertTrue(calls.get(RECORDED) != null && !calls.get(RECORDED).isEmpty(), "the transformer instrumented prepare: " + calls);
    assertEquals(Collections.emptyList(), lines);
  }

  /** The table says which agent methods the transformer calls from the method; another call into the agent is no evidence. */
  @Test
  void onlyTheRecordedCalleeInTheRecordedMethodCounts() throws Exception {
    byte[] input = classWith(HANDLER, RECORDED);

    ClassFileTransformer right = watched("Java{N}JdbcTransformer " + HANDLER + " report " + RECORDED + "=enterStatement,exitStatement\n",
        new Java8JdbcTransformer());
    right.transform(APPLICATION, HANDLER, null, null, input);
    assertEquals(Collections.emptyList(), lines, "MyBatisSqlTrace.enterStatement is the recorded callee");

    ClassFileTransformer wrong = watched("Java{N}JdbcTransformer " + HANDLER + " report " + RECORDED + "=neverCalledByTheTransformer\n",
        new Java8JdbcTransformer());
    wrong.transform(APPLICATION, HANDLER, null, null, input);
    assertEquals(1, lines.size(), "prepare was instrumented, but not as the recorded maps show");
  }

  /** A call into the agent in another method of the class is not evidence for the method the transformer looks for. */
  @Test
  void aCallInAnotherMethodDoesNotHideTheMiss() throws Exception {
    ClassFileTransformer jdbc = watched(TABLE, new Java8JdbcTransformer());

    jdbc.transform(APPLICATION, HANDLER, null, null,
        agentCallIn("unrelated", "()V", "somethingElse", classWith(HANDLER, CHANGED, "unrelated()V")));

    assertEquals(1, lines.size());
  }

  /** A transformer that returns nothing for a class that already carries its hook has not missed it. */
  @Test
  void aHookTheClassAlreadyCarriesIsNoMissWhenTheTransformerReturnsNothing() throws Exception {
    HookMisses.start(HookExpectations.parse("Java{N}QuietTransformer " + HANDLER + " report " + RECORDED + "=prepareHook\n"), recorder(), true);
    ClassFileTransformer quiet = HookMissWatch.wrap(new Java8QuietTransformer());
    assertTrue(quiet instanceof HookMissWatch);
    byte[] hooked = agentCallIn("prepare", "(Ljava/sql/Connection;Ljava/lang/Integer;)Ljava/sql/Statement;", "prepareHook",
        classWith(HANDLER, RECORDED));

    assertEquals(null, quiet.transform(APPLICATION, HANDLER, null, null, hooked));
    assertEquals(Collections.emptyList(), lines, "the input already calls prepareHook from prepare");

    assertEquals(null, quiet.transform(APPLICATION, HANDLER, null, null, classWith(HANDLER, RECORDED)));
    assertEquals(1, lines.size(), "without the call, nothing was instrumented");
  }

  /** What a transformer throws is reported as a failed transform and thrown again, unchanged. */
  @Test
  void aTransformerThatThrowsIsReportedAndItsFailureGoesOn() throws Exception {
    final IllegalStateException failure = new IllegalStateException("transformer down");
    HookMisses.start(HookExpectations.parse("Java{N}ThrowingTransformer " + HANDLER + " report " + RECORDED + "\n"), recorder(), true);
    ClassFileTransformer throwing = HookMissWatch.wrap(new Java8ThrowingTransformer(failure));
    assertTrue(throwing instanceof HookMissWatch);

    try {
      throwing.transform(APPLICATION, HANDLER, null, null, classWith(HANDLER, RECORDED));
      throw new AssertionError("the failure was swallowed");
    } catch (IllegalStateException thrown) {
      assertSame(failure, thrown);
    }

    assertEquals(1, lines.size());
    assertTrue(lines.get(0)[1].contains("\"reason\":\"transform_failed\",\"exception\":\"java.lang.IllegalStateException\""), lines.get(0)[1]);
  }

  /** Named so that its simple name gives the table's {@code Java{N}ThrowingTransformer}. */
  static final class Java8ThrowingTransformer implements ClassFileTransformer {
    private final RuntimeException failure;

    Java8ThrowingTransformer(RuntimeException failure) {
      this.failure = failure;
    }

    @Override public byte[] transform(ClassLoader loader, String className, Class<?> redefined,
        java.security.ProtectionDomain domain, byte[] classfileBuffer) {
      throw failure;
    }
  }

  /** A transformer that never changes a class: {@code Java{N}QuietTransformer} in the table. */
  static final class Java8QuietTransformer implements ClassFileTransformer {
    @Override public byte[] transform(ClassLoader loader, String className, Class<?> redefined,
        java.security.ProtectionDomain domain, byte[] classfileBuffer) {
      return null;
    }
  }

  /**
   * The request-body transformer skips a class whose loader cannot see the agent on purpose, which is no miss; for an
   * application loader it checks every class the table names, whatever the class extends.
   */
  @Test
  void theRequestBodyTransformerIsCheckedForEveryTableClassExceptAnUnseeingLoader() throws Exception {
    String stream = "org/springframework/web/util/ContentCachingRequestWrapper$ContentCachingInputStream";
    ClassFileTransformer body = watched("Java{N}RequestBodyTransformer " + stream + " report read()I\n",
        new io.ohmyrasp.agent.java8.Java8RequestBodyTransformer());
    byte[] unrelated = classWith(stream, "read()I");

    assertEquals(null, body.transform(null, stream, null, null, unrelated), "the bootstrap loader: left alone on purpose");
    assertEquals(Collections.emptyList(), lines);

    assertEquals(null, body.transform(APPLICATION, stream, null, null, unrelated), "no servlet superclass: not transformed");
    assertEquals(1, lines.size(), "the table names it, so the loss of the hook is reported");
    assertTrue(lines.get(0)[1].contains("\"reason\":\"not_transformed\""), lines.get(0)[1]);
  }

  /** A copy of {@code classFile} whose method {@code name}{@code descriptor} calls {@code Java8RaspHooks.callee()} first. */
  static byte[] agentCallIn(final String name, final String descriptor, final String callee, byte[] classFile) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    new org.objectweb.asm.ClassReader(classFile).accept(new org.objectweb.asm.ClassVisitor(Opcodes.ASM9, writer) {
      @Override
      public MethodVisitor visitMethod(int access, String methodName, String methodDescriptor, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, methodName, methodDescriptor, signature, exceptions);
        if (!methodName.equals(name) || !methodDescriptor.equals(descriptor)) {
          return mv;
        }
        return new MethodVisitor(Opcodes.ASM9, mv) {
          @Override public void visitCode() {
            super.visitCode();
            super.visitMethodInsn(Opcodes.INVOKESTATIC, "io/ohmyrasp/agent/java8/Java8RaspHooks", callee, "()V", false);
          }
        };
      }
    }, 0);
    return writer.toByteArray();
  }

  @Test
  void aClassTheTableDoesNotExpectIsNotChecked() throws Exception {
    ClassFileTransformer jdbc = watched(TABLE, new Java8JdbcTransformer());

    jdbc.transform(APPLICATION, "org/h2/jdbc/Other", null, null, classWith("org/h2/jdbc/Other", "close()V"));

    assertEquals(Collections.emptyList(), lines);
  }

  /** The JDBC transformer also takes a class by the interface it implements; that choice is by content, not by name. */
  @Test
  void aClassTheTransformerTakesByWhatItImplementsIsNotChecked() throws Exception {
    String statement = "org/example/AppStatement";
    ClassFileTransformer jdbc = watched("Java{N}JdbcTransformer " + statement + " report execute(Ljava/lang/String;)Z\n",
        new Java8JdbcTransformer());

    byte[] out = jdbc.transform(APPLICATION, statement, null, null,
        classWith(statement, new String[] {"java/sql/Statement"}, "close()V"));

    assertNotNull(out, "taken for its interface");
    assertEquals(Collections.emptyList(), lines);
  }

  /** A transformer that returns no bytes for a class it is expected to instrument: the class loads unchanged. */
  @Test
  void aClassTheTransformerLeftUnchangedIsReported() throws Exception {
    String part = "org/apache/catalina/core/ApplicationPart";
    ClassFileTransformer multipart = watched("Java{N}MultipartUploadTransformer " + part
        + " report getSubmittedFileName()Ljava/lang/String;\n", new Java8MultipartUploadTransformer());

    assertEquals(null, multipart.transform(APPLICATION, part, null, null, classWith(part, "getFileName()Ljava/lang/String;")));

    assertEquals(1, lines.size());
    assertTrue(lines.get(0)[1].contains("\"reason\":\"not_transformed\",\"looked_for\":[\"getSubmittedFileName()Ljava/lang/String;\"],\"found\":[]"),
        lines.get(0)[1]);
  }

  @Test
  void aTransformerTheTableDoesNotNameIsRegisteredAsItIs() {
    HookMisses.start(HookExpectations.parse(TABLE), recorder(), true);
    Java8Base64Transformer base64 = new Java8Base64Transformer();
    Java8JdbcTransformer jdbc = new Java8JdbcTransformer();

    assertSame(base64, HookMissWatch.wrap(base64));
    assertSame(jdbc, ((HookMissWatch) HookMissWatch.wrap(jdbc)).delegate());
    HookMisses.stop();
    assertSame(jdbc, HookMissWatch.wrap(jdbc), "with the report off, nothing is wrapped");
  }

  @Test
  void theReportStopsAtTheLimitWithOneSuppressedLine() throws Exception {
    StringBuilder table = new StringBuilder();
    for (int i = 0; i < HookMisses.LIMIT + 8; i++) {
      table.append("Java{N}JdbcTransformer org/h2/jdbc/Missing").append(i).append(" report execute(Ljava/lang/String;)Z\n");
    }
    ClassFileTransformer jdbc = watched(table.toString(), new Java8JdbcTransformer());

    for (int i = 0; i < HookMisses.LIMIT + 8; i++) {
      String name = "org/h2/jdbc/Missing" + i;
      assertNotNull(jdbc.transform(APPLICATION, name, null, null, classWith(name, "close()V")));
    }

    assertEquals(HookMisses.LIMIT + 1, lines.size());
    for (int i = 0; i < HookMisses.LIMIT; i++) {
      assertEquals("hook_miss", lines.get(i)[0]);
    }
    assertEquals("hook_miss_suppressed", lines.get(HookMisses.LIMIT)[0]);
  }

  @Test
  void aWriterThatThrowsNeverChangesWhatTheTransformerReturns() throws Exception {
    byte[] input = classWith(HANDLER, CHANGED);
    byte[] unwatched = new Java8JdbcTransformer().transform(APPLICATION, HANDLER, null, null, input);
    for (final Throwable failure : Arrays.asList(new IllegalStateException("writer"), new StackOverflowError("writer"))) {
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
      ClassFileTransformer jdbc = HookMissWatch.wrap(new Java8JdbcTransformer());

      assertArrayEquals(unwatched, jdbc.transform(APPLICATION, HANDLER, null, null, input), failure.toString());
    }
  }

  @Test
  void theLineReadsItsTableAndMarksTheWorkersReadsAsItsOwnIo() {
    assertTrue(BackportHookMisses.start(), "the backport table is on the test class path");
    assertTrue(HookMisses.table().size() > 0);
    BackportHookMisses sink = new BackportHookMisses();
    boolean entered = sink.enterOwnIo();
    try {
      assertTrue(entered);
      assertTrue(RaspRuntime.inOwnIo());
    } finally {
      sink.exitOwnIo(entered);
    }
    assertTrue(!RaspRuntime.inOwnIo());
  }

  // ---- helpers ------------------------------------------------------------------------------------------

  private ClassFileTransformer watched(String table, ClassFileTransformer transformer) {
    HookMisses.start(HookExpectations.parse(table), recorder(), true);
    ClassFileTransformer watched = HookMissWatch.wrap(transformer);
    assertTrue(watched instanceof HookMissWatch, "the table names the transformer");
    return watched;
  }

  private HookMissSink recorder() {
    return new HookMissSink() {
      @Override public void write(String diagnostic, String fields) {
        lines.add(new String[] {diagnostic, fields});
      }

      @Override public boolean enterOwnIo() {
        return false;
      }

      @Override public void exitOwnIo(boolean entered) {}
    };
  }

  static java.security.ProtectionDomain domain(java.net.URL location) {
    return new java.security.ProtectionDomain(
        new java.security.CodeSource(location, (java.security.cert.Certificate[]) null), null);
  }

  /** An empty JAR whose manifest says {@code Implementation-Version: version}. */
  static java.nio.file.Path jar(java.nio.file.Path file, String version) throws Exception {
    java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().put(java.util.jar.Attributes.Name.IMPLEMENTATION_VERSION, version);
    java.util.jar.JarOutputStream out = new java.util.jar.JarOutputStream(java.nio.file.Files.newOutputStream(file), manifest);
    out.close();
    return file;
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
      int sort = Type.getReturnType(descriptor).getSort();
      if (sort == Type.VOID) {
        mv.visitInsn(Opcodes.RETURN);
      } else if (sort == Type.OBJECT || sort == Type.ARRAY) {
        mv.visitInsn(Opcodes.ACONST_NULL);
        mv.visitInsn(Opcodes.ARETURN);
      } else {
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitInsn(Opcodes.IRETURN);
      }
      mv.visitMaxs(0, 0);
      mv.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }
}
