package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Runs the real janino 3.1.12 with the backport agent's hook on commons-compiler's {@code Cookable}, and
 * records what the hook is handed. The hook owner is replaced by a recorder, so the count and the text
 * do not depend on what the detector decides.
 */
final class Java8JaninoCompilationHookTest {
  private static final String COOKABLE = "org/codehaus/commons/compiler/Cookable";
  private static final String HOOKS = "io/ohmyrasp/agent/java8/Java8RaspHooks";
  private static final String SOURCE = "public class Demo { public int one() { return 1; } }";

  /** What the hook was called with: the compiler name and the text. */
  public static final class Recorder {
    static final List<String> CALLS = new ArrayList<>();

    public static void record(String compiler, Object source) {
      CALLS.add(compiler + ":" + source);
    }
  }

  @BeforeEach
  @AfterEach
  void clear() {
    Recorder.CALLS.clear();
  }

  @Test
  void cookOfTextReportsTheTextOnce() throws Exception {
    Object compiler = newInstance("org.codehaus.janino.SimpleCompiler");

    invoke(compiler, "cook", new Class<?>[] {String.class}, SOURCE);

    assertEquals(Collections.singletonList("janino:" + SOURCE), Recorder.CALLS);
  }

  @Test
  void cookOfAFileNameAndTextReportsTheTextAndNotTheFileName() throws Exception {
    Object compiler = newInstance("org.codehaus.janino.SimpleCompiler");

    invoke(compiler, "cook", new Class<?>[] {String.class, String.class}, "Runtime.getRuntime().exec(\"id\").java", SOURCE);

    assertEquals(Collections.singletonList("janino:" + SOURCE), Recorder.CALLS);
  }

  @Test
  void aReaderOrStreamIsNotReadAndItsFileNameIsNeverTakenForSource() throws Exception {
    String fileName = "Runtime.getRuntime().exec(\"id\").java";
    Object reader = newInstance("org.codehaus.janino.SimpleCompiler");
    Object stream = newInstance("org.codehaus.janino.SimpleCompiler");
    Object unnamed = newInstance("org.codehaus.janino.SimpleCompiler");

    invoke(reader, "cook", new Class<?>[] {String.class, java.io.Reader.class}, fileName, new StringReader(SOURCE));
    invoke(stream, "cook", new Class<?>[] {String.class, InputStream.class}, fileName, new ByteArrayInputStream(SOURCE.getBytes("UTF-8")));
    invoke(unnamed, "cook", new Class<?>[] {java.io.Reader.class}, new StringReader(SOURCE));

    assertEquals(Collections.<String>emptyList(), Recorder.CALLS);
  }

  @Test
  void theEvaluatorsReportTheirTextOnce() throws Exception {
    Object script = newInstance("org.codehaus.janino.ScriptEvaluator");
    invoke(script, "cook", new Class<?>[] {String.class}, "int a = 1;");
    assertEquals(Collections.singletonList("janino:int a = 1;"), Recorder.CALLS);

    Recorder.CALLS.clear();
    Object body = newInstance("org.codehaus.janino.ClassBodyEvaluator");
    invoke(body, "cook", new Class<?>[] {String.class}, "public int one() { return 1; }");
    assertEquals(Collections.singletonList("janino:public int one() { return 1; }"), Recorder.CALLS);

    Recorder.CALLS.clear();
    Object expression = newInstance("org.codehaus.janino.ExpressionEvaluator");
    invoke(expression, "setExpressionType", new Class<?>[] {Class.class}, int.class);
    invoke(expression, "cook", new Class<?>[] {String.class}, "1 + 1");
    assertEquals(Collections.singletonList("janino:1 + 1"), Recorder.CALLS);
  }

  private static Object newInstance(String className) throws Exception {
    return loader().loadClass(className).getConstructor().newInstance();
  }

  private static void invoke(Object target, String method, Class<?>[] types, Object... arguments) throws Exception {
    target.getClass().getMethod(method, types).invoke(target, arguments);
  }

  /** A loader that defines the janino classes, as the agent transforms them, and the hook recorder in place of the hook class. */
  private static ClassLoader loader() throws IOException {
    return new ClassLoader(Java8JaninoCompilationHookTest.class.getClassLoader()) {
      @Override
      protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized (getClassLoadingLock(name)) {
          Class<?> loaded = findLoadedClass(name);
          if (loaded == null) {
            byte[] bytes = bytesOf(name);
            loaded = bytes == null ? super.loadClass(name, false) : defineClass(name, bytes, 0, bytes.length);
          }
          if (resolve) {
            resolveClass(loaded);
          }
          return loaded;
        }
      }

      private byte[] bytesOf(String name) throws ClassNotFoundException {
        String internal = name.replace('.', '/');
        if (internal.equals(HOOKS)) {
          return recorderStub();
        }
        if (!name.startsWith("org.codehaus.")) {
          return null;
        }
        try {
          byte[] original = classBytes(internal);
          // Every janino class goes through the agent's transformer, so a hook on any of them is in effect.
          byte[] hooked = new Java8JavaCompilationTransformer().transform(null, internal, null, null, original);
          return hooked == null ? original : hooked;
        } catch (IOException e) {
          throw new ClassNotFoundException(name, e);
        }
      }
    };
  }

  /** public static void beforeJavaCompilationSource(String, Object): hands both arguments to Recorder.record. */
  private static byte[] recorderStub() {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, HOOKS, null, "java/lang/Object", null);
    MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "beforeJavaCompilationSource",
            "(Ljava/lang/String;Ljava/lang/Object;)V",
            null,
            null);
    method.visitCode();
    method.visitVarInsn(Opcodes.ALOAD, 0);
    method.visitVarInsn(Opcodes.ALOAD, 1);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        Recorder.class.getName().replace('.', '/'),
        "record",
        "(Ljava/lang/String;Ljava/lang/Object;)V",
        false);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] classBytes(String internalName) throws IOException {
    try (InputStream input =
        Java8JaninoCompilationHookTest.class.getClassLoader().getResourceAsStream(internalName + ".class")) {
      if (input == null) {
        throw new IOException("missing class resource " + internalName);
      }
      java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        output.write(buffer, 0, count);
      }
      return output.toByteArray();
    }
  }
}
