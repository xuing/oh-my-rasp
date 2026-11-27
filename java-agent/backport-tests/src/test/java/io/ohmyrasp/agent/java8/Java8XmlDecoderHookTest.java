package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * XMLDecoder's {@code <method>}, {@code <property>} and {@code <new>} elements reach their operation without a
 * {@code java.beans.Statement}: the line's transformer rewrites the decoder classes of the JDK running the test, and
 * the entries it calls classify as the statement path does, with no stack to walk.
 */
final class Java8XmlDecoderHookTest {
  private static final String HOOKS = Type.getInternalName(Java8RaspHooks.class);
  private static final String INVOKE = "sun/reflect/misc/MethodUtil.invoke"
      + "(Ljava/lang/reflect/Method;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";

  @AfterEach
  void clearProperties() {
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.java8.block");
  }

  @Test
  void everyMethodUtilInvokeOfTheMethodAndPropertyElementsIsObservedWithItsOperands() throws Exception {
    assertEquals(1, observedInvokes("com/sun/beans/decoder/MethodElementHandler"));
    // getPropertyValue and setPropertyValue, each with and without an index.
    assertEquals(4, observedInvokes("com/sun/beans/decoder/PropertyElementHandler"));
  }

  @Test
  void theNewElementIsObservedAtTheEntryOfItsOwnBody() throws Exception {
    List<String> calls = new ArrayList<String>();
    read(transformed("com/sun/beans/decoder/NewElementHandler"), "getValueObject",
        "(Ljava/lang/Class;[Ljava/lang/Object;)Lcom/sun/beans/decoder/ValueObject;", calls);
    assertTrue(calls.size() > 3, String.valueOf(calls));
    assertEquals(Arrays.asList("ALOAD 1", "ALOAD 2",
        HOOKS + ".beforeXmlDecoderNew(Ljava/lang/Class;[Ljava/lang/Object;)V"), calls.subList(0, 3));
  }

  @Test
  void blocksAProcessBuilderStartedByAMethodElement() throws Exception {
    final Path log = blockMode();
    final ProcessBuilder target = new ProcessBuilder("sh", "-c", "id");
    blocked(new Executable() {
      @Override public void execute() throws Throwable {
        Java8RaspHooks.beforeXmlDecoderInvoke(new Object[0], ProcessBuilder.class.getMethod("start"), target);
      }
    });
    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_xml_decoder_runtime_execution\""), text);
    assertTrue(text.contains("java.lang.ProcessBuilder start sh -c id"), text);
  }

  @Test
  void blocksAScriptWriterBuiltByANewElement() throws Exception {
    Path log = blockMode();
    blocked(new Executable() {
      @Override public void execute() {
        Java8RaspHooks.beforeXmlDecoderNew(PrintWriter.class, new Object[] {"/tmp/webapps/ROOT/shell.jsp"});
      }
    });
    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_xml_decoder_script_file_write\""), text);
  }

  @Test
  void passesAnOrdinaryCallItsOwnArguments() throws Exception {
    Path log = blockMode();
    Object[] arguments = {"7"};
    assertSame(arguments, Java8RaspHooks.beforeXmlDecoderInvoke(
        arguments, Integer.class.getMethod("valueOf", String.class), Integer.class));
    Java8RaspHooks.beforeXmlDecoderNew(StringBuilder.class, new Object[] {"weekly"});
    Java8RaspHooks.beforeXmlDecoderNew(null, new Object[0]);
    assertSame(arguments, Java8RaspHooks.beforeXmlDecoderInvoke(arguments, null, null));
    assertFalse(Files.exists(log));
  }

  private static Path blockMode() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xml-decoder-elements", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");
    return log;
  }

  private static void blocked(Executable call) {
    assertThrows(Java8RaspBlockException.class, call);
  }

  /**
   * The number of {@code MethodUtil.invoke} calls in the class, after checking that each one is preceded by the
   * stack copy and the hook: {@code DUP_X2 POP DUP2_X1} turns {@code [method, target, arguments]} into {@code
   * [method, target, arguments, method, target]}, and the hook takes the top three and returns the arguments.
   */
  private static int observedInvokes(String className) throws Exception {
    List<String> instructions = new ArrayList<String>();
    read(transformed(className), null, null, instructions);
    String hook = HOOKS + ".beforeXmlDecoderInvoke"
        + "([Ljava/lang/Object;Ljava/lang/reflect/Method;Ljava/lang/Object;)[Ljava/lang/Object;";
    int invokes = 0;
    for (int i = 0; i < instructions.size(); i++) {
      if (!instructions.get(i).equals(INVOKE)) {
        continue;
      }
      invokes++;
      assertTrue(i >= 4, className + ": the call has nothing before it");
      assertEquals(Arrays.asList("DUP_X2", "POP", "DUP2_X1", hook), instructions.subList(i - 4, i),
          className + ": MethodUtil.invoke #" + invokes + " is not observed");
    }
    assertTrue(invokes > 0, className + " calls MethodUtil.invoke nowhere");
    return invokes;
  }

  private static byte[] transformed(String className) throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    // A .class resource is never encapsulated, also in a module that does not open its package.
    InputStream input = ClassLoader.getSystemResourceAsStream(className + ".class");
    assertNotNull(input, className);
    try {
      byte[] buffer = new byte[8192];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        output.write(buffer, 0, count);
      }
    } finally {
      input.close();
    }
    byte[] transformed =
        new Java8JavaBeansTransformer().transform(null, className, null, null, output.toByteArray());
    assertNotNull(transformed, className + " is not rewritten");
    return transformed;
  }

  /** The instructions that matter here, of one method or (name null) of every method, in order. */
  private static void read(byte[] classFile, final String method, final String descriptor, final List<String> out) {
    new ClassReader(classFile).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(
          int access, String name, String desc, String signature, String[] exceptions) {
        if (method != null && !(method.equals(name) && descriptor.equals(desc))) {
          return null;
        }
        return new MethodVisitor(Opcodes.ASM9) {
          @Override
          public void visitInsn(int opcode) {
            out.add(opcode == Opcodes.DUP_X2 ? "DUP_X2" : opcode == Opcodes.POP ? "POP"
                : opcode == Opcodes.DUP2_X1 ? "DUP2_X1" : "insn " + opcode);
          }

          @Override
          public void visitVarInsn(int opcode, int varIndex) {
            out.add((opcode == Opcodes.ALOAD ? "ALOAD " : "var " + opcode + " ") + varIndex);
          }

          @Override
          public void visitMethodInsn(
              int opcode, String owner, String name, String desc, boolean isInterface) {
            out.add(owner + "." + name + desc);
          }
        };
      }
    }, 0);
  }
}
