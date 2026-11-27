package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * XMLDecoder's {@code <method>}, {@code <property>} and {@code <new>} elements reach their operation without a
 * {@code java.beans.Statement}: the module rewrites the decoder classes of the JDK running the test.
 */
final class JavaBeansHookModuleTest {
  private static final String HOOKS = "io/ohmyrasp/agent/hook/OhMyRaspHooks";
  private static final String INVOKE = "sun/reflect/misc/MethodUtil.invoke"
      + "(Ljava/lang/reflect/Method;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";
  private static final String BEFORE_INVOKE = HOOKS + ".beforeXmlDecoderInvoke"
      + "([Ljava/lang/Object;Ljava/lang/reflect/Method;Ljava/lang/Object;)[Ljava/lang/Object;";

  @Test
  void everyMethodUtilInvokeOfTheMethodElementIsObservedWithItsOperands() throws Exception {
    assertEquals(1, observedInvokes("com/sun/beans/decoder/MethodElementHandler"));
  }

  @Test
  void everyMethodUtilInvokeOfThePropertyElementIsObservedWithItsOperands() throws Exception {
    // getPropertyValue and setPropertyValue, each with and without an index.
    assertEquals(4, observedInvokes("com/sun/beans/decoder/PropertyElementHandler"));
  }

  @Test
  void theNewElementIsObservedAtTheEntryOfItsOwnBody() throws Exception {
    List<String> calls = new ArrayList<>();
    read(transformed("com/sun/beans/decoder/NewElementHandler"), "getValueObject",
        "(Ljava/lang/Class;[Ljava/lang/Object;)Lcom/sun/beans/decoder/ValueObject;", calls);
    assertTrue(calls.size() > 3, String.valueOf(calls));
    assertEquals(List.of("ALOAD 1", "ALOAD 2",
        HOOKS + ".beforeXmlDecoderNew(Ljava/lang/Class;[Ljava/lang/Object;)V"), calls.subList(0, 3));
  }

  /**
   * The number of {@code MethodUtil.invoke} calls in the class, after checking that each one is preceded by the
   * stack copy and the hook: {@code DUP_X2 POP DUP2_X1} turns {@code [method, target, arguments]} into {@code
   * [method, target, arguments, method, target]}, and the hook takes the top three and returns the arguments.
   */
  private static int observedInvokes(String className) throws Exception {
    List<String> instructions = new ArrayList<>();
    read(transformed(className), null, null, instructions);
    int invokes = 0;
    for (int i = 0; i < instructions.size(); i++) {
      if (!instructions.get(i).equals(INVOKE)) {
        continue;
      }
      invokes++;
      assertTrue(i >= 4, className + ": the call has nothing before it");
      assertEquals(List.of("DUP_X2", "POP", "DUP2_X1", BEFORE_INVOKE), instructions.subList(i - 4, i),
          className + ": MethodUtil.invoke #" + invokes + " is not observed");
    }
    assertTrue(invokes > 0, className + " calls MethodUtil.invoke nowhere");
    return invokes;
  }

  private static byte[] transformed(String className) throws Exception {
    byte[] original;
    // A .class resource is never encapsulated, also in a module that does not open its package.
    try (InputStream input = ClassLoader.getSystemResourceAsStream(className + ".class")) {
      assertNotNull(input, className);
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      input.transferTo(output);
      original = output.toByteArray();
    }
    byte[] transformed = new OhMyRaspTransformer().transform(null, null, className, null, null, original);
    assertNotNull(transformed, className + " is not rewritten");
    return transformed;
  }

  /** The instructions that matter here, of one method or (name null) of every method, in order. */
  private static void read(byte[] classFile, String method, String descriptor, List<String> out) {
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
