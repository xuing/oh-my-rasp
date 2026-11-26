package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Transforms real classes of the library releases that probes/hook-targets records and checks what the
 * hook passes the agent. The recorded map shows which methods are hooked; these tests show the call
 * carries the value the detector needs.
 */
final class LibraryHookTargetsTest {
  private static final String HOOKS = "io/ohmyrasp/agent/hook/OhMyRaspHooks";
  private static final String TRACE = "io/ohmyrasp/agent/sql/MyBatisSqlTrace";

  @Test
  void struts7OgnlUtilPassesTheExpressionToTheExpressionDetector() throws Exception {
    // Struts 7 moved OgnlUtil from com.opensymphony.xwork2.ognl to org.apache.struts2.ognl.
    String name = "org/apache/struts2/ognl/OgnlUtil";
    byte[] transformed = transform(name);

    String entry = "ldc=ognl load=1 beforeExpressionEvaluation(Ljava/lang/String;Ljava/lang/Object;)V";
    assertEquals(List.of(entry), hookCalls(transformed, "getValue", "(Ljava/lang/String;Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;"));
    assertEquals(
        List.of(entry),
        hookCalls(transformed, "getValue", "(Ljava/lang/String;Ljava/util/Map;Ljava/lang/Object;Ljava/lang/Class;)Ljava/lang/Object;"));
    assertEquals(
        List.of(entry),
        hookCalls(transformed, "setValue", "(Ljava/lang/String;Ljava/util/Map;Ljava/lang/Object;Ljava/lang/Object;)V"));
  }

  @Test
  void pageHelper42DialectsAreTracedThroughTheirFourArgumentGetPageSql() throws Exception {
    // PageHelper 4.2.x takes (String, Page, RowBounds, CacheKey); 5.x takes (String, Page, CacheKey).
    String name = "com/github/pagehelper/dialect/MySqlDialect";
    String descriptor =
        "(Ljava/lang/String;Lcom/github/pagehelper/Page;Lorg/apache/ibatis/session/RowBounds;Lorg/apache/ibatis/cache/CacheKey;)Ljava/lang/String;";

    List<String> before = calls(classBytes(name), "getPageSql", descriptor, TRACE);
    List<String> after = calls(transform(name), "getPageSql", descriptor, TRACE);

    assertEquals(List.of(), before);
    assertTrue(after.contains("appendPiece"), after.toString());
    assertTrue(after.contains("built"), after.toString());
  }

  /** Runs the primary agent's transformer over the class as the library ships it. */
  private static byte[] transform(String internalName) throws IOException {
    byte[] transformed = new OhMyRaspTransformer().transform(null, null, internalName, null, null, classBytes(internalName));
    assertNotNull(transformed, internalName + " is not hooked");
    return transformed;
  }

  /** One entry per call into the agent's hook class in the method, with the constant and local loaded just before it. */
  private static List<String> hookCalls(byte[] classBytes, String method, String descriptor) {
    return invocations(classBytes, method, descriptor, HOOKS, true);
  }

  /** The names of the static methods of one agent class that the method calls, in order. */
  private static List<String> calls(byte[] classBytes, String method, String descriptor, String owner) {
    return invocations(classBytes, method, descriptor, owner, false);
  }

  private static List<String> invocations(byte[] classBytes, String method, String descriptor, String hookOwner, boolean detailed) {
    List<String> calls = new ArrayList<>();
    new ClassReader(classBytes)
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
                if (!name.equals(method) || !desc.equals(descriptor)) {
                  return null;
                }
                return new MethodVisitor(Opcodes.ASM9) {
                  private Object constant;
                  private int local = -1;

                  @Override
                  public void visitLdcInsn(Object value) {
                    constant = value;
                  }

                  @Override
                  public void visitVarInsn(int opcode, int varIndex) {
                    if (opcode == Opcodes.ALOAD) {
                      local = varIndex;
                    }
                  }

                  @Override
                  public void visitMethodInsn(int opcode, String owner, String callee, String calleeDescriptor, boolean itf) {
                    if (opcode == Opcodes.INVOKESTATIC && owner.equals(hookOwner)) {
                      calls.add(detailed ? "ldc=" + constant + " load=" + local + " " + callee + calleeDescriptor : callee);
                    }
                  }
                };
              }
            },
            0);
    return calls;
  }

  private static byte[] classBytes(String internalName) throws IOException {
    try (InputStream input = LibraryHookTargetsTest.class.getClassLoader().getResourceAsStream(internalName + ".class")) {
      if (input == null) {
        throw new IOException("missing class resource " + internalName);
      }
      return input.readAllBytes();
    }
  }
}
