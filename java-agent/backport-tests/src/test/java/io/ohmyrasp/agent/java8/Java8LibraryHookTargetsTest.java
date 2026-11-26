package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.rules.product.hessian.HessianAllocationVisitor;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** The names the backport lines hook in third-party libraries, kept to the classes real releases have. */
final class Java8LibraryHookTargetsTest {
  @Test
  void hessianLiteHooksTheDeserializersItShipsAndNotAnUnsafeOne() {
    assertTrue(HessianAllocationVisitor.matches("com/alibaba/com/caucho/hessian/io/JavaDeserializer"));
    assertTrue(HessianAllocationVisitor.matches("com/alibaba/com/caucho/hessian/io/BeanDeserializer"));
    assertFalse(HessianAllocationVisitor.matches("com/alibaba/com/caucho/hessian/io/UnsafeDeserializer"));
    assertTrue(HessianAllocationVisitor.matches("com/caucho/hessian/io/UnsafeDeserializer"));
  }

  @Test
  void jexl2HooksItsExpressionClassAndNamesNoScriptImpl() throws Exception {
    // JEXL 2.0.1 to 2.1.1 evaluate scripts and expressions in ExpressionImpl; only JEXL 1.x has a ScriptImpl.
    byte[] expression = classBytes("org/apache/commons/jexl2/ExpressionImpl");
    Java8JexlTransformer transformer = new Java8JexlTransformer();

    byte[] hooked = transformer.transform(null, "org/apache/commons/jexl2/ExpressionImpl", null, null, expression);

    assertNotNull(hooked);
    assertTrue(new String(hooked, StandardCharsets.ISO_8859_1).contains("beforeJexlExpression"));
    assertNull(transformer.transform(null, "org/apache/commons/jexl2/ScriptImpl", null, null, expression));
  }

  @Test
  void pageHelper42DialectsAreTracedThroughTheirFourArgumentGetPageSql() throws Exception {
    // PageHelper 4.2.x takes (String, Page, RowBounds, CacheKey); 5.x takes (String, Page, CacheKey).
    String name = "com/github/pagehelper/dialect/MySqlDialect";
    String descriptor =
        "(Ljava/lang/String;Lcom/github/pagehelper/Page;Lorg/apache/ibatis/session/RowBounds;Lorg/apache/ibatis/cache/CacheKey;)Ljava/lang/String;";
    byte[] original = classBytes(name);

    byte[] hooked = new Java8JdbcTransformer().transform(null, name, null, null, original);

    assertNotNull(hooked);
    assertEquals(new ArrayList<String>(), calls(original, "getPageSql", descriptor, "io/ohmyrasp/agent/sql/MyBatisSqlTrace"));
    List<String> after = calls(hooked, "getPageSql", descriptor, "io/ohmyrasp/agent/sql/MyBatisSqlTrace");
    assertTrue(after.contains("appendPiece"), after.toString());
    assertTrue(after.contains("built"), after.toString());
  }

  /** The names of the static methods of one agent class that the method calls, in order. */
  private static List<String> calls(byte[] classBytes, final String method, final String descriptor, final String owner) {
    final List<String> calls = new ArrayList<String>();
    new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        if (!name.equals(method) || !desc.equals(descriptor)) {
          return null;
        }
        return new MethodVisitor(Opcodes.ASM9) {
          @Override public void visitMethodInsn(int opcode, String target, String callee, String calleeDescriptor, boolean itf) {
            if (opcode == Opcodes.INVOKESTATIC && target.equals(owner)) {
              calls.add(callee);
            }
          }
        };
      }
    }, 0);
    return calls;
  }

  private static byte[] classBytes(String internalName) throws IOException {
    try (InputStream input = Java8LibraryHookTargetsTest.class.getClassLoader().getResourceAsStream(internalName + ".class")) {
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
