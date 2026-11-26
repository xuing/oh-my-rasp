package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.rules.product.hessian.HessianAllocationVisitor;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

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
