package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.rules.product.hessian.HessianAllocationVisitor;
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
}
