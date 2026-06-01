package io.ohmyrasp.agent.asm;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class HookRegistryTest {
  private final HookRegistry registry = HookRegistry.defaults();

  @Test
  void recognizesJvmAndMiddlewareHookTargets() {
    assertTrue(registry.isDirectTarget("java/lang/ProcessBuilder"));
    assertTrue(registry.isDirectTarget("java.nio.file.Files"));
    assertTrue(registry.isDirectTarget("javax/servlet/http/HttpServlet"));
    assertTrue(registry.isDirectTarget("jakarta.servlet.http.HttpServlet"));
    assertTrue(registry.isDirectTarget("com.sun.jndi.ldap.LdapCtx"));
    assertTrue(registry.isDirectTarget("org/h2/jdbc/JdbcStatement"));
  }

  @Test
  void leavesUnrelatedJdkClassesAlone() {
    assertFalse(registry.isDirectTarget("java/lang/String"));
    assertFalse(registry.isRetransformTarget("java.util.ArrayList"));
  }
}
