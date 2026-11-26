package io.ohmyrasp.agent.backport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.java8.Java8RaspBlockException;
import io.ohmyrasp.agent.java8.Java8RaspLine;
import io.ohmyrasp.agent.java8.OhMyRaspJava8Agent;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import org.junit.jupiter.api.Test;

/**
 * The line descriptor: the names each line used before the backport runtime and decisions became one copy, and a
 * runtime that refuses to run until its line has started.
 */
final class Java8RaspLineTest {
  @Test
  void theLineKeepsItsNames() {
    BackportLine line = BackportLine.current();
    assertEquals("java8_", line.token + "_");
    assertEquals("Java 8", line.displayName);
    assertEquals("java8_", line.rulePrefix);
    assertEquals("ohmyrasp.java8.", line.propertyPrefix);
    assertEquals("OHMYRASP_JAVA8_", line.environmentPrefix);
    assertEquals("[OHMYRASP-JAVA8]", line.logPrefix);
    assertEquals(OhMyRaspJava8Agent.class.getName(), line.entryClass);
    assertEquals("ohmyrasp-java8-control", line.controlThreadName);
    assertEquals("ohmyrasp-java8-writer", line.writerThreadName);
    assertEquals("ohmyrasp.java8.log", line.logProperty);
    assertEquals("ohmyrasp.java8.block", line.blockProperty);
    assertEquals("OHMYRASP_JAVA8_BLOCK", line.blockEnvironment);
  }

  @Test
  void theLineMakesAndRecognisesItsOwnBlockException() {
    BackportLine line = BackportLine.current();
    RuntimeException blocked = line.block("OhMyRASP Java 8 blocked a test");
    assertSame(Java8RaspBlockException.class, blocked.getClass());
    assertEquals("OhMyRASP Java 8 blocked a test", blocked.getMessage());
    assertTrue(line.isBlock(blocked));
    assertFalse(line.isBlock(new RuntimeException("not a block")));
    assertFalse(line.isBlock(null));
  }

  @Test
  void aJvmRunsOneLine() {
    BackportLine first = BackportLine.current();
    Java8RaspLine.start();
    assertSame(first, BackportLine.current(), "starting the same line again changes nothing");
    BackportLine other =
        new BackportLine("99") {
          public RuntimeException block(String message) {
            return new IllegalStateException(message);
          }

          public boolean isBlock(Throwable thrown) {
            return false;
          }
        };
    assertThrows(IllegalStateException.class, () -> BackportLine.install(other));
    assertSame(first, BackportLine.current());
  }

  @Test
  void nothingRunsBeforeTheLineHasStarted() throws Exception {
    URLClassLoader fresh =
        new URLClassLoader(
            new URL[] {
              RaspRuntime.class.getProtectionDomain().getCodeSource().getLocation(),
              Java8RaspLine.class.getProtectionDomain().getCodeSource().getLocation()
            },
            null);
    try {
      Class<?> line = Class.forName(BackportLine.class.getName(), true, fresh);
      assertCause(IllegalStateException.class, () -> line.getMethod("current").invoke(null));
      Class<?> runtime = Class.forName(RaspRuntime.class.getName(), true, fresh);
      Method detectionOff = runtime.getDeclaredMethod("detectionOff");
      detectionOff.setAccessible(true);
      assertCause(IllegalStateException.class, () -> detectionOff.invoke(null));
      assertCause(IllegalStateException.class, () -> runtime.getMethod("resolveLogPath").invoke(null));
      assertCause(
          IllegalStateException.class,
          () -> runtime.getMethod("writeEvent", String.class, String.class).invoke(null, "none", "{}"));
      assertCause(IllegalStateException.class, () -> runtime.getMethod("start").invoke(null));

      // Started as the entry class starts it, the same calls run. No control file: no poller thread.
      String previous = System.getProperty("ohmyrasp.control");
      System.setProperty("ohmyrasp.control", "none");
      try {
        Class.forName(Java8RaspLine.class.getName(), true, fresh).getMethod("start").invoke(null);
      } finally {
        if (previous == null) {
          System.clearProperty("ohmyrasp.control");
        } else {
          System.setProperty("ohmyrasp.control", previous);
        }
      }
      assertEquals("java8_", line.getField("rulePrefix").get(line.getMethod("current").invoke(null)));
      assertFalse((Boolean) detectionOff.invoke(null));
      runtime.getMethod("writeEvent", String.class, String.class).invoke(null, "none", "{}");
    } finally {
      fresh.close();
    }
  }

  private interface Call {
    Object run() throws Exception;
  }

  private static void assertCause(Class<? extends Throwable> expected, Call call) throws Exception {
    InvocationTargetException failure = assertThrows(InvocationTargetException.class, call::run);
    assertSame(expected, failure.getCause().getClass(), String.valueOf(failure.getCause()));
  }
}
