package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.ohmyrasp.agent.hook.compile.CompilationUnits;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The hook reads the source text out of the compilation units a request hands to the Java compiler. */
final class OhMyRaspHooksJavaCompilationTest {
  private static final String RUNTIME_EXEC =
      "public class Demo { static void run() throws Exception { Runtime.getRuntime().exec(\"id\"); } }";
  private static final String HARMLESS = "public class Demo { int add(int a, int b) { return a + b; } }";

  @AfterEach
  void reset() {
    OhMyRaspHooks.exitHttpRequest();
    System.clearProperty("ohmyrasp.block");
  }

  private static void inRequest() {
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.enterHttpRequest(
        new OhMyRaspHooksPolicyTest.FakeRequest(), new OhMyRaspHooksPolicyTest.FakeResponse());
  }

  @Test
  void blocksRuntimeExecInASourceHeldByAnAnonymousFileObject() {
    inRequest();
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeJavaCompilationUnits(List.of(CompilationUnits.anonymous(RUNTIME_EXEC))),
        "the source of an anonymous SimpleJavaFileObject was not read");
  }

  @Test
  void blocksRuntimeExecInASourceHeldByANonPublicNamedFileObject() {
    inRequest();
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeJavaCompilationUnits(List.of(CompilationUnits.packagePrivate(RUNTIME_EXEC))));
  }

  @Test
  void letsAHarmlessSourceInAnAnonymousFileObjectThrough() {
    inRequest();
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeJavaCompilationUnits(List.of(CompilationUnits.anonymous(HARMLESS))));
  }

  @Test
  void stillReadsASourceGivenAsText() {
    inRequest();
    assertThrows(
        OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeJavaCompilationUnits("janino", RUNTIME_EXEC));
  }
}
