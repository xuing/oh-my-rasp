package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.backport.ControlAccess;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The control setting {@code outside_request} on the backport lines: a finding on a thread that serves no HTTP
 * request blocks by default, and only logs when the control file says {@code log}; inside a request nothing
 * changes. The primary agent reads the same setting (OutsideRequestTest there).
 */
final class Java8OutsideRequestTest {
  private static final String RMI = "rmi://127.0.0.1:1099/Exploit";

  @TempDir Path dir;
  private Path log;

  @BeforeEach
  void blockMode() throws Exception {
    log = dir.resolve("events.jsonl");
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");
  }

  @AfterEach
  void restore() {
    ControlAccess.poll(dir.resolve("no-control-file.json"));
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.java8.block");
  }

  @Test
  void aFindingOutsideARequestBlocksByDefault() {
    assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJndiLookup(RMI));
    assertTrue(events().contains("\"action\":\"block\""));
  }

  @Test
  void logOnlyOutsideARequestRecordsTheFindingAndLetsTheOperationRun() throws Exception {
    control("{\"outside_request\":\"log\"}");

    Java8RaspHooks.beforeJndiLookup(RMI);

    assertTrue(events().contains("\"algorithm\":\"java8_jndi_remote_lookup\""));
    assertTrue(events().contains("\"action\":\"log\""));
  }

  @Test
  void logOnlyLeavesAFindingInsideARequestBlocking() throws Exception {
    control("{\"outside_request\":\"log\"}");
    Java8RaspHooks.beforeHttpRequest(new Java8RaspHooksTest.RequestStub("GET", "/reports", "id=7"));
    try {
      assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJndiLookup(RMI));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }
  }

  @Test
  void aDocumentWithoutTheSettingReturnsToTheStartUpValue() throws Exception {
    control("{\"outside_request\":\"log\"}");
    control("{\"outside_request\":\"sometimes\",\"revision\":2}");
    Java8RaspHooks.beforeJndiLookup(RMI);

    control("{\"revision\":3}");
    assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJndiLookup(RMI));
  }

  private void control(String json) throws Exception {
    Path file = dir.resolve("control.json");
    Files.write(file, json.getBytes(StandardCharsets.UTF_8));
    ControlAccess.poll(file);
  }

  private String events() {
    try {
      return new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    } catch (java.io.IOException e) {
      throw new AssertionError(e);
    }
  }
}
