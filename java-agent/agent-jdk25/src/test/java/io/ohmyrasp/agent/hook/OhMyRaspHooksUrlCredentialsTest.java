package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A URL in an event's details reaches the spool without its credentials, outside a request and in log-only mode too:
 * a JDBC URL a pool configured, with the password in its user information and in its parameters. The backports do the
 * same (Java8RaspHooksTest).
 */
final class OhMyRaspHooksUrlCredentialsTest {
  private static final String SENTINEL = "Sentinel-Pw-9";

  @AfterEach
  void reset() {
    OhMyRaspHooks.reportTo(null);
    System.clearProperty("ohmyrasp.block");
  }

  @Test
  void aConfiguredJdbcUrlNeverWritesItsPassword(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));
    // Blocking on, as WarmupTest turns it on: the finding is written and thrown.
    System.setProperty("ohmyrasp.block", "true");

    // MySQL (the evidence replaces the URL), H2 and Derby (the URL stays, its credentials go).
    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeJdbcConnect(
        "jdbc:mysql://reporter:" + SENTINEL + "@db.internal:3306/app?password=" + SENTINEL
            + "&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"));
    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeJdbcConnect(
        "jdbc:h2:mem:reports;PASSWORD=" + SENTINEL + ";INIT=RUNSCRIPT FROM 'http://127.0.0.1:1/init.sql'"));

    String spooled = Files.readString(log);
    assertTrue(spooled.contains("jdbc_mysql_deserialization"), spooled);
    assertTrue(spooled.contains("jdbc_h2_init"), spooled);
    assertTrue(spooled.contains("RUNSCRIPT FROM 'http://127.0.0.1:1/init.sql'"), "the evidence stays: " + spooled);
    assertFalse(spooled.contains(SENTINEL), spooled);
  }

  private static JsonEventLogger logger(Path log) {
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    return JsonEventLogger.newForTesting(null, log.toString(), 0, true, console, console);
  }
}
