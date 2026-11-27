package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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

  /**
   * Both rewrites of an event's details, in their order: the body's value is named first (fix/body), then the URL's
   * own credentials are removed around that name (fix/scope). The application builds a URL with its credentials to
   * a host the request body chose; the event and the block both carry the field's name, and neither the host nor a
   * credential.
   */
  @Test
  void aUrlWithCredentialsOnARequestWithABodyIsWithheldWholeAndTheMatchedFieldIsNamed(@TempDir Path dir)
      throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));
    System.setProperty("ohmyrasp.block", "true");
    String host = "10.20.30.40";
    byte[] body = ("{\"host\":\"" + host + "\"}").getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new OhMyRaspHooksRequestBodyTest.BodyRequest("/app/ping", "application/json",
        body.length), new OhMyRaspHooksPolicyTest.FakeResponse());
    try {
      Object stream = new Object();
      OhMyRaspHooks.exitBodyRead(body.length, OhMyRaspHooks.enterBodyRead(stream), body, 0);
      URL url = new URL("http://reporter:" + SENTINEL + "@" + host + "/hook?password=" + SENTINEL);

      OhMyRaspBlockException blocked = assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeUrlOpen(url));

      // The URL is an operand: withheld whole, credentials and all; the event names the body field it matched.
      String spooled = Files.readString(log);
      assertTrue(spooled.contains("\"input_field\":\"host\""), spooled);
      assertTrue(spooled.contains("\"input_value\":\"" + host + "\""), spooled);
      assertFalse(spooled.contains(SENTINEL), spooled);
      assertFalse(spooled.contains("/hook"), spooled);
      String shown = blocked.detection().details() + " " + blocked.getMessage();
      assertFalse(shown.contains(SENTINEL), shown);
      assertFalse(shown.contains("/hook"), shown);

      // The same in a JDBC URL whose script URL the body's host is inside, as the backports test it.
      Files.delete(log);
      assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeJdbcConnect("jdbc:h2:mem:reports;PASSWORD="
          + SENTINEL + ";INIT=RUNSCRIPT FROM 'http://loader:" + SENTINEL + "@" + host + "/init.sql'"));
      spooled = Files.readString(log);
      assertFalse(spooled.contains("RUNSCRIPT"), spooled);
      assertFalse(spooled.contains(SENTINEL), spooled);
    } finally {
      OhMyRaspHooks.exitHttpRequest();
    }
  }

  private static JsonEventLogger logger(Path log) {
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    return JsonEventLogger.newForTesting(null, log.toString(), 0, true, console, console);
  }
}
