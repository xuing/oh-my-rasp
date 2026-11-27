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
  void aBodyValueInsideAUrlWithCredentialsIsNamedAndTheCredentialsAreStillRemoved(@TempDir Path dir) throws Exception {
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

      String expected = "http://[redacted]@[body:host]/hook?password=[redacted]";
      String spooled = Files.readString(log);
      assertTrue(spooled.contains("\"url\":\"" + expected + "\""), spooled);
      assertFalse(spooled.contains(SENTINEL), spooled);
      assertFalse(spooled.contains(host), spooled);
      assertEquals(expected, blocked.detection().details().get("url"), "the block carries what the event carries");
      String shown = blocked.detection().details() + " " + blocked.getMessage();
      assertFalse(shown.contains(SENTINEL), shown);
      assertFalse(shown.contains(host), shown);

      // The same in a JDBC URL whose script URL the body's host is inside, as the backports test it.
      Files.delete(log);
      assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeJdbcConnect("jdbc:h2:mem:reports;PASSWORD="
          + SENTINEL + ";INIT=RUNSCRIPT FROM 'http://loader:" + SENTINEL + "@" + host + "/init.sql'"));
      spooled = Files.readString(log);
      assertTrue(spooled.contains("RUNSCRIPT FROM 'http://[redacted]@[body:host]/init.sql'"), spooled);
      assertFalse(spooled.contains(SENTINEL), spooled);
      assertFalse(spooled.contains(host), spooled);
    } finally {
      OhMyRaspHooks.exitHttpRequest();
    }
  }

  /**
   * A body value equal to a credential's name ("password") inside a URL that carries that credential: the redaction
   * reads the URL as the application built it, before the body scrubber renames the value, so neither the event nor
   * the block carries the password. Scrubbing first left {@code ?[body:field]=<password>}.
   */
  @Test
  void aBodyValueThatIsACredentialsNameDoesNotHideTheCredential(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));
    System.setProperty("ohmyrasp.block", "true");
    byte[] body = "{\"field\":\"password\"}".getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new OhMyRaspHooksRequestBodyTest.BodyRequest("/app/ping", "application/json",
        body.length), new OhMyRaspHooksPolicyTest.FakeResponse());
    try {
      OhMyRaspHooks.exitBodyRead(body.length, OhMyRaspHooks.enterBodyRead(new Object()), body, 0);
      URL url = new URL("http://169.254.169.254/hook?password=" + SENTINEL);
      OhMyRaspBlockException blocked = assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeUrlOpen(url));
      String shown = blocked.detection().details() + " " + blocked.getMessage();
      assertFalse(shown.contains(SENTINEL), shown);

      assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeJdbcConnect(
          "jdbc:h2:mem:reports;password=" + SENTINEL + ";INIT=RUNSCRIPT FROM 'http://127.0.0.1:1/init.sql'"));
    } finally {
      OhMyRaspHooks.exitHttpRequest();
    }
    String spooled = Files.readString(log);
    assertTrue(spooled.contains("ssrf_aws") && spooled.contains("jdbc_h2_init"), spooled);
    assertFalse(spooled.contains(SENTINEL), spooled);
  }

  /**
   * A failure while the evidence is made safe (here the redaction and scrubbing step throws) never turns a block into
   * an allow: the operation is still stopped, and the block carries the finding without its evidence.
   */
  @Test
  void aScrubbingFailureStillBlocks(@TempDir Path dir) throws Exception {
    OhMyRaspHooks.reportTo(logger(dir.resolve("events.jsonl")));
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.scrubberForTesting = event -> {
      throw new IllegalStateException("scrubber failed");
    };
    try {
      OhMyRaspBlockException blocked = assertThrows(OhMyRaspBlockException.class,
          () -> OhMyRaspHooks.beforeJdbcConnect("jdbc:h2:mem:reports;password=" + SENTINEL
              + ";INIT=RUNSCRIPT FROM 'http://127.0.0.1:1/init.sql'"));
      assertEquals("jdbc_h2_init", blocked.detection().algorithm());
      assertTrue(blocked.detection().details().isEmpty(), blocked.detection().details().toString());
      assertFalse(blocked.getMessage().contains(SENTINEL), blocked.getMessage());
    } finally {
      OhMyRaspHooks.scrubberForTesting = null;
    }
  }

  private static JsonEventLogger logger(Path log) {
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    return JsonEventLogger.newForTesting(null, log.toString(), 0, true, console, console);
  }
}
