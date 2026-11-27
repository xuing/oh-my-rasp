package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** What the application reads of a request body reaches the rules, and never an event line. */
final class OhMyRaspHooksRequestBodyTest {
  private ByteArrayOutputStream events;

  @BeforeEach
  void captureEvents() {
    events = new ByteArrayOutputStream();
    PrintStream out = new PrintStream(events, true, StandardCharsets.UTF_8);
    OhMyRaspHooks.reportTo(JsonEventLogger.newForTesting(null, "stdout", 0, false, out, out));
  }

  @AfterEach
  void reset() {
    OhMyRaspHooks.reportTo(null);
    OhMyRaspHooks.exitHttpRequest();
    System.clearProperty("ohmyrasp.block");
  }

  /** A request with a body: its metadata comes from the public servlet method names, as on a container. */
  public static final class BodyRequest {
    private final String method;
    private final String path;
    private final String contentType;
    private final long length;

    BodyRequest(String path, String contentType, long length) {
      this("POST", path, contentType, length);
    }

    BodyRequest(String method, String path, String contentType, long length) {
      this.method = method;
      this.path = path;
      this.contentType = contentType;
      this.length = length;
    }

    public String getMethod() { return method; }
    public String getRequestURI() { return path; }
    public String getQueryString() { return null; }
    public Map<String, List<String>> getParameterMap() { return Map.of(); }
    public Enumeration<String> getHeaderNames() { return Collections.enumeration(List.of("content-type")); }
    public String getHeader(String name) { return "content-type".equalsIgnoreCase(name) ? contentType : null; }
    public String getContentType() { return contentType; }
    public String getCharacterEncoding() { return "UTF-8"; }
    public long getContentLengthLong() { return length; }
  }

  /** The application reads the body with one array read, as a JSON parser does. */
  private static void read(byte[] body) {
    Object token = OhMyRaspHooks.enterBodyRead();
    OhMyRaspHooks.exitBodyRead(body.length, token, body, 0);
  }

  private String eventText() {
    return events.toString(StandardCharsets.UTF_8);
  }

  @Test
  void aBlockOnABodyValueRecordsNoOtherPartOfTheBody() {
    System.setProperty("ohmyrasp.block", "true");
    byte[] body = "{\"username\":\"a\",\"password\":\"hunter2-Secret\",\"cmd\":\"127.0.0.1; id\"}"
        .getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new BodyRequest("/app/ping", "application/json", body.length),
        new OhMyRaspHooksPolicyTest.FakeResponse());
    read(body);
    assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "echo 127.0.0.1; id")));
    String recorded = eventText();
    assertTrue(recorded.contains("\"algorithm\":\"command_userinput\""), recorded);
    assertTrue(recorded.contains("\"action\":\"block\""), recorded);
    assertFalse(recorded.contains("hunter2-Secret"), "the event carries the body: " + recorded);
  }

  @Test
  void aBodyOnlyRuleBlocksInsideTheReadThatCompletesTheBody() {
    System.setProperty("ohmyrasp.block", "true");
    byte[] body = ("[{\"op\":\"replace\",\"path\":\"T(java.lang.Runtime).getRuntime().exec('id')/lastname\","
        + "\"value\":\"hunter2-Secret\"}]").getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new BodyRequest("PATCH", "/customers/1", "application/json-patch+json", body.length),
        new OhMyRaspHooksPolicyTest.FakeResponse());
    Object first = OhMyRaspHooks.enterBodyRead();
    assertDoesNotThrow(() -> OhMyRaspHooks.exitBodyRead(10, first, body, 0), "the body is not complete yet");
    Object second = OhMyRaspHooks.enterBodyRead();
    assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.exitBodyRead(body.length - 10, second, body, 10));
    String recorded = eventText();
    assertTrue(recorded.contains("\"algorithm\":\"request_json_patch_expression\""), recorded);
    assertFalse(recorded.contains("hunter2-Secret"), recorded);
  }

  @Test
  void anotherHookDecidesTheBodyFirstWhenTheBodyIsNotComplete() {
    // No Content-Length and no end of stream: the next decision of any hook decides the body first.
    byte[] body = "[{\"op\":\"replace\",\"path\":\"T(java.lang.Runtime).getRuntime().exec('id')/x\",\"value\":\"v\"}]"
        .getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new BodyRequest("PATCH", "/customers/1", "application/json-patch+json", -1),
        new OhMyRaspHooksPolicyTest.FakeResponse());
    read(body);
    assertEquals("", eventText());
    OhMyRaspHooks.beforeFileWrite("/tmp/ohmyrasp-request-body-test.txt");
    assertTrue(eventText().contains("request_json_patch_expression"), eventText());
    int length = eventText().length();
    OhMyRaspHooks.beforeFileWrite("/tmp/ohmyrasp-request-body-test.txt");
    assertEquals(length, eventText().length(), "one state of the body is decided once");
  }

  @Test
  void aReadOutsideARequestIsNotRecorded() {
    assertNull(OhMyRaspHooks.enterBodyRead());
    assertDoesNotThrow(() -> OhMyRaspHooks.exitBodyRead(3, null, new byte[] {1, 2, 3}, 0));
  }

  @Test
  void theSameInputAsAQueryParameterAndAsABodyFieldIsMatchedTheSameWay() {
    System.setProperty("ohmyrasp.block", "true");
    byte[] body = "{\"file\":\"/etc/hosts\"}".getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new BodyRequest("/download", "application/json", body.length),
        new OhMyRaspHooksPolicyTest.FakeResponse());
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeFileRead("/etc/hosts"), "before the body is read");
    read(body);
    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeFileRead("/etc/hosts"));
  }
}
