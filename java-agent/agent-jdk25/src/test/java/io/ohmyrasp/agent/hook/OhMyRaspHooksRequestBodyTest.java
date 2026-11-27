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
  /** The stream the request reads its body from. */
  private static final Object STREAM = new Object();
  private static final String CANARY_BODY =
      "{\"username\":\"a\",\"password\":\"hunter2-Secret\",\"cmd\":\"127.0.0.1; id\"}";
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
    Object token = OhMyRaspHooks.enterBodyRead(STREAM);
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

  /**
   * The event of a finding on a request with a body shows the one field it matched, with that field's value (the
   * attacker's payload), and nothing else of the body: not another field's name or value, not the command as
   * executed. The same holds for the block exception and the block page it redirects to.
   */
  @Test
  void theCanaryBodyShowsOnlyTheMatchedFieldInTheEventTheBlockAndTheBlockPage() {
    System.setProperty("ohmyrasp.block", "true");
    byte[] body = CANARY_BODY.getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooksPolicyTest.FakeResponse response = new OhMyRaspHooksPolicyTest.FakeResponse();
    OhMyRaspHooks.enterHttpRequest(new BodyRequest("/app/ping", "application/json", body.length), response);
    read(body);
    OhMyRaspBlockException blocked = assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "echo 127.0.0.1; id")));
    String recorded = eventText();
    assertTrue(recorded.contains("\"algorithm\":\"command_userinput\""), recorded);
    assertTrue(recorded.contains("\"input_field\":\"cmd\""), recorded);
    assertTrue(recorded.contains("\"input_value\":\"127.0.0.1; id\""), recorded);
    assertTrue(recorded.contains("\"operand\":\"command, "), "the command as a kind and a length: " + recorded);
    assertFalse(recorded.contains("echo"), "the command as executed: " + recorded);
    String shown = blocked.getMessage() + " " + blocked.detection().message() + " " + blocked.detection().details()
        + " " + blocked.detection().request().parameters() + " " + response.location();
    for (String secret : List.of("hunter2", "Secret", "username", "password")) {
      assertFalse(recorded.contains(secret), "the event carries " + secret + ": " + recorded);
      assertFalse(shown.contains(secret), "the block carries " + secret + ": " + shown);
    }
    assertFalse(String.valueOf(response.location()).contains("127.0.0.1"), "the block page shows no input: " + response.location());
    assertEquals("", blocked.detection().request().body(), "the block's detection keeps no body");
  }

  /** Form fields the container parsed from a body are body-derived: the event shows no parameter map. */
  @Test
  void aFormTheContainerParsedCountsAsABody() {
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.enterHttpRequest(new FormRequest(Map.of("note", new String[] {"hunter2-Secret"},
        "cmd", new String[] {"127.0.0.1; id"})), new OhMyRaspHooksPolicyTest.FakeResponse());
    assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "echo 127.0.0.1; id")));
    String recorded = eventText();
    assertTrue(recorded.contains("\"input_field\":\"cmd\""), recorded);
    assertFalse(recorded.contains("hunter2"), recorded);
    assertFalse(recorded.contains("note"), recorded);
  }

  /** A POST whose container parsed a form body: the parameters are not in the query string. */
  public static class FormRequest {
    private final Map<String, String[]> parameters;

    FormRequest(Map<String, String[]> parameters) {
      this.parameters = parameters;
    }

    public String getMethod() { return "POST"; }
    public String getRequestURI() { return "/app/ping"; }
    public String getQueryString() { return "lang=en"; }
    public Map<String, String[]> getParameterMap() {
      Map<String, String[]> all = new java.util.LinkedHashMap<>(parameters);
      all.put("lang", new String[] {"en"});
      return all;
    }
    public Enumeration<String> getHeaderNames() { return Collections.enumeration(List.of("content-type")); }
    public String getHeader(String name) {
      return "content-type".equalsIgnoreCase(name) ? "application/x-www-form-urlencoded" : null;
    }
    public String getContentType() { return "application/x-www-form-urlencoded"; }
    public String getCharacterEncoding() { return "UTF-8"; }
    public long getContentLengthLong() { return 40; }
  }

  /** A request without a body keeps its event as the rule made it, operands included. */
  @Test
  void aRequestWithoutABodyKeepsItsOperands() {
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.enterHttpRequest(new QueryRequest("cmd=127.0.0.1%3B+id"), new OhMyRaspHooksPolicyTest.FakeResponse());
    assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "echo 127.0.0.1; id")));
    String recorded = eventText();
    assertTrue(recorded.contains("echo 127.0.0.1; id"), "the command, as before: " + recorded);
    assertFalse(recorded.contains("input_field"), recorded);
  }

  /** A GET whose only parameters are its query string's. */
  public static final class QueryRequest {
    private final String query;

    QueryRequest(String query) {
      this.query = query;
    }

    public String getMethod() { return "GET"; }
    public String getRequestURI() { return "/app/ping"; }
    public String getQueryString() { return query; }
    public Map<String, String[]> getParameterMap() {
      return Map.of("cmd", new String[] {"127.0.0.1; id"});
    }
    public Enumeration<String> getHeaderNames() { return Collections.enumeration(List.of()); }
    public String getHeader(String name) { return null; }
  }

  @Test
  void aBodyOnlyRulesEventNamesTheFieldAndCarriesNoBodyText() {
    byte[] body = ("[{\"op\":\"replace\",\"path\":\"T(java.lang.Runtime).getRuntime().exec('id')/lastname\","
        + "\"value\":\"hunter2-Secret\"}]").getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new BodyRequest("PATCH", "/customers/1", "application/json-patch+json", body.length),
        new OhMyRaspHooksPolicyTest.FakeResponse());
    read(body);
    String recorded = eventText();
    assertTrue(recorded.contains("request_json_patch_expression"), recorded);
    assertFalse(recorded.contains("hunter2"), "another field's value: " + recorded);
    assertFalse(recorded.contains("\"parameters\":{\"path\""), "a body field among the event's parameters: " + recorded);
  }

  @Test
  void aFindingTheRequestGivesWithoutItsBodyDoesNotHideTheBodysOwn() {
    // The request's own first finding (an internal identity on a control path) was the servlet entry's: before,
    // the body's run of the chain stopped at it and the body's later finding was never reported.
    byte[] body = "[{\"op\":\"replace\",\"path\":\"T(java.lang.Runtime).getRuntime().exec('id')/x\",\"value\":\"v\"}]"
        .getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new AgentRequest("PATCH", "/admin/customers/1", "application/json-patch+json",
        body.length, "nacos-server"), new OhMyRaspHooksPolicyTest.FakeResponse());
    String atEntry = eventText();
    assertTrue(atEntry.contains("request_internal_identity"), atEntry);
    read(body);
    String recorded = eventText().substring(atEntry.length());
    assertTrue(recorded.contains("\"algorithm\":\"request_expression_parameter\""), "the body's finding: " + recorded);
    assertFalse(recorded.contains("request_internal_identity"), "the entry's finding is not reported again: " + recorded);
    assertTrue(recorded.contains(io.ohmyrasp.agent.http.BodyEvidence.fixedMessage("request_expression_parameter")),
        "the rule's fixed message: " + recorded);
  }

  @Test
  void aBlockOnTheBodyIsThrownAgainByEveryLaterReadOfTheRequest() {
    System.setProperty("ohmyrasp.block", "true");
    byte[] body = "[{\"op\":\"replace\",\"path\":\"T(java.lang.Runtime).getRuntime().exec('id')/x\",\"value\":\"v\"}]"
        .getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new BodyRequest("PATCH", "/customers/1", "application/json-patch+json", body.length),
        new OhMyRaspHooksPolicyTest.FakeResponse());
    Object token = OhMyRaspHooks.enterBodyRead(STREAM);
    OhMyRaspBlockException blocked = assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.exitBodyRead(body.length, token, body, 0));
    // The application catches the block and reads on.
    OhMyRaspBlockException again = assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.enterBodyRead(STREAM));
    assertEquals(blocked, again);
    OhMyRaspHooks.exitHttpRequest();
    assertDoesNotThrow(() -> OhMyRaspHooks.enterBodyRead(STREAM), "the next request is not denied");
  }

  @Test
  void aContextCarriedPastTheDispatchKeepsNoBody() {
    byte[] body = CANARY_BODY.getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new BodyRequest("/app/ping", "application/json", body.length),
        new OhMyRaspHooksPolicyTest.FakeResponse());
    read(body);
    var carried = OhMyRaspHooks.currentRequest(); // what an HTTP exchange or a directory walk takes along
    assertTrue(carried.body().contains("hunter2-Secret"));
    OhMyRaspHooks.exitHttpRequest();
    assertEquals("", carried.body(), "the dispatch ended: the carried context dropped the body");
    assertNull(carried.bodySnapshot());
    assertTrue(carried.bodyDerived(), "an event of the carried operation is still built as on a request with a body");
    var detection = io.ohmyrasp.agent.model.Detection.log("ssrf", "ssrf_userinput", 90, "SSRF to http://10.0.0.1/",
        carried, Map.of("url", "http://10.0.0.1/?q=hunter2-Secret"));
    var shown = OhMyRaspHooks.publicView(detection);
    assertFalse(shown.toString().contains("hunter2"), shown.toString());
    assertFalse(shown.toString().contains("10.0.0.1"), "the operand as executed: " + shown);
  }

  /** A request with a User-Agent, for rules that read it. */
  public static final class AgentRequest {
    private final String method;
    private final String path;
    private final String contentType;
    private final long length;
    private final String userAgent;

    AgentRequest(String method, String path, String contentType, long length, String userAgent) {
      this.method = method;
      this.path = path;
      this.contentType = contentType;
      this.length = length;
      this.userAgent = userAgent;
    }

    public String getMethod() { return method; }
    public String getRequestURI() { return path; }
    public String getQueryString() { return null; }
    public Map<String, List<String>> getParameterMap() { return Map.of(); }
    public Enumeration<String> getHeaderNames() { return Collections.enumeration(List.of("content-type", "user-agent")); }
    public String getHeader(String name) {
      return "content-type".equalsIgnoreCase(name) ? contentType : "user-agent".equalsIgnoreCase(name) ? userAgent : null;
    }
    public String getContentType() { return contentType; }
    public String getCharacterEncoding() { return "UTF-8"; }
    public long getContentLengthLong() { return length; }
  }

  @Test
  void aBodyOnlyRuleBlocksInsideTheReadThatCompletesTheBody() {
    System.setProperty("ohmyrasp.block", "true");
    byte[] body = ("[{\"op\":\"replace\",\"path\":\"T(java.lang.Runtime).getRuntime().exec('id')/lastname\","
        + "\"value\":\"hunter2-Secret\"}]").getBytes(StandardCharsets.UTF_8);
    OhMyRaspHooks.enterHttpRequest(new BodyRequest("PATCH", "/customers/1", "application/json-patch+json", body.length),
        new OhMyRaspHooksPolicyTest.FakeResponse());
    Object first = OhMyRaspHooks.enterBodyRead(STREAM);
    assertDoesNotThrow(() -> OhMyRaspHooks.exitBodyRead(10, first, body, 0), "the body is not complete yet");
    Object second = OhMyRaspHooks.enterBodyRead(STREAM);
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
    assertNull(OhMyRaspHooks.enterBodyRead(STREAM));
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
