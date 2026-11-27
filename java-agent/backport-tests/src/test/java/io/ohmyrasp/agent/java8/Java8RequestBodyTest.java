package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** What the application reads of a request body reaches the backport rules, and never an event line. */
final class Java8RequestBodyTest {
  /** Other tests on this thread can leave a dispatch open: start each test outside any request. */
  @BeforeEach
  void leaveEveryRequest() {
    for (int i = 0; i < 16; i++) Java8RaspHooks.afterHttpRequest();
  }

  @AfterEach
  void clearProperties() {
    Java8RaspHooks.afterHttpRequest();
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.java8.block");
  }

  /** A request with a body: its metadata comes from the public servlet method names, as on a container. */
  public static final class BodyRequest {
    private final String uri;
    private final String contentType;
    private final long length;

    BodyRequest(String uri, String contentType, long length) {
      this.uri = uri;
      this.contentType = contentType;
      this.length = length;
    }

    public String getMethod() { return "POST"; }
    public String getRequestURI() { return uri; }
    public String getQueryString() { return null; }
    public Map<String, String[]> getParameterMap() { return Collections.<String, String[]>emptyMap(); }
    public String getHeader(String name) { return "Content-Type".equalsIgnoreCase(name) ? contentType : null; }
    public String getContentType() { return contentType; }
    public String getCharacterEncoding() { return "UTF-8"; }
    public long getContentLengthLong() { return length; }
  }

  private static Path log() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-request-body", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    return log;
  }

  private static String read(Path log) throws Exception {
    return Files.exists(log) ? new String(Files.readAllBytes(log), StandardCharsets.UTF_8) : "";
  }

  @Test
  void aBlockOnABodyValueRecordsNoOtherPartOfTheBody() throws Exception {
    Path log = log();
    System.setProperty("ohmyrasp.java8.block", "true");
    byte[] body = "{\"username\":\"a\",\"password\":\"hunter2-Secret\",\"cmd\":\"127.0.0.1; id\"}"
        .getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeHttpRequest(new BodyRequest("/app/ping", "application/json", body.length));
    Object token = Java8RaspHooks.enterBodyRead();
    Java8RaspHooks.exitBodyRead(body.length, token, body, 0);
    assertThrows(Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "echo 127.0.0.1; id")));
    String recorded = read(log);
    assertTrue(recorded.contains("java8_command_execution_shell_meta"), recorded);
    assertFalse(recorded.contains("hunter2-Secret"), "the event carries the body: " + recorded);
  }

  @Test
  void aRequestRuleOnTheBodyBlocksInsideTheReadThatCompletesIt() throws Exception {
    Path log = log();
    System.setProperty("ohmyrasp.java8.block", "true");
    final byte[] body = "{\"exePath\":\"id\"}".getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeHttpRequest(new BodyRequest("/app/rest/debug/processes", "application/json", body.length));
    final Object token = Java8RaspHooks.enterBodyRead();
    assertThrows(Java8RaspBlockException.class, new org.junit.jupiter.api.function.Executable() {
      @Override public void execute() {
        Java8RaspHooks.exitBodyRead(body.length, token, body, 0);
      }
    });
    assertTrue(read(log).contains("java8_request_debug_process_launch"), read(log));
  }

  @Test
  void aReadOutsideARequestIsNotRecorded() {
    assertNull(Java8RaspHooks.enterBodyRead());
    Java8RaspHooks.exitBodyRead(3, null, new byte[] {1, 2, 3}, 0);
  }
}
