package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
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
  /** The stream the request reads its body from. */
  private static final Object STREAM = new Object();
  /**
   * Other tests on this thread can leave dispatches open: start each test outside any request, with the thread's
   * body recorder closed.
   */
  @BeforeEach
  void leaveEveryRequest() {
    // Java8RaspHooksTest leaves more than 16 nested dispatches open on this thread: with one still open, a
    // request is not the outermost, and its body is not recorded.
    for (int i = 0; i < 1024; i++) Java8RaspHooks.afterHttpRequest();
    io.ohmyrasp.agent.http.RequestBodyCapture.dispatchExited(true);
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
    private final String userAgent;

    BodyRequest(String uri, String contentType, long length) {
      this(uri, contentType, length, null);
    }

    BodyRequest(String uri, String contentType, long length, String userAgent) {
      this.uri = uri;
      this.contentType = contentType;
      this.length = length;
      this.userAgent = userAgent;
    }

    public String getMethod() { return "POST"; }
    public String getRequestURI() { return uri; }
    public String getQueryString() { return null; }
    public Map<String, String[]> getParameterMap() { return Collections.<String, String[]>emptyMap(); }
    public String getHeader(String name) {
      return "Content-Type".equalsIgnoreCase(name) ? contentType : "User-Agent".equalsIgnoreCase(name) ? userAgent : null;
    }
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
    Object token = Java8RaspHooks.enterBodyRead(STREAM);
    Java8RaspHooks.exitBodyRead(body.length, token, body, 0);
    assertThrows(Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "echo 127.0.0.1; id")));
    String recorded = read(log);
    assertTrue(recorded.contains("java8_command_execution_shell_meta"), recorded);
    // The one field the finding matched, with its value (the payload), and nothing else of the body.
    assertTrue(recorded.contains("\"input_field\":\"cmd\""), recorded);
    assertTrue(recorded.contains("\"input_value\":\"127.0.0.1; id\""), recorded);
    assertTrue(recorded.contains("\"operand\":\"command, "), "the command as a kind and a length: " + recorded);
    assertFalse(recorded.contains("echo"), "the command as executed: " + recorded);
    for (String secret : new String[] {"hunter2", "Secret", "username", "password"}) {
      assertFalse(recorded.contains(secret), "the event carries " + secret + ": " + recorded);
    }
  }

  @Test
  void aBlockOnTheBodyIsThrownAgainByEveryLaterReadOfTheRequest() throws Exception {
    final Path log = log();
    System.setProperty("ohmyrasp.java8.block", "true");
    final byte[] body = "{\"exePath\":\"id\"}".getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeHttpRequest(new BodyRequest("/app/rest/debug/processes", "application/json", body.length));
    final Object token = Java8RaspHooks.enterBodyRead(STREAM);
    Java8RaspBlockException blocked = assertThrows(Java8RaspBlockException.class,
        new org.junit.jupiter.api.function.Executable() {
          @Override public void execute() {
            Java8RaspHooks.exitBodyRead(body.length, token, body, 0);
          }
        }, new java.util.function.Supplier<String>() {
          @Override public String get() {
            try {
              StringBuilder state = new StringBuilder();
              Object recorder = io.ohmyrasp.agent.http.RequestBodyCapture.current();
              if (recorder != null) {
                for (java.lang.reflect.Field field : recorder.getClass().getDeclaredFields()) {
                  if (java.lang.reflect.Modifier.isStatic(field.getModifiers())) continue;
                  field.setAccessible(true);
                  Object value = field.get(recorder);
                  state.append(field.getName()).append('=')
                      .append(value instanceof byte[] || value instanceof char[] ? "[...]" : value).append(' ');
                }
              }
              return "token " + token + ", recorder {" + state + "}, events: " + read(log);
            } catch (Exception e) {
              return e.toString();
            }
          }
        });
    Java8RaspBlockException again = assertThrows(Java8RaspBlockException.class,
        new org.junit.jupiter.api.function.Executable() {
          @Override public void execute() {
            Java8RaspHooks.enterBodyRead(STREAM); // the application caught the block and reads on
          }
        });
    assertSame(blocked, again);
    Java8RaspHooks.afterHttpRequest();
    Java8RaspHooks.enterBodyRead(STREAM); // the next request is not denied
  }

  @Test
  void aFindingTheRequestGivesWithoutItsBodyDoesNotHideTheBodysOwn() throws Exception {
    Path log = log();
    final byte[] body = "{\"exePath\":\"id\"}".getBytes(StandardCharsets.UTF_8);
    // An internal identity on a control path: the request's first finding, the servlet entry's.
    Java8RaspHooks.beforeHttpRequest(new BodyRequest("/admin/app/rest/debug/processes", "application/json",
        body.length, "nacos-server"));
    String atEntry = read(log);
    assertTrue(atEntry.contains("java8_request_internal_identity"), atEntry);
    Object token = Java8RaspHooks.enterBodyRead(STREAM);
    Java8RaspHooks.exitBodyRead(body.length, token, body, 0);
    String recorded = read(log).substring(atEntry.length());
    assertTrue(recorded.contains("java8_request_debug_process_launch"), "the body's finding: " + recorded);
    assertFalse(recorded.contains("request_internal_identity"), recorded);
  }

  @Test
  void aRequestRuleOnTheBodyBlocksInsideTheReadThatCompletesIt() throws Exception {
    Path log = log();
    System.setProperty("ohmyrasp.java8.block", "true");
    final byte[] body = "{\"exePath\":\"id\"}".getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeHttpRequest(new BodyRequest("/app/rest/debug/processes", "application/json", body.length));
    final Object token = Java8RaspHooks.enterBodyRead(STREAM);
    assertThrows(Java8RaspBlockException.class, new org.junit.jupiter.api.function.Executable() {
      @Override public void execute() {
        Java8RaspHooks.exitBodyRead(body.length, token, body, 0);
      }
    });
    assertTrue(read(log).contains("java8_request_debug_process_launch"), read(log));
  }

  @Test
  void aReadOutsideARequestIsNotRecorded() {
    assertNull(Java8RaspHooks.enterBodyRead(STREAM));
    Java8RaspHooks.exitBodyRead(3, null, new byte[] {1, 2, 3}, 0);
  }
}
