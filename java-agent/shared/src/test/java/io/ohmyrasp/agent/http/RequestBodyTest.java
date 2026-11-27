package io.ohmyrasp.agent.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class RequestBodyTest {
  /** What the recorder asks a servlet request, through the same public method names. */
  public static final class FakeRequest {
    private final String contentType;
    private final String encoding;
    private final long length;
    private final String coding;

    FakeRequest(String contentType, String encoding, long length, String coding) {
      this.contentType = contentType;
      this.encoding = encoding;
      this.length = length;
      this.coding = coding;
    }

    public String getContentType() { return contentType; }
    public String getCharacterEncoding() { return encoding; }
    public long getContentLengthLong() { return length; }
    public String getHeader(String name) { return "Content-Encoding".equals(name) ? coding : null; }
  }

  @AfterEach
  void leaveRequest() {
    RequestBodyCapture.dispatchExited(true);
  }

  private static RequestBody request(String contentType, String encoding, long length) {
    return request(new FakeRequest(contentType, encoding, length, null));
  }

  private static RequestBody request(Object servletRequest) {
    RequestBodyCapture.dispatchEntered();
    RequestBodyCapture.applicationEntered(true, servletRequest, true);
    RequestBody body = RequestBodyCapture.current();
    assertNotNull(body);
    return body;
  }

  private static boolean read(byte[] bytes, int offset, int count) {
    Object token = RequestBodyCapture.enter();
    assertNotNull(token, "the read is recorded");
    return RequestBodyCapture.exitBytes(count, token, bytes, offset);
  }

  @Test
  void nothingIsRecordedOnAThreadThatServesNoRequest() {
    RequestBodyCapture.dispatchExited(true);
    assertNull(RequestBodyCapture.enter());
    assertFalse(RequestBodyCapture.exitBytes(3, null, new byte[3], 0));
  }

  @Test
  void nothingIsAllocatedForTheBodyBeforeItsFirstByte() throws Exception {
    RequestBody body = request("application/json", "UTF-8", 10);
    java.lang.reflect.Field bytes = RequestBody.class.getDeclaredField("bytes");
    bytes.setAccessible(true);
    // A thread that served a body before keeps its buffer for the next request: start from a fresh thread.
    final Object[] seen = new Object[2];
    Thread fresh = new Thread(new Runnable() {
      @Override public void run() {
        try {
          RequestBodyCapture.dispatchEntered();
          RequestBodyCapture.applicationEntered(true, new FakeRequest("application/json", "UTF-8", 10, null), true);
          seen[0] = bytes.get(RequestBodyCapture.current());
          Object token = RequestBodyCapture.enter();
          RequestBodyCapture.exitBytes(-1, token, null, 0);
          seen[1] = bytes.get(RequestBodyCapture.current());
        } catch (Exception failure) {
          seen[0] = failure;
        }
      }
    });
    fresh.start();
    fresh.join();
    assertNull(seen[0]);
    assertNull(seen[1], "an empty body allocates nothing");
    assertNull(body.snapshot());
  }

  @Test
  void theBodyCompletesWhenTheBytesReachContentLength() {
    byte[] json = "{\"host\":\"127.0.0.1; id\"}".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request("application/json", null, json.length);
    assertFalse(read(json, 0, 10));
    assertTrue(body.pending());
    assertTrue(read(json, 10, json.length - 10), "the read that reaches Content-Length completes the body");
    assertTrue(body.done());
    assertNull(RequestBodyCapture.enter(), "a completed body records nothing more: a wrapper's replay is not counted");
    assertEquals("{\"host\":\"127.0.0.1; id\"}", body.snapshot().text());
    assertEquals(Collections.singletonList("127.0.0.1; id"), body.snapshot().values().values());
    body.markDecided();
    assertFalse(body.pending());
  }

  @Test
  void endOfStreamCompletesABodyOfUnknownLength() {
    byte[] text = "a=1".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request("application/x-www-form-urlencoded", null, -1);
    assertFalse(read(text, 0, text.length));
    assertTrue(read(new byte[8], 0, -1));
    assertEquals(Collections.singletonList("1"), body.snapshot().values().parameters().get("a"));
  }

  @Test
  void theCapStopsRecordingAndMarksTheBodyTruncated() {
    byte[] big = new byte[RequestBody.MAX_UNITS + 100];
    Arrays.fill(big, (byte) 'a');
    RequestBody body = request("text/plain", null, big.length);
    assertTrue(read(big, 0, big.length));
    assertTrue(body.truncated());
    assertEquals(RequestBody.MAX_UNITS, body.snapshot().text().length());
    assertTrue(body.snapshot().truncated());
    assertNull(RequestBodyCapture.enter(), "past the cap a read is a thread-local read and a branch");
  }

  @Test
  void aBodyExactlyAtTheCapIsComplete() {
    byte[] exact = new byte[RequestBody.MAX_UNITS];
    Arrays.fill(exact, (byte) 'a');
    RequestBody body = request("text/plain", null, exact.length);
    assertTrue(read(exact, 0, exact.length));
    assertFalse(body.truncated());
  }

  @Test
  void aReadInsideARecordedReadIsNotRecordedAgain() {
    RequestBody body = request("text/plain", null, -1);
    Object outer = RequestBodyCapture.enter();
    assertNotNull(outer);
    assertNull(RequestBodyCapture.enter(), "the wrapped stream's read, inside the wrapper's");
    RequestBodyCapture.exitBytes(2, null, "ab".getBytes(StandardCharsets.UTF_8), 0);
    RequestBodyCapture.exitBytes(2, outer, "ab".getBytes(StandardCharsets.UTF_8), 0);
    assertEquals("ab", body.snapshot().text());
    assertNotNull(RequestBodyCapture.enter(), "the next outermost read records again");
  }

  @Test
  void aCharacterSplitAcrossTwoReadsDecodesWhole() {
    byte[] bytes = "{\"q\":\"\u4e2d\u6587\"}".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request("application/json; charset=UTF-8", null, bytes.length);
    int split = 8; // inside the first CJK character's three bytes
    read(bytes, 0, split);
    assertEquals("{\"q\":\"", body.snapshot().text(), "the incomplete character waits for its last bytes");
    assertTrue(read(bytes, split, bytes.length - split));
    assertEquals(Collections.singletonList("\u4e2d\u6587"), body.snapshot().values().values());
  }

  @Test
  void theRequestsCharsetDecodesTheBytes() {
    byte[] bytes = "{\"q\":\"caf\u00e9\"}".getBytes(StandardCharsets.ISO_8859_1);
    RequestBody body = request("application/json", "ISO-8859-1", bytes.length);
    assertTrue(read(bytes, 0, bytes.length));
    assertEquals(Collections.singletonList("caf\u00e9"), body.snapshot().values().values());
  }

  @Test
  void binaryAndEncodedBodiesAreNotRecorded() {
    RequestBody binary = request("application/octet-stream", null, 4);
    assertFalse(read(new byte[] {1, 2, 3, 4}, 0, 4));
    assertTrue(binary.done());
    assertNull(binary.snapshot());
    RequestBodyCapture.dispatchExited(true);
    RequestBody multipart = request("multipart/form-data; boundary=x", null, 4);
    assertFalse(read("--x\n".getBytes(StandardCharsets.UTF_8), 0, 4));
    assertNull(multipart.snapshot());
    RequestBodyCapture.dispatchExited(true);
    RequestBody gzip = request(new FakeRequest("application/json", null, 4, "gzip"));
    assertFalse(read(new byte[] {0x1f, (byte) 0x8b, 8, 0}, 0, 4));
    assertNull(gzip.snapshot());
  }

  @Test
  void aBodyWithNoContentTypeIsReadAsJsonWhenItLooksLikeJson() {
    byte[] bytes = "{\"exePath\":\"id\"}".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request(null, null, bytes.length);
    assertTrue(read(bytes, 0, bytes.length));
    assertEquals(Collections.singletonList("id"), body.snapshot().values().parameters().get("exePath"));
  }

  @Test
  void readsDuringTheAgentsOwnInspectionAreNotRecorded() {
    request("application/x-www-form-urlencoded", null, -1);
    RequestBodyCapture.dispatchEntered(); // a nested dispatch is being inspected
    assertNull(RequestBodyCapture.enter());
    RequestBodyCapture.applicationEntered(false, null, true);
    assertNotNull(RequestBodyCapture.enter());
  }

  @Test
  void detectionOffRecordsNothing() {
    RequestBodyCapture.dispatchEntered();
    RequestBodyCapture.applicationEntered(true, new FakeRequest("application/json", null, 3, null), false);
    assertNull(RequestBodyCapture.enter());
  }

  @Test
  void theReaderPathRecordsCharactersAndLines() {
    RequestBody body = request("application/json", "UTF-8", -1);
    Object token = RequestBodyCapture.enter();
    RequestBodyCapture.exitChars(4, token, "{\"a\":".toCharArray(), 1);
    token = RequestBodyCapture.enter();
    RequestBodyCapture.exitChar('x', token);
    token = RequestBodyCapture.enter();
    assertFalse(RequestBodyCapture.exitLine("\"b\"}", token));
    token = RequestBodyCapture.enter();
    assertTrue(RequestBodyCapture.exitLine(null, token));
    assertEquals("\"a\":x\"b\"}\n", body.snapshot().text());
  }

  @Test
  void aReaderCompletesByContentLengthInUtf8ButKeepsRecording() {
    String text = "{\"q\":\"\u00e9\"}"; // 10 bytes in UTF-8, 9 chars
    RequestBody body = request("application/json", "UTF-8", text.getBytes(StandardCharsets.UTF_8).length);
    Object token = RequestBodyCapture.enter();
    assertTrue(RequestBodyCapture.exitChars(text.length(), token, text.toCharArray(), 0));
    assertFalse(body.done());
    body.markDecided();
    token = RequestBodyCapture.enter();
    assertFalse(RequestBodyCapture.exitChar(-1, token), "end of stream with nothing new: nothing to decide");
  }

  @Test
  void byteBuffersAndWholeArraysAreRecorded() {
    RequestBody body = request("text/plain", null, -1);
    ByteBuffer buffer = ByteBuffer.allocate(16);
    buffer.put("xxab".getBytes(StandardCharsets.UTF_8));
    Object token = RequestBodyCapture.enter();
    RequestBodyCapture.exitBuffer(2, token, buffer);
    token = RequestBodyCapture.enter();
    assertTrue(RequestBodyCapture.exitAll("cd".getBytes(StandardCharsets.UTF_8), token, true));
    assertEquals("abcd", body.snapshot().text());
    RequestBodyCapture.dispatchExited(true);
    RequestBody chars = request("text/plain", null, -1);
    CharBuffer read = CharBuffer.allocate(8);
    read.put("hey");
    token = RequestBodyCapture.enter();
    RequestBodyCapture.exitCharBuffer(3, token, read);
    assertEquals("hey", chars.snapshot().text());
  }

  @Test
  void aSnapshotIsBuiltOncePerState() {
    RequestBody body = request("text/plain", null, -1);
    read("ab".getBytes(StandardCharsets.UTF_8), 0, 2);
    RequestBodySnapshot first = body.snapshot();
    assertSame(first, body.snapshot());
    read("cd".getBytes(StandardCharsets.UTF_8), 0, 2);
    assertTrue(body.snapshot().version() > first.version());
    assertEquals("abcd", body.snapshot().text());
  }

  @Test
  void theNextRequestStartsEmpty() {
    RequestBody body = request("text/plain", null, -1);
    read("ab".getBytes(StandardCharsets.UTF_8), 0, 2);
    RequestBodyCapture.dispatchExited(true);
    assertNull(RequestBodyCapture.enter());
    RequestBody next = request("text/plain", null, -1);
    assertSame(body, next, "one recorder per thread");
    assertNull(next.snapshot());
    assertFalse(next.pending());
  }
}
