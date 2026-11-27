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
  /** The stream the request reads its body from in these tests. */
  static final Object SOURCE = new Object();

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
    Object token = RequestBodyCapture.enter(SOURCE);
    assertNotNull(token, "the read is recorded");
    return RequestBodyCapture.exitBytes(count, token, bytes, offset);
  }

  @Test
  void nothingIsRecordedOnAThreadThatServesNoRequest() {
    RequestBodyCapture.dispatchExited(true);
    assertNull(RequestBodyCapture.enter(SOURCE));
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
          Object token = RequestBodyCapture.enter(SOURCE);
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
    int prefix = body.snapshot().version();
    assertTrue(read(json, 10, json.length - 10), "the read that reaches Content-Length completes the body");
    assertTrue(body.snapshot().version() > prefix);
    assertTrue(body.done());
    assertNull(RequestBodyCapture.enter(SOURCE), "a completed body records nothing more: a wrapper's replay is not counted");
    assertEquals("{\"host\":\"127.0.0.1; id\"}", body.snapshot().text());
    assertEquals(Collections.singletonList("127.0.0.1; id"), body.snapshot().values().values());
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
    assertNull(RequestBodyCapture.enter(SOURCE), "past the cap a read is a thread-local read and a branch");
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
    Object outer = RequestBodyCapture.enter(SOURCE);
    assertNotNull(outer);
    assertNull(RequestBodyCapture.enter(SOURCE), "the wrapped stream's read, inside the wrapper's");
    RequestBodyCapture.exitBytes(2, null, "ab".getBytes(StandardCharsets.UTF_8), 0);
    RequestBodyCapture.exitBytes(2, outer, "ab".getBytes(StandardCharsets.UTF_8), 0);
    assertEquals("ab", body.snapshot().text());
    assertNotNull(RequestBodyCapture.enter(SOURCE), "the next outermost read records again");
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
    assertNull(RequestBodyCapture.enter(SOURCE));
    RequestBodyCapture.applicationEntered(false, null, true);
    assertNotNull(RequestBodyCapture.enter(SOURCE));
  }

  @Test
  void detectionOffRecordsNothing() {
    RequestBodyCapture.dispatchEntered();
    RequestBodyCapture.applicationEntered(true, new FakeRequest("application/json", null, 3, null), false);
    assertNull(RequestBodyCapture.enter(SOURCE));
  }

  @Test
  void theReaderPathRecordsCharactersAndLines() {
    RequestBody body = request("application/json", "UTF-8", -1);
    Object token = RequestBodyCapture.enter(SOURCE);
    RequestBodyCapture.exitChars(4, token, "{\"a\":".toCharArray(), 1);
    token = RequestBodyCapture.enter(SOURCE);
    RequestBodyCapture.exitChar('x', token);
    token = RequestBodyCapture.enter(SOURCE);
    assertFalse(RequestBodyCapture.exitLine("\"b\"}", token));
    token = RequestBodyCapture.enter(SOURCE);
    assertTrue(RequestBodyCapture.exitLine(null, token));
    assertEquals("\"a\":x\"b\"}", body.snapshot().text(), "readLine's last line had no terminator to record");
  }

  @Test
  void aReaderCompletesByContentLengthInUtf8ButKeepsRecording() {
    String text = "{\"q\":\"\u00e9\"}"; // 10 bytes in UTF-8, 9 chars
    RequestBody body = request("application/json", "UTF-8", text.getBytes(StandardCharsets.UTF_8).length);
    Object token = RequestBodyCapture.enter(SOURCE);
    assertTrue(RequestBodyCapture.exitChars(text.length(), token, text.toCharArray(), 0));
    assertFalse(body.done());
    int estimated = body.snapshot().version();
    token = RequestBodyCapture.enter(SOURCE);
    assertTrue(RequestBodyCapture.exitChar(-1, token), "end of stream completes the body: a state of its own");
    assertTrue(body.snapshot().version() > estimated);
  }

  @Test
  void byteBuffersAndWholeArraysAreRecorded() {
    RequestBody body = request("text/plain", null, -1);
    ByteBuffer buffer = ByteBuffer.allocate(16);
    buffer.put("xx".getBytes(StandardCharsets.UTF_8));
    Object token = RequestBodyCapture.enter(SOURCE, buffer);
    buffer.put("ab".getBytes(StandardCharsets.UTF_8)); // a read that advances the position past its bytes
    RequestBodyCapture.exitBuffer(2, token, buffer);
    token = RequestBodyCapture.enter(SOURCE);
    assertTrue(RequestBodyCapture.exitAll("cd".getBytes(StandardCharsets.UTF_8), token, true));
    assertEquals("abcd", body.snapshot().text());
    RequestBodyCapture.dispatchExited(true);
    RequestBody chars = request("text/plain", null, -1);
    CharBuffer read = CharBuffer.allocate(8);
    token = RequestBodyCapture.enter(SOURCE, read);
    read.put("hey");
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
    assertNull(RequestBodyCapture.enter(SOURCE));
    RequestBody next = request("text/plain", null, -1);
    assertSame(body, next, "one recorder per thread");
    assertNull(next.snapshot());
    assertEquals(0, next.version());
  }

  // ---- review fixes: the buffer contract, ownership, exceptions, retention, final states, budget ----------------

  /** Tomcat's read(ByteBuffer): the bytes go in at the position, which is restored; the limit ends after them. */
  private static int tomcatRead(ByteBuffer to, byte[] data) {
    to.put(data);
    to.limit(to.position());
    to.position(to.position() - data.length);
    return data.length;
  }

  @Test
  void aBufferReadIsRecordedFromWhereTheBufferStoodOnBothContracts() {
    byte[] data = "{\"cmd\":\"id\"}".getBytes(StandardCharsets.UTF_8);
    for (boolean direct : new boolean[] {false, true}) {
      for (int position : new int[] {0, 7}) {
        for (boolean tomcat : new boolean[] {false, true}) {
          RequestBody body = request("application/json", "UTF-8", data.length);
          ByteBuffer buffer = direct ? ByteBuffer.allocateDirect(64) : ByteBuffer.allocate(64);
          while (buffer.hasRemaining()) buffer.put((byte) 'x'); // bytes before the read's position are not the body
          buffer.clear();
          buffer.position(position);
          Object token = RequestBodyCapture.enter(SOURCE, buffer);
          int count;
          if (tomcat) {
            count = tomcatRead(buffer, data);
          } else {
            buffer.put(data);
            count = data.length;
          }
          int positionAfter = buffer.position();
          int limitAfter = buffer.limit();
          assertTrue(RequestBodyCapture.exitBuffer(count, token, buffer));
          String label = (direct ? "direct" : "heap") + " position " + position + (tomcat ? " tomcat" : " nio");
          assertEquals("{\"cmd\":\"id\"}", body.snapshot().text(), label);
          assertEquals(positionAfter, buffer.position(), "the recorder leaves the position: " + label);
          assertEquals(limitAfter, buffer.limit(), "the recorder leaves the limit: " + label);
          RequestBodyCapture.dispatchExited(true);
        }
      }
    }
  }

  @Test
  void onlyTheStreamTheRequestReadFirstIsRecorded() {
    RequestBody body = request("text/plain", null, -1);
    read("ab".getBytes(StandardCharsets.UTF_8), 0, 2);
    Object mock = new Object();
    assertNull(RequestBodyCapture.enter(mock), "another stream read on the thread: a mock, a replay, another request's");
    assertNotNull(RequestBodyCapture.enter(SOURCE), "the request's own stream still records");
    RequestBodyCapture.dispatchExited(true);
    request("text/plain", null, -1);
    Object token = RequestBodyCapture.enter(mock);
    assertNotNull(token, "the next request binds to the stream it reads first");
    RequestBodyCapture.exitBytes(1, token, new byte[] {'z'}, 0);
    assertNull(RequestBodyCapture.enter(SOURCE));
  }

  @Test
  void aReadThatThrowsReleasesTheRecorderForTheRetry() {
    RequestBody body = request("text/plain", null, -1);
    Object failed = RequestBodyCapture.enter(SOURCE);
    assertNotNull(failed);
    RequestBodyCapture.abort(failed); // what the rewritten method's handler does when the read throws
    read("ok".getBytes(StandardCharsets.UTF_8), 0, 2);
    assertEquals("ok", body.snapshot().text(), "the retry is recorded");
  }

  @Test
  void aDeniedRequestThrowsTheSameBlockOnEveryLaterRead() {
    request("application/json", null, -1);
    RuntimeException block = new RuntimeException("blocked");
    RequestBodyCapture.deny(block);
    try {
      RequestBodyCapture.enter(SOURCE);
      throw new AssertionError("the read went on");
    } catch (RuntimeException thrown) {
      assertSame(block, thrown);
    }
    try {
      RequestBodyCapture.enter(new Object());
      throw new AssertionError("a read of another stream went on");
    } catch (RuntimeException thrown) {
      assertSame(block, thrown);
    }
    RequestBodyCapture.dispatchExited(true);
    request("application/json", null, -1);
    assertNotNull(RequestBodyCapture.enter(SOURCE), "the next request is not denied");
  }

  private static Object field(RequestBody body, String name) throws Exception {
    java.lang.reflect.Field field = RequestBody.class.getDeclaredField(name);
    field.setAccessible(true);
    return field.get(body);
  }

  @Test
  void theEndOfTheRequestOverwritesTheRecordedBytesAndCharacters() throws Exception {
    byte[] secret = "{\"password\":\"hunter2-Secret\"}".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request("application/json", null, -1);
    read(secret, 0, secret.length);
    byte[] kept = (byte[]) field(body, "bytes");
    RequestBodyCapture.dispatchExited(true);
    for (byte b : kept) assertEquals(0, b, "a byte of the last request is left on the idle thread");
    assertSame(kept, field(body, "bytes"), "a small buffer is kept, zeroed, for the next request");

    request("text/plain", null, -1);
    Object token = RequestBodyCapture.enter(SOURCE);
    RequestBodyCapture.exitChars(6, token, "secret".toCharArray(), 0);
    char[] chars = (char[]) field(body, "chars");
    RequestBodyCapture.dispatchExited(true);
    for (char c : chars) assertEquals('\0', c);

    byte[] large = new byte[5000];
    Arrays.fill(large, (byte) 's');
    request("text/plain", null, -1);
    read(large, 0, 1000);
    byte[] small = (byte[]) field(body, "bytes");
    read(large, 1000, 4000); // grows the buffer: the old copy is overwritten
    for (byte b : small) assertEquals(0, b, "the buffer the recorder grew out of keeps nothing");
    byte[] grown = (byte[]) field(body, "bytes");
    RequestBodyCapture.dispatchExited(true);
    for (byte b : grown) assertEquals(0, b);
    assertNull(field(body, "bytes"), "a buffer larger than the kept size is dropped");
    assertNull(field(body, "source"));
    assertNull(body.lastSnapshot());
    assertNull(body.servletRequest());
  }

  @Test
  void aThreadReusedWithoutAnEndStillStartsClean() throws Exception {
    RequestBody body = request("text/plain", null, -1);
    read("secret".getBytes(StandardCharsets.UTF_8), 0, 6);
    byte[] kept = (byte[]) field(body, "bytes");
    // The next request starts on the thread without the last one having ended (an exit hook that did not run).
    RequestBodyCapture.dispatchEntered();
    RequestBodyCapture.applicationEntered(true, new FakeRequest("text/plain", null, -1, null), true);
    for (byte b : kept) assertEquals(0, b);
  }

  @Test
  void endOfStreamMakesTheCompleteBodyAStateOfItsOwn() {
    byte[] text = "{\"q\":\"\u00e9\"}".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request("application/json", null, -1);
    assertFalse(read(text, 0, text.length), "no Content-Length: the body may go on");
    RequestBodySnapshot prefix = body.snapshot();
    Object token = RequestBodyCapture.enter(SOURCE);
    assertTrue(RequestBodyCapture.exitBytes(-1, token, null, 0), "end of stream: the complete body is decided");
    assertTrue(body.snapshot().version() > prefix.version(), "a prefix decided before end of stream is decided again");
    token = RequestBodyCapture.enter(SOURCE);
    assertNull(token, "nothing is recorded after the end");
  }

  @Test
  void aLineIsFollowedByItsTerminatorOnlyWhenAnotherRecordFollows() {
    RequestBody body = request("text/plain", "UTF-8", -1);
    Object token = RequestBodyCapture.enter(SOURCE);
    RequestBodyCapture.exitLine("a", token);
    token = RequestBodyCapture.enter(SOURCE);
    RequestBodyCapture.exitLine("b", token);
    token = RequestBodyCapture.enter(SOURCE);
    RequestBodyCapture.exitLine(null, token);
    assertEquals("a\nb", body.snapshot().text());
  }

  @Test
  void theStatesBeforeCompletionThatGetASnapshotAreBounded() {
    byte[] text = new byte[200];
    Arrays.fill(text, (byte) 'a');
    RequestBody body = request("text/plain", null, text.length);
    java.util.Set<RequestBodySnapshot> built = java.util.Collections.newSetFromMap(
        new java.util.IdentityHashMap<RequestBodySnapshot, Boolean>());
    for (int i = 0; i < text.length - 1; i++) {
      read(text, i, 1); // one byte per read, and a hook that decides after each
      built.add(body.snapshot());
    }
    assertEquals(RequestBody.MAX_STATES, built.size());
    assertTrue(read(text, text.length - 1, 1));
    assertEquals(text.length, body.snapshot().text().length(), "the complete body always gets its snapshot");
  }
}
