package io.ohmyrasp.agent.http;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Locale;

/**
 * Records what one request's body read calls returned to the application, on the thread that serves the
 * request. The agent never reads the stream itself: it copies what the application's own read returned.
 *
 * <p>One object per thread, made the first time the thread serves a request and reused for each request after
 * it; nothing is recorded until the request's first body byte, and the buffers grow to the cap and no further.
 * Bytes (from the servlet input stream) or characters (from a container reader that does not read through the
 * stream) are kept up to {@link #MAX_UNITS}; past it nothing more is recorded and {@link #truncated} is set.
 * A body whose content type is not text (multipart, octet-stream, images, any type not listed in
 * {@link #kindOf}) or that is content-encoded is not recorded at all.
 *
 * <p>The body is complete when the bytes recorded reach the request's Content-Length, when a read returns end
 * of stream, or when the cap is reached; recording stops then, so a wrapper that re-serves a body it already
 * read whole is not recorded twice. Each record makes a new state ({@link #version}); the engines decide the
 * rules that read the body at most once per state ({@link #pending}, {@link #markDecided}).
 */
public final class RequestBody {
  /** The cap: bytes on the stream path, characters on the reader path. */
  public static final int MAX_UNITS = 8192;
  private static final int FIRST_CAPACITY = 1024;

  static final int UNKNOWN = 0;
  static final int NONE = 1;
  static final int JSON = 2;
  static final int FORM = 3;
  static final int TEXT = 4;
  static final int AUTO = 5;

  // Thread confinement: every field is read and written by the thread that serves the request.
  private boolean active;
  private boolean inspecting;
  private boolean reading;
  private boolean done;
  boolean open;

  private Object servletRequest;
  private int kind;
  private String encoding;
  private long contentLength;
  private int bytesPerChar;

  private byte[] bytes;
  private int byteCount;
  private char[] chars;
  private int charCount;
  private boolean charMode;
  private long charBytes;
  private boolean truncated;

  private int version;
  private int decided;
  private RequestBodySnapshot snapshot;
  /** Whatever the engine keeps between decisions of one request (the last finding it reported). */
  public Object engineState;

  RequestBody() {}

  // ---- the request's lifetime, driven by the engines' servlet entry and exit ----------------------------------

  void start(Object request) {
    reset();
    servletRequest = request;
    active = true;
    recompute();
  }

  void end() {
    reset();
    servletRequest = null;
    recompute();
  }

  void inspecting(boolean value) {
    inspecting = value;
    recompute();
  }

  private void reset() {
    active = false;
    inspecting = false;
    reading = false;
    done = false;
    kind = UNKNOWN;
    encoding = null;
    contentLength = -1;
    bytesPerChar = -1;
    byteCount = 0;
    charCount = 0;
    charMode = false;
    charBytes = 0;
    truncated = false;
    version = 0;
    decided = 0;
    snapshot = null;
    engineState = null;
  }

  private void recompute() {
    open = active && !inspecting && !done && !reading;
  }

  /** The outermost read starts: reads it makes on this or a wrapped stream are not recorded again. */
  boolean claim() {
    if (!open) return false;
    reading = true;
    open = false;
    return true;
  }

  void release() {
    reading = false;
    recompute();
  }

  // ---- what a read returned -----------------------------------------------------------------------------------

  /** One byte (or end of stream when {@code value} is negative); true when the body is complete and undecided. */
  boolean recordByte(int value) {
    if (value < 0) return finish();
    if (!admit(false)) return false;
    if (byteCount >= MAX_UNITS) return cap();
    ensureBytes(1);
    bytes[byteCount++] = (byte) value;
    version++;
    return afterBytes();
  }

  boolean recordBytes(byte[] source, int offset, int count) {
    if (count < 0) return finish();
    if (count == 0 || source == null || offset < 0 || offset > source.length - count) return false;
    if (!admit(false)) return false;
    int take = Math.min(count, MAX_UNITS - byteCount);
    if (take > 0) {
      ensureBytes(take);
      System.arraycopy(source, offset, bytes, byteCount, take);
      byteCount += take;
      version++;
    }
    if (take < count) return cap();
    return afterBytes();
  }

  /** The {@code count} bytes a read just put into {@code buffer}, which end at its position. */
  boolean recordBuffer(ByteBuffer buffer, int count) {
    if (count < 0) return finish();
    if (count == 0 || buffer == null || buffer.position() < count) return false;
    if (!admit(false)) return false;
    int take = Math.min(count, MAX_UNITS - byteCount);
    if (take > 0) {
      ensureBytes(take);
      ByteBuffer view = buffer.duplicate();
      view.position(buffer.position() - count);
      view.get(bytes, byteCount, take);
      byteCount += take;
      version++;
    }
    if (take < count) return cap();
    return afterBytes();
  }

  boolean recordChar(int value) {
    if (value < 0) return finish();
    if (!admit(true)) return false;
    if (charCount >= MAX_UNITS) return cap();
    ensureChars(1);
    chars[charCount++] = (char) value;
    countCharBytes(chars, charCount - 1, 1);
    version++;
    return afterChars();
  }

  boolean recordChars(char[] source, int offset, int count) {
    if (count < 0) return finish();
    if (count == 0 || source == null || offset < 0 || offset > source.length - count) return false;
    if (!admit(true)) return false;
    int take = Math.min(count, MAX_UNITS - charCount);
    if (take > 0) {
      ensureChars(take);
      System.arraycopy(source, offset, chars, charCount, take);
      countCharBytes(chars, charCount, take);
      charCount += take;
      version++;
    }
    if (take < count) return cap();
    return afterChars();
  }

  boolean recordCharBuffer(CharBuffer buffer, int count) {
    if (count < 0) return finish();
    if (count == 0 || buffer == null || buffer.position() < count) return false;
    if (!admit(true)) return false;
    int take = Math.min(count, MAX_UNITS - charCount);
    if (take > 0) {
      ensureChars(take);
      CharBuffer view = buffer.duplicate();
      view.position(buffer.position() - count);
      view.get(chars, charCount, take);
      countCharBytes(chars, charCount, take);
      charCount += take;
      version++;
    }
    if (take < count) return cap();
    return afterChars();
  }

  /** A line from a reader's readLine (null at end of stream); its terminator, which readLine drops, as one newline. */
  boolean recordLine(String line) {
    if (line == null) return finish();
    if (!admit(true)) return false;
    int count = line.length() + 1;
    int take = Math.min(count, MAX_UNITS - charCount);
    if (take > 0) {
      ensureChars(take);
      int fromLine = Math.min(take, line.length());
      line.getChars(0, fromLine, chars, charCount);
      if (take > fromLine) chars[charCount + fromLine] = '\n';
      countCharBytes(chars, charCount, take);
      charCount += take;
      version++;
    }
    if (take < count) return cap();
    return afterChars();
  }

  /** A whole array a read returned: readAllBytes, which reads to end of stream ({@code toEnd}), or readNBytes. */
  boolean recordAll(byte[] all, boolean toEnd) {
    if (all == null) return false;
    boolean due = all.length > 0 && recordBytes(all, 0, all.length);
    return toEnd ? finish() : due;
  }

  // ---- state for the engines ----------------------------------------------------------------------------------

  /** Whether a state was recorded that no decision has seen yet. */
  public boolean pending() {
    return version != decided;
  }

  /** The current state is being decided: until more is recorded, nothing is pending. */
  public void markDecided() {
    decided = version;
  }

  public int version() {
    return version;
  }

  public boolean truncated() {
    return truncated;
  }

  /** Whether recording has stopped: the body completed, reached the cap, or is not text. */
  public boolean done() {
    return done;
  }

  /** The text and values recorded so far, or null before the first body byte. Built once per state. */
  public RequestBodySnapshot snapshot() {
    if (version == 0) return null;
    RequestBodySnapshot current = snapshot;
    if (current != null && current.version() == version) return current;
    String text = charMode ? new String(chars, 0, charCount) : BodyText.decode(bytes, byteCount, encoding, done && !truncated);
    current = new RequestBodySnapshot(text, kind, version, truncated);
    snapshot = current;
    return current;
  }

  // ---- internals ----------------------------------------------------------------------------------------------

  /** Whether data of this mode is recorded: the first data reads the request's metadata and fixes the mode. */
  private boolean admit(boolean characters) {
    if (done) return false;
    if (kind == UNKNOWN) {
      readMetadata();
      charMode = characters;
      if (kind == NONE) {
        done = true;
        recompute();
        return false;
      }
    }
    return charMode == characters;
  }

  private boolean afterBytes() {
    if (byteCount >= MAX_UNITS) return cap();
    if (contentLength >= 0 && byteCount >= contentLength) return finish();
    return false;
  }

  private boolean afterChars() {
    if (charCount >= MAX_UNITS) return cap();
    // The characters' size in the request's encoding reached Content-Length: decide now, but keep recording,
    // since the estimate can be off when the container decodes with another charset than the one it reports.
    return contentLength >= 0 && bytesPerChar >= 0 && charBytes >= contentLength && pending();
  }

  private boolean cap() {
    // Truncated unless Content-Length says the cap holds the whole body.
    truncated = !(contentLength >= 0 && (charMode ? charBytes : byteCount) >= contentLength);
    return finish();
  }

  private boolean finish() {
    done = true;
    recompute();
    return version > 0 && pending();
  }

  private void countCharBytes(char[] source, int from, int count) {
    if (bytesPerChar < 0) return;
    if (bytesPerChar == 1) {
      charBytes += count;
      return;
    }
    for (int i = from; i < from + count; i++) {
      char ch = source[i];
      charBytes += ch < 0x80 ? 1 : ch < 0x800 ? 2 : Character.isSurrogate(ch) ? 2 : 3;
    }
  }

  private void ensureBytes(int more) {
    int needed = byteCount + more;
    if (bytes != null && bytes.length >= needed) return;
    int size = Math.min(MAX_UNITS, Math.max(needed, bytes == null ? FIRST_CAPACITY : bytes.length * 2));
    byte[] grown = new byte[size];
    if (bytes != null) System.arraycopy(bytes, 0, grown, 0, byteCount);
    bytes = grown;
  }

  private void ensureChars(int more) {
    int needed = charCount + more;
    if (chars != null && chars.length >= needed) return;
    int size = Math.min(MAX_UNITS, Math.max(needed, chars == null ? FIRST_CAPACITY : chars.length * 2));
    char[] grown = new char[size];
    if (chars != null) System.arraycopy(chars, 0, grown, 0, charCount);
    chars = grown;
  }

  /** Content type, encoding, length and content coding of the request, through its public servlet methods. */
  private void readMetadata() {
    kind = AUTO;
    Object request = servletRequest;
    if (request == null) return;
    try {
      Method[] methods = METHODS.get(ServletContracts.of(request));
      String contentType = (String) call(methods[0], request);
      encoding = (String) call(methods[1], request);
      Object length = call(methods[2], request);
      if (length == null) length = call(methods[3], request);
      if (length instanceof Number) contentLength = ((Number) length).longValue();
      String coding = (String) call(methods[4], request, "Content-Encoding");
      kind = coding != null && !coding.trim().isEmpty() && !"identity".equalsIgnoreCase(coding.trim())
          ? NONE : kindOf(contentType);
      if (encoding == null) encoding = charsetParameter(contentType);
      bytesPerChar = BodyText.bytesPerCharKind(encoding);
    } catch (Throwable unreadable) {
      kind = AUTO;
    }
  }

  private static Object call(Method method, Object target, Object... arguments) throws Exception {
    return method == null ? null : method.invoke(target, arguments);
  }

  private static final ClassValue<Method[]> METHODS = new ClassValue<Method[]>() {
    @Override protected Method[] computeValue(Class<?> type) {
      return new Method[] {method(type, "getContentType"), method(type, "getCharacterEncoding"),
          method(type, "getContentLengthLong"), method(type, "getContentLength"), method(type, "getHeader", String.class)};
    }
  };

  private static Method method(Class<?> type, String name, Class<?>... parameters) {
    try {
      return type.getMethod(name, parameters);
    } catch (Throwable missing) {
      return null;
    }
  }

  /**
   * How a body of this content type is recorded and read: JSON, a form, other text, or not at all. A request
   * that names no content type is recorded, and read as JSON when it looks like JSON.
   */
  static int kindOf(String contentType) {
    if (contentType == null) return AUTO;
    String type = contentType;
    int semicolon = type.indexOf(';');
    if (semicolon >= 0) type = type.substring(0, semicolon);
    type = type.trim().toLowerCase(Locale.ROOT);
    if (type.isEmpty()) return AUTO;
    if (type.contains("json")) return JSON;
    if (type.equals("application/x-www-form-urlencoded")) return FORM;
    if (type.startsWith("text/") || type.contains("xml") || type.contains("javascript") || type.contains("yaml")
        || type.contains("graphql")) return TEXT;
    return NONE;
  }

  private static String charsetParameter(String contentType) {
    if (contentType == null) return null;
    String lower = contentType.toLowerCase(Locale.ROOT);
    int at = lower.indexOf("charset=");
    if (at < 0) return null;
    String value = contentType.substring(at + 8).trim();
    int end = value.indexOf(';');
    if (end >= 0) value = value.substring(0, end);
    value = value.trim();
    if (value.length() >= 2 && value.charAt(0) == '"' && value.charAt(value.length() - 1) == '"') {
      value = value.substring(1, value.length() - 1);
    }
    return value.isEmpty() ? null : value;
  }
}
