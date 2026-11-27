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
 * A distinct request served inside another one on the same thread (a dispatch whose request is not the outer
 * request or a wrapper of it) gets a recorder of its own for as long as its dispatch lasts ({@link #parent}).
 * Only one source is recorded per request: the stream or reader whose read was the first to return data inside
 * the request ({@link #claim}, then {@link #own}); a read that throws, returns nothing or returns end of stream
 * before that claims nothing, and reads of any other object on the thread are not recorded. When the request
 * ends, or the thread starts another request, the recorded bytes and characters are overwritten with zeros,
 * buffers larger than {@link #KEPT_CAPACITY} are dropped, and the snapshot, source and request references are
 * cleared.
 * Bytes (from the servlet input stream) or characters (from a container reader that does not read through the
 * stream) are kept up to {@link #MAX_UNITS}; past it nothing more is recorded and {@link #truncated} is set.
 * A body whose content type is not text (multipart, octet-stream, images, any type not listed in
 * {@link #kindOf}) or that is content-encoded is not recorded at all.
 *
 * <p>The body is complete when the bytes recorded reach the request's Content-Length, when a read returns end
 * of stream, or when the cap is reached; recording stops then, so a wrapper that re-serves a body it already
 * read whole is not recorded twice. Each record makes a new state ({@link #version}), and so does the end of the
 * body (the decoding of a complete body can differ from that of its prefix). The engines decide the rules that
 * read the body at most once per state and dispatch. At most {@link #MAX_STATES} states before the body is
 * complete get a snapshot of their own; after that the last one stands until the body completes, whose final
 * state always gets one. That bounds the work a request's body causes on its thread (see docs/agent.md).
 */
public final class RequestBody {
  /** The cap: bytes on the stream path, characters on the reader path. */
  public static final int MAX_UNITS = 8192;
  /** The states before the body completes that get a snapshot (and a decision) of their own. */
  public static final int MAX_STATES = 16;
  /**
   * The rule evaluations the body states of one request may cause, over every dispatch of the request: past it,
   * no body state of the request is decided again ({@link #evaluate}).
   */
  public static final int MAX_EVALUATIONS = 2 * MAX_STATES + 2;
  private static final int FIRST_CAPACITY = 1024;
  /** A buffer this size or smaller is kept, zeroed, for the thread's next request; a larger one is dropped. */
  static final int KEPT_CAPACITY = FIRST_CAPACITY;

  static final int UNKNOWN = 0;
  static final int NONE = 1;
  static final int JSON = 2;
  static final int FORM = 3;
  static final int TEXT = 4;
  static final int AUTO = 5;

  // Thread confinement: every field is read and written by the thread that serves the request.
  private boolean active;
  private boolean inspecting;
  private boolean done;
  boolean open;

  // The recorder of the request this one's dispatch was served inside, while that dispatch lasts; else null.
  RequestBody parent;
  // Dispatches of this recorder's request entered on the thread and not left yet.
  int dispatches;
  // Rewritten reads in progress on the thread (entered and not yet returned or thrown out of), and the depth of
  // the one that holds the claim (0: none). The claim is released by the read at that depth only.
  private int depth;
  private int claimDepth;

  private Object servletRequest;
  // The stream or reader the request's body is read from: the first whose read returned data inside the request.
  private Object source;
  // The source of the read that holds the claim, which becomes the source when the read returns data.
  private Object candidate;
  // Rule evaluations caused by this request's body states (see MAX_EVALUATIONS).
  private int evaluations;
  // Where the NIO buffer of the current read stood when the read started; -1 when the read is not into one.
  int bufferStart = -1;
  // The block the engine threw on this request's body: every later read of the request throws it again.
  RuntimeException denial;
  // The last record was a line from readLine, whose terminator is recorded when another record follows.
  private boolean lineOpen;
  // Snapshots built for states before the body completed (see MAX_STATES).
  private int builds;
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
  private RequestBodySnapshot snapshot;
  /** Whatever the engine keeps between decisions of one request (the last finding it reported). */
  public Object engineState;

  RequestBody() {}

  // ---- the request's lifetime, driven by the engines' servlet entry and exit ----------------------------------

  void start(Object request) {
    reset();
    servletRequest = request;
    active = true;
    dispatches = 1;
    recompute();
  }

  void end() {
    reset();
    servletRequest = null;
    dispatches = 0;
    recompute();
  }

  void inspecting(boolean value) {
    inspecting = value;
    recompute();
  }

  private void reset() {
    wipe();
    source = null;
    candidate = null;
    depth = 0;
    claimDepth = 0;
    evaluations = 0;
    bufferStart = -1;
    denial = null;
    lineOpen = false;
    builds = 0;
    active = false;
    inspecting = false;
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
    snapshot = null;
    engineState = null;
  }

  /** Overwrites what was recorded and drops a buffer too large to keep for the next request. */
  private void wipe() {
    if (bytes != null) {
      java.util.Arrays.fill(bytes, 0, Math.min(byteCount, bytes.length), (byte) 0);
      if (bytes.length > KEPT_CAPACITY) bytes = null;
    }
    if (chars != null) {
      java.util.Arrays.fill(chars, 0, Math.min(charCount, chars.length), '\0');
      if (chars.length > KEPT_CAPACITY) chars = null;
    }
  }

  /** Whether a request is being recorded (the outermost dispatch entered with detection on). */
  boolean active() {
    return active;
  }

  private void recompute() {
    open = active && !inspecting && !done && claimDepth == 0;
  }

  boolean inspecting() {
    return inspecting;
  }

  /** Whether {@code from} is the stream or reader whose data this request recorded. */
  boolean owns(Object from) {
    return from != null && source == from;
  }

  /**
   * A rewritten read of {@code from} starts; true when it holds the claim, as the outermost read of the
   * request's source (or of a candidate for it while no read returned data yet): reads it makes on this or a
   * wrapped stream are not recorded again, and a read of any other object than the source is not recorded.
   * Every call is matched by one {@link #leave} or {@link #abort}.
   */
  boolean claim(Object from) {
    depth++;
    if (!open || from == null || (source != null && source != from)) return false;
    candidate = from;
    claimDepth = depth;
    recompute();
    return true;
  }

  /** The read that holds the claim returned: whatever it recorded, the next read may claim. */
  void release() {
    if (claimDepth > 0) depth = claimDepth;
    claimDepth = 0;
    candidate = null;
    leave();
  }

  /** A read that does not hold the claim returned. */
  void leave() {
    if (depth > 0) depth--;
    recompute();
  }

  /** A read threw: when it is the one that holds the claim, the next read may claim. */
  void abort() {
    if (claimDepth > 0 && claimDepth == depth) {
      claimDepth = 0;
      candidate = null;
    }
    leave();
  }

  /**
   * The read that holds the claim returned data: its source is the request's from now on. False when another
   * source returned data first (the claim then records nothing).
   */
  private boolean own() {
    if (source == null) source = candidate;
    return source != null && source == candidate;
  }

  /** End of stream from the read that holds the claim: the body ends only when it is the source's. */
  private boolean ended() {
    return source != null && source == candidate && finish();
  }

  // ---- what a read returned -----------------------------------------------------------------------------------

  /** One byte (or end of stream when {@code value} is negative); true when the body is complete and undecided. */
  boolean recordByte(int value) {
    if (value < 0) return ended();
    if (!own() || !admit(false)) return false;
    if (byteCount >= MAX_UNITS) return cap();
    ensureBytes(1);
    bytes[byteCount++] = (byte) value;
    version++;
    return afterBytes();
  }

  boolean recordBytes(byte[] source, int offset, int count) {
    if (count < 0) return ended();
    if (count == 0 || source == null || offset < 0 || offset > source.length - count) return false;
    if (!own() || !admit(false)) return false;
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

  /**
   * The {@code count} bytes a read just put into {@code buffer}, which start where the buffer's position stood
   * when the read started ({@link #bufferStart}). That holds for both contracts in use: a read that advances the
   * position past the bytes (the NIO convention), and Tomcat's, which restores the position and sets the limit
   * after the bytes. The buffer itself is not touched: the bytes are copied through a duplicate.
   */
  boolean recordBuffer(ByteBuffer buffer, int count) {
    int start = bufferStart;
    bufferStart = -1;
    if (count < 0) return ended();
    if (count == 0 || buffer == null || start < 0 || start > buffer.capacity() - count) return false;
    if (!own() || !admit(false)) return false;
    int take = Math.min(count, MAX_UNITS - byteCount);
    if (take > 0) {
      ensureBytes(take);
      ByteBuffer view = buffer.duplicate();
      view.limit(view.capacity());
      view.position(start);
      view.get(bytes, byteCount, take);
      byteCount += take;
      version++;
    }
    if (take < count) return cap();
    return afterBytes();
  }

  boolean recordChar(int value) {
    if (value < 0) return ended();
    if (!own() || !admit(true)) return false;
    closeLine();
    if (charCount >= MAX_UNITS) return cap();
    ensureChars(1);
    chars[charCount++] = (char) value;
    countCharBytes(chars, charCount - 1, 1);
    version++;
    return afterChars();
  }

  boolean recordChars(char[] source, int offset, int count) {
    if (count < 0) return ended();
    if (count == 0 || source == null || offset < 0 || offset > source.length - count) return false;
    if (!own() || !admit(true)) return false;
    closeLine();
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

  /** The {@code count} characters a read just put into {@code buffer}: see {@link #recordBuffer}. */
  boolean recordCharBuffer(CharBuffer buffer, int count) {
    int start = bufferStart;
    bufferStart = -1;
    if (count < 0) return ended();
    if (count == 0 || buffer == null || start < 0 || start > buffer.capacity() - count) return false;
    if (!own() || !admit(true)) return false;
    closeLine();
    int take = Math.min(count, MAX_UNITS - charCount);
    if (take > 0) {
      ensureChars(take);
      CharBuffer view = buffer.duplicate();
      view.limit(view.capacity());
      view.position(start);
      view.get(chars, charCount, take);
      countCharBytes(chars, charCount, take);
      charCount += take;
      version++;
    }
    if (take < count) return cap();
    return afterChars();
  }

  /**
   * A line from a reader's readLine (null at end of stream). readLine drops the line's terminator, and the last
   * line of a body may have none: the terminator is recorded as one newline only when another record follows
   * ({@link #closeLine}), and counted as one byte towards Content-Length (a CRLF body completes by end of stream).
   */
  boolean recordLine(String line) {
    if (line == null) return ended();
    if (!own() || !admit(true)) return false;
    closeLine();
    int count = line.length();
    int take = Math.min(count, MAX_UNITS - charCount);
    if (take > 0) {
      ensureChars(take);
      line.getChars(0, take, chars, charCount);
      countCharBytes(chars, charCount, take);
      charCount += take;
      version++;
    }
    if (take < count) return cap();
    lineOpen = true;
    return afterChars();
  }

  /** The previous record was a line and another record follows: its terminator was there. */
  private void closeLine() {
    if (!lineOpen) return;
    lineOpen = false;
    if (charCount >= MAX_UNITS) return;
    ensureChars(1);
    chars[charCount++] = '\n';
    countCharBytes(chars, charCount - 1, 1);
    version++;
  }

  /** A whole array a read returned: readAllBytes, which reads to end of stream ({@code toEnd}), or readNBytes. */
  boolean recordAll(byte[] all, boolean toEnd) {
    if (all == null) return false;
    boolean due = all.length > 0 && recordBytes(all, 0, all.length);
    return toEnd ? ended() || due : due;
  }

  /**
   * Whether the request's body may cause one more rule evaluation; counts it when it may. At most
   * {@link #MAX_EVALUATIONS} per request, over all its dispatches.
   */
  public boolean evaluate() {
    if (evaluations >= MAX_EVALUATIONS) return false;
    evaluations++;
    return true;
  }

  /** The rule evaluations the request's body states caused so far. */
  public int evaluations() {
    return evaluations;
  }

  // ---- state for the engines ----------------------------------------------------------------------------------

  /** The last snapshot built, without building one: for taking body text out of what an event carries. */
  public RequestBodySnapshot lastSnapshot() {
    return snapshot;
  }

  public int version() {
    return version;
  }

  /** The servlet request the outermost dispatch of this request was entered with (null for a container hook's). */
  public Object servletRequest() {
    return servletRequest;
  }

  public boolean truncated() {
    return truncated;
  }

  /** Whether recording has stopped: the body completed, reached the cap, or is not text. */
  public boolean done() {
    return done;
  }

  /**
   * The text and values recorded so far, or null before the first body byte. Built once per state, and for at
   * most {@link #MAX_STATES} states before the body completes: past that, the last one built stands until the
   * body is complete. An engine decides a snapshot whose version it has not decided yet.
   */
  public RequestBodySnapshot snapshot() {
    if (version == 0) return null;
    RequestBodySnapshot current = snapshot;
    if (current != null && (current.version() == version || (!done && builds >= MAX_STATES))) return current;
    if (!done) builds++;
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
    return contentLength >= 0 && bytesPerChar >= 0 && charBytes >= contentLength;
  }

  private boolean cap() {
    // Truncated unless Content-Length says the cap holds the whole body.
    truncated = !(contentLength >= 0 && (charMode ? charBytes : byteCount) >= contentLength);
    return finish();
  }

  /** Recording failed: record nothing more; true when that makes a state no decision has seen. */
  boolean stop() {
    return finish();
  }

  /** The body is complete (or recording stopped): a new state, the complete one, when there is a body. */
  private boolean finish() {
    if (done) return false;
    done = true;
    lineOpen = false;
    recompute();
    if (version == 0) return false;
    version++;
    return true;
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
    if (bytes != null) {
      System.arraycopy(bytes, 0, grown, 0, byteCount);
      java.util.Arrays.fill(bytes, 0, byteCount, (byte) 0); // the old copy is garbage now: leave nothing in it
    }
    bytes = grown;
  }

  private void ensureChars(int more) {
    int needed = charCount + more;
    if (chars != null && chars.length >= needed) return;
    int size = Math.min(MAX_UNITS, Math.max(needed, chars == null ? FIRST_CAPACITY : chars.length * 2));
    char[] grown = new char[size];
    if (chars != null) {
      System.arraycopy(chars, 0, grown, 0, charCount);
      java.util.Arrays.fill(chars, 0, charCount, '\0');
    }
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
