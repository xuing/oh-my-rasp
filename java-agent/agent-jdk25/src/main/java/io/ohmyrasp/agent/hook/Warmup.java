package io.ohmyrasp.agent.hook;

import io.ohmyrasp.agent.log.JsonEventLogger;
import io.ohmyrasp.agent.runtime.AgentRuntime;
import io.ohmyrasp.agent.runtime.DetectionMode;
import java.io.ObjectInputFilter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One pass, at start, of the entries the hook modules inject on the paths every request takes, on harmless input.
 * Preloading loads and initialises every class; what is left for the first hooked call is what only running code
 * does: linking its lambdas and method references and loading the JDK classes (streams, for one) it first uses.
 * Doing that here keeps it off the first request's thread.
 *
 * <p>The entries are the ones the transformers really call: servlet admission and exit
 * ({@link OhMyRaspHooks#admitServletRequest}, {@link OhMyRaspHooks#exitHttpRequest}), the request-body reads
 * inside a POST as a rewritten read makes them, on a stream object of the warm-up's own that the request's recorder
 * binds to ({@link OhMyRaspHooks#enterBodyRead(Object)} with {@link OhMyRaspHooks#exitBodyRead(int, Object, byte[],
 * int)}, a read that throws and is released by {@link OhMyRaspHooks#abortBodyRead}, and the end of the body through a
 * buffer read, {@link OhMyRaspHooks#enterBodyRead(Object, java.nio.Buffer)} with
 * {@link OhMyRaspHooks#exitBodyRead(int, Object, java.nio.ByteBuffer)}),
 * the receiver-aware JDBC entry ({@link OhMyRaspHooks#beforeSql(Object, String)}) inside and outside a request,
 * and the deserialization filter wrapper ({@link DeserializationGuard#filterOrGuard},
 * {@link DeserializationGuard#checkInput(ObjectInputFilter, ObjectInputFilter.FilterInfo, java.io.ObjectInputStream)}).
 *
 * <p>No side effect on the application or anything outside the agent: it runs on a thread of its own, which ends
 * with it, so no thread-local the hooks set survives it; the hooks act for that thread alone before the start
 * commits ({@link HookActivation}); the body it records is the request's own, which the request's end overwrites,
 * on that thread; every report goes to a logger that writes nothing ({@link
 * JsonEventLogger#discarding}: no event, no telemetry, no cloud error, no stderr line); each input is a constant held
 * in memory, and no entry called here reads a file, opens a socket or starts a process. With detection off the
 * entries return at once, and the warm-up does nothing. A failure is ignored: the warm-up is an optimisation, not a
 * condition of starting. Run it before the transformer is registered, so no instrumented call can reach it.
 */
public final class Warmup {
  private Warmup() {}

  /** How long the start waits for the warm-up thread. */
  private static final long JOIN_MILLIS = 10_000;

  static final int STEPS = 4;

  /**
   * Runs the warm-up on its own thread and waits for it; never throws.
   *
   * @return how many of the {@value #STEPS} steps returned normally
   */
  public static int run() {
    JsonEventLogger previous = OhMyRaspHooks.reportingTo();
    OhMyRaspHooks.reportTo(JsonEventLogger.discarding());
    final int[] completed = new int[1];
    Thread thread = new Thread(new Runnable() {
      @Override public void run() {
        completed[0] = runHere();
      }
    }, "ohmyrasp-warmup");
    thread.setDaemon(true);
    try {
      thread.start();
      thread.join(JOIN_MILLIS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (Throwable ignored) {
      // No thread for the warm-up: the first request does this work.
    } finally {
      HookActivation.endWarmUp();
      OhMyRaspHooks.reportTo(previous);
    }
    return thread.isAlive() ? 0 : completed[0];
  }

  private static int runHere() {
    HookActivation.beginWarmUp();
    int completed = 0;
    try {
      for (int step = 0; step < STEPS; step++) {
        try {
          call(step);
          completed++;
        } catch (Throwable ignored) {
          // Nothing to report: the hook did what it would for any input, and the start goes on.
        }
      }
    } finally {
      HookActivation.endWarmUp();
    }
    return completed;
  }

  private static void call(int step) {
    switch (step) {
      case 0 -> {
        Request get = new Request("GET", "/index.html", "page=2&sort=name", "",
            Map.of("page", new String[] {"2"}, "sort", new String[] {"name"}),
            Map.of("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)", "Accept", "text/html", "Host", "localhost"));
        if (OhMyRaspHooks.admitServletRequest(get, null, false)) {
          try {
            OhMyRaspHooks.beforeSql(Statement.INSTANCE, "SELECT id, name FROM items WHERE id = ?");
          } finally {
            OhMyRaspHooks.exitHttpRequest();
          }
        }
      }
      case 1 -> {
        String form = "name=widget&count=3&tag=a&tag=b";
        Request post = new Request("POST", "/api/items", "", "application/x-www-form-urlencoded",
            Map.of("name", new String[] {"widget"}, "count", new String[] {"3"}, "tag", new String[] {"a", "b"}),
            Map.of("User-Agent", "curl/8.5.0", "Content-Type", "application/x-www-form-urlencoded",
                "Content-Length", Integer.toString(form.length()), "Cookie", "theme=dark", "Host", "localhost"));
        if (OhMyRaspHooks.admitServletRequest(post, null, false)) {
          try {
            byte[] body = form.getBytes(StandardCharsets.US_ASCII);
            // The recorder binds to the first object that reads inside the request, as it binds to a container's
            // input stream: here an object of the warm-up's own, which nothing else can read from.
            BodyStream stream = new BodyStream();
            Object token = OhMyRaspHooks.enterBodyRead(stream);
            if (token == null && AgentRuntime.get().mode() != DetectionMode.OFF) {
              // With detection on the request records its body; a null token means this pass warmed nothing.
              throw new IllegalStateException("the warm-up's body read was not recorded");
            }
            OhMyRaspHooks.exitBodyRead(body.length, token, body, 0);
            // A read that throws: the handler of a rewritten read releases the recorder, and the exception goes on.
            OhMyRaspHooks.abortBodyRead(OhMyRaspHooks.enterBodyRead(stream));
            // The end of the body, through a read into an NIO buffer, as Tomcat's read(ByteBuffer) returns it.
            ByteBuffer buffer = ByteBuffer.allocate(16);
            OhMyRaspHooks.exitBodyRead(-1, OhMyRaspHooks.enterBodyRead(stream, buffer), buffer);
            OhMyRaspHooks.beforeSql(Statement.INSTANCE, "INSERT INTO items (name, count) VALUES (?, ?)");
          } finally {
            OhMyRaspHooks.exitHttpRequest();
          }
        }
      }
      case 2 -> OhMyRaspHooks.beforeSql(Statement.INSTANCE, "SELECT id, name FROM items WHERE id = 1");
      case 3 -> {
        ObjectInputFilter filter = DeserializationGuard.filterOrGuard(null);
        DeserializationGuard.checkInput(filter, new FilterInfo(String.class), null);
        DeserializationGuard.checkInput(filter, new FilterInfo(Integer.class), null);
      }
      default -> { }
    }
  }

  /** The stream the warm-up's request reads its body from: only its identity matters to the recorder. */
  static final class BodyStream {}

  /** A JDBC receiver for the receiver-aware SQL entry: an object of no driver, as an unknown driver's would be. */
  static final class Statement {
    static final Statement INSTANCE = new Statement();
  }

  /** What the JDK's serial filter passes to a filter, for one class. */
  private static final class FilterInfo implements ObjectInputFilter.FilterInfo {
    private final Class<?> serialClass;

    FilterInfo(Class<?> serialClass) {
      this.serialClass = serialClass;
    }

    @Override public Class<?> serialClass() {
      return serialClass;
    }

    @Override public long arrayLength() {
      return -1;
    }

    @Override public long depth() {
      return 1;
    }

    @Override public long references() {
      return 1;
    }

    @Override public long streamBytes() {
      return 64;
    }
  }

  /**
   * The servlet request surface the request entries read by reflection (method, URI, query, parameters, headers,
   * attributes, content type and length), as constants. Public methods on a class of the hooks' own package.
   */
  public static final class Request {
    private final String method;
    private final String uri;
    private final String query;
    private final String contentType;
    private final Map<String, String[]> parameters;
    private final Map<String, String> headers;

    Request(String method, String uri, String query, String contentType, Map<String, String[]> parameters,
        Map<String, String> headers) {
      this.method = method;
      this.uri = uri;
      this.query = query;
      this.contentType = contentType;
      this.parameters = new LinkedHashMap<>(parameters);
      this.headers = new LinkedHashMap<>(headers);
    }

    public String getMethod() {
      return method;
    }

    public String getRequestURI() {
      return uri;
    }

    public String getQueryString() {
      return query.isEmpty() ? null : query;
    }

    public Map<String, String[]> getParameterMap() {
      return parameters;
    }

    public Enumeration<String> getHeaderNames() {
      return Collections.enumeration(List.copyOf(headers.keySet()));
    }

    public String getHeader(String name) {
      return headers.get(name);
    }

    public Enumeration<String> getAttributeNames() {
      return Collections.emptyEnumeration();
    }

    public Object getAttribute(String name) {
      return null;
    }

    public String getContentType() {
      return contentType.isEmpty() ? null : contentType;
    }

    public String getCharacterEncoding() {
      return null;
    }

    public long getContentLengthLong() {
      String length = headers.get("Content-Length");
      return length == null ? -1 : Long.parseLong(length);
    }

    public int getContentLength() {
      return (int) getContentLengthLong();
    }
  }
}
