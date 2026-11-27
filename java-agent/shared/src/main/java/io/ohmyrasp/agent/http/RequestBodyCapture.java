package io.ohmyrasp.agent.http;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * The request-body hooks of every agent line: which thread serves a request, and what its body read calls
 * returned (see {@link RequestBody}). {@link RequestBodyVisitor} injects {@link #enter} at the start of each
 * read method of a servlet input stream (or container reader), an exit call with the read's result at each
 * return and {@link #abort} where the read throws; the engines call the lifetime methods from their servlet entry
 * and exit.
 *
 * <p>Costs on an application thread: a read on a thread that serves no request is one thread-local read and a
 * branch in {@link #enter} and in its exit; one past the cap or after the body completed adds a counter.
 * A read inside another recorded read (a wrapper's read calling the container's, or a stream's read(byte[])
 * calling its own read()) records nothing: only the outermost read on the thread does. A read of another
 * stream than the one whose read first returned data inside the request (a mock stream, a replay of cached
 * bytes, another request's stream) records nothing either.
 *
 * <p>A dispatch of a distinct request inside another one (its request object is neither the outer one nor a
 * wrapper around it, nor wrapped by it) gets a recorder of its own while it lasts, and the outer request's
 * recorder is current again when it leaves: one request's body is never decided under another's dispatch.
 *
 * <p>Nothing here throws to the application, except {@link #enter} with the block the engine latched by
 * {@link #deny}, and only for a read of the stream whose data the blocked request recorded, outside the
 * agent's own inspection: a failure while recording stops recording for the request.
 * The exit methods return true when the read completed a body that has a state no decision has seen,
 * and the engine then decides the rules that read the body.
 */
public final class RequestBodyCapture {
  private static final ThreadLocal<RequestBody> CURRENT = new ThreadLocal<RequestBody>();
  private static final int MAX_WRAPPERS = 16;

  private RequestBodyCapture() {}

  // ---- lifetime, from the engines' servlet entry and exit ------------------------------------------------------

  /**
   * A servlet dispatch was entered on this thread and is being inspected: reads from now until
   * {@link #applicationEntered} are the agent's own (a parameter lookup can make the container read a form
   * body) and are not recorded.
   */
  public static void dispatchEntered() {
    RequestBody body = CURRENT.get();
    if (body == null) return;
    body.dispatches++;
    body.inspecting(true);
  }

  /**
   * The application runs inside the dispatch. The outermost dispatch of a request starts recording for
   * {@code servletRequest} when {@code record} (detection is on); an inner dispatch of the same request resumes
   * the request's recorder, and one of a distinct request starts a recorder of its own until it leaves.
   */
  public static void applicationEntered(boolean outermost, Object servletRequest, boolean record) {
    RequestBody body = CURRENT.get();
    if (outermost) {
      if (body != null) body = root(body);
      if (!record) {
        if (body != null) body.end();
        return;
      }
      if (body == null) {
        body = new RequestBody(); // once per thread; reused by every later request on it
      }
      CURRENT.set(body);
      body.start(servletRequest);
    } else if (body != null) {
      body.inspecting(false);
      if (record && body.active() && servletRequest != null
          && !sameRequest(body.servletRequest(), servletRequest)) {
        // This dispatch belongs to the inner recorder from now on.
        body.dispatches--;
        RequestBody inner = new RequestBody();
        inner.parent = body;
        inner.start(servletRequest);
        CURRENT.set(inner);
      }
    }
  }

  /**
   * A dispatch left; when it was the outermost ({@code requestEnded}), the request's record is dropped, and
   * when it was the last of a distinct inner request, the outer request's recorder is current again.
   */
  public static void dispatchExited(boolean requestEnded) {
    RequestBody body = CURRENT.get();
    if (body == null) return;
    if (requestEnded) {
      while (body.parent != null) {
        RequestBody outer = body.parent;
        body.parent = null;
        body.end();
        body = outer;
      }
      CURRENT.set(body);
      body.end();
      return;
    }
    if (body.dispatches > 0) body.dispatches--;
    if (body.dispatches == 0 && body.parent != null) {
      RequestBody outer = body.parent;
      body.parent = null;
      body.end();
      CURRENT.set(outer);
      outer.inspecting(false);
    } else {
      body.inspecting(false);
    }
  }

  /** The body of the request this thread serves, or null outside a request. */
  public static RequestBody current() {
    return CURRENT.get();
  }

  private static RequestBody root(RequestBody body) {
    RequestBody outermost = body;
    while (outermost.parent != null) {
      RequestBody outer = outermost.parent;
      outermost.parent = null;
      outermost.end();
      outermost = outer;
    }
    return outermost;
  }

  /**
   * Whether two servlet request objects are one request: the same object, or one reached from the other through
   * the servlet API's request wrappers ({@code getRequest()} of javax or jakarta ServletRequestWrapper).
   */
  static boolean sameRequest(Object outer, Object inner) {
    if (outer == null || inner == null || outer == inner) return true;
    return wraps(inner, outer) || wraps(outer, inner);
  }

  private static boolean wraps(Object wrapper, Object wrapped) {
    Object at = wrapper;
    for (int i = 0; i < MAX_WRAPPERS && at != null; i++) {
      java.lang.reflect.Method unwrap = UNWRAP.get(at.getClass());
      if (unwrap == null) return false;
      try {
        at = unwrap.invoke(at);
      } catch (Throwable unreadable) {
        return false;
      }
      if (at == wrapped) return true;
    }
    return false;
  }

  // A nested class, not a lambda: backport hooks reach this.
  private static final ClassValue<java.lang.reflect.Method> UNWRAP = new ClassValue<java.lang.reflect.Method>() {
    @Override protected java.lang.reflect.Method computeValue(Class<?> type) {
      for (Class<?> at = type; at != null; at = at.getSuperclass()) {
        String name = at.getName();
        if ("javax.servlet.ServletRequestWrapper".equals(name) || "jakarta.servlet.ServletRequestWrapper".equals(name)) {
          try {
            return at.getMethod("getRequest");
          } catch (Throwable missing) {
            return null;
          }
        }
      }
      return null;
    }
  };

  // ---- reads ---------------------------------------------------------------------------------------------------

  /**
   * At the start of a read of {@code source}: the recorder when this read is the outermost one of a request and
   * {@code source} is the stream or reader the request reads its body from (or, before any read returned data,
   * may be), else null. After a block on the request's body, every read of that stream throws the block again
   * (not a read of another stream, and not the agent's own reads while it inspects a dispatch).
   */
  public static Object enter(Object source) {
    RequestBody body = CURRENT.get();
    if (body == null) return null;
    RuntimeException denial = body.denial;
    if (denial != null && !body.inspecting() && body.owns(source)) throw denial;
    return body.claim(source) ? body : null;
  }

  /** {@link #enter} for a read into an NIO buffer: notes where the buffer stood, where the read puts its data. */
  public static Object enter(Object source, Buffer buffer) {
    Object token = enter(source);
    if (token != null) ((RequestBody) token).bufferStart = buffer == null ? -1 : buffer.position();
    return token;
  }

  /** A read threw: when it held the claim, the recorder is free for the request's next read. */
  public static void abort() {
    try {
      RequestBody body = CURRENT.get();
      if (body != null) body.abort();
    } catch (Throwable ignored) {
      // The application's own throwable goes on.
    }
  }

  /**
   * The engine blocked the request on its body: from now until the request ends, every read of the stream the
   * request's body was recorded from throws {@code block}, and {@link #denial} returns it to the engine's hooks.
   */
  public static void deny(RuntimeException block) {
    RequestBody body = CURRENT.get();
    if (body != null && body.active() && body.denial == null) body.denial = block;
  }

  /** The block the current request's body was denied with, or null. */
  public static RuntimeException denial() {
    RequestBody body = CURRENT.get();
    return body == null ? null : body.denial;
  }

  /** A read that holds no claim returned. */
  private static boolean unclaimed() {
    try {
      RequestBody body = CURRENT.get();
      if (body != null) body.leave();
    } catch (Throwable ignored) {
      // The next request on the thread starts from a clean recorder.
    }
    return false;
  }

  private static void release(RequestBody body) {
    try {
      body.release();
    } catch (Throwable ignored) {
      // As above.
    }
  }

  public static boolean exitByte(int result, Object token) {
    if (token == null) return unclaimed();
    RequestBody body = (RequestBody) token;
    try {
      return body.recordByte(result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      release(body);
    }
  }

  public static boolean exitBytes(int result, Object token, byte[] buffer, int offset) {
    if (token == null) return unclaimed();
    RequestBody body = (RequestBody) token;
    try {
      return body.recordBytes(buffer, offset, result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      release(body);
    }
  }

  public static boolean exitBuffer(int result, Object token, ByteBuffer buffer) {
    if (token == null) return unclaimed();
    RequestBody body = (RequestBody) token;
    try {
      return body.recordBuffer(buffer, result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      release(body);
    }
  }

  public static boolean exitAll(byte[] result, Object token, boolean toEnd) {
    if (token == null) return unclaimed();
    RequestBody body = (RequestBody) token;
    try {
      return body.recordAll(result, toEnd);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      release(body);
    }
  }

  public static boolean exitChar(int result, Object token) {
    if (token == null) return unclaimed();
    RequestBody body = (RequestBody) token;
    try {
      return body.recordChar(result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      release(body);
    }
  }

  public static boolean exitChars(int result, Object token, char[] buffer, int offset) {
    if (token == null) return unclaimed();
    RequestBody body = (RequestBody) token;
    try {
      return body.recordChars(buffer, offset, result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      release(body);
    }
  }

  public static boolean exitCharBuffer(int result, Object token, CharBuffer buffer) {
    if (token == null) return unclaimed();
    RequestBody body = (RequestBody) token;
    try {
      return body.recordCharBuffer(buffer, result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      release(body);
    }
  }

  public static boolean exitLine(String result, Object token) {
    if (token == null) return unclaimed();
    RequestBody body = (RequestBody) token;
    try {
      return body.recordLine(result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      release(body);
    }
  }

  /** Recording failed: keep what was recorded and record nothing more; decide it if it was not. */
  private static boolean stop(RequestBody body) {
    try {
      return body.stop();
    } catch (Throwable ignored) {
      return false;
    }
  }
}
