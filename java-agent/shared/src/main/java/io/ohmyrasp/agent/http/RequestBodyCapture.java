package io.ohmyrasp.agent.http;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * The request-body hooks of every agent line: which thread serves a request, and what its body read calls
 * returned (see {@link RequestBody}). {@link RequestBodyVisitor} injects {@link #enter} at the start of each
 * read method of a servlet input stream (or container reader) and an exit call with the read's result at each
 * return; the engines call the lifetime methods from their servlet entry and exit.
 *
 * <p>Costs on an application thread: a read on a thread that serves no request, or one past the cap or after
 * the body completed, is one thread-local read and a branch in {@link #enter}, and a null check at exit.
 * A read inside another recorded read (a wrapper's read calling the container's, or a stream's read(byte[])
 * calling its own read()) records nothing: only the outermost read on the thread does. A read of another
 * stream than the one the request's first read used (a mock stream, a replay of cached bytes, another
 * request's stream in a nested dispatch) records nothing either.
 *
 * <p>Nothing here throws to the application, except {@link #enter} with the block the engine latched by
 * {@link #deny}: a failure while recording stops recording for the request.
 * The exit methods return true when the read completed a body that has a state no decision has seen,
 * and the engine then decides the rules that read the body.
 */
public final class RequestBodyCapture {
  private static final ThreadLocal<RequestBody> CURRENT = new ThreadLocal<RequestBody>();

  private RequestBodyCapture() {}

  // ---- lifetime, from the engines' servlet entry and exit ------------------------------------------------------

  /**
   * A servlet dispatch was entered on this thread and is being inspected: reads from now until
   * {@link #applicationEntered} are the agent's own (a parameter lookup can make the container read a form
   * body) and are not recorded.
   */
  public static void dispatchEntered() {
    RequestBody body = CURRENT.get();
    if (body != null) body.inspecting(true);
  }

  /**
   * The application runs inside the dispatch. The outermost dispatch of a request starts recording for
   * {@code servletRequest} when {@code record} (detection is on); an inner dispatch resumes the request's.
   */
  public static void applicationEntered(boolean outermost, Object servletRequest, boolean record) {
    RequestBody body = CURRENT.get();
    if (outermost) {
      if (!record) {
        if (body != null) body.end();
        return;
      }
      if (body == null) {
        body = new RequestBody(); // once per thread; reused by every later request on it
        CURRENT.set(body);
      }
      body.start(servletRequest);
    } else if (body != null) {
      body.inspecting(false);
    }
  }

  /** A dispatch left; when it was the outermost ({@code requestEnded}), the request's record is dropped. */
  public static void dispatchExited(boolean requestEnded) {
    RequestBody body = CURRENT.get();
    if (body == null) return;
    if (requestEnded) body.end();
    else body.inspecting(false);
  }

  /** The body of the request this thread serves, or null outside a request. */
  public static RequestBody current() {
    return CURRENT.get();
  }

  // ---- reads ---------------------------------------------------------------------------------------------------

  /**
   * At the start of a read of {@code source}: the recorder when this read is the outermost one of a request and
   * {@code source} is the stream or reader the request reads its body from (the first one that read inside the
   * request), else null. After a block on the request's body, every read of the request throws that block again.
   */
  public static Object enter(Object source) {
    RequestBody body = CURRENT.get();
    if (body == null) return null;
    RuntimeException denial = body.denial;
    if (denial != null) throw denial;
    return body.open && body.claim(source) ? body : null;
  }

  /** {@link #enter} for a read into an NIO buffer: notes where the buffer stood, where the read puts its data. */
  public static Object enter(Object source, Buffer buffer) {
    Object token = enter(source);
    if (token != null) ((RequestBody) token).bufferStart = buffer == null ? -1 : buffer.position();
    return token;
  }

  /** The read threw: the recorder is free for the request's next read. */
  public static void abort(Object token) {
    if (token != null) ((RequestBody) token).release();
  }

  /**
   * The engine blocked the request on its body: from now until the request ends, every read of a body on this
   * thread throws {@code block}, and {@link #denial} returns it to the engine's hooks.
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

  public static boolean exitByte(int result, Object token) {
    if (token == null) return false;
    RequestBody body = (RequestBody) token;
    try {
      return body.recordByte(result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      body.release();
    }
  }

  public static boolean exitBytes(int result, Object token, byte[] buffer, int offset) {
    if (token == null) return false;
    RequestBody body = (RequestBody) token;
    try {
      return body.recordBytes(buffer, offset, result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      body.release();
    }
  }

  public static boolean exitBuffer(int result, Object token, ByteBuffer buffer) {
    if (token == null) return false;
    RequestBody body = (RequestBody) token;
    try {
      return body.recordBuffer(buffer, result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      body.release();
    }
  }

  public static boolean exitAll(byte[] result, Object token, boolean toEnd) {
    if (token == null) return false;
    RequestBody body = (RequestBody) token;
    try {
      return body.recordAll(result, toEnd);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      body.release();
    }
  }

  public static boolean exitChar(int result, Object token) {
    if (token == null) return false;
    RequestBody body = (RequestBody) token;
    try {
      return body.recordChar(result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      body.release();
    }
  }

  public static boolean exitChars(int result, Object token, char[] buffer, int offset) {
    if (token == null) return false;
    RequestBody body = (RequestBody) token;
    try {
      return body.recordChars(buffer, offset, result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      body.release();
    }
  }

  public static boolean exitCharBuffer(int result, Object token, CharBuffer buffer) {
    if (token == null) return false;
    RequestBody body = (RequestBody) token;
    try {
      return body.recordCharBuffer(buffer, result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      body.release();
    }
  }

  public static boolean exitLine(String result, Object token) {
    if (token == null) return false;
    RequestBody body = (RequestBody) token;
    try {
      return body.recordLine(result);
    } catch (Throwable failure) {
      return stop(body);
    } finally {
      body.release();
    }
  }

  /** Recording failed: keep what was recorded and record nothing more; decide it if it was not. */
  private static boolean stop(RequestBody body) {
    try {
      return body.recordByte(-1);
    } catch (Throwable ignored) {
      return false;
    }
  }
}
