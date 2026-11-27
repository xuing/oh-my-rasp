package io.ohmyrasp.agent.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * The rewritten read methods, run: classes rewritten by {@link RequestBodyVisitor} as the transformers rewrite
 * them, defined and verified by the JVM, and called. Synthetic streams cover what a read can do (throw once and
 * be retried, catch its own exception, return through its own handler); Tomcat's real CoyoteInputStream, read
 * through Tomcat's real InputBuffer, covers the read(ByteBuffer) contract on Tomcat 9.0, 10.1 and 11.0.
 */
class RequestBodyVisitorTest {
  private static final Type HOOKS = Type.getType(Hooks.class);

  /** The hooks the rewritten methods call: the capture, with failures to inject on demand. */
  public static final class Hooks {
    static volatile Error enterError;
    static volatile Error exitError;
    static volatile RuntimeException exitBlock;
    static final List<Integer> completed = new ArrayList<Integer>();

    private Hooks() {}

    public static Object enterBodyRead(Object source) {
      if (enterError != null) throw enterError;
      return RequestBodyCapture.enter(source);
    }

    public static Object enterBodyRead(Object source, Buffer buffer) {
      if (enterError != null) throw enterError;
      return RequestBodyCapture.enter(source, buffer);
    }

    public static void abortBodyRead(Object token) {
      RequestBodyCapture.abort(token);
    }

    private static void exited(boolean complete, int result) {
      if (exitError != null) throw exitError;
      if (complete) completed.add(result);
      if (exitBlock != null && complete) {
        RequestBodyCapture.deny(exitBlock);
        throw exitBlock;
      }
    }

    public static void exitBodyRead(int result, Object token) {
      exited(RequestBodyCapture.exitByte(result, token), result);
    }

    public static void exitBodyRead(int result, Object token, byte[] buffer, int offset) {
      exited(RequestBodyCapture.exitBytes(result, token, buffer, offset), result);
    }

    public static void exitBodyRead(int result, Object token, ByteBuffer buffer) {
      exited(RequestBodyCapture.exitBuffer(result, token, buffer), result);
    }

    public static void exitBodyRead(byte[] result, Object token, boolean toEnd) {
      exited(RequestBodyCapture.exitAll(result, token, toEnd), result == null ? -1 : result.length);
    }

    public static void exitBodyChars(int result, Object token) {
      exited(RequestBodyCapture.exitChar(result, token), result);
    }

    public static void exitBodyChars(int result, Object token, char[] buffer, int offset) {
      exited(RequestBodyCapture.exitChars(result, token, buffer, offset), result);
    }

    public static void exitBodyChars(int result, Object token, CharBuffer buffer) {
      exited(RequestBodyCapture.exitCharBuffer(result, token, buffer), result);
    }

    public static void exitBodyLine(String result, Object token) {
      exited(RequestBodyCapture.exitLine(result, token), result == null ? -1 : result.length());
    }
  }

  /** A stream that serves {@code data} and throws an IOException on the read numbered {@code failAt}. */
  public static class ScriptedStream extends InputStream {
    public byte[] data = new byte[0];
    public int position;
    public int calls;
    public int failAt = -1;

    @Override public int read() throws IOException {
      calls++;
      if (calls == failAt) throw new IOException("the connection hiccupped");
      return position < data.length ? data[position++] & 0xff : -1;
    }

    @Override public int read(byte[] buffer, int offset, int length) throws IOException {
      calls++;
      if (calls == failAt) throw new IOException("the connection hiccupped");
      if (position >= data.length) return -1;
      int count = Math.min(length, data.length - position);
      System.arraycopy(data, position, buffer, offset, count);
      position += count;
      return count;
    }

    /** Tomcat's contract: the position is restored, the limit ends after the bytes. */
    public int read(ByteBuffer to) throws IOException {
      calls++;
      if (position >= data.length) return -1;
      int count = Math.min(to.remaining(), data.length - position);
      to.put(data, position, count);
      position += count;
      to.limit(to.position());
      to.position(to.position() - count);
      return count;
    }
  }

  /** A stream whose read catches an exception of its own, and returns through a handler of its own. */
  public static class CatchingStream extends InputStream {
    public byte[] data = new byte[0];
    public int position;
    public boolean stumble = true;

    @Override public int read(byte[] buffer, int offset, int length) {
      try {
        if (stumble) {
          stumble = false;
          throw new IllegalStateException("recovered inside the read");
        }
      } catch (IllegalStateException recovered) {
        // The read goes on.
      }
      if (position >= data.length) return -1;
      int count = Math.min(length, data.length - position);
      System.arraycopy(data, position, buffer, offset, count);
      position += count;
      return count;
    }

    @Override public int read() {
      try {
        return position < data.length ? data[position++] & 0xff : -1;
      } catch (RuntimeException swallowed) {
        return -2; // a handler of the read's own around its return: the line's block must not end here
      }
    }
  }

  /** What the recorder asks a servlet request. */
  public static final class Request {
    private final String contentType;
    private final long length;

    Request(String contentType, long length) {
      this.contentType = contentType;
      this.length = length;
    }

    public String getContentType() { return contentType; }
    public String getCharacterEncoding() { return "UTF-8"; }
    public long getContentLengthLong() { return length; }
    public String getHeader(String name) { return null; }
  }

  @AfterEach
  void reset() {
    Hooks.enterError = null;
    Hooks.exitError = null;
    Hooks.exitBlock = null;
    Hooks.completed.clear();
    RequestBodyCapture.dispatchExited(true);
  }

  private static RequestBody request(String contentType, long length) {
    RequestBodyCapture.dispatchEntered();
    RequestBodyCapture.applicationEntered(true, new Request(contentType, length), true);
    return RequestBodyCapture.current();
  }

  // ---- rewriting and loading ----------------------------------------------------------------------------------

  static byte[] rewrite(byte[] original, final boolean reader) {
    ClassReader classReader = new ClassReader(original);
    ClassWriter writer = new ClassWriter(classReader, ClassWriter.COMPUTE_MAXS);
    final String owner = classReader.getClassName();
    classReader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
      @Override public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
          String[] exceptions) {
        MethodVisitor original = super.visitMethod(access, name, descriptor, signature, exceptions);
        return original == null ? null
            : RequestBodyVisitor.wrap(reader, original, owner, access, name, descriptor, HOOKS);
      }
    }, ClassReader.EXPAND_FRAMES);
    return writer.toByteArray();
  }

  /** Defines the named classes itself, rewritten, and the classes of {@code jars} child first. */
  static final class RewritingLoader extends URLClassLoader {
    private final Set<String> streams;
    private final Set<String> readers;

    RewritingLoader(URL[] jars, Set<String> streams, Set<String> readers) {
      super(jars, RequestBodyVisitorTest.class.getClassLoader());
      this.streams = streams;
      this.readers = readers;
    }

    @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      synchronized (getClassLoadingLock(name)) {
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null) {
          boolean rewritten = streams.contains(name) || readers.contains(name);
          if (rewritten) {
            byte[] bytes = rewrite(bytesOf(name), readers.contains(name));
            loaded = defineClass(name, bytes, 0, bytes.length);
          } else if (getURLs().length > 0 && findResource(name.replace('.', '/') + ".class") != null) {
            loaded = findClass(name);
          } else {
            return super.loadClass(name, resolve);
          }
        }
        if (resolve) resolveClass(loaded);
        return loaded;
      }
    }

    private byte[] bytesOf(String name) throws ClassNotFoundException {
      String resource = name.replace('.', '/') + ".class";
      URL url = findResource(resource);
      if (url == null) url = getParent().getResource(resource);
      if (url == null) throw new ClassNotFoundException(name);
      try (InputStream in = url.openStream()) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        for (int n; (n = in.read(chunk)) > 0;) out.write(chunk, 0, n);
        return out.toByteArray();
      } catch (IOException failure) {
        throw new ClassNotFoundException(name, failure);
      }
    }
  }

  private static InputStream rewritten(Class<?> type) throws Exception {
    RewritingLoader loader = new RewritingLoader(new URL[0], java.util.Collections.singleton(type.getName()),
        java.util.Collections.<String>emptySet());
    Class<?> rewritten = loader.loadClass(type.getName());
    assertTrue(rewritten.getClassLoader() == loader, "the class under test is the rewritten one");
    return (InputStream) rewritten.getConstructor().newInstance();
  }

  private static void set(Object target, String field, Object value) throws Exception {
    target.getClass().getField(field).set(target, value);
  }

  // ---- synthetic streams ----------------------------------------------------------------------------------------

  @Test
  void aReadThatThrowsOnceIsRetriedAndTheRetryIsRecorded() throws Exception {
    byte[] data = "{\"cmd\":\"id\"}".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request("application/json", data.length);
    InputStream in = rewritten(ScriptedStream.class);
    set(in, "data", data);
    set(in, "failAt", 1);
    byte[] buffer = new byte[64];
    try {
      in.read(buffer, 0, buffer.length);
      fail("the application's read must throw its own exception");
    } catch (IOException own) {
      assertEquals("the connection hiccupped", own.getMessage(), "the same throwable, unchanged");
    }
    assertEquals(data.length, in.read(buffer, 0, buffer.length));
    assertEquals("{\"cmd\":\"id\"}", body.snapshot().text(), "the retry after the failure is recorded");
    assertEquals(1, Hooks.completed.size());
  }

  @Test
  void anExceptionTheReadCatchesItselfChangesNothing() throws Exception {
    byte[] data = "abc".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request("text/plain", data.length);
    InputStream in = rewritten(CatchingStream.class);
    set(in, "data", data);
    byte[] buffer = new byte[8];
    assertEquals(3, in.read(buffer, 0, 8));
    assertEquals("abc", body.snapshot().text());
  }

  @Test
  void anErrorFromTheHooksNeverReachesTheApplication() throws Exception {
    byte[] data = "abcdef".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request("text/plain", -1);
    InputStream in = rewritten(ScriptedStream.class);
    set(in, "data", data);
    Hooks.enterError = new NoClassDefFoundError("the hooks class is not visible from this loader");
    byte[] buffer = new byte[2];
    assertEquals(2, in.read(buffer, 0, 2), "an Error from the entry hook: the read goes on");
    assertArrayEquals("ab".getBytes(StandardCharsets.UTF_8), buffer);
    Hooks.enterError = null;
    Hooks.exitError = new ExceptionInInitializerError("the hooks class failed to initialise");
    assertEquals(2, in.read(buffer, 0, 2), "an Error from the exit hook: the read returns its own value");
    assertArrayEquals("cd".getBytes(StandardCharsets.UTF_8), buffer);
    assertEquals('e', in.read(), "single-byte reads too");
    Hooks.exitError = null;
    assertEquals('f', in.read(), "the recorder was not left claimed by the failed exit");
    assertEquals("cdef", body.snapshot().text(), "only the reads whose entry hook ran are recorded");
  }

  @Test
  void theBlockIsThrownPastTheReadsOwnHandlerAndEveryLaterReadThrowsItToo() throws Exception {
    byte[] data = "x".getBytes(StandardCharsets.UTF_8);
    request("text/plain", data.length);
    InputStream in = rewritten(CatchingStream.class);
    set(in, "data", data);
    RuntimeException block = new RuntimeException("the line's block");
    Hooks.exitBlock = block;
    try {
      in.read();
      fail("the read completing a blocked body returned");
    } catch (RuntimeException thrown) {
      assertSame(block, thrown, "the read's own catch (RuntimeException) did not take the block");
    }
    Hooks.exitBlock = null;
    try {
      in.read(new byte[4], 0, 4);
      fail("a read after the block went on");
    } catch (RuntimeException thrown) {
      assertSame(block, thrown);
    }
  }

  @Test
  void aBufferReadOnTomcatsContractIsRecordedFromItsStart() throws Exception {
    byte[] data = "{\"a\":\"b\"}".getBytes(StandardCharsets.UTF_8);
    RequestBody body = request("application/json", data.length);
    InputStream in = rewritten(ScriptedStream.class);
    set(in, "data", data);
    ByteBuffer buffer = ByteBuffer.allocate(32);
    buffer.position(5);
    Method read = in.getClass().getMethod("read", ByteBuffer.class);
    assertEquals(data.length, read.invoke(in, buffer));
    assertEquals(5, buffer.position());
    assertEquals("{\"a\":\"b\"}", body.snapshot().text());
  }

  // ---- Tomcat's own classes -------------------------------------------------------------------------------------

  @Test
  void tomcatsCoyoteInputStreamRecordsByteBufferReadsAsTomcatFillsThem() throws Exception {
    int lines = 0;
    for (String line : new String[] {"9", "10", "11"}) {
      String path = System.getProperty("ohmyrasp.test.tomcat" + line);
      if (path == null || path.isEmpty()) continue;
      lines++;
      readThroughTomcat(line, path);
    }
    Assumptions.assumeTrue(lines > 0, "the build passes no Tomcat classpath");
    assertEquals(3, lines, "every Tomcat line is tested");
  }

  private void readThroughTomcat(String line, String classpath) throws Exception {
    List<URL> urls = new ArrayList<URL>();
    for (String part : classpath.split(File.pathSeparator)) urls.add(new File(part).toURI().toURL());
    RewritingLoader loader = new RewritingLoader(urls.toArray(new URL[0]),
        java.util.Collections.singleton("org.apache.catalina.connector.CoyoteInputStream"),
        java.util.Collections.singleton("org.apache.catalina.connector.CoyoteReader"));
    final byte[] data = "{\"cmd\":\"127.0.0.1; id\",\"pad\":\"0123456789\"}".getBytes(StandardCharsets.UTF_8);
    for (boolean direct : new boolean[] {false, true}) {
      for (int position : new int[] {0, 7}) {
        String label = "Tomcat " + line + (direct ? " direct" : " heap") + " position " + position;
        RequestBody body = request("application/json", data.length);
        InputStream in = tomcatStream(loader, data, 11);
        Method read = in.getClass().getMethod("read", ByteBuffer.class);
        ByteBuffer buffer = direct ? ByteBuffer.allocateDirect(64) : ByteBuffer.allocate(64);
        while (buffer.hasRemaining()) buffer.put((byte) 'x');
        ByteArrayOutputStream application = new ByteArrayOutputStream();
        while (true) {
          buffer.clear();
          buffer.position(position);
          int count = (Integer) read.invoke(in, buffer);
          if (count < 0) break;
          assertEquals(position, buffer.position(), "Tomcat restores the position: " + label);
          assertEquals(position + count, buffer.limit(), "Tomcat sets the limit after the bytes: " + label);
          byte[] got = new byte[count];
          buffer.get(got);
          application.write(got);
        }
        assertArrayEquals(data, application.toByteArray(), label);
        assertNotNull(body.snapshot(), label);
        assertEquals(new String(data, StandardCharsets.UTF_8), body.snapshot().text(), label);
        assertTrue(body.done(), label);
        RequestBodyCapture.dispatchExited(true);
      }
    }
    // The array read of the same class, and a read on a thread that serves no request.
    RequestBody body = request("application/json", data.length);
    InputStream in = tomcatStream(loader, data, data.length);
    byte[] all = new byte[128];
    assertEquals(data.length, in.read(all, 0, all.length));
    assertEquals(new String(data, StandardCharsets.UTF_8), body.snapshot().text(), "Tomcat " + line + " read(byte[])");
    RequestBodyCapture.dispatchExited(true);
    InputStream outside = tomcatStream(loader, data, data.length);
    assertEquals(data.length, outside.read(all, 0, all.length), "outside a request the read is the container's own");
    assertNull(RequestBodyCapture.current() == null ? null : RequestBodyCapture.current().lastSnapshot());
  }

  /** Tomcat's CoyoteInputStream over its InputBuffer over a coyote request that serves {@code data} in chunks. */
  private static InputStream tomcatStream(ClassLoader loader, final byte[] data, final int chunk) throws Exception {
    Class<?> coyoteRequestType = loader.loadClass("org.apache.coyote.Request");
    Class<?> coyoteResponseType = loader.loadClass("org.apache.coyote.Response");
    final Class<?> handlerType = loader.loadClass("org.apache.tomcat.util.net.ApplicationBufferHandler");
    Class<?> coyoteInputType = loader.loadClass("org.apache.coyote.InputBuffer");
    Object coyoteRequest = coyoteRequestType.getConstructor().newInstance();
    Object coyoteResponse = coyoteResponseType.getConstructor().newInstance();
    coyoteRequestType.getMethod("setResponse", coyoteResponseType).invoke(coyoteRequest, coyoteResponse);
    final int[] served = {0};
    Object source = Proxy.newProxyInstance(loader, new Class<?>[] {coyoteInputType}, new InvocationHandler() {
      @Override public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
        if ("doRead".equals(method.getName())) {
          if (served[0] >= data.length) return -1;
          int count = Math.min(chunk, data.length - served[0]);
          ByteBuffer bytes = ByteBuffer.wrap(data, served[0], count).slice();
          served[0] += count;
          handlerType.getMethod("setByteBuffer", ByteBuffer.class).invoke(arguments[0], bytes);
          return count;
        }
        if (method.getReturnType() == int.class) return 0;
        if (method.getReturnType() == long.class) return 0L;
        if (method.getReturnType() == boolean.class) return served[0] >= data.length;
        return null;
      }
    });
    coyoteRequestType.getMethod("setInputBuffer", coyoteInputType).invoke(coyoteRequest, source);
    Class<?> inputBufferType = loader.loadClass("org.apache.catalina.connector.InputBuffer");
    Object inputBuffer;
    try {
      inputBuffer = inputBufferType.getConstructor(int.class).newInstance(8192); // 9.0 and 10.1
      inputBufferType.getMethod("setRequest", coyoteRequestType).invoke(inputBuffer, coyoteRequest);
    } catch (NoSuchMethodException eleven) {
      inputBuffer = inputBufferType.getConstructor(int.class, coyoteRequestType).newInstance(8192, coyoteRequest);
    }
    Class<?> streamType = loader.loadClass("org.apache.catalina.connector.CoyoteInputStream");
    Constructor<?> constructor = streamType.getDeclaredConstructor(inputBufferType);
    constructor.setAccessible(true);
    try {
      return (InputStream) constructor.newInstance(inputBuffer);
    } catch (InvocationTargetException failure) {
      throw new AssertionError(failure.getCause());
    }
  }
}
