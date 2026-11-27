package io.ohmyrasp.agent.http;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/**
 * Instruments the read methods of request-body sources so that each line's hooks class sees what they return
 * (see {@link RequestBodyCapture}). The sources are:
 * <ul>
 * <li>every class whose direct superclass is {@code javax.servlet.ServletInputStream} or
 *     {@code jakarta.servlet.ServletInputStream}: the containers' own streams (Tomcat's CoyoteInputStream,
 *     Jetty's HttpInput, Undertow's ServletInputStreamImpl) and wrappers that re-serve one (Spring's
 *     ContentCachingInputStream); and</li>
 * <li>Tomcat's {@code org.apache.catalina.connector.CoyoteReader}, the reader Tomcat's getReader() returns,
 *     which reads characters from Tomcat's buffer and not through its input stream. Jetty and Undertow return
 *     a reader over their input stream, which the stream hook already sees.</li>
 * </ul>
 * The methods are the read methods a class declares itself, with the signatures of InputStream and
 * ServletInputStream (read, readLine, readAllBytes, readNBytes, read(ByteBuffer)) or of Reader (read,
 * read(CharBuffer), readLine). Inherited ones are not rewritten: InputStream's read(byte[]) calls the class's
 * own read(). Classes of the bootstrap loader and of OSGi framework loaders, which cannot see the agent's
 * classes, are left alone.
 */
public final class RequestBodyVisitor {
  public static final String COYOTE_READER = "org/apache/catalina/connector/CoyoteReader";
  private static final Type OBJECT = Type.getType(Object.class);
  private static final Method ENTER = Method.getMethod("Object enterBodyRead()");
  private static final Method EXIT_BYTE = Method.getMethod("void exitBodyRead(int, Object)");
  private static final Method EXIT_BYTES = Method.getMethod("void exitBodyRead(int, Object, byte[], int)");
  private static final Method EXIT_BUFFER = Method.getMethod("void exitBodyRead(int, Object, java.nio.ByteBuffer)");
  private static final Method EXIT_ALL = Method.getMethod("void exitBodyRead(byte[], Object, boolean)");
  private static final Method EXIT_CHAR = Method.getMethod("void exitBodyChars(int, Object)");
  private static final Method EXIT_CHARS = Method.getMethod("void exitBodyChars(int, Object, char[], int)");
  private static final Method EXIT_CHAR_BUFFER = Method.getMethod("void exitBodyChars(int, Object, java.nio.CharBuffer)");
  private static final Method EXIT_LINE = Method.getMethod("void exitBodyLine(String, Object)");

  private RequestBodyVisitor() {}

  /** Whether a class with this superclass is a servlet input stream the hook rewrites. */
  public static boolean isStream(String superName) {
    return "javax/servlet/ServletInputStream".equals(superName) || "jakarta/servlet/ServletInputStream".equals(superName);
  }

  /** Whether the class is a container reader the hook rewrites. */
  public static boolean isReader(String className) {
    return COYOTE_READER.equals(className);
  }

  public static boolean matches(String className, String superName) {
    return isStream(superName) || isReader(className);
  }

  /** Whether a class this loader defines can call the agent: not the bootstrap loader, not an OSGi framework's. */
  public static boolean loaderSeesAgent(ClassLoader loader) {
    if (loader == null) return false;
    String name = loader.getClass().getName();
    return !name.startsWith("org.apache.felix.framework.") && !name.startsWith("org.eclipse.osgi.")
        && !name.startsWith("org.knopflerfish.");
  }

  /** An already-loaded class the hook applies to, for retransformation on a late attach. */
  public static boolean loadedTarget(Class<?> type) {
    if (type == null || type.isInterface() || !loaderSeesAgent(type.getClassLoader())) return false;
    Class<?> parent = type.getSuperclass();
    return isReader(type.getName().replace('.', '/'))
        || (parent != null && isStream(parent.getName().replace('.', '/')));
  }

  /**
   * The method visitor that records what this method returns, or {@code visitor} itself for a method that is
   * not a read method of this kind of source. {@code hooks} is the line's hooks class, which has the
   * enterBodyRead, exitBodyRead, exitBodyChars and exitBodyLine methods named above.
   */
  public static MethodVisitor wrap(boolean reader, MethodVisitor visitor, int access, String name, String descriptor,
      final Type hooks) {
    if ((access & (Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_BRIDGE)) != 0) {
      return visitor;
    }
    final Shape shape = reader ? readerShape(name, descriptor) : streamShape(name, descriptor);
    if (shape == null) return visitor;
    return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
      private int token = -1;
      private int array = -1;
      private int offset = -1;

      @Override protected void onMethodEnter() {
        // The arguments as the caller passed them: the method may reassign its parameters before it returns.
        if (shape.array != null) {
          loadArg(0);
          array = newLocal(shape.array);
          storeLocal(array);
        }
        if (shape.offset) {
          loadArg(1);
          offset = newLocal(Type.INT_TYPE);
          storeLocal(offset);
        }
        invokeStatic(hooks, ENTER);
        token = newLocal(OBJECT);
        storeLocal(token);
      }

      @Override protected void onMethodExit(int opcode) {
        if (opcode == ATHROW) return;
        dup();
        loadLocal(token);
        if (shape.array != null) loadLocal(array);
        if (shape.offset) loadLocal(offset);
        else if (shape.zeroOffset) push(0);
        if (shape.toEnd != null) push(shape.toEnd.booleanValue());
        invokeStatic(hooks, shape.exit);
      }
    };
  }

  /** What a read method takes and which exit records its result. */
  private static final class Shape {
    final Method exit;
    final Type array;        // the buffer argument to keep, or null
    final boolean offset;    // the second argument is the offset into it
    final boolean zeroOffset;
    final Boolean toEnd;     // readAllBytes (true) or readNBytes(int) (false)

    Shape(Method exit, Type array, boolean offset, boolean zeroOffset, Boolean toEnd) {
      this.exit = exit;
      this.array = array;
      this.offset = offset;
      this.zeroOffset = zeroOffset;
      this.toEnd = toEnd;
    }
  }

  private static final Type BYTES = Type.getType(byte[].class);
  private static final Type CHARS = Type.getType(char[].class);
  private static final Type BYTE_BUFFER = Type.getType(java.nio.ByteBuffer.class);
  private static final Type CHAR_BUFFER = Type.getType(java.nio.CharBuffer.class);

  private static Shape streamShape(String name, String descriptor) {
    if ("read".equals(name)) {
      if ("()I".equals(descriptor)) return new Shape(EXIT_BYTE, null, false, false, null);
      if ("([B)I".equals(descriptor)) return new Shape(EXIT_BYTES, BYTES, false, true, null);
      if ("([BII)I".equals(descriptor)) return new Shape(EXIT_BYTES, BYTES, true, false, null);
      if ("(Ljava/nio/ByteBuffer;)I".equals(descriptor)) return new Shape(EXIT_BUFFER, BYTE_BUFFER, false, false, null);
    }
    if (("readLine".equals(name) || "readNBytes".equals(name)) && "([BII)I".equals(descriptor)) {
      return new Shape(EXIT_BYTES, BYTES, true, false, null);
    }
    if ("readAllBytes".equals(name) && "()[B".equals(descriptor)) return new Shape(EXIT_ALL, null, false, false, Boolean.TRUE);
    if ("readNBytes".equals(name) && "(I)[B".equals(descriptor)) return new Shape(EXIT_ALL, null, false, false, Boolean.FALSE);
    return null;
  }

  private static Shape readerShape(String name, String descriptor) {
    if ("read".equals(name)) {
      if ("()I".equals(descriptor)) return new Shape(EXIT_CHAR, null, false, false, null);
      if ("([C)I".equals(descriptor)) return new Shape(EXIT_CHARS, CHARS, false, true, null);
      if ("([CII)I".equals(descriptor)) return new Shape(EXIT_CHARS, CHARS, true, false, null);
      if ("(Ljava/nio/CharBuffer;)I".equals(descriptor)) return new Shape(EXIT_CHAR_BUFFER, CHAR_BUFFER, false, false, null);
    }
    if ("readLine".equals(name) && "()Ljava/lang/String;".equals(descriptor)) {
      return new Shape(EXIT_LINE, null, false, false, null);
    }
    return null;
  }
}
