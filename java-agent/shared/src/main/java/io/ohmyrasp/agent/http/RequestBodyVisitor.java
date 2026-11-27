package io.ohmyrasp.agent.http;

import org.objectweb.asm.Label;
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
 * own read(). A read method of an indirect subclass of ServletInputStream (a subclass of a container's stream)
 * is not rewritten, and its data is seen only when it calls a read method of a direct subclass. Classes of the
 * bootstrap loader and of OSGi framework loaders, which cannot see the agent's classes, are left alone. Static,
 * abstract, native and bridge methods and constructors are never rewritten.
 *
 * <p>What the rewritten method does. The original code and its exception table stay as they were: no branch and
 * no stack map frame is added inside them, and no original handler is moved, so a class the JVM accepted
 * before is accepted after (the {@code hook-targets} probe verifies every rewritten library class on each JDK).
 * <ol>
 * <li>Before the original code: the arguments a later record needs are copied to locals of their own (a read
 *     may reassign its parameters), then {@code token = enterBodyRead(this)} (for a buffer read,
 *     {@code enterBodyRead(this, buffer)}), straight-line.</li>
 * <li>At each return: the returned value is duplicated and {@code exitBodyRead(value, token, ...)}, which
 *     returns nothing, is called, straight-line; the original return then returns the original value.</li>
 * <li>One handler, entered last in the exception table (after every original handler, which keep their order
 *     and priority) and covering the original code: its frame declares every local unset and one Throwable on
 *     the stack; it stores the throwable in a slot above every other local, calls {@code abortBodyRead()} and
 *     throws the same throwable again. It reads no other local, {@code this} included.</li>
 * </ol>
 * The hooks are plain static methods whose Java bodies catch every throwable of the agent's own code and throw
 * only the line's block (the entry and exit hooks) or nothing (the release hook). An application handler around
 * a return inside the read can catch that block; the block is latched (see {@link RequestBodyCapture#deny}) and
 * the next read of the same stream throws it again. The local sorter numbers a method's locals densely in the
 * order they are used, so the added ones stay far below the class format's limit of 65535 slots for any method
 * within the 65535-byte code limit; one that would pass it fails the transform, and the class is left as it was.
 */
public final class RequestBodyVisitor {
  public static final String COYOTE_READER = "org/apache/catalina/connector/CoyoteReader";
  private static final Type OBJECT = Type.getType(Object.class);
  private static final String THROWABLE = "java/lang/Throwable";
  private static final int MAX_LOCAL_SLOTS = 0xFFFF;
  private static final Method ENTER = Method.getMethod("Object enterBodyRead(Object)");
  private static final Method ENTER_BUFFER = Method.getMethod("Object enterBodyRead(Object, java.nio.Buffer)");
  private static final Method ABORT = Method.getMethod("void abortBodyRead()");
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
   * not a read method of this kind of source. {@code owner} is the internal name of the class being rewritten
   * and {@code hooks} the line's hooks class, which has the enterBodyRead, abortBodyRead, exitBodyRead,
   * exitBodyChars and exitBodyLine methods named above. The class reader must expand frames
   * ({@code ClassReader.EXPAND_FRAMES}): the local variable sorter renumbers the method's locals in its frames.
   */
  public static MethodVisitor wrap(boolean reader, MethodVisitor visitor, String owner, int access, String name,
      String descriptor, Type hooks) {
    if ((access & (Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_BRIDGE)) != 0
        || "<init>".equals(name) || "<clinit>".equals(name)) {
      return visitor;
    }
    Shape shape = reader ? readerShape(name, descriptor) : streamShape(name, descriptor);
    if (shape == null) return visitor;
    return new Advice(visitor, access, name, descriptor, shape, hooks);
  }

  /** One rewritten read method. */
  private static final class Advice extends AdviceAdapter {
    private final Shape shape;
    private final Type hooks;

    private int token = -1;
    private int array = -1;
    private int offset = -1;
    private Label start;

    Advice(MethodVisitor visitor, int access, String name, String descriptor, Shape shape, Type hooks) {
      super(Opcodes.ASM9, visitor, access, name, descriptor);
      this.shape = shape;
      this.hooks = hooks;
    }

    @Override protected void onMethodEnter() {
      // Every local the advice adds is set here, before any of the method's code, so that the type the local
      // sorter gives it in each of the method's frames holds wherever that frame applies.
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
      token = newLocal(OBJECT);
      loadThis();
      if (shape.buffer) {
        loadArg(0);
        invokeStatic(hooks, ENTER_BUFFER);
      } else {
        invokeStatic(hooks, ENTER);
      }
      storeLocal(token);
      start = mark();
    }

    @Override protected void onMethodExit(int opcode) {
      if (opcode == ATHROW) return;
      // The returned value is on top of the stack; whatever is under it stays there.
      dup();
      loadLocal(token);
      if (shape.array != null) loadLocal(array);
      if (shape.offset) loadLocal(offset);
      else if (shape.zeroOffset) push(0);
      if (shape.toEnd != null) push(shape.toEnd.booleanValue());
      invokeStatic(hooks, shape.exit);
    }

    @Override public void visitMaxs(int maxStack, int maxLocals) {
      // Every exception the method lets out: release the recorder, then the same throwable goes on. Written
      // to the next visitor directly, past the local sorter, so that the frame stays as written (every local
      // unset) and the slot is the first one above every local the method has after sorting.
      int thrown = nextLocal;
      if (thrown + 1 > MAX_LOCAL_SLOTS) {
        throw new IllegalStateException("too many locals to rewrite " + getName());
      }
      Label end = new Label();
      mv.visitLabel(end);
      mv.visitFrame(Opcodes.F_NEW, 0, new Object[0], 1, new Object[] {THROWABLE});
      mv.visitVarInsn(Opcodes.ASTORE, thrown);
      mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks.getInternalName(), ABORT.getName(), ABORT.getDescriptor(), false);
      mv.visitVarInsn(Opcodes.ALOAD, thrown);
      mv.visitInsn(Opcodes.ATHROW);
      mv.visitTryCatchBlock(start, end, end, null);
      super.visitMaxs(maxStack, Math.max(maxLocals, thrown + 1));
    }
  }

  /** What a read method takes and which exit records its result. */
  private static final class Shape {
    final Method exit;
    final Type array;        // the buffer argument to keep, or null
    final boolean offset;    // the second argument is the offset into it
    final boolean zeroOffset;
    final Boolean toEnd;     // readAllBytes (true) or readNBytes(int) (false)
    final boolean buffer;    // the argument is an NIO buffer, whose position the entry notes

    Shape(Method exit, Type array, boolean offset, boolean zeroOffset, Boolean toEnd, boolean buffer) {
      this.exit = exit;
      this.array = array;
      this.offset = offset;
      this.zeroOffset = zeroOffset;
      this.toEnd = toEnd;
      this.buffer = buffer;
    }
  }

  private static final Type BYTES = Type.getType(byte[].class);
  private static final Type CHARS = Type.getType(char[].class);
  private static final Type BYTE_BUFFER = Type.getType(java.nio.ByteBuffer.class);
  private static final Type CHAR_BUFFER = Type.getType(java.nio.CharBuffer.class);

  private static Shape streamShape(String name, String descriptor) {
    if ("read".equals(name)) {
      if ("()I".equals(descriptor)) return new Shape(EXIT_BYTE, null, false, false, null, false);
      if ("([B)I".equals(descriptor)) return new Shape(EXIT_BYTES, BYTES, false, true, null, false);
      if ("([BII)I".equals(descriptor)) return new Shape(EXIT_BYTES, BYTES, true, false, null, false);
      if ("(Ljava/nio/ByteBuffer;)I".equals(descriptor)) {
        return new Shape(EXIT_BUFFER, BYTE_BUFFER, false, false, null, true);
      }
    }
    if (("readLine".equals(name) || "readNBytes".equals(name)) && "([BII)I".equals(descriptor)) {
      return new Shape(EXIT_BYTES, BYTES, true, false, null, false);
    }
    if ("readAllBytes".equals(name) && "()[B".equals(descriptor)) {
      return new Shape(EXIT_ALL, null, false, false, Boolean.TRUE, false);
    }
    if ("readNBytes".equals(name) && "(I)[B".equals(descriptor)) {
      return new Shape(EXIT_ALL, null, false, false, Boolean.FALSE, false);
    }
    return null;
  }

  private static Shape readerShape(String name, String descriptor) {
    if ("read".equals(name)) {
      if ("()I".equals(descriptor)) return new Shape(EXIT_CHAR, null, false, false, null, false);
      if ("([C)I".equals(descriptor)) return new Shape(EXIT_CHARS, CHARS, false, true, null, false);
      if ("([CII)I".equals(descriptor)) return new Shape(EXIT_CHARS, CHARS, true, false, null, false);
      if ("(Ljava/nio/CharBuffer;)I".equals(descriptor)) {
        return new Shape(EXIT_CHAR_BUFFER, CHAR_BUFFER, false, false, null, true);
      }
    }
    if ("readLine".equals(name) && "()Ljava/lang/String;".equals(descriptor)) {
      return new Shape(EXIT_LINE, null, false, false, null, false);
    }
    return null;
  }
}
