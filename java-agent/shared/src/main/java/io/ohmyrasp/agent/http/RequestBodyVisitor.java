package io.ohmyrasp.agent.http;

import java.util.ArrayList;
import java.util.List;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.TypePath;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.AnalyzerAdapter;
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
 * own read(). A class that overrides a read method without calling one of these (an indirect subclass of
 * ServletInputStream) is not seen. Classes of the bootstrap loader and of OSGi framework loaders, which cannot
 * see the agent's classes, are left alone.
 *
 * <p>What the rewritten method does, in order:
 * <ol>
 * <li>{@code token = enterBodyRead(this)} (for a buffer read, {@code enterBodyRead(this, buffer)}, which notes
 *     where the buffer stood): the recorder of the request this thread serves, or null. The call is guarded: an
 *     Error from it (the hooks class cannot be linked from this loader) leaves the token null, and only a
 *     RuntimeException, which the hooks throw only as the line's block, reaches the caller.</li>
 * <li>The original code, unchanged. Every exception it lets out passes through one handler, entered after the
 *     method's own handlers, that calls {@code abortBodyRead(token)} when the token is set (which releases the
 *     recorder for the next read) and rethrows the same throwable.</li>
 * <li>At each return, the value is kept, {@code exitBodyRead(value, token, ...)} records it under the same
 *     guard as the entry (a RuntimeException, the line's block, is thrown from outside the method's own
 *     handlers; anything else is dropped), and the kept value is returned.</li>
 * </ol>
 */
public final class RequestBodyVisitor {
  public static final String COYOTE_READER = "org/apache/catalina/connector/CoyoteReader";
  private static final Type OBJECT = Type.getType(Object.class);
  private static final Type THROWABLE = Type.getType(Throwable.class);
  private static final Type RUNTIME_EXCEPTION = Type.getType(RuntimeException.class);
  private static final Method ENTER = Method.getMethod("Object enterBodyRead(Object)");
  private static final Method ENTER_BUFFER = Method.getMethod("Object enterBodyRead(Object, java.nio.Buffer)");
  private static final Method ABORT = Method.getMethod("void abortBodyRead(Object)");
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
   * ({@code ClassReader.EXPAND_FRAMES}): the rewritten method carries the frames of its new branches.
   */
  public static MethodVisitor wrap(boolean reader, MethodVisitor visitor, String owner, int access, String name,
      String descriptor, Type hooks) {
    if ((access & (Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_BRIDGE)) != 0
        || "<init>".equals(name)) {
      return visitor;
    }
    Shape shape = reader ? readerShape(name, descriptor) : streamShape(name, descriptor);
    if (shape == null) return visitor;
    Advice advice = new Advice(visitor, owner, access, name, descriptor, shape, hooks);
    // The analyzer sees the original instructions only: it tells the advice what is on the stack at a return.
    AnalyzerAdapter analyzer = new AnalyzerAdapter(owner, access, name, descriptor, advice);
    advice.analyzer = analyzer;
    return analyzer;
  }

  /** One rewritten read method. */
  private static final class Advice extends AdviceAdapter {
    private final Shape shape;
    private final Type hooks;
    private final Type returnType;
    private final Object[] entryLocals;
    AnalyzerAdapter analyzer;

    private int token = -1;
    private int array = -1;
    private int offset = -1;
    private int kept = -1;
    private Label start;
    // The method's own handlers, entered after the exit guards (which must come first) and before the handler
    // that covers the whole method (which must come last).
    private final List<Object[]> ownHandlers = new ArrayList<Object[]>();
    private final List<Label[]> exitGuards = new ArrayList<Label[]>();

    Advice(MethodVisitor visitor, String owner, int access, String name, String descriptor, Shape shape, Type hooks) {
      super(Opcodes.ASM9, visitor, access, name, descriptor);
      this.shape = shape;
      this.hooks = hooks;
      this.returnType = Type.getReturnType(descriptor);
      Type[] arguments = Type.getArgumentTypes(descriptor);
      entryLocals = new Object[arguments.length + 1];
      entryLocals[0] = owner;
      for (int i = 0; i < arguments.length; i++) entryLocals[i + 1] = frameType(arguments[i]);
    }

    @Override protected void onMethodEnter() {
      // Every local the advice adds is set here, before any of the method's code, so that every frame of the
      // method (which names the added locals with their types) holds wherever it applies.
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
      visitInsn(Opcodes.ACONST_NULL);
      storeLocal(token);
      kept = newLocal(returnType);
      if (returnType.getSort() == Type.OBJECT || returnType.getSort() == Type.ARRAY) visitInsn(Opcodes.ACONST_NULL);
      else push(0);
      storeLocal(kept);

      Label from = mark();
      loadThis();
      if (shape.buffer) {
        loadArg(0);
        invokeStatic(hooks, ENTER_BUFFER);
      } else {
        invokeStatic(hooks, ENTER);
      }
      storeLocal(token);
      Label to = mark();
      Label after = new Label();
      goTo(after);
      Label handler = mark();
      frame(entryLocals, THROWABLE);
      dropUnlessBlock(entryLocals);
      visitInsn(Opcodes.POP);
      visitLabel(after);
      frame(entryLocals, null);
      visitInsn(Opcodes.NOP); // the method's own first frame, if it has one at its first instruction, is not here
      visitTryCatchBlockNow(from, to, handler, null);
      start = mark();
    }

    @Override protected void onMethodExit(int opcode) {
      if (opcode == ATHROW) return;
      if (!onlyTheReturnValue()) {
        // Code a Java compiler does not write: something is under the value. Record without the guard.
        dup();
        pushExitArguments();
        invokeStatic(hooks, shape.exit);
        return;
      }
      storeLocal(kept);
      Label from = mark();
      loadLocal(kept);
      pushExitArguments();
      invokeStatic(hooks, shape.exit);
      Label to = mark();
      Label resume = mark();
      frame(new Object[0], null);
      loadLocal(kept);
      exitGuards.add(new Label[] {from, to, resume});
    }

    private void pushExitArguments() {
      loadLocal(token);
      if (shape.array != null) loadLocal(array);
      if (shape.offset) loadLocal(offset);
      else if (shape.zeroOffset) push(0);
      if (shape.toEnd != null) push(shape.toEnd.booleanValue());
    }

    /** Whether the stack holds the return value and nothing under it, as at every return javac writes. */
    private boolean onlyTheReturnValue() {
      List<Object> stack = analyzer == null ? null : analyzer.stack;
      if (stack == null) return false;
      return stack.size() == returnType.getSize();
    }

    /**
     * On the stack: a throwable, with {@code locals} as the handler's frame named them. A RuntimeException (the
     * line's block) is thrown on; anything else stays on the stack for the caller to drop.
     */
    private void dropUnlessBlock(Object[] locals) {
      Label drop = new Label();
      dup();
      instanceOf(RUNTIME_EXCEPTION);
      visitJumpInsn(Opcodes.IFEQ, drop);
      visitInsn(Opcodes.ATHROW);
      visitLabel(drop);
      frame(locals, THROWABLE);
    }

    /**
     * A full frame: {@code locals} are the method's own locals in its own numbering (null: those at entry), the
     * added locals are named by the local sorter; {@code stack} is one throwable or nothing.
     */
    private void frame(Object[] locals, Type stack) {
      Object[] own = locals == null ? entryLocals : locals;
      Object[] onStack = stack == null ? new Object[0] : new Object[] {stack.getInternalName()};
      visitFrame(Opcodes.F_NEW, own.length, own, onStack.length, onStack);
    }

    @Override public void visitTryCatchBlock(Label from, Label to, Label handler, String type) {
      ownHandlers.add(new Object[] {from, to, handler, type});
    }

    @Override public AnnotationVisitor visitTryCatchAnnotation(int typeRef, TypePath typePath, String descriptor,
        boolean visible) {
      return null; // the handlers are entered later, in a new order; their type annotations are not kept
    }

    private void visitTryCatchBlockNow(Label from, Label to, Label handler, String type) {
      super.visitTryCatchBlock(from, to, handler, type);
    }

    @Override public void visitMaxs(int maxStack, int maxLocals) {
      Label end = mark();
      // Every exception the method lets out: release the recorder, then the same throwable goes on.
      Label release = mark();
      frame(new Object[0], THROWABLE);
      Label rethrow = new Label();
      loadLocal(token);
      ifNull(rethrow);
      loadLocal(token);
      invokeStatic(hooks, ABORT);
      visitLabel(rethrow);
      frame(new Object[0], THROWABLE);
      visitInsn(Opcodes.ATHROW);
      // The exit guards' handlers, out of every range of the method's own handlers.
      List<Label> exitHandlers = new ArrayList<Label>();
      for (Label[] guard : exitGuards) {
        Label handler = mark();
        exitHandlers.add(handler);
        frame(new Object[0], THROWABLE);
        dropUnlessBlock(new Object[0]);
        visitInsn(Opcodes.POP);
        goTo(guard[2]);
      }
      for (int i = 0; i < exitGuards.size(); i++) {
        visitTryCatchBlockNow(exitGuards.get(i)[0], exitGuards.get(i)[1], exitHandlers.get(i), null);
      }
      for (Object[] own : ownHandlers) {
        visitTryCatchBlockNow((Label) own[0], (Label) own[1], (Label) own[2], (String) own[3]);
      }
      visitTryCatchBlockNow(start, end, release, null);
      super.visitMaxs(maxStack, maxLocals);
    }

    private static Object frameType(Type type) {
      switch (type.getSort()) {
        case Type.BOOLEAN:
        case Type.CHAR:
        case Type.BYTE:
        case Type.SHORT:
        case Type.INT:
          return Opcodes.INTEGER;
        case Type.FLOAT:
          return Opcodes.FLOAT;
        case Type.LONG:
          return Opcodes.LONG;
        case Type.DOUBLE:
          return Opcodes.DOUBLE;
        default:
          return type.getInternalName();
      }
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
