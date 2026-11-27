import io.ohmyrasp.agent.shaded.asm.ClassWriter;
import io.ohmyrasp.agent.shaded.asm.Label;
import io.ohmyrasp.agent.shaded.asm.MethodVisitor;
import io.ohmyrasp.agent.shaded.asm.Opcodes;
import java.util.ArrayList;
import java.util.List;

/**
 * Request-body sources made for the purpose, each with read methods of one shape the JVM accepts and a rewrite of
 * read methods has to keep valid. HookVerify puts each through the line's transformers and verifies the result.
 *
 * <p>Two kinds of source: a servlet input stream (direct superclass {@code javax/servlet/ServletInputStream}, whose
 * class the staged servlet API provides; read {@code read([BII)I}) and Tomcat's reader (named
 * {@code org/apache/catalina/connector/CoyoteReader}, superclass {@code java/io/Reader}; {@code read([CII)I} and
 * {@code readLine()}). Every class has a field {@code count}, a constructor and a private {@code fill} of the read's
 * descriptor that returns its length argument. The shapes:
 * <ul>
 * <li>a: a synchronized block (MONITORENTER on this) around a try with a catch and a finally whose handlers load
 *     this and an int local, then MONITOREXIT and rethrow, as javac writes it;</li>
 * <li>b: an exception range that covers the IRETURN (and for the reader, readLine's ARETURN), whose handler uses
 *     this and a local. A rewrite that resumes after its exit hook with a frame naming every local TOP puts that
 *     frame inside the range, and the JVM rejects the handler ("Stack map does not match the one at exception
 *     handler");</li>
 * <li>c: reads that call the rewritten read: {@code read([B)I} calls {@code this.read(b, 0, b.length)} and
 *     {@code read()I} calls {@code read([BII)I};</li>
 * <li>d: a tableswitch with a return in each case;</li>
 * <li>e: a parameter slot that takes another type: a String in the array's slot and a long over the offset and
 *     length, with a branch after so that a frame names them;</li>
 * <li>f: max_locals 65535, the most a method can have: a rewrite that adds locals either leaves the method alone
 *     or still writes a valid class.</li>
 * </ul>
 */
final class BodyReadShapes {
  static final String STREAM_SUPER = "javax/servlet/ServletInputStream";
  static final String READER = "org/apache/catalina/connector/CoyoteReader";

  static final class Shape {
    final String name;
    final String className;
    final byte[] bytes;
    /** Only shape f may come out unchanged: a transformer that cannot add locals leaves the method alone. */
    final boolean mayStayUntouched;

    Shape(String name, String className, byte[] bytes, boolean mayStayUntouched) {
      this.name = name;
      this.className = className;
      this.bytes = bytes;
      this.mayStayUntouched = mayStayUntouched;
    }
  }

  private interface Body {
    void emit(MethodVisitor m, Kind kind);
  }

  /** What differs between the stream and the reader. */
  static final class Kind {
    final String label;
    final String className;
    final String superName;
    final String array;       // [B or [C
    final int arrayStore;     // BASTORE or CASTORE
    final int newArrayType;   // T_BYTE or T_CHAR

    Kind(String label, String className, String superName, String array, int arrayStore, int newArrayType) {
      this.label = label;
      this.className = className;
      this.superName = superName;
      this.array = array;
      this.arrayStore = arrayStore;
      this.newArrayType = newArrayType;
    }

    String read() {
      return "(" + array + "II)I";
    }
  }

  static List<Shape> all() {
    List<Shape> shapes = new ArrayList<Shape>();
    Kind stream = new Kind("stream", "ohmyrasp/synthetic/BodyStream", STREAM_SUPER, "[B", Opcodes.BASTORE, Opcodes.T_BYTE);
    Kind reader = new Kind("reader", READER, "java/io/Reader", "[C", Opcodes.CASTORE, Opcodes.T_CHAR);
    for (Kind kind : new Kind[] {stream, reader}) {
      shapes.add(shape(kind, "a-synchronized-try-catch-finally", false, read(kind, SYNCHRONIZED)));
      if (kind == reader) {
        shapes.add(shape(kind, "b-range-covers-return", false, read(kind, RANGE_OVER_RETURN), readLineRangeOverReturn()));
      } else {
        shapes.add(shape(kind, "b-range-covers-return", false, read(kind, RANGE_OVER_RETURN)));
      }
      shapes.add(shape(kind, "c-read-calls-read", false, read(kind, FILL), readArray(kind), readOne(kind)));
      shapes.add(shape(kind, "d-tableswitch", false, read(kind, TABLESWITCH)));
      shapes.add(shape(kind, "e-parameter-slot-retyped", false, read(kind, RETYPED_PARAMETERS)));
      shapes.add(shape(kind, "f-max-locals", true, read(kind, MAX_LOCALS)));
    }
    return shapes;
  }

  /** A method of the class: name, descriptor, body. */
  private static final class Method {
    final String name;
    final String descriptor;
    final int access;
    final Body body;

    Method(String name, String descriptor, int access, Body body) {
      this.name = name;
      this.descriptor = descriptor;
      this.access = access;
      this.body = body;
    }
  }

  private static Method read(Kind kind, Body body) {
    return new Method("read", kind.read(), Opcodes.ACC_PUBLIC, body);
  }

  private static Shape shape(Kind kind, String name, boolean mayStayUntouched, Method... methods) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
      @Override protected String getCommonSuperClass(String a, String b) {
        return "java/lang/Object";
      }
    };
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, kind.className, null, kind.superName, null);
    writer.visitField(Opcodes.ACC_PRIVATE, "count", "I", null, null).visitEnd();
    MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    init.visitCode();
    init.visitVarInsn(Opcodes.ALOAD, 0);
    init.visitMethodInsn(Opcodes.INVOKESPECIAL, kind.superName, "<init>", "()V", false);
    init.visitInsn(Opcodes.RETURN);
    init.visitMaxs(0, 0);
    init.visitEnd();
    MethodVisitor fill = writer.visitMethod(Opcodes.ACC_PRIVATE, "fill", kind.read(), null, null);
    fill.visitCode();
    fill.visitVarInsn(Opcodes.ILOAD, 3);
    fill.visitInsn(Opcodes.IRETURN);
    fill.visitMaxs(0, 0);
    fill.visitEnd();
    for (Method method : methods) {
      MethodVisitor m = writer.visitMethod(method.access, method.name, method.descriptor, null, null);
      m.visitCode();
      method.body.emit(m, kind);
      m.visitMaxs(0, 0);
      m.visitEnd();
    }
    writer.visitEnd();
    return new Shape(kind.label + " " + name, kind.className, writer.toByteArray(), mayStayUntouched);
  }

  private static void callFill(MethodVisitor m, Kind kind, int lengthLocal) {
    m.visitVarInsn(Opcodes.ALOAD, 0);
    m.visitVarInsn(Opcodes.ALOAD, 1);
    m.visitVarInsn(Opcodes.ILOAD, 2);
    m.visitVarInsn(Opcodes.ILOAD, lengthLocal);
    m.visitMethodInsn(Opcodes.INVOKESPECIAL, kind.className, "fill", kind.read(), false);
  }

  /** this.count += local (an int local). */
  private static void addToCount(MethodVisitor m, Kind kind, int local) {
    m.visitVarInsn(Opcodes.ALOAD, 0);
    m.visitInsn(Opcodes.DUP);
    m.visitFieldInsn(Opcodes.GETFIELD, kind.className, "count", "I");
    m.visitVarInsn(Opcodes.ILOAD, local);
    m.visitInsn(Opcodes.IADD);
    m.visitFieldInsn(Opcodes.PUTFIELD, kind.className, "count", "I");
  }

  /** The read itself: return fill(array, off, len). */
  private static final Body FILL = new Body() {
    public void emit(MethodVisitor m, Kind kind) {
      callFill(m, kind, 3);
      m.visitInsn(Opcodes.IRETURN);
    }
  };

  /**
   * What javac writes for
   * <pre>
   * synchronized (this) {
   *   int n = len;
   *   try { n = fill(b, off, n); return n; }
   *   catch (RuntimeException e) { count = n; throw e; }
   *   finally { count += n; }
   * }
   * </pre>
   * Locals: 4 the monitor, 5 n, 6 the kept return value, 7 and 8 caught throwables.
   */
  private static final Body SYNCHRONIZED = new Body() {
    public void emit(MethodVisitor m, Kind kind) {
      Label monitorStart = new Label(), monitorEnd = new Label(), tryStart = new Label(), tryEnd = new Label();
      Label catchHandler = new Label(), finallyHandler = new Label(), handlersEnd = new Label(), monitorHandler = new Label();
      m.visitTryCatchBlock(tryStart, tryEnd, catchHandler, "java/lang/RuntimeException");
      m.visitTryCatchBlock(tryStart, tryEnd, finallyHandler, null);
      m.visitTryCatchBlock(catchHandler, finallyHandler, finallyHandler, null);
      m.visitTryCatchBlock(monitorStart, monitorEnd, monitorHandler, null);
      m.visitTryCatchBlock(catchHandler, handlersEnd, monitorHandler, null);
      m.visitVarInsn(Opcodes.ALOAD, 0);
      m.visitInsn(Opcodes.DUP);
      m.visitVarInsn(Opcodes.ASTORE, 4);
      m.visitInsn(Opcodes.MONITORENTER);
      m.visitLabel(monitorStart);
      m.visitVarInsn(Opcodes.ILOAD, 3);
      m.visitVarInsn(Opcodes.ISTORE, 5);
      m.visitLabel(tryStart);
      callFill(m, kind, 5);
      m.visitVarInsn(Opcodes.ISTORE, 5);
      m.visitVarInsn(Opcodes.ILOAD, 5);
      m.visitVarInsn(Opcodes.ISTORE, 6);
      m.visitLabel(tryEnd);
      addToCount(m, kind, 5);
      m.visitVarInsn(Opcodes.ALOAD, 4);
      m.visitInsn(Opcodes.MONITOREXIT);
      m.visitLabel(monitorEnd);
      m.visitVarInsn(Opcodes.ILOAD, 6);
      m.visitInsn(Opcodes.IRETURN);
      // catch (RuntimeException e) { count = n; throw e; }
      m.visitLabel(catchHandler);
      m.visitVarInsn(Opcodes.ASTORE, 7);
      m.visitVarInsn(Opcodes.ALOAD, 0);
      m.visitVarInsn(Opcodes.ILOAD, 5);
      m.visitFieldInsn(Opcodes.PUTFIELD, kind.className, "count", "I");
      m.visitVarInsn(Opcodes.ALOAD, 7);
      m.visitInsn(Opcodes.ATHROW);
      // finally, on the exceptional path: count += n; rethrow
      m.visitLabel(finallyHandler);
      m.visitVarInsn(Opcodes.ASTORE, 8);
      addToCount(m, kind, 5);
      m.visitVarInsn(Opcodes.ALOAD, 8);
      m.visitInsn(Opcodes.ATHROW);
      m.visitLabel(handlersEnd);
      // leave the monitor on any throwable from inside it
      m.visitLabel(monitorHandler);
      m.visitVarInsn(Opcodes.ASTORE, 8);
      m.visitVarInsn(Opcodes.ALOAD, 4);
      m.visitInsn(Opcodes.MONITOREXIT);
      m.visitVarInsn(Opcodes.ALOAD, 8);
      m.visitInsn(Opcodes.ATHROW);
    }
  };

  /** int n = 0; try { n = fill(b, off, len); return n; } catch (Throwable t) { count = n; throw t; } */
  private static final Body RANGE_OVER_RETURN = new Body() {
    public void emit(MethodVisitor m, Kind kind) {
      Label start = new Label(), end = new Label(), handler = new Label();
      m.visitTryCatchBlock(start, end, handler, null);
      m.visitInsn(Opcodes.ICONST_0);
      m.visitVarInsn(Opcodes.ISTORE, 4);
      m.visitLabel(start);
      callFill(m, kind, 3);
      m.visitVarInsn(Opcodes.ISTORE, 4);
      m.visitVarInsn(Opcodes.ILOAD, 4);
      m.visitInsn(Opcodes.IRETURN);
      m.visitLabel(end);
      m.visitLabel(handler);
      m.visitVarInsn(Opcodes.ASTORE, 5);
      m.visitVarInsn(Opcodes.ALOAD, 0);
      m.visitVarInsn(Opcodes.ILOAD, 4);
      m.visitFieldInsn(Opcodes.PUTFIELD, kind.className, "count", "I");
      m.visitVarInsn(Opcodes.ALOAD, 5);
      m.visitInsn(Opcodes.ATHROW);
    }
  };

  /** String line = null; try { line = "line"; return line; } catch (Throwable t) { count = line.length(); throw t; } */
  private static Method readLineRangeOverReturn() {
    return new Method("readLine", "()Ljava/lang/String;", Opcodes.ACC_PUBLIC, new Body() {
      public void emit(MethodVisitor m, Kind kind) {
        Label start = new Label(), end = new Label(), handler = new Label(), unset = new Label();
        m.visitTryCatchBlock(start, end, handler, null);
        m.visitInsn(Opcodes.ACONST_NULL);
        m.visitVarInsn(Opcodes.ASTORE, 1);
        m.visitLabel(start);
        m.visitLdcInsn("line");
        m.visitVarInsn(Opcodes.ASTORE, 1);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitInsn(Opcodes.ARETURN);
        m.visitLabel(end);
        m.visitLabel(handler);
        m.visitVarInsn(Opcodes.ASTORE, 2);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitJumpInsn(Opcodes.IFNULL, unset);
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        m.visitFieldInsn(Opcodes.PUTFIELD, kind.className, "count", "I");
        m.visitLabel(unset);
        m.visitVarInsn(Opcodes.ALOAD, 2);
        m.visitInsn(Opcodes.ATHROW);
      }
    });
  }

  /** read(b) { return read(b, 0, b.length); } */
  private static Method readArray(final Kind kind) {
    return new Method("read", "(" + kind.array + ")I", Opcodes.ACC_PUBLIC, new Body() {
      public void emit(MethodVisitor m, Kind k) {
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitInsn(Opcodes.ICONST_0);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitInsn(Opcodes.ARRAYLENGTH);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, k.className, "read", k.read(), false);
        m.visitInsn(Opcodes.IRETURN);
      }
    });
  }

  /** read() { one = new T[1]; n = read(one, 0, 1); return n < 0 ? -1 : one[0] (& 0xff for bytes); } */
  private static Method readOne(final Kind kind) {
    return new Method("read", "()I", Opcodes.ACC_PUBLIC, new Body() {
      public void emit(MethodVisitor m, Kind k) {
        Label got = new Label();
        m.visitInsn(Opcodes.ICONST_1);
        m.visitIntInsn(Opcodes.NEWARRAY, k.newArrayType);
        m.visitVarInsn(Opcodes.ASTORE, 1);
        m.visitVarInsn(Opcodes.ALOAD, 0);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitInsn(Opcodes.ICONST_0);
        m.visitInsn(Opcodes.ICONST_1);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, k.className, "read", k.read(), false);
        m.visitVarInsn(Opcodes.ISTORE, 2);
        m.visitVarInsn(Opcodes.ILOAD, 2);
        m.visitJumpInsn(Opcodes.IFGE, got);
        m.visitInsn(Opcodes.ICONST_M1);
        m.visitInsn(Opcodes.IRETURN);
        m.visitLabel(got);
        m.visitVarInsn(Opcodes.ALOAD, 1);
        m.visitInsn(Opcodes.ICONST_0);
        if (k.newArrayType == Opcodes.T_BYTE) {
          m.visitInsn(Opcodes.BALOAD);
          m.visitIntInsn(Opcodes.SIPUSH, 0xff);
          m.visitInsn(Opcodes.IAND);
        } else {
          m.visitInsn(Opcodes.CALOAD);
        }
        m.visitInsn(Opcodes.IRETURN);
      }
    });
  }

  /** switch (len) { case 0: return 0; case 1: b[off] = 1; return 1; case 2: return -1; default: return fill(b, off, len); } */
  private static final Body TABLESWITCH = new Body() {
    public void emit(MethodVisitor m, Kind kind) {
      Label zero = new Label(), one = new Label(), two = new Label(), other = new Label();
      m.visitVarInsn(Opcodes.ILOAD, 3);
      m.visitTableSwitchInsn(0, 2, other, zero, one, two);
      m.visitLabel(zero);
      m.visitInsn(Opcodes.ICONST_0);
      m.visitInsn(Opcodes.IRETURN);
      m.visitLabel(one);
      m.visitVarInsn(Opcodes.ALOAD, 1);
      m.visitVarInsn(Opcodes.ILOAD, 2);
      m.visitInsn(Opcodes.ICONST_1);
      m.visitInsn(kind.arrayStore);
      m.visitInsn(Opcodes.ICONST_1);
      m.visitInsn(Opcodes.IRETURN);
      m.visitLabel(two);
      m.visitInsn(Opcodes.ICONST_M1);
      m.visitInsn(Opcodes.IRETURN);
      m.visitLabel(other);
      callFill(m, kind, 3);
      m.visitInsn(Opcodes.IRETURN);
    }
  };

  /** n = fill(b, off, len); b's slot = "replaced"; off and len's slots = 1L; return n < 0 ? -1 : n; */
  private static final Body RETYPED_PARAMETERS = new Body() {
    public void emit(MethodVisitor m, Kind kind) {
      Label positive = new Label();
      callFill(m, kind, 3);
      m.visitVarInsn(Opcodes.ISTORE, 4);
      m.visitLdcInsn("replaced");
      m.visitVarInsn(Opcodes.ASTORE, 1);
      m.visitInsn(Opcodes.LCONST_1);
      m.visitVarInsn(Opcodes.LSTORE, 2);
      m.visitVarInsn(Opcodes.ILOAD, 4);
      m.visitJumpInsn(Opcodes.IFGE, positive);
      m.visitInsn(Opcodes.ICONST_M1);
      m.visitInsn(Opcodes.IRETURN);
      m.visitLabel(positive);
      m.visitVarInsn(Opcodes.ILOAD, 4);
      m.visitInsn(Opcodes.IRETURN);
    }
  };

  /** int unused = 0 in local 65534, so that max_locals is 65535; return fill(b, off, len). */
  private static final Body MAX_LOCALS = new Body() {
    public void emit(MethodVisitor m, Kind kind) {
      m.visitInsn(Opcodes.ICONST_0);
      m.visitVarInsn(Opcodes.ISTORE, 65534);
      callFill(m, kind, 3);
      m.visitInsn(Opcodes.IRETURN);
    }
  };

  /** A class (or interface) with a static method m()I that is valid, or returns `this`'s type as an int. */
  static byte[] canary(String name, boolean iface, boolean invalid) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | (iface ? Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT : Opcodes.ACC_SUPER),
        name, null, "java/lang/Object", null);
    if (!iface) {
      MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
      init.visitCode();
      init.visitVarInsn(Opcodes.ALOAD, 0);
      init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
      init.visitInsn(Opcodes.RETURN);
      init.visitMaxs(0, 0);
      init.visitEnd();
    }
    // A static initialiser that throws: linking must not run it.
    MethodVisitor clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
    clinit.visitCode();
    clinit.visitTypeInsn(Opcodes.NEW, "java/lang/IllegalStateException");
    clinit.visitInsn(Opcodes.DUP);
    clinit.visitLdcInsn("the canary's static initialiser ran");
    clinit.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "(Ljava/lang/String;)V", false);
    clinit.visitInsn(Opcodes.ATHROW);
    clinit.visitMaxs(0, 0);
    clinit.visitEnd();
    MethodVisitor m = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m", "()I", null, null);
    m.visitCode();
    if (invalid) m.visitLdcInsn("not an int");
    else m.visitInsn(Opcodes.ICONST_0);
    m.visitInsn(Opcodes.IRETURN);
    m.visitMaxs(0, 0);
    m.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private BodyReadShapes() {}
}
