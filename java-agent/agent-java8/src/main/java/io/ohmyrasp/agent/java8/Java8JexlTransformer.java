package io.ohmyrasp.agent.java8;

import java.lang.instrument.ClassFileTransformer;
import java.lang.reflect.InvocationTargetException;
import java.security.ProtectionDomain;
import org.objectweb.asm.Label;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

public final class Java8JexlTransformer implements ClassFileTransformer {
  private static final String HOOKS_CLASS_NAME = "io.ohmyrasp.agent.java8.Java8RaspHooks";
  private static final Type CLASS_LOADER = Type.getType(ClassLoader.class);
  private static final Type CLASS_TYPE = Type.getType(Class.class);
  private static final Type REFLECT_METHOD = Type.getType(java.lang.reflect.Method.class);
  private static final Type OBJECT_TYPE = Type.getType(Object.class);
  private static final Type INVOCATION_TARGET_EXCEPTION = Type.getType(InvocationTargetException.class);
  private static final Type THROWABLE = Type.getType(Throwable.class);
  private static final Type RUNTIME_EXCEPTION = Type.getType(RuntimeException.class);
  private static final Type ERROR = Type.getType(Error.class);
  private static final Method GET_SYSTEM_CLASS_LOADER =
      new Method("getSystemClassLoader", "()Ljava/lang/ClassLoader;");
  private static final Method LOAD_CLASS =
      new Method("loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
  private static final Method GET_METHOD =
      new Method("getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
  private static final Method INVOKE =
      new Method("invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
  private static final Method GET_CAUSE = new Method("getCause", "()Ljava/lang/Throwable;");
  private static final Method RUNTIME_EXCEPTION_INIT =
      new Method("<init>", "(Ljava/lang/Throwable;)V");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !isTarget(className)) {
      return null;
    }
    if (classfileMajorVersion(classfileBuffer) < Opcodes.V1_5) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new JexlClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] JEXL transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "org/apache/commons/jexl3/internal/Script".equals(className)
        || "org/apache/commons/jexl2/ExpressionImpl".equals(className)
        || "org/apache/commons/jexl/ExpressionImpl".equals(className)
        || "org/apache/commons/jexl/Script".equals(className);
  }

  private static int classfileMajorVersion(byte[] classfileBuffer) {
    if (classfileBuffer.length < 8) {
      return 0;
    }
    return ((classfileBuffer[6] & 0xff) << 8) | (classfileBuffer[7] & 0xff);
  }

  private static final class JexlClassVisitor extends ClassVisitor {
    private String owner;

    JexlClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName,
        String[] interfaces) {
      owner = name;
      super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null
          || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_STATIC)) != 0
          || !isEvaluationMethod(name)) {
        return methodVisitor;
      }
      return new ReflectiveAdviceAdapter(Opcodes.ASM9, methodVisitor, owner, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          invokeReflectiveHook();
        }
      };
    }

    private static boolean isEvaluationMethod(String name) {
      return "evaluate".equals(name) || "execute".equals(name);
    }
  }

  /**
   * Calls the hook reflectively at the start of the method. The injected code uses no local of its own and gives
   * every branch target a full stack map frame with the method's entry locals, so the rewritten method verifies
   * on class files that need stack map frames (version 50 and later), without recomputing the method's own.
   */
  private abstract static class ReflectiveAdviceAdapter extends AdviceAdapter {
    private final Object[] entryLocals;

    ReflectiveAdviceAdapter(
        int api, MethodVisitor methodVisitor, String owner, int access, String name, String descriptor) {
      super(api, methodVisitor, access, name, descriptor);
      Type[] arguments = Type.getArgumentTypes(descriptor);
      entryLocals = new Object[arguments.length + 1];
      entryLocals[0] = owner;
      for (int i = 0; i < arguments.length; i++) {
        entryLocals[i + 1] = frameType(arguments[i]);
      }
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

    /** A full frame: the entry locals, and {@code stack} (an internal name) or nothing on the stack. */
    private void frame(String stack) {
      Object[] onStack = stack == null ? new Object[0] : new Object[] {stack};
      visitFrame(Opcodes.F_NEW, entryLocals.length, entryLocals.clone(), onStack.length, onStack);
    }

    protected final void invokeReflectiveHook() {
      Label start = new Label();
      Label end = new Label();
      Label invocationTargetHandler = new Label();
      Label throwableHandler = new Label();
      Label done = new Label();
      visitTryCatchBlock(
          start,
          end,
          invocationTargetHandler,
          "java/lang/reflect/InvocationTargetException");
      visitTryCatchBlock(start, end, throwableHandler, "java/lang/Throwable");

      visitLabel(start);
      invokeStatic(CLASS_LOADER, GET_SYSTEM_CLASS_LOADER);
      push(HOOKS_CLASS_NAME);
      invokeVirtual(CLASS_LOADER, LOAD_CLASS);
      push("beforeJexlExpression");
      push(1);
      newArray(CLASS_TYPE);
      dup();
      push(0);
      push(OBJECT_TYPE);
      arrayStore(CLASS_TYPE);
      invokeVirtual(CLASS_TYPE, GET_METHOD);
      visitInsn(Opcodes.ACONST_NULL);
      push(1);
      newArray(OBJECT_TYPE);
      dup();
      push(0);
      loadThis();
      arrayStore(OBJECT_TYPE);
      invokeVirtual(REFLECT_METHOD, INVOKE);
      pop();
      visitLabel(end);
      goTo(done);

      visitLabel(invocationTargetHandler);
      frame("java/lang/reflect/InvocationTargetException");
      invokeVirtual(INVOCATION_TARGET_EXCEPTION, GET_CAUSE);

      Label notRuntimeException = new Label();
      dup();
      instanceOf(RUNTIME_EXCEPTION);
      ifZCmp(Opcodes.IFEQ, notRuntimeException);
      checkCast(RUNTIME_EXCEPTION);
      visitInsn(Opcodes.ATHROW);

      visitLabel(notRuntimeException);
      frame("java/lang/Throwable");
      Label notError = new Label();
      dup();
      instanceOf(ERROR);
      ifZCmp(Opcodes.IFEQ, notError);
      checkCast(ERROR);
      visitInsn(Opcodes.ATHROW);

      visitLabel(notError);
      frame("java/lang/Throwable");
      newInstance(RUNTIME_EXCEPTION);
      visitInsn(Opcodes.DUP_X1);
      swap();
      invokeConstructor(RUNTIME_EXCEPTION, RUNTIME_EXCEPTION_INIT);
      visitInsn(Opcodes.ATHROW);

      visitLabel(throwableHandler);
      frame("java/lang/Throwable");
      pop();
      visitLabel(done);
      frame(null);
      visitInsn(Opcodes.NOP); // the method's own first frame, if it has one at its first instruction, is not here
    }
  }
}
