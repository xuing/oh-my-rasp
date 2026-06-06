package io.ohmyrasp.agent.java11;

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

public final class Java11ElTransformer implements ClassFileTransformer {
  private static final String HOOKS_CLASS_NAME = "io.ohmyrasp.agent.java11.Java11RaspHooks";
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
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = newClassWriter(reader);
      reader.accept(new ElClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA11] EL transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static ClassWriter newClassWriter(ClassReader reader) {
    return new ClassWriter(reader, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES) {
      @Override
      protected String getCommonSuperClass(String type1, String type2) {
        return "java/lang/Object";
      }
    };
  }

  private static boolean isTarget(String className) {
    return "com/sun/el/ValueExpressionImpl".equals(className)
        || "com/sun/el/MethodExpressionImpl".equals(className)
        || "org/apache/el/ValueExpressionImpl".equals(className)
        || "org/apache/el/MethodExpressionImpl".equals(className)
        || "de/odysseus/el/TreeValueExpression".equals(className)
        || "de/odysseus/el/TreeMethodExpression".equals(className)
        || "org/jboss/el/ValueExpressionImpl".equals(className)
        || "org/jboss/el/MethodExpressionImpl".equals(className);
  }

  private static final class ElClassVisitor extends ClassVisitor {
    ElClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || (access & Opcodes.ACC_ABSTRACT) != 0 || !isEvaluationMethod(name)) {
        return methodVisitor;
      }
      return new ReflectiveAdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          invokeReflectiveHook();
        }
      };
    }

    private static boolean isEvaluationMethod(String name) {
      return "getValue".equals(name)
          || "setValue".equals(name)
          || "getType".equals(name)
          || "getValueReference".equals(name)
          || "isReadOnly".equals(name)
          || "invoke".equals(name);
    }
  }

  private abstract static class ReflectiveAdviceAdapter extends AdviceAdapter {
    ReflectiveAdviceAdapter(
        int api, MethodVisitor methodVisitor, int access, String name, String descriptor) {
      super(api, methodVisitor, access, name, descriptor);
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
      push("beforeElExpression");
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
      int exception = newLocal(INVOCATION_TARGET_EXCEPTION);
      storeLocal(exception);
      loadLocal(exception);
      invokeVirtual(INVOCATION_TARGET_EXCEPTION, GET_CAUSE);
      int cause = newLocal(THROWABLE);
      storeLocal(cause);

      Label notRuntimeException = new Label();
      loadLocal(cause);
      instanceOf(RUNTIME_EXCEPTION);
      ifZCmp(Opcodes.IFEQ, notRuntimeException);
      loadLocal(cause);
      checkCast(RUNTIME_EXCEPTION);
      visitInsn(Opcodes.ATHROW);

      visitLabel(notRuntimeException);
      Label notError = new Label();
      loadLocal(cause);
      instanceOf(ERROR);
      ifZCmp(Opcodes.IFEQ, notError);
      loadLocal(cause);
      checkCast(ERROR);
      visitInsn(Opcodes.ATHROW);

      visitLabel(notError);
      newInstance(RUNTIME_EXCEPTION);
      dup();
      loadLocal(cause);
      invokeConstructor(RUNTIME_EXCEPTION, RUNTIME_EXCEPTION_INIT);
      visitInsn(Opcodes.ATHROW);

      visitLabel(throwableHandler);
      pop();
      visitLabel(done);
    }
  }
}
