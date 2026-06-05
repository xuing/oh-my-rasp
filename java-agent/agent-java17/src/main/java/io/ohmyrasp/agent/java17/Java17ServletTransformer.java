package io.ohmyrasp.agent.java17;

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

public final class Java17ServletTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java17RaspHooks.class);
  private static final Method BEFORE_HTTP_REQUEST =
      Method.getMethod("void beforeHttpRequest(java.lang.Object)");
  private static final Method AFTER_HTTP_REQUEST = Method.getMethod("void afterHttpRequest()");
  private static final String HOOKS_CLASS_NAME = "io.ohmyrasp.agent.java17.Java17RaspHooks";
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
  private static final String JAKARTA_HTTP_SERVICE =
      "(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V";
  private static final String JAVAX_HTTP_SERVICE =
      "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V";
  private static final String JAKARTA_GENERIC_SERVICE =
      "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V";
  private static final String JAVAX_GENERIC_SERVICE =
      "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V";
  private static final String JAKARTA_FILTER =
      "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;Ljakarta/servlet/FilterChain;)V";
  private static final String JAVAX_FILTER =
      "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;Ljavax/servlet/FilterChain;)V";

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
      boolean reflectiveHook = requiresReflectiveHook(loader);
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = newClassWriter(reader, reflectiveHook);
      reader.accept(new ServletClassVisitor(writer, reflectiveHook), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] servlet transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "javax/servlet/http/HttpServlet".equals(className)
        || "jakarta/servlet/http/HttpServlet".equals(className)
        || "org/apache/shiro/web/servlet/AbstractShiroFilter".equals(className);
  }

  private static boolean requiresReflectiveHook(ClassLoader loader) {
    if (loader == null) {
      return false;
    }
    String name = loader.getClass().getName();
    return name.startsWith("org.apache.felix.framework.")
        || name.startsWith("org.eclipse.osgi.")
        || name.startsWith("org.knopflerfish.");
  }

  private static ClassWriter newClassWriter(ClassReader reader, boolean reflectiveHook) {
    int flags =
        reflectiveHook
            ? ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES
            : ClassWriter.COMPUTE_MAXS;
    return new ClassWriter(reader, flags) {
      @Override
      protected String getCommonSuperClass(String type1, String type2) {
        return "java/lang/Object";
      }
    };
  }

  private static final class ServletClassVisitor extends ClassVisitor {
    private final boolean reflectiveHook;

    ServletClassVisitor(ClassVisitor delegate, boolean reflectiveHook) {
      super(Opcodes.ASM9, delegate);
      this.reflectiveHook = reflectiveHook;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null) {
        return null;
      }
      if ("service".equals(name) && isServiceDescriptor(descriptor)) {
        return new ReflectiveAdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            if (reflectiveHook) {
              invokeReflectiveHook("beforeHttpRequest", true);
            } else {
              loadArg(0);
              invokeStatic(HOOKS, BEFORE_HTTP_REQUEST);
            }
          }

          @Override
          protected void onMethodExit(int opcode) {
            if (reflectiveHook) {
              invokeReflectiveHook("afterHttpRequest", false);
            } else {
              invokeStatic(HOOKS, AFTER_HTTP_REQUEST);
            }
          }
        };
      }
      if ("doFilterInternal".equals(name) && isFilterDescriptor(descriptor)) {
        return new ReflectiveAdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            if (reflectiveHook) {
              invokeReflectiveHook("beforeHttpRequest", true);
            } else {
              loadArg(0);
              invokeStatic(HOOKS, BEFORE_HTTP_REQUEST);
            }
          }

          @Override
          protected void onMethodExit(int opcode) {
            if (reflectiveHook) {
              invokeReflectiveHook("afterHttpRequest", false);
            } else {
              invokeStatic(HOOKS, AFTER_HTTP_REQUEST);
            }
          }
        };
      }
      return methodVisitor;
    }

    private static boolean isServiceDescriptor(String descriptor) {
      return JAKARTA_HTTP_SERVICE.equals(descriptor)
          || JAVAX_HTTP_SERVICE.equals(descriptor)
          || JAKARTA_GENERIC_SERVICE.equals(descriptor)
          || JAVAX_GENERIC_SERVICE.equals(descriptor);
    }

    private static boolean isFilterDescriptor(String descriptor) {
      return JAKARTA_FILTER.equals(descriptor) || JAVAX_FILTER.equals(descriptor);
    }
  }

  private abstract static class ReflectiveAdviceAdapter extends AdviceAdapter {
    ReflectiveAdviceAdapter(
        int api, MethodVisitor methodVisitor, int access, String name, String descriptor) {
      super(api, methodVisitor, access, name, descriptor);
    }

    protected final void invokeReflectiveHook(String hookName, boolean withRequest) {
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
      push(hookName);
      push(withRequest ? 1 : 0);
      newArray(CLASS_TYPE);
      if (withRequest) {
        dup();
        push(0);
        push(OBJECT_TYPE);
        arrayStore(CLASS_TYPE);
      }
      invokeVirtual(CLASS_TYPE, GET_METHOD);
      visitInsn(Opcodes.ACONST_NULL);
      push(withRequest ? 1 : 0);
      newArray(OBJECT_TYPE);
      if (withRequest) {
        dup();
        push(0);
        loadArg(0);
        arrayStore(OBJECT_TYPE);
      }
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
