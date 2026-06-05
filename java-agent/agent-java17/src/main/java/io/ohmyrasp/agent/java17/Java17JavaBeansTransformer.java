package io.ohmyrasp.agent.java17;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

public final class Java17JavaBeansTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java17RaspHooks.class);
  private static final Method BEFORE_JAVA_BEANS_STATEMENT =
      Method.getMethod("void beforeJavaBeansStatement(java.lang.Object)");
  private static final Method RETHROW_IF_JAVA17_RASP_BLOCK =
      Method.getMethod("void rethrowIfJava17RaspBlock(java.lang.Object)");

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
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new JavaBeansClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println(
            "[OHMYRASP-JAVA17] JavaBeans transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "java/beans/Expression".equals(className)
        || "java/beans/Statement".equals(className)
        || "com/sun/beans/decoder/DocumentHandler".equals(className);
  }

  private static final class JavaBeansClassVisitor extends ClassVisitor {
    private final String className;

    JavaBeansClassVisitor(String className, ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null) {
        return null;
      }
      if ("java/beans/Expression".equals(className)
          && "getValue".equals(name)
          && "()Ljava/lang/Object;".equals(descriptor)) {
        return statementAdvice(methodVisitor, access, name, descriptor);
      }
      if ("java/beans/Statement".equals(className)
          && "execute".equals(name)
          && "()V".equals(descriptor)) {
        return statementAdvice(methodVisitor, access, name, descriptor);
      }
      if ("com/sun/beans/decoder/DocumentHandler".equals(className)
          && "handleException".equals(name)
          && "(Ljava/lang/Exception;)V".equals(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, RETHROW_IF_JAVA17_RASP_BLOCK);
          }
        };
      }
      return methodVisitor;
    }

    private static MethodVisitor statementAdvice(
        MethodVisitor methodVisitor, int access, String name, String descriptor) {
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeStatic(HOOKS, BEFORE_JAVA_BEANS_STATEMENT);
        }
      };
    }
  }
}
