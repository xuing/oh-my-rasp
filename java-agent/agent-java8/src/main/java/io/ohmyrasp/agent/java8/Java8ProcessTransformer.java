package io.ohmyrasp.agent.java8;

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

public final class Java8ProcessTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method BEFORE_PROCESS_BUILDER_START =
      Method.getMethod("void beforeProcessBuilderStart(java.lang.ProcessBuilder)");
  private static final Method BEFORE_RUNTIME_EXEC_STRING =
      Method.getMethod("void beforeRuntimeExecString(java.lang.String)");
  private static final Method BEFORE_RUNTIME_EXEC_ARRAY =
      Method.getMethod("void beforeRuntimeExecArray(java.lang.String[])");

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
      reader.accept(new ProcessClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] process transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "java/lang/ProcessBuilder".equals(className) || "java/lang/Runtime".equals(className);
  }

  private static final class ProcessClassVisitor extends ClassVisitor {
    private final String className;

    ProcessClassVisitor(String className, ClassVisitor delegate) {
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
      if ("java/lang/ProcessBuilder".equals(className)
          && "start".equals(name)
          && "()Ljava/lang/Process;".equals(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadThis();
            invokeStatic(HOOKS, BEFORE_PROCESS_BUILDER_START);
          }
        };
      }
      if ("java/lang/Runtime".equals(className)
          && "exec".equals(name)
          && descriptor.startsWith("(Ljava/lang/String;")) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_RUNTIME_EXEC_STRING);
          }
        };
      }
      if ("java/lang/Runtime".equals(className)
          && "exec".equals(name)
          && descriptor.startsWith("([Ljava/lang/String;")) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_RUNTIME_EXEC_ARRAY);
          }
        };
      }
      return methodVisitor;
    }
  }
}
