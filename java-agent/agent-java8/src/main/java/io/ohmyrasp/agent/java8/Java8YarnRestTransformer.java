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

public final class Java8YarnRestTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method BEFORE_YARN_APPLICATION_SUBMIT =
      Method.getMethod("void beforeYarnApplicationSubmit(java.lang.Object)");

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
      reader.accept(new YarnRestClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] YARN REST transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "org/apache/hadoop/yarn/server/resourcemanager/webapp/RMWebServices".equals(className);
  }

  private static final class YarnRestClassVisitor extends ClassVisitor {
    YarnRestClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null) {
        return null;
      }
      if ("submitApplication".equals(name)
          && descriptor.startsWith(
              "(Lorg/apache/hadoop/yarn/server/resourcemanager/webapp/dao/ApplicationSubmissionContextInfo;")) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_YARN_APPLICATION_SUBMIT);
          }
        };
      }
      return methodVisitor;
    }
  }
}
