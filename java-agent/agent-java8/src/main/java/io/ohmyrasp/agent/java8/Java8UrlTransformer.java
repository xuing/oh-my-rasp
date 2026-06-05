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

public final class Java8UrlTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method BEFORE_URL_OPEN =
      Method.getMethod("void beforeUrlOpen(java.lang.Object)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !"java/net/URL".equals(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new UrlClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] URL transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class UrlClassVisitor extends ClassVisitor {
    UrlClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || !isOpenMethod(name, descriptor)) {
        return methodVisitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeStatic(HOOKS, BEFORE_URL_OPEN);
        }
      };
    }

    private static boolean isOpenMethod(String name, String descriptor) {
      if ("openConnection".equals(name)) {
        return "()Ljava/net/URLConnection;".equals(descriptor)
            || "(Ljava/net/Proxy;)Ljava/net/URLConnection;".equals(descriptor);
      }
      return "openStream".equals(name) && "()Ljava/io/InputStream;".equals(descriptor);
    }
  }
}
