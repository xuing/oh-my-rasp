package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.process.ProcessLaunchVisitor;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

public final class Java17ProcessTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java17RaspHooks.class);
  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !ProcessLaunchVisitor.matches(className)) {
      return null;
    }
    try {
      var reader = new ClassReader(classfileBuffer);
      var writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new ProcessClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] process transform failed for " + className + ": " + throwable);
      }
      return null;
    }
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
      return ProcessLaunchVisitor.wrap(className, methodVisitor, access, name, descriptor, HOOKS);
    }
  }
}
