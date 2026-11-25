package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.net.HttpTransportVisitor;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public final class Java17UrlTransformer implements ClassFileTransformer {
  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !HttpTransportVisitor.matches(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new UrlClassVisitor(writer, className), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] URL transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class UrlClassVisitor extends ClassVisitor {
    private final String owner;
    UrlClassVisitor(ClassVisitor delegate, String owner) {
      super(Opcodes.ASM9, delegate);
      this.owner = owner;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor next = super.visitMethod(access, name, descriptor, signature, exceptions);
      return next == null ? null : HttpTransportVisitor.wrap(owner, next, access, name, descriptor,
          "io/ohmyrasp/agent/java17/Java17RaspHooks");
    }
  }
}
