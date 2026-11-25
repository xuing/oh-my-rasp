package io.ohmyrasp.agent.java17;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import io.ohmyrasp.agent.naming.JndiLookupVisitor;

public final class Java17JndiTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java17RaspHooks.class);
  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null
        || classfileBuffer == null
        || !JndiLookupVisitor.target(className)) {
      return null;
    }
    try {
      var reader = new ClassReader(classfileBuffer);
      var writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new JndiClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] JNDI transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class JndiClassVisitor extends ClassVisitor {
    private final String owner;
    JndiClassVisitor(String owner, ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
      this.owner = owner;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      return JndiLookupVisitor.wrap(owner, methodVisitor, access, name, descriptor, HOOKS);
    }
  }
}
