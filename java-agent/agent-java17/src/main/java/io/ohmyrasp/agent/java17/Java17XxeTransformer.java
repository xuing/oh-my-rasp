package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.xml.XmlEntityOpenVisitor;
import io.ohmyrasp.agent.xml.AttachmentFileVisitor;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

public final class Java17XxeTransformer implements ClassFileTransformer {
  private static final Type XML_INPUT_SOURCE =
      Type.getObjectType("com/sun/org/apache/xerces/internal/xni/parser/XMLInputSource");
  private static final String HOOKS = Type.getInternalName(Java17RaspHooks.class);

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null
        || classfileBuffer == null
        || (!XmlEntityOpenVisitor.matches(className) && !AttachmentFileVisitor.matches(className))) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new XxeClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA17] XXE transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class XxeClassVisitor extends ClassVisitor {
    private final String className;

    XxeClassVisitor(String className, ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (AttachmentFileVisitor.matches(className)) {
        return AttachmentFileVisitor.wrap(className, methodVisitor, access, name, descriptor, Type.getObjectType(HOOKS));
      }
      return XmlEntityOpenVisitor.wrap(className, methodVisitor, access, name, descriptor, HOOKS);
    }
  }
}
