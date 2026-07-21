package io.ohmyrasp.agent.java11;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Hooks Fastjson 1.x at the last instruction before it dereferences a class resource. */
public final class Java11FastjsonTransformer implements ClassFileTransformer {
  private static final String TARGET = "com/alibaba/fastjson/parser/ParserConfig";
  private static final String HOOKS = "io/ohmyrasp/agent/java11/Java11RaspHooks";

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !TARGET.equals(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new FastjsonClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println(
            "[OHMYRASP-JAVA11] Fastjson transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static final class FastjsonClassVisitor extends ClassVisitor {
    FastjsonClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor =
          super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || !"checkAutoType".equals(name)) {
        return methodVisitor;
      }
      return new MethodVisitor(Opcodes.ASM9, methodVisitor) {
        @Override
        public void visitMethodInsn(
            int opcode, String owner, String invokedName, String invokedDescriptor, boolean itf) {
          if (isClassResourceLookup(owner, invokedName, invokedDescriptor)) {
            super.visitInsn(Opcodes.DUP);
            super.visitMethodInsn(
                Opcodes.INVOKESTATIC,
                HOOKS,
                "beforeFastjsonClassResource",
                "(Ljava/lang/String;)V",
                false);
          }
          super.visitMethodInsn(opcode, owner, invokedName, invokedDescriptor, itf);
        }
      };
    }
  }

  private static boolean isClassResourceLookup(
      String owner, String name, String descriptor) {
    return "java/lang/ClassLoader".equals(owner)
        && "getResourceAsStream".equals(name)
        && "(Ljava/lang/String;)Ljava/io/InputStream;".equals(descriptor);
  }
}
