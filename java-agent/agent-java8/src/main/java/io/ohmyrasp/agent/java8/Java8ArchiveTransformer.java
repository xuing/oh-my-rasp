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

public final class Java8ArchiveTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method AFTER_ARCHIVE_ENTRY_NAME =
      Method.getMethod("void afterArchiveEntryName(java.lang.String)");

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
      reader.accept(new ArchiveClassVisitor(writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] archive transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "java/util/zip/ZipEntry".equals(className)
        || "net/sf/sevenzipjbinding/simple/impl/SimpleInArchiveItemImpl".equals(className);
  }

  private static final class ArchiveClassVisitor extends ClassVisitor {
    ArchiveClassVisitor(ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || !isEntryNameMethod(name, descriptor)) {
        return methodVisitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodExit(int opcode) {
          if (opcode == ARETURN) {
            dup();
            invokeStatic(HOOKS, AFTER_ARCHIVE_ENTRY_NAME);
          }
        }
      };
    }

    private static boolean isEntryNameMethod(String name, String descriptor) {
      return ("getName".equals(name) || "getPath".equals(name))
          && "()Ljava/lang/String;".equals(descriptor);
    }
  }
}
