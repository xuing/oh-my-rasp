package io.ohmyrasp.agent.file;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Both FileInputStream constructors and every valid RandomAccessFile mode reach a single path open. */
public final class StreamReadVisitor {
  private static final String RANDOM = "java/io/RandomAccessFile";
  private StreamReadVisitor() {}

  public static boolean matches(String owner) {
    return RANDOM.equals(owner) || "java/io/FileInputStream".equals(owner);
  }

  public static MethodVisitor outputOpen(MethodVisitor visitor, String name, String descriptor, final String hooks) {
    if (!"open".equals(name) || !"(Ljava/lang/String;Z)V".equals(descriptor)) return visitor;
    return new MethodVisitor(Opcodes.ASM9, visitor) {
      @Override public void visitCode() {
        super.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeJmxStreamWrite", "(Ljava/lang/String;I)V", false);
      }
    };
  }

  public static MethodVisitor wrap(String owner, MethodVisitor visitor, String name, String descriptor,
      final String hooks, final boolean inspectWrites) {
    final boolean random = RANDOM.equals(owner);
    if (!"open".equals(name) || !(random ? "(Ljava/lang/String;I)V" : "(Ljava/lang/String;)V").equals(descriptor)) return visitor;
    return new MethodVisitor(Opcodes.ASM9, visitor) {
      @Override public void visitCode() {
        super.visitCode();
        if (random) {
          mv.visitVarInsn(Opcodes.ALOAD, 1);
          mv.visitVarInsn(Opcodes.ILOAD, 2);
          mv.visitFieldInsn(Opcodes.GETSTATIC, RANDOM, "O_RDWR", "I");
          mv.visitInsn(Opcodes.IAND);
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeJmxStreamWrite", "(Ljava/lang/String;I)V", false);
        }
        if (random && inspectWrites) {
          mv.visitVarInsn(Opcodes.ALOAD, 1);
          mv.visitVarInsn(Opcodes.ILOAD, 2);
          mv.visitFieldInsn(Opcodes.GETSTATIC, RANDOM, "O_RDWR", "I");
          mv.visitInsn(Opcodes.IAND);
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeRandomFileWrite", "(Ljava/lang/String;I)V", false);
        }
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitLdcInsn(random ? "RandomAccessFile.open" : "FileInputStream.open");
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeStreamFileRead", "(Ljava/lang/String;Ljava/lang/String;)V", false);
      }
    };
  }
}
