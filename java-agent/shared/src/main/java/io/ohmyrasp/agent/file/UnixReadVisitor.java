package io.ohmyrasp.agent.file;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Uses the access flags the JDK has validated, before the native open/openat call. */
public final class UnixReadVisitor {
  public static final String FACTORY = "sun/nio/fs/UnixChannelFactory";
  private static final String FLAGS = FACTORY + "$Flags";
  private static final String PATH = "(ILsun/nio/fs/UnixPath;";
  private static final String RESULT = "L" + FLAGS + ";I)Ljava/io/FileDescriptor;";

  private UnixReadVisitor() {}

  public static MethodVisitor method(MethodVisitor visitor, String name, String descriptor, final String hooks) {
    if (!"open".equals(name)) return visitor;
    final int flags;
    if ((PATH + RESULT).equals(descriptor)) flags = 2;
    else if ((PATH + "Ljava/lang/String;" + RESULT).equals(descriptor)) flags = 3;
    else return visitor;
    return new MethodVisitor(Opcodes.ASM9, visitor) {
      @Override public void visitCode() {
        super.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        flag("write");
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeJmxChannelWrite", "(Ljava/nio/file/Path;IZ)V", false);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitVarInsn(Opcodes.ALOAD, flags);
        mv.visitFieldInsn(Opcodes.GETFIELD, FLAGS, "read", "Z");
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        flag("noFollowLinks");
        flag("deleteOnClose");
        mv.visitInsn(Opcodes.IOR);
        flag("write");
        flag("createNew");
        mv.visitInsn(Opcodes.IAND);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeUnixFileOpen", "(Ljava/nio/file/Path;ZIZZ)V", false);
      }

      private void flag(String name) {
        mv.visitVarInsn(Opcodes.ALOAD, flags);
        mv.visitFieldInsn(Opcodes.GETFIELD, FLAGS, name, "Z");
      }
    };
  }
}
