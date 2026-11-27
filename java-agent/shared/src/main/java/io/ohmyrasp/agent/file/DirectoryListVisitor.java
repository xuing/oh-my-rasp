package io.ohmyrasp.agent.file;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** Observes completed listings and successfully opened host streams, before handoff to application code. */
public final class DirectoryListVisitor {
  private static final String WALKER = "java/nio/file/FileTreeWalker";
  private static final String EVENT = "Ljava/nio/file/FileTreeWalker$Event;";
  private static final String STATE = "io/ohmyrasp/agent/file/HostDirectory";
  private static final String FILE_LIST = "(Ljava/io/File;)[Ljava/lang/String;";
  private static final String OPEN = "(Ljava/nio/file/Path;Ljava/nio/file/DirectoryStream$Filter;)Ljava/nio/file/DirectoryStream;";
  private static final String OPEN_RELATIVE = "(Ljava/nio/file/Path;[Ljava/nio/file/LinkOption;)Ljava/nio/file/SecureDirectoryStream;";

  private DirectoryListVisitor() {}

  public static boolean matches(String owner) {
    return WALKER.equals(owner) || "java/io/File".equals(owner) || "java/io/UnixFileSystem".equals(owner)
        || "java/io/WinNTFileSystem".equals(owner) || "sun/nio/fs/UnixFileSystemProvider".equals(owner)
        || "sun/nio/fs/WindowsFileSystemProvider".equals(owner) || "sun/nio/fs/UnixSecureDirectoryStream".equals(owner);
  }

  public static MethodVisitor wrap(final String owner, MethodVisitor visitor, int access, String name, String desc, final String hooks) {
    if (WALKER.equals(owner)) {
      if ("walk".equals(name) && ("(Ljava/nio/file/Path;)" + EVENT).equals(desc)) {
        return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, desc) {
          @Override protected void onMethodEnter() {
            loadThis(); loadArg(0);
            invokeStatic(Type.getObjectType(hooks), Method.getMethod("void captureDirectoryWalk(Object, java.nio.file.Path)"));
          }
        };
      }
      if ("visit".equals(name) && (("(Ljava/nio/file/Path;ZZ)" + EVENT).equals(desc)
          || ("(Ljava/nio/file/Path;Z)" + EVENT).equals(desc))) {
        return new ScopedMethodAdvice(Opcodes.ASM9, visitor, access, name, desc, true) {
          @Override protected void enterDispatch() {
            loadThis(); loadArg(0);
            invokeStatic(Type.getObjectType(hooks), Method.getMethod("Object beginDirectoryVisit(Object, java.nio.file.Path)"));
          }
          @Override protected void exitDispatch() {
            loadToken();
            invokeStatic(Type.getObjectType(STATE), Method.getMethod("void visited(Object)"));
          }
        };
      }
      if ("close".equals(name) && "()V".equals(desc)) {
        return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, desc) {
          @Override protected void onMethodEnter() {
            loadThis();
            invokeStatic(Type.getObjectType(STATE), Method.getMethod("void closed(Object)"));
          }
        };
      }
    }
    if ("java/io/File".equals(owner) && ("normalizedList".equals(name) || "list".equals(name))) {
      return new MethodVisitor(Opcodes.ASM9, visitor) {
        @Override public void visitMethodInsn(int op, String callee, String method, String signature, boolean itf) {
          if (!"java/io/FileSystem".equals(callee) || !"list".equals(method) || !FILE_LIST.equals(signature)
              || op != Opcodes.INVOKEVIRTUAL) {
            super.visitMethodInsn(op, callee, method, signature, itf);
            return;
          }
          // Preserve the File operand across the backend call, then keep its array on the return stack.
          mv.visitInsn(Opcodes.DUP_X1);
          super.visitMethodInsn(op, callee, method, signature, itf);
          mv.visitInsn(Opcodes.DUP_X1);
          mv.visitInsn(Opcodes.DUP_X1);
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, STATE, "selectedFile", "(Ljava/io/File;[Ljava/lang/String;)Ljava/io/File;", false);
          mv.visitFieldInsn(Opcodes.GETFIELD, "java/io/File", "path", "Ljava/lang/String;");
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "afterFileList", "([Ljava/lang/String;Ljava/lang/String;)V", false);
        }
      };
    }
    if (owner.startsWith("java/io/") && "list".equals(name) && FILE_LIST.equals(desc)) {
      return new MethodVisitor(Opcodes.ASM9, visitor) {
        @Override public void visitMethodInsn(int op, String callee, String method, String signature, boolean itf) {
          if (!owner.equals(callee) || !"list0".equals(method) || !FILE_LIST.equals(signature)
              || (op != Opcodes.INVOKEVIRTUAL && op != Opcodes.INVOKESPECIAL)) {
            super.visitMethodInsn(op, callee, method, signature, itf);
            return;
          }
          mv.visitInsn(Opcodes.DUP_X1);
          super.visitMethodInsn(op, callee, method, signature, itf);
          mv.visitInsn(Opcodes.DUP_X1);
          mv.visitVarInsn(Opcodes.ALOAD, 1);
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, STATE, "listed", "(Ljava/io/File;[Ljava/lang/String;Ljava/io/File;)V", false);
        }
      };
    }
    final boolean relative = OPEN_RELATIVE.equals(desc);
    if (!"newDirectoryStream".equals(name) || (!OPEN.equals(desc) && !relative)) return visitor;
    return new MethodVisitor(Opcodes.ASM9, visitor) {
      @Override public void visitInsn(int op) {
        if (op == Opcodes.ARETURN) {
          mv.visitInsn(Opcodes.DUP);
          mv.visitVarInsn(Opcodes.ALOAD, 1);
          mv.visitInsn(relative ? Opcodes.ICONST_1 : Opcodes.ICONST_0);
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "afterDirectoryOpen", "(Ljava/nio/file/DirectoryStream;Ljava/nio/file/Path;Z)V", false);
        }
        super.visitInsn(op);
      }
    };
  }
}
