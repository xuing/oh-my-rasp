package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

final class ArchiveHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/util/zip/ZipInputStream")
        || className.equals("java/util/zip/ZipFile");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (className.equals("java/util/zip/ZipInputStream")
        && methodName.equals("getNextEntry")
        && descriptor.equals("()Ljava/util/zip/ZipEntry;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override protected void onMethodEnter() {
          invokeHook("clearArchiveEntry", "()V");
        }

        @Override
        protected void onMethodExit(int opcode) {
          if (opcode == Opcodes.ARETURN) {
            dup();
            loadThis();
            invokeHook("afterZipEntryRead", "(Ljava/lang/Object;Ljava/lang/Object;)V");
          }
        }
      };
    }
    if (matchesClass(className) && (methodName.equals("close") || methodName.equals("closeEntry")) && descriptor.equals("()V")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeHook("closeArchiveReader", "(Ljava/lang/Object;)V");
        }
      };
    }
    if (className.equals("java/util/zip/ZipFile")
        && methodName.equals("getInputStream")
        && descriptor.equals("(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        private int selectedName;

        @Override protected void onMethodEnter() {
          invokeHook("clearArchiveEntry", "()V");
          selectedName = newLocal(Type.getType(String.class));
          visitInsn(ACONST_NULL);
          checkCast(Type.getType(String.class));
          storeLocal(selectedName);
        }

        @Override public void visitFieldInsn(int op, String owner, String name, String desc) {
          super.visitFieldInsn(op, owner, name, desc);
          if (op == GETFIELD && owner.equals("java/util/zip/ZipEntry") && name.equals("name")
              && desc.equals("Ljava/lang/String;")) {
            dup();
            storeLocal(selectedName);
          }
        }

        @Override protected void onMethodExit(int op) {
          if (op == ARETURN) {
            dup();
            loadLocal(selectedName);
            loadThis();
            invokeHook("afterZipLookup", "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;)V");
          }
        }
      };
    }
    return methodVisitor;
  }
}
