package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

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
        @Override
        protected void onMethodExit(int opcode) {
          if (opcode == Opcodes.ARETURN) {
            dup();
            invokeHook("afterArchiveEntry", "(Ljava/lang/Object;)V");
          }
        }
      };
    }
    if (className.equals("java/util/zip/ZipInputStream")
        && methodName.equals("closeEntry")
        && descriptor.equals("()V")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          invokeHook("clearArchiveEntry", "()V");
        }
      };
    }
    if (className.equals("java/util/zip/ZipFile")
        && methodName.equals("getInputStream")
        && descriptor.equals("(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("afterArchiveEntry", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }
}
