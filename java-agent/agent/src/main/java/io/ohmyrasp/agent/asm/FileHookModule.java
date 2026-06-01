package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class FileHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/io/FileInputStream")
        || className.equals("java/io/FileOutputStream")
        || className.equals("java/io/File")
        || className.equals("java/nio/file/Files");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (className.equals("java/io/FileInputStream") && methodName.equals("<init>")) {
      return new FileConstructorAdvice(methodVisitor, access, methodName, descriptor, true);
    }
    if (className.equals("java/io/FileOutputStream") && methodName.equals("<init>")) {
      return new FileConstructorAdvice(methodVisitor, access, methodName, descriptor, false);
    }
    if (className.equals("java/io/File")) {
      return fileMethod(methodVisitor, access, methodName, descriptor);
    }
    if (className.equals("java/nio/file/Files")) {
      return nioFilesMethod(methodVisitor, access, methodName, descriptor);
    }
    return methodVisitor;
  }

  private MethodVisitor fileMethod(
      MethodVisitor methodVisitor, int access, String methodName, String descriptor) {
    if ((methodName.equals("delete") || methodName.equals("deleteOnExit"))
        && descriptor.startsWith("()")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeHook("beforeFileDelete", "(Ljava/lang/Object;)V");
        }
      };
    }
    if ((methodName.equals("list") || methodName.equals("listFiles"))
        && descriptor.startsWith("()")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeHook("beforeDirectoryList", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }

  private MethodVisitor nioFilesMethod(
      MethodVisitor methodVisitor, int access, String methodName, String descriptor) {
    if (!descriptor.startsWith("(Ljava/nio/file/Path;")) {
      return methodVisitor;
    }
    if (methodName.startsWith("read")
        || methodName.equals("newInputStream")
        || methodName.equals("lines")
        || methodName.equals("list")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook(
              methodName.equals("list") ? "beforeDirectoryList" : "beforePathRead",
              "(Ljava/lang/Object;)V");
        }
      };
    }
    if (methodName.startsWith("write")
        || methodName.equals("newOutputStream")
        || methodName.equals("createFile")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforePathWrite", "(Ljava/lang/Object;)V");
        }
      };
    }
    if (methodName.equals("delete") || methodName.equals("deleteIfExists")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforePathDelete", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }

  private static final class FileConstructorAdvice extends EntryAdvice {
    private final boolean read;
    private final String descriptor;

    FileConstructorAdvice(
        MethodVisitor methodVisitor, int access, String methodName, String descriptor, boolean read) {
      super(methodVisitor, access, methodName, descriptor);
      this.read = read;
      this.descriptor = descriptor;
    }

    @Override
    protected void onMethodEnter() {
      if (descriptor.startsWith("(Ljava/lang/String;")) {
        loadArg(0);
        invokeHook(read ? "beforeFileRead" : "beforeFileWrite", "(Ljava/lang/String;)V");
      } else if (descriptor.startsWith("(Ljava/io/File;")) {
        loadArg(0);
        invokeHook(
            read ? "beforeFileReadObject" : "beforeFileWriteObject", "(Ljava/lang/Object;)V");
      }
    }
  }
}
