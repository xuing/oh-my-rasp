package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import io.ohmyrasp.agent.file.UnixReadVisitor;
import io.ohmyrasp.agent.file.DirectoryListVisitor;
import io.ohmyrasp.agent.file.StreamReadVisitor;

final class FileHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals(UnixReadVisitor.FACTORY) || StreamReadVisitor.matches(className)
        || className.equals("java/io/FileOutputStream")
        || DirectoryListVisitor.matches(className)
        || className.equals("java/nio/file/Files");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    methodVisitor = io.ohmyrasp.agent.file.UnixDeleteVisitor.wrap(className, methodVisitor, methodName, descriptor,
        "io/ohmyrasp/agent/hook/OhMyRaspHooks");
    if (DirectoryListVisitor.matches(className)) {
      methodVisitor = DirectoryListVisitor.wrap(className, methodVisitor, access, methodName, descriptor, "io/ohmyrasp/agent/hook/OhMyRaspHooks");
    }
    if (className.equals(UnixReadVisitor.FACTORY)) {
      return UnixReadVisitor.method(methodVisitor, methodName, descriptor, "io/ohmyrasp/agent/hook/OhMyRaspHooks");
    }
    if (StreamReadVisitor.matches(className)) {
      return StreamReadVisitor.wrap(className, methodVisitor, methodName, descriptor, "io/ohmyrasp/agent/hook/OhMyRaspHooks", false);
    }
    if (className.equals("java/io/FileOutputStream") && methodName.equals("open")) {
      return StreamReadVisitor.outputOpen(methodVisitor, methodName, descriptor, "io/ohmyrasp/agent/hook/OhMyRaspHooks");
    }
    if (className.equals("java/io/FileOutputStream") && methodName.equals("<init>")) {
      return new FileConstructorAdvice(methodVisitor, access, methodName, descriptor);
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
        public void visitMethodInsn(int op, String owner, String name, String desc, boolean itf) {
          if (op == INVOKEVIRTUAL && "java/io/FileSystem".equals(owner) && "delete".equals(name)
              && "(Ljava/io/File;)Z".equals(desc)) {
            dup();
            visitFieldInsn(GETFIELD, "java/io/File", "path", "Ljava/lang/String;");
            push("file_api_delete");
            invokeHook("beforeFileDeletePath", "(Ljava/lang/String;Ljava/lang/String;)V");
          } else if (op == INVOKESTATIC && "java/io/DeleteOnExitHook".equals(owner) && "add".equals(name)
              && "(Ljava/lang/String;)V".equals(desc)) {
            dup();
            push("delete_on_exit_registration");
            invokeHook("beforeFileDeletePath", "(Ljava/lang/String;Ljava/lang/String;)V");
          }
          super.visitMethodInsn(op, owner, name, desc, itf);
        }
      };
    }
    return methodVisitor;
  }

  private MethodVisitor nioFilesMethod(
      MethodVisitor methodVisitor, int access, String methodName, String descriptor) {
    if (methodName.equals("copy")
        && descriptor.startsWith("(Ljava/io/InputStream;Ljava/nio/file/Path;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(1);
          invokeHook("beforePathWrite", "(Ljava/lang/Object;)V");
        }
      };
    }
    if (!descriptor.startsWith("(Ljava/nio/file/Path;")) {
      return methodVisitor;
    }
    if (methodName.equals("writeString") || (methodName.equals("write")
        && descriptor.startsWith("(Ljava/nio/file/Path;Ljava/lang/Iterable;"))) {
      return GeneratedWriteAdvice.wrap(methodVisitor, access, methodName, descriptor);
    }
    if (methodName.equals("write") && descriptor.startsWith("(Ljava/nio/file/Path;[B")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(1);
          invokeHook(
              "beforeGeneratedScriptFileWrite", "(Ljava/lang/Object;Ljava/lang/Object;)V");
          loadArg(0);
          invokeHook("beforePathWrite", "(Ljava/lang/Object;)V");
        }
      };
    }
    if (methodName.equals("readAllBytes")
        || methodName.equals("readAllLines")
        || methodName.equals("readString")
        || methodName.equals("newBufferedReader")
        || (methodName.equals("copy") && descriptor.startsWith("(Ljava/nio/file/Path;Ljava/io/OutputStream;"))
        || methodName.equals("newInputStream")
        || methodName.equals("lines")) {
      return io.ohmyrasp.agent.file.FacadeReadVisitor.wrap(methodVisitor, access, methodName, descriptor,
          org.objectweb.asm.Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks"), false);
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
          invokeHook("beforePortablePathDelete", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }

  private static final class FileConstructorAdvice extends EntryAdvice {
    private final String descriptor;

    FileConstructorAdvice(
        MethodVisitor methodVisitor, int access, String methodName, String descriptor) {
      super(methodVisitor, access, methodName, descriptor);
      this.descriptor = descriptor;
    }

    @Override
    protected void onMethodEnter() {
      if (descriptor.startsWith("(Ljava/lang/String;")) {
        loadArg(0);
        invokeHook("beforeFileWrite", "(Ljava/lang/String;)V");
      } else if (descriptor.startsWith("(Ljava/io/File;")) {
        loadArg(0);
        invokeHook(
            "beforeFileWriteObject", "(Ljava/lang/Object;)V");
      }
    }
  }
}
