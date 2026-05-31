package io.ohmyrasp.agent.asm;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class HookClassVisitor extends ClassVisitor {
  private final String className;

  HookClassVisitor(String className, ClassVisitor delegate) {
    super(OhMyRaspTransformer.api(), delegate);
    this.className = className;
  }

  static boolean isDirectTarget(String className) {
    return className.equals("java/lang/ProcessBuilder")
        || className.equals("java/io/FileInputStream")
        || className.equals("java/io/FileOutputStream")
        || className.equals("java/io/File")
        || className.equals("java/nio/file/Files")
        || className.equals("java/net/URL")
        || className.equals("java/net/InetAddress")
        || className.equals("javax/naming/InitialContext")
        || className.startsWith("com/sun/jndi/")
        || className.startsWith("org/h2/jdbc/")
        || className.equals("jakarta/servlet/http/HttpServlet")
        || className.equals("com/sun/org/apache/xerces/internal/impl/XMLEntityManager");
  }

  @Override
  public MethodVisitor visitMethod(
      int access, String name, String descriptor, String signature, String[] exceptions) {
    MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
    if (methodVisitor == null) {
      return null;
    }
    if (className.equals("java/lang/ProcessBuilder") && name.equals("start") && descriptor.equals("()Ljava/lang/Process;")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeHook("beforeProcessBuilderStart", "(Ljava/lang/ProcessBuilder;)V");
        }
      };
    }
    if (className.equals("java/io/FileInputStream") && name.equals("<init>")) {
      return new FileConstructorAdvice(methodVisitor, access, name, descriptor, true);
    }
    if (className.equals("java/io/FileOutputStream") && name.equals("<init>")) {
      return new FileConstructorAdvice(methodVisitor, access, name, descriptor, false);
    }
    if (className.equals("java/io/File")) {
      return fileMethod(methodVisitor, access, name, descriptor);
    }
    if (className.equals("java/nio/file/Files")) {
      return nioFilesMethod(methodVisitor, access, name, descriptor);
    }
    if (className.equals("java/net/URL") && name.equals("openConnection")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeHook("beforeUrlOpen", "(Ljava/lang/Object;)V");
        }
      };
    }
    if (className.equals("java/net/InetAddress") && name.equals("getAllByName") && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeDnsLookup", "(Ljava/lang/String;)V");
        }
      };
    }
    if (className.equals("javax/naming/InitialContext") && name.equals("lookup")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeJndiLookup", "(Ljava/lang/Object;)V");
        }
      };
    }
    if (className.startsWith("com/sun/jndi/") && name.toLowerCase(java.util.Locale.ROOT).contains("lookup")) {
      return jndiMethod(methodVisitor, access, name, descriptor);
    }
    if (className.startsWith("org/h2/jdbc/")) {
      MethodVisitor jdbcMethod = jdbcMethod(methodVisitor, access, name, descriptor);
      if (jdbcMethod != methodVisitor) {
        return jdbcMethod;
      }
    }
    if (className.equals("jakarta/servlet/http/HttpServlet")
        && name.equals("service")
        && descriptor.equals("(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(1);
          invokeHook("enterHttpRequest", "(Ljava/lang/Object;Ljava/lang/Object;)V");
        }

        @Override
        protected void onMethodExit(int opcode) {
          invokeHook("exitHttpRequest", "()V");
        }
      };
    }
    if (className.equals("com/sun/org/apache/xerces/internal/impl/XMLEntityManager")
        && name.equals("setupCurrentEntity")
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(1);
          invokeHook("beforeXmlEntity", "(Ljava/lang/String;Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }

  private MethodVisitor fileMethod(MethodVisitor methodVisitor, int access, String name, String descriptor) {
    if ((name.equals("delete") || name.equals("deleteOnExit")) && descriptor.startsWith("()")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeHook("beforeFileDelete", "(Ljava/lang/Object;)V");
        }
      };
    }
    if ((name.equals("list") || name.equals("listFiles")) && descriptor.startsWith("()")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeHook("beforeDirectoryList", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }

  private MethodVisitor jndiMethod(MethodVisitor methodVisitor, int access, String name, String descriptor) {
    if (descriptor.startsWith("(Ljava/lang/String;") || descriptor.startsWith("(Ljavax/naming/Name;")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeJndiLookup", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }

  private MethodVisitor jdbcMethod(MethodVisitor methodVisitor, int access, String name, String descriptor) {
    if ((name.equals("execute")
            || name.equals("executeQuery")
            || name.equals("executeUpdate")
            || name.equals("executeLargeUpdate")
            || name.equals("addBatch")
            || name.equals("prepareCommand"))
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeSql", "(Ljava/lang/String;)V");
        }
      };
    }
    return methodVisitor;
  }

  private MethodVisitor nioFilesMethod(MethodVisitor methodVisitor, int access, String name, String descriptor) {
    if (descriptor.startsWith("(Ljava/nio/file/Path;")) {
      if (name.startsWith("read") || name.equals("newInputStream") || name.equals("lines") || name.equals("list")) {
        return new EntryAdvice(methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeHook(name.equals("list") ? "beforeDirectoryList" : "beforePathRead", "(Ljava/lang/Object;)V");
          }
        };
      }
      if (name.startsWith("write") || name.equals("newOutputStream") || name.equals("createFile")) {
        return new EntryAdvice(methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeHook("beforePathWrite", "(Ljava/lang/Object;)V");
          }
        };
      }
      if (name.equals("delete") || name.equals("deleteIfExists")) {
        return new EntryAdvice(methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeHook("beforePathDelete", "(Ljava/lang/Object;)V");
          }
        };
      }
    }
    return methodVisitor;
  }

  private static final class FileConstructorAdvice extends EntryAdvice {
    private final boolean read;
    private final String descriptor;

    FileConstructorAdvice(
        MethodVisitor methodVisitor, int access, String name, String descriptor, boolean read) {
      super(methodVisitor, access, name, descriptor);
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
        invokeHook(read ? "beforeFileReadObject" : "beforeFileWriteObject", "(Ljava/lang/Object;)V");
      }
    }
  }
}
