package io.ohmyrasp.agent.java11;

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

public final class Java11FileTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java11RaspHooks.class);
  private static final Method BEFORE_FILE_READ =
      Method.getMethod("void beforeFileRead(java.lang.Object)");
  private static final Method BEFORE_FILE_WRITE =
      Method.getMethod("void beforeFileWrite(java.lang.Object)");
  private static final Method BEFORE_FILE_CONTENT_WRITE =
      Method.getMethod("void beforeFileContentWrite(byte[], int, int)");
  private static final Method BEFORE_RANDOM_ACCESS_FILE_OPEN =
      Method.getMethod("void beforeRandomAccessFileOpen(java.lang.Object, java.lang.String)");
  private static final Method BEFORE_NIO_FILE_READ =
      Method.getMethod("void beforeNioFileRead(java.lang.Object)");
  private static final Method BEFORE_NIO_FILE_WRITE =
      Method.getMethod("void beforeNioFileWrite(java.lang.Object)");
  private static final Method BEFORE_NIO_BYTE_CHANNEL_OPEN =
      Method.getMethod("void beforeNioByteChannelOpen(java.lang.Object, java.lang.Object)");

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
      reader.accept(new FileClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA11] file transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "java/io/File".equals(className)
        || "java/io/FileInputStream".equals(className)
        || "java/io/FileOutputStream".equals(className)
        || "java/io/RandomAccessFile".equals(className)
        || "java/nio/file/Files".equals(className);
  }

  private static final class FileClassVisitor extends ClassVisitor {
    private final String className;

    FileClassVisitor(String className, ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null) {
        return methodVisitor;
      }
      if ("java/io/File".equals(className) && isFileRenameTo(name, descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_FILE_WRITE);
          }
        };
      }
      if ("java/nio/file/Files".equals(className)) {
        return visitNioFilesMethod(methodVisitor, access, name, descriptor);
      }
      if ("java/io/FileOutputStream".equals(className) && isFileOutputStreamByteWrite(name, descriptor)) {
        return visitFileOutputStreamWrite(methodVisitor, access, name, descriptor);
      }
      if (!"<init>".equals(name)) {
        return methodVisitor;
      }
      if ("java/io/FileInputStream".equals(className) && hasPathFirstArg(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_FILE_READ);
          }
        };
      }
      if ("java/io/FileOutputStream".equals(className) && hasPathFirstArg(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_FILE_WRITE);
          }
        };
      }
      if ("java/io/RandomAccessFile".equals(className) && hasPathAndModeArgs(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            loadArg(1);
            invokeStatic(HOOKS, BEFORE_RANDOM_ACCESS_FILE_OPEN);
          }
        };
      }
      return methodVisitor;
    }

    private MethodVisitor visitFileOutputStreamWrite(
        MethodVisitor methodVisitor, int access, String name, String descriptor) {
      if ("write".equals(name) && "([B)V".equals(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            push(0);
            loadArg(0);
            arrayLength();
            invokeStatic(HOOKS, BEFORE_FILE_CONTENT_WRITE);
          }
        };
      }
      if ("write".equals(name) && "([BII)V".equals(descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            loadArg(1);
            loadArg(2);
            invokeStatic(HOOKS, BEFORE_FILE_CONTENT_WRITE);
          }
        };
      }
      return methodVisitor;
    }

    private MethodVisitor visitNioFilesMethod(
        MethodVisitor methodVisitor, int access, String name, String descriptor) {
      if (isNioByteChannelOpen(name, descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            loadArg(1);
            invokeStatic(HOOKS, BEFORE_NIO_BYTE_CHANNEL_OPEN);
          }
        };
      }
      if (isNioPathFirstRead(name, descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_NIO_FILE_READ);
          }
        };
      }
      if (isNioPathFirstWrite(name, descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeStatic(HOOKS, BEFORE_NIO_FILE_WRITE);
          }
        };
      }
      if (isNioCopyInputStreamToPath(name, descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(1);
            invokeStatic(HOOKS, BEFORE_NIO_FILE_WRITE);
          }
        };
      }
      if (isNioPathSecondWrite(name, descriptor)) {
        return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(1);
            invokeStatic(HOOKS, BEFORE_NIO_FILE_WRITE);
          }
        };
      }
      return methodVisitor;
    }

    private static boolean isFileRenameTo(String name, String descriptor) {
      return "renameTo".equals(name) && "(Ljava/io/File;)Z".equals(descriptor);
    }

    private static boolean hasPathFirstArg(String descriptor) {
      return descriptor.startsWith("(Ljava/lang/String;")
          || descriptor.startsWith("(Ljava/io/File;");
    }

    private static boolean hasPathAndModeArgs(String descriptor) {
      return descriptor.startsWith("(Ljava/lang/String;Ljava/lang/String;")
          || descriptor.startsWith("(Ljava/io/File;Ljava/lang/String;");
    }

    private static boolean isNioByteChannelOpen(String name, String descriptor) {
      return "newByteChannel".equals(name)
          && (descriptor.startsWith("(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;")
              || descriptor.startsWith("(Ljava/nio/file/Path;Ljava/util/Set;"));
    }

    private static boolean isNioPathFirstRead(String name, String descriptor) {
      if (!descriptor.startsWith("(Ljava/nio/file/Path;")) {
        return false;
      }
      return "newInputStream".equals(name)
          || "readAllBytes".equals(name)
          || "readString".equals(name)
          || "readAllLines".equals(name)
          || "lines".equals(name)
          || ("copy".equals(name) && descriptor.startsWith("(Ljava/nio/file/Path;Ljava/io/OutputStream;"));
    }

    private static boolean isNioPathFirstWrite(String name, String descriptor) {
      if (!descriptor.startsWith("(Ljava/nio/file/Path;")) {
        return false;
      }
      return "newOutputStream".equals(name)
          || "write".equals(name)
          || "writeString".equals(name);
    }

    private static boolean isNioCopyInputStreamToPath(String name, String descriptor) {
      return "copy".equals(name)
          && descriptor.startsWith("(Ljava/io/InputStream;Ljava/nio/file/Path;");
    }

    private static boolean isNioPathSecondWrite(String name, String descriptor) {
      return ("copy".equals(name) || "move".equals(name))
          && descriptor.startsWith("(Ljava/nio/file/Path;Ljava/nio/file/Path;");
    }

    private static boolean isFileOutputStreamByteWrite(String name, String descriptor) {
      return "write".equals(name) && ("([B)V".equals(descriptor) || "([BII)V".equals(descriptor));
    }
  }
}
