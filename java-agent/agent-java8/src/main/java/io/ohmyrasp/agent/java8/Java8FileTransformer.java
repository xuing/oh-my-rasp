package io.ohmyrasp.agent.java8;

import io.ohmyrasp.agent.file.UnixDeleteVisitor;
import io.ohmyrasp.agent.file.UnixReadVisitor;
import io.ohmyrasp.agent.file.DirectoryListVisitor;
import io.ohmyrasp.agent.file.StreamReadVisitor;
import io.ohmyrasp.agent.file.PlotWriteVisitor;
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

public final class Java8FileTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java8RaspHooks.class);
  private static final Method BEFORE_FILE_WRITE =
      Method.getMethod("void beforeFileWrite(java.lang.Object)");
  private static final Method BEFORE_NIO_FILE_WRITE =
      Method.getMethod("void beforeNioFileWrite(java.lang.Object)");

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
      ClassWriter writer = new ClassWriter(reader, PlotWriteVisitor.OWNER.equals(className) ? ClassWriter.COMPUTE_FRAMES : ClassWriter.COMPUTE_MAXS);
      reader.accept(new FileClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA8] file transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return UnixReadVisitor.FACTORY.equals(className) || DirectoryListVisitor.matches(className)
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
      if (PlotWriteVisitor.OWNER.equals(className))
        methodVisitor = PlotWriteVisitor.wrap(methodVisitor, access, name, descriptor, HOOKS);
      if ("java/io/FileOutputStream".equals(className) && "open".equals(name)) {
        return StreamReadVisitor.outputOpen(methodVisitor, name, descriptor, HOOKS.getInternalName());
      }
      if (DirectoryListVisitor.matches(className)) {
        methodVisitor = UnixDeleteVisitor.wrap(className, methodVisitor, name, descriptor, HOOKS.getInternalName());
        methodVisitor = DirectoryListVisitor.wrap(className, methodVisitor, access, name, descriptor, HOOKS.getInternalName());
      }
      if (StreamReadVisitor.matches(className)) {
        return StreamReadVisitor.wrap(className, methodVisitor, name, descriptor, HOOKS.getInternalName(), true);
      }
      if (UnixReadVisitor.FACTORY.equals(className)) {
        return UnixReadVisitor.method(methodVisitor, name, descriptor, HOOKS.getInternalName());
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
      if (!"<init>".equals(name)) {
        return methodVisitor;
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
      return methodVisitor;
    }

    private MethodVisitor visitNioFilesMethod(
        MethodVisitor methodVisitor, int access, String name, String descriptor) {
      boolean channel = isNioByteChannelOpen(name, descriptor);
      if (channel || isNioPathFirstRead(name, descriptor)) {
        return io.ohmyrasp.agent.file.FacadeReadVisitor.wrap(methodVisitor, access, name, descriptor, HOOKS, channel);
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
  }
}
