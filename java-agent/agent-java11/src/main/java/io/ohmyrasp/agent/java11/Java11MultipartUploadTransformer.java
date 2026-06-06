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

public final class Java11MultipartUploadTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java11RaspHooks.class);
  private static final Method BEFORE_FILE_UPLOAD =
      Method.getMethod("void beforeFileUpload(java.lang.String)");

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
      reader.accept(new MultipartUploadClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP-JAVA11] multipart upload transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "javax/servlet/http/Part".equals(className)
        || "jakarta/servlet/http/Part".equals(className)
        || "org/apache/catalina/core/ApplicationPart".equals(className)
        || "io/undertow/servlet/spec/PartImpl".equals(className)
        || "org/apache/commons/fileupload/disk/DiskFileItem".equals(className)
        || "org/glassfish/jersey/media/multipart/ContentDisposition".equals(className)
        || "org/eclipse/jetty/util/MultiPartInputStreamParser$MultiPart".equals(className)
        || "org/eclipse/jetty/server/MultiPartFormInputStream$MultiPart".equals(className)
        || "org/springframework/web/multipart/MultipartFile".equals(className)
        || "org/springframework/web/multipart/commons/CommonsMultipartFile".equals(className)
        || "org/springframework/web/multipart/support/StandardMultipartHttpServletRequest$StandardMultipartFile"
            .equals(className)
        || "org/springframework/mock/web/MockMultipartFile".equals(className);
  }

  private static final class MultipartUploadClassVisitor extends ClassVisitor {
    private final String className;

    MultipartUploadClassVisitor(String className, ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null
          || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
          || !isFileNameMethod(className, name, descriptor)) {
        return methodVisitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodExit(int opcode) {
          if (opcode == ARETURN) {
            dup();
            invokeStatic(HOOKS, BEFORE_FILE_UPLOAD);
          }
        }
      };
    }

    private static boolean isFileNameMethod(String className, String name, String descriptor) {
      if (!"()Ljava/lang/String;".equals(descriptor)) {
        return false;
      }
      return "getSubmittedFileName".equals(name)
          || "getOriginalFilename".equals(name)
          || ("org/glassfish/jersey/media/multipart/ContentDisposition".equals(className)
              && "getFileName".equals(name))
          || ("org/apache/commons/fileupload/disk/DiskFileItem".equals(className)
              && "getName".equals(name));
    }
  }
}
