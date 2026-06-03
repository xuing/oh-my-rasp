package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class MultipartUploadHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("javax/servlet/http/Part")
        || className.equals("jakarta/servlet/http/Part")
        || className.equals("org/apache/catalina/core/ApplicationPart")
        || className.equals("io/undertow/servlet/spec/PartImpl")
        || className.equals("org/apache/commons/fileupload/disk/DiskFileItem")
        || className.equals("org/eclipse/jetty/util/MultiPartInputStreamParser$MultiPart")
        || className.equals("org/eclipse/jetty/server/MultiPartFormInputStream$MultiPart");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    boolean fileNameMethod =
        methodName.equals("getSubmittedFileName")
            || (className.equals("org/apache/commons/fileupload/disk/DiskFileItem")
                && methodName.equals("getName"));
    if (!fileNameMethod || !descriptor.equals("()Ljava/lang/String;")) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodExit(int opcode) {
        if (opcode == Opcodes.ARETURN) {
          dup();
          invokeHook("beforeFileUpload", "(Ljava/lang/String;)V");
        }
      }
    };
  }
}
