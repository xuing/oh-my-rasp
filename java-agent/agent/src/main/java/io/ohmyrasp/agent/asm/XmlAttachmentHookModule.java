package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class XmlAttachmentHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("javax/activation/URLDataSource")
        || className.equals("jakarta/activation/URLDataSource");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (methodName.equals("<init>") && descriptor.equals("(Ljava/net/URL;)V")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeUrlDataSource", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }
}
