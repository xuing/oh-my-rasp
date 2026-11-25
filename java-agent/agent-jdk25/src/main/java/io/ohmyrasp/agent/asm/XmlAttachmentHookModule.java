package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.xml.AttachmentFileVisitor;
import org.objectweb.asm.MethodVisitor;

final class XmlAttachmentHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return AttachmentFileVisitor.matches(className);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    methodVisitor = AttachmentFileVisitor.wrap(className, methodVisitor, access, methodName, descriptor,
        org.objectweb.asm.Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks"));
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
