package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class XxeHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("com/sun/org/apache/xerces/internal/impl/XMLEntityManager");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (methodName.equals("setupCurrentEntity") && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
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
}
