package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class JavaBeansHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/beans/Expression")
        || className.equals("java/beans/Statement")
        || className.equals("com/sun/beans/decoder/DocumentHandler");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (className.equals("java/beans/Expression")
        && methodName.equals("getValue")
        && descriptor.equals("()Ljava/lang/Object;")) {
      return advice(methodVisitor, access, methodName, descriptor);
    }
    if (className.equals("java/beans/Statement")
        && methodName.equals("execute")
        && descriptor.equals("()V")) {
      return advice(methodVisitor, access, methodName, descriptor);
    }
    if (className.equals("com/sun/beans/decoder/DocumentHandler")
        && methodName.equals("handleException")
        && descriptor.equals("(Ljava/lang/Exception;)V")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("rethrowIfOhMyRaspBlock", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }

  private static MethodVisitor advice(
      MethodVisitor methodVisitor, int access, String methodName, String descriptor) {
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        loadThis();
        invokeHook("beforeJavaBeansStatement", "(Ljava/lang/Object;)V");
      }
    };
  }
}
