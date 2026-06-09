package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class ServletHookModule implements HookModule {
  private static final String JAKARTA_SERVICE =
      "(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V";
  private static final String JAVAX_SERVICE =
      "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V";
  private static final String JAKARTA_GENERIC_SERVICE =
      "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V";
  private static final String JAVAX_GENERIC_SERVICE =
      "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V";

  @Override
  public boolean matchesClass(String className) {
    return className.equals("jakarta/servlet/http/HttpServlet")
        || className.equals("javax/servlet/http/HttpServlet");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (methodName.equals("service")
        && (descriptor.equals(JAKARTA_SERVICE)
            || descriptor.equals(JAVAX_SERVICE)
            || descriptor.equals(JAKARTA_GENERIC_SERVICE)
            || descriptor.equals(JAVAX_GENERIC_SERVICE))) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
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
    return methodVisitor;
  }
}
