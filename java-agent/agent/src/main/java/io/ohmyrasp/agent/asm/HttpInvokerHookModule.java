package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class HttpInvokerHookModule implements HookModule {
  private static final String HTTP_INVOKER_EXPORTER =
      "org/springframework/remoting/httpinvoker/HttpInvokerServiceExporter";

  @Override
  public boolean matchesClass(String className) {
    return HTTP_INVOKER_EXPORTER.equals(className);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (!methodName.equals("readRemoteInvocation") || !isRequestStreamDescriptor(descriptor)) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        push("SpringHttpInvoker");
        invokeHook("beforeHttpInvokerDeserialization", "(Ljava/lang/String;)V");
      }
    };
  }

  private static boolean isRequestStreamDescriptor(String descriptor) {
    return descriptor.startsWith(
            "(Ljavax/servlet/http/HttpServletRequest;Ljava/io/InputStream;)")
        || descriptor.startsWith(
            "(Ljakarta/servlet/http/HttpServletRequest;Ljava/io/InputStream;)");
  }
}
