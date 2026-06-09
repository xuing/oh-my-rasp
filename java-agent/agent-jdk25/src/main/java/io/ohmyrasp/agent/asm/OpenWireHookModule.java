package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class OpenWireHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.startsWith("org/apache/activemq/openwire/v")
        && className.endsWith("/BaseDataStreamMarshaller");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (!methodName.equals("createThrowable")
        || !descriptor.equals("(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Throwable;")) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        push("OpenWire");
        loadArg(0);
        loadArg(1);
        invokeHook(
            "beforeProtocolClassInstantiation",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V");
      }
    };
  }
}
