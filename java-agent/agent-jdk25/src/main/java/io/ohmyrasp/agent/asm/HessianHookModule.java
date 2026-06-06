package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class HessianHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("com/caucho/hessian/io/SerializerFactory");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (!methodName.equals("getDeserializer")
        || !descriptor.equals("(Ljava/lang/String;)Lcom/caucho/hessian/io/Deserializer;")) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        loadArg(0);
        invokeHook("beforeHessianType", "(Ljava/lang/String;)V");
      }
    };
  }
}
