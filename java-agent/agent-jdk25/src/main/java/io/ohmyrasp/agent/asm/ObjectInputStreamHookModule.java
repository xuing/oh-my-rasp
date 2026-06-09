package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class ObjectInputStreamHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/io/ObjectInputStream");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (!methodName.equals("<init>") || !descriptor.equals("(Ljava/io/InputStream;)V")) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        loadArg(0);
        invokeHook("beforeObjectInputStream", "(Ljava/lang/Object;)V");
      }
    };
  }
}
