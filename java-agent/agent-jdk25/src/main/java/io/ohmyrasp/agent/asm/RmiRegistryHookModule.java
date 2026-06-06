package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class RmiRegistryHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("sun/rmi/registry/RegistryImpl");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (!(methodName.equals("bind") || methodName.equals("rebind"))
        || !descriptor.equals("(Ljava/lang/String;Ljava/rmi/Remote;)V")) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        push(methodName);
        loadArg(0);
        loadArg(1);
        invokeHook(
            "beforeRmiRegistryBind", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V");
      }
    };
  }
}
