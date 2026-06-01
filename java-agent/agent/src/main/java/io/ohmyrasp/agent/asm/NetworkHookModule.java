package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class NetworkHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/net/URL") || className.equals("java/net/InetAddress");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (className.equals("java/net/URL") && methodName.equals("openConnection")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeHook("beforeUrlOpen", "(Ljava/lang/Object;)V");
        }
      };
    }
    if (className.equals("java/net/InetAddress")
        && methodName.equals("getAllByName")
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeDnsLookup", "(Ljava/lang/String;)V");
        }
      };
    }
    return methodVisitor;
  }
}
