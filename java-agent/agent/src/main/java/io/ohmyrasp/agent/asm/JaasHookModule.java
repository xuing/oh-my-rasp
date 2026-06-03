package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class JaasHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("javax/security/auth/login/AppConfigurationEntry");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (methodName.equals("<init>")
        && descriptor.startsWith(
            "(Ljava/lang/String;Ljavax/security/auth/login/AppConfigurationEntry$LoginModuleControlFlag;Ljava/util/Map;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(2);
          invokeHook("beforeJaasConfigEntry", "(Ljava/lang/Object;Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }
}
