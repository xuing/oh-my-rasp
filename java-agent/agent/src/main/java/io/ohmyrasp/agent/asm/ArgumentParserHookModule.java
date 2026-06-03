package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class ArgumentParserHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("org/kohsuke/args4j/CmdLineParser");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (methodName.equals("expandAtFiles") && descriptor.equals("([Ljava/lang/String;)[Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeArgumentFileExpansion", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }
}
