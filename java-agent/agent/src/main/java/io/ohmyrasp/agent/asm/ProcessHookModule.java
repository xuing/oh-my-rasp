package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class ProcessHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/lang/ProcessBuilder") || className.equals("java/lang/Runtime");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (methodName.equals("start") && descriptor.equals("()Ljava/lang/Process;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadThis();
          invokeHook("beforeProcessBuilderStart", "(Ljava/lang/ProcessBuilder;)V");
        }
      };
    }
    if (methodName.equals("exec") && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeRuntimeExecString", "(Ljava/lang/String;)V");
        }
      };
    }
    if (methodName.equals("exec") && descriptor.startsWith("([Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeRuntimeExecArray", "([Ljava/lang/String;)V");
        }
      };
    }
    return methodVisitor;
  }
}
