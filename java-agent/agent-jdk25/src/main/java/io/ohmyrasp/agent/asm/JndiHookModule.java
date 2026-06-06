package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class JndiHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("javax/naming/InitialContext") || className.startsWith("com/sun/jndi/");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (className.equals("javax/naming/InitialContext") && methodName.equals("lookup")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeJndiLookup", "(Ljava/lang/Object;)V");
        }
      };
    }
    if (className.startsWith("com/sun/jndi/")
        && HookRegistry.methodNameContains(methodName, "lookup")
        && (descriptor.startsWith("(Ljava/lang/String;")
            || descriptor.startsWith("(Ljavax/naming/Name;"))) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          invokeHook("beforeJndiLookup", "(Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }
}
