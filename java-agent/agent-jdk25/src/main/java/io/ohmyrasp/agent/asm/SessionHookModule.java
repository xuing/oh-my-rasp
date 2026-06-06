package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class SessionHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("org/apache/catalina/session/FileStore")
        || className.equals("org/apache/catalina/session/PersistentManagerBase");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if ((methodName.equals("load") || methodName.equals("swapIn"))
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          push(className.equals("org/apache/catalina/session/FileStore")
              ? "TomcatFileStore"
              : "TomcatPersistentManager");
          invokeHook("beforeSessionDeserialization", "(Ljava/lang/String;Ljava/lang/String;)V");
        }
      };
    }
    return methodVisitor;
  }
}
