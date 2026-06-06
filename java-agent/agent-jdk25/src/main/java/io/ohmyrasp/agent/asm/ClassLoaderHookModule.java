package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class ClassLoaderHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/net/URLClassLoader")
        || className.equals("java/rmi/server/RMIClassLoader");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (className.equals("java/net/URLClassLoader")) {
      if (methodName.equals("<init>") && descriptor.startsWith("([Ljava/net/URL;")) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeHook("beforeClassLoaderUrls", "(Ljava/lang/Object;)V");
          }
        };
      }
      if (methodName.equals("addURL") && descriptor.equals("(Ljava/net/URL;)V")) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeHook("beforeClassLoaderUrl", "(Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (className.equals("java/rmi/server/RMIClassLoader")
        && (methodName.equals("loadClass")
            || methodName.equals("loadProxyClass")
            || methodName.equals("getClassLoader"))) {
      if (descriptor.startsWith("(Ljava/lang/String;")) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeHook("beforeRmiClassLoaderCodebase", "(Ljava/lang/String;)V");
          }
        };
      }
      if (descriptor.startsWith("(Ljava/net/URL;")) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            loadArg(0);
            invokeHook("beforeClassLoaderUrl", "(Ljava/lang/Object;)V");
          }
        };
      }
    }
    return methodVisitor;
  }
}
