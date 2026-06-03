package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class XmlRpcHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("org/apache/xmlrpc/parser/SerializableParser");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (!methodName.equals("getResult") || !descriptor.equals("()Ljava/lang/Object;")) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        push("ApacheXmlRpc");
        invokeHook("beforeXmlRpcSerializableValue", "(Ljava/lang/String;)V");
      }
    };
  }
}
