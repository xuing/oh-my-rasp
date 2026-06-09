package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

final class JmxHookModule implements HookModule {
  private static final String JMX_INVOKE_DESCRIPTOR =
      "(Ljavax/management/ObjectName;Ljava/lang/String;[Ljava/lang/Object;[Ljava/lang/String;)Ljava/lang/Object;";

  @Override
  public boolean matchesClass(String className) {
    return className.equals("com/sun/jmx/mbeanserver/JmxMBeanServer");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (methodName.equals("invoke") && descriptor.equals(JMX_INVOKE_DESCRIPTOR)) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(0);
          loadArg(1);
          loadArg(2);
          invokeHook(
              "beforeJmxMBeanInvoke",
              "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
  }
}
