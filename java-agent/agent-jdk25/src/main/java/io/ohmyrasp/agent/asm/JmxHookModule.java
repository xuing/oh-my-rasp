package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.jmx.JmxDispatchVisitor;
import io.ohmyrasp.agent.hook.OhMyRaspHooks;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class JmxHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return JmxDispatchVisitor.TARGET.equals(className);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    return JmxDispatchVisitor.wrap(methodVisitor, access, methodName, descriptor, Type.getType(OhMyRaspHooks.class));
  }
}
