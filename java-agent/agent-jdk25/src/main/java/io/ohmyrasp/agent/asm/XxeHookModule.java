package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.xml.XmlEntityOpenVisitor;
import org.objectweb.asm.MethodVisitor;

final class XxeHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return XmlEntityOpenVisitor.matches(className);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    return XmlEntityOpenVisitor.wrap(className, methodVisitor, access, methodName, descriptor,
        "io/ohmyrasp/agent/hook/OhMyRaspHooks");
  }
}
