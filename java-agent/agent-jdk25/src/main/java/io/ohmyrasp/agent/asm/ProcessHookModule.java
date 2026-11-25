package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.process.ProcessLaunchVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class ProcessHookModule implements HookModule {
  @Override public boolean matchesClass(String className) {
    return ProcessLaunchVisitor.matches(className);
  }

  @Override public MethodVisitor visitMethod(String className, MethodVisitor visitor, int access, String name, String descriptor) {
    return ProcessLaunchVisitor.wrap(className, visitor, access, name, descriptor,
        Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks"));
  }
}
