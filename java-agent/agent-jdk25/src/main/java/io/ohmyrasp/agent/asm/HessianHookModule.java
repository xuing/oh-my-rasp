package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.rules.product.hessian.HessianAllocationVisitor;
import org.objectweb.asm.MethodVisitor;

final class HessianHookModule implements HookModule {
  @Override public boolean matchesClass(String name) { return HessianAllocationVisitor.matches(name); }
  @Override public MethodVisitor visitMethod(String owner, MethodVisitor mv, int access, String name, String desc) {
    return HessianAllocationVisitor.wrap(owner, mv, access, name, desc, "io/ohmyrasp/agent/hook/OhMyRaspHooks");
  }
}
