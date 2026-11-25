package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.rules.product.activemq.OpenWireThrowableVisitor;
import org.objectweb.asm.MethodVisitor;

final class OpenWireHookModule implements HookModule {
  @Override public boolean matchesClass(String name) { return OpenWireThrowableVisitor.matches(name); }

  @Override public MethodVisitor visitMethod(String owner, MethodVisitor mv, int access, String name, String desc) {
    return OpenWireThrowableVisitor.wrap(mv, name, desc, "io/ohmyrasp/agent/hook/OhMyRaspHooks");
  }
}
