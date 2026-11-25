package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.naming.JndiLookupVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class JndiHookModule implements HookModule {
  @Override public boolean matchesClass(String name) { return JndiLookupVisitor.target(name); }

  @Override public MethodVisitor visitMethod(String owner, MethodVisitor mv, int access, String name, String desc) {
    return JndiLookupVisitor.wrap(owner, mv, access, name, desc, Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks"));
  }
}
