package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.loading.CodebaseVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class ClassLoaderHookModule implements HookModule {
  private static final Type HOOKS = Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks");

  @Override public boolean matchesClass(String owner) { return CodebaseVisitor.target(owner); }

  @Override public MethodVisitor visitMethod(String owner, MethodVisitor mv, int access, String name, String desc) {
    return CodebaseVisitor.wrap(owner, mv, access, name, desc, HOOKS);
  }
}
