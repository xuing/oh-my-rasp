package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.http.MultipartFilenameVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class MultipartUploadHookModule implements HookModule {
  private static final Type HOOKS = Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks");

  @Override public boolean matchesClass(String className) { return MultipartFilenameVisitor.known(className, false); }

  @Override public MethodVisitor visitMethod(String owner, MethodVisitor visitor, int access, String name, String desc) {
    return MultipartFilenameVisitor.wrap(owner, visitor, access, name, desc, HOOKS, false);
  }
}
