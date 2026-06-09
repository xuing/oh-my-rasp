package io.ohmyrasp.agent.asm;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

final class HookClassVisitor extends ClassVisitor {
  private final String className;
  private final HookRegistry registry;

  HookClassVisitor(String className, HookRegistry registry, ClassVisitor delegate) {
    super(OhMyRaspTransformer.api(), delegate);
    this.className = className;
    this.registry = registry;
  }

  @Override
  public MethodVisitor visitMethod(
      int access, String name, String descriptor, String signature, String[] exceptions) {
    MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
    if (methodVisitor == null) {
      return null;
    }
    return registry.visitMethod(className, methodVisitor, access, name, descriptor);
  }
}
