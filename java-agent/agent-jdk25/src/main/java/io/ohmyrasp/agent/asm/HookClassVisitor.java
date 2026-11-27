package io.ohmyrasp.agent.asm;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

final class HookClassVisitor extends ClassVisitor {
  private final String className;
  private final HookRegistry registry;
  private final boolean jdbcImplementation;
  private final HookMissProbe probe;

  HookClassVisitor(String className, HookRegistry registry, ClassVisitor delegate, boolean jdbcImplementation) {
    this(className, registry, delegate, jdbcImplementation, null);
  }

  HookClassVisitor(String className, HookRegistry registry, ClassVisitor delegate, boolean jdbcImplementation,
      HookMissProbe probe) {
    super(OhMyRaspTransformer.api(), delegate);
    this.className = className;
    this.registry = registry;
    this.jdbcImplementation = jdbcImplementation;
    this.probe = probe;
  }

  @Override
  public MethodVisitor visitMethod(
      int access, String name, String descriptor, String signature, String[] exceptions) {
    MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
    if (methodVisitor == null) {
      return null;
    }
    return registry.visitMethod(className, methodVisitor, access, name, descriptor, jdbcImplementation, probe);
  }
}
