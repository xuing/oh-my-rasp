package io.ohmyrasp.agent.asm;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

final class HookClassVisitor extends ClassVisitor {
  private final String className;
  private final HookRegistry registry;
  private final boolean jdbcImplementation;
  private final HookMissProbe probe;
  private final boolean bodyHooks;
  private String superName;

  HookClassVisitor(String className, HookRegistry registry, ClassVisitor delegate, boolean jdbcImplementation) {
    this(className, registry, delegate, jdbcImplementation, true, null);
  }

  HookClassVisitor(String className, HookRegistry registry, ClassVisitor delegate, boolean jdbcImplementation,
      boolean bodyHooks, HookMissProbe probe) {
    super(OhMyRaspTransformer.api(), delegate);
    this.className = className;
    this.registry = registry;
    this.jdbcImplementation = jdbcImplementation;
    this.probe = probe;
    this.bodyHooks = bodyHooks;
  }

  @Override
  public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
    this.superName = superName;
    super.visit(version, access, name, signature, superName, interfaces);
  }

  @Override
  public MethodVisitor visitMethod(
      int access, String name, String descriptor, String signature, String[] exceptions) {
    MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
    if (methodVisitor == null) {
      return null;
    }
    return registry.visitMethod(className, superName, bodyHooks, methodVisitor, access, name, descriptor, jdbcImplementation, probe);
  }
}
