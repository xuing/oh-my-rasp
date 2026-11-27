package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

interface HookModule {
  boolean matchesClass(String className);

  /** Whether the module rewrites this class, knowing its direct superclass (null when it has none). */
  default boolean matchesClass(String className, String superName) {
    return matchesClass(className);
  }

  MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor);
}
