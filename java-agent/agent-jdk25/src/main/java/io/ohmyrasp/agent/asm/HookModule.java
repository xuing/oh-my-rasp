package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

interface HookModule {
  boolean matchesClass(String className);

  /** Whether the module rewrites this class, knowing its direct superclass (null when it has none). */
  default boolean matchesClass(String className, String superName) {
    return matchesClass(className);
  }

  /**
   * Whether the hook-miss report expects this module to instrument the class when the table names it for the module:
   * by default, when it selects the class by name. A module that selects classes by something the name does not
   * show (a superclass) says here which of the table's classes it means.
   */
  default boolean expectedFor(String className) {
    return matchesClass(className);
  }

  MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor);
}
