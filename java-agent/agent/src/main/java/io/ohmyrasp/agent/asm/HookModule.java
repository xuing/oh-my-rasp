package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

interface HookModule {
  boolean matchesClass(String className);

  MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor);
}
