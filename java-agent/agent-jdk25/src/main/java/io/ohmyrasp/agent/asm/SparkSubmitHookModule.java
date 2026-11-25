package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;
import io.ohmyrasp.agent.rules.product.spark.SparkSubmitVisitor;

final class SparkSubmitHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return SparkSubmitVisitor.OWNER.equals(className);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    return SparkSubmitVisitor.wrap(methodVisitor, access, methodName, descriptor,
        Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks"));
  }
}
