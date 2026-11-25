package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import io.ohmyrasp.agent.rules.product.elasticsearch.Lz4TransportVisitor;

final class ElasticLz4HookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return Lz4TransportVisitor.OWNER.equals(className);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    return Lz4TransportVisitor.wrap(methodVisitor, access, methodName, descriptor,
        "io/ohmyrasp/agent/hook/OhMyRaspHooks");
  }
}
