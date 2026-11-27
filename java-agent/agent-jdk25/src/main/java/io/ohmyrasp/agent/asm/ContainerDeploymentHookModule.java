package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.file.ContainerDeploymentVisitor;
import org.objectweb.asm.MethodVisitor;

/**
 * Tomcat's WAR unpack and Jasper's JSP compile, observed as scopes so the script-write rule can leave their own writes
 * alone (see {@code io.ohmyrasp.agent.file.ContainerDeployment}). The injected calls go to that shared observer, which
 * decides nothing and throws nothing, so they have no {@code OhMyRaspHooks} entry.
 */
final class ContainerDeploymentHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return ContainerDeploymentVisitor.matches(className);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    return ContainerDeploymentVisitor.wrap(className, methodVisitor, access, methodName, descriptor);
  }
}
