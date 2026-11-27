package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.http.RequestBodyVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

/**
 * The read methods of servlet input streams and of Tomcat's reader, which record what the application read of
 * a request body; see {@link RequestBodyVisitor}. A stream is matched by its superclass, so the module sees it
 * through {@link #matchesClass(String, String)}.
 */
final class RequestBodyHookModule implements HookModule {
  private static final Type HOOKS = Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks");

  @Override
  public boolean matchesClass(String className) {
    return RequestBodyVisitor.isReader(className);
  }

  @Override
  public boolean matchesClass(String className, String superName) {
    return RequestBodyVisitor.matches(className, superName);
  }

  @Override
  public MethodVisitor visitMethod(
      String className, MethodVisitor methodVisitor, int access, String methodName, String descriptor) {
    return RequestBodyVisitor.wrap(
        RequestBodyVisitor.isReader(className), methodVisitor, className, access, methodName, descriptor, HOOKS);
  }
}
