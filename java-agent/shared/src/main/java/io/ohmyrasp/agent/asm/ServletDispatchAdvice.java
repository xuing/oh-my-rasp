package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;

/** Servlet dispatch scope shared by the primary and backport transformers. */
public abstract class ServletDispatchAdvice extends ScopedMethodAdvice {
  protected ServletDispatchAdvice(int api, MethodVisitor visitor, int access, String name, String descriptor) {
    super(api, visitor, access, name, descriptor);
  }
}
