package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

abstract class EntryAdvice extends AdviceAdapter {
  private static final Type HOOKS = Type.getObjectType("io/ohmyrasp/agent/hook/OhMyRaspHooks");

  EntryAdvice(MethodVisitor methodVisitor, int access, String name, String descriptor) {
    super(OhMyRaspTransformer.api(), methodVisitor, access, name, descriptor);
  }

  protected final void invokeHook(String name, String descriptor) {
    invokeStatic(HOOKS, new Method(name, descriptor));
  }
}
