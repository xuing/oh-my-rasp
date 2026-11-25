package io.ohmyrasp.agent.asm;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

/** Balances an instrumentation scope on return and after the method's own exception handlers. */
public abstract class ScopedMethodAdvice extends AdviceAdapter {
  private final Label body = new Label();

  protected ScopedMethodAdvice(int api, MethodVisitor visitor, int access, String name, String descriptor) {
    super(api, visitor, access, name, descriptor);
  }

  protected abstract void enterDispatch();
  /** Cleanup runs even when none of the original method locals are live. */
  protected abstract void exitDispatch();

  @Override
  protected final void onMethodEnter() {
    enterDispatch();
    mark(body);
  }

  @Override
  protected final void onMethodExit(int opcode) {
    if (opcode != ATHROW) {
      exitDispatch();
    }
  }

  @Override
  public void visitMaxs(int maxStack, int maxLocals) {
    Label handler = new Label();
    visitTryCatchBlock(body, handler, handler, null);
    mark(handler);
    // The handler uses only the escaping throwable, regardless of which
    // application locals were live when the method threw.
    mv.visitFrame(Opcodes.F_NEW, 0, new Object[0], 1, new Object[] {"java/lang/Throwable"});
    int failure = newLocal(Type.getType(Throwable.class));
    storeLocal(failure);
    exitDispatch();
    loadLocal(failure);
    mv.visitInsn(ATHROW);
    super.visitMaxs(maxStack, maxLocals);
  }
}
