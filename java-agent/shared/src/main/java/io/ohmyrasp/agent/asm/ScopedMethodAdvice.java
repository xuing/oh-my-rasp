package io.ohmyrasp.agent.asm;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

/**
 * Balances an instrumentation scope on return and after the method's own exception handlers.
 *
 * <p>A scope whose entry returns a token ({@link #ScopedMethodAdvice(int, MethodVisitor, int, String, String,
 * boolean)}) keeps it in a local of its own: {@link #enterDispatch} leaves it on the stack, and {@link #exitDispatch}
 * passes it back with {@link #loadToken}. The entry returns the scope it opened, or null when it opened none (the
 * hooks were off, or nothing needed one), so the exit undoes exactly what its own entry did, also when the hooks
 * turned on or off in between.
 */
public abstract class ScopedMethodAdvice extends AdviceAdapter {
  private static final Type TOKEN = Type.getType(Object.class);
  private final Label body = new Label();
  private final boolean tokens;
  private int token = -1;

  protected ScopedMethodAdvice(int api, MethodVisitor visitor, int access, String name, String descriptor) {
    this(api, visitor, access, name, descriptor, false);
  }

  /** @param tokens whether {@link #enterDispatch} leaves a token ({@code Object}) on the stack */
  protected ScopedMethodAdvice(int api, MethodVisitor visitor, int access, String name, String descriptor,
      boolean tokens) {
    super(api, visitor, access, name, descriptor);
    this.tokens = tokens;
  }

  protected abstract void enterDispatch();
  /** Cleanup runs even when none of the original method locals are live. */
  protected abstract void exitDispatch();

  /** Pushes the token the entry left, in {@link #exitDispatch} of a scope that has one. */
  protected final void loadToken() {
    if (token < 0) throw new IllegalStateException("this scope has no token");
    loadLocal(token);
  }

  @Override
  protected final void onMethodEnter() {
    enterDispatch();
    if (tokens) {
      token = newLocal(TOKEN);
      storeLocal(token);
    }
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
    // The handler uses only the escaping throwable and the token, regardless of which application locals were live
    // when the method threw: every other local is TOP. The token is stored before the body starts, and no
    // application local shares its slot, so it is an Object everywhere the handler covers.
    Object[] locals = new Object[token + 1];
    for (int i = 0; i < token; i++) {
      locals[i] = Opcodes.TOP;
    }
    if (token >= 0) {
      locals[token] = TOKEN.getInternalName();
    }
    mv.visitFrame(Opcodes.F_NEW, locals.length, locals, 1, new Object[] {"java/lang/Throwable"});
    int failure = newLocal(Type.getType(Throwable.class));
    storeLocal(failure);
    exitDispatch();
    loadLocal(failure);
    mv.visitInsn(ATHROW);
    super.visitMaxs(maxStack, maxLocals);
  }
}
