package io.ohmyrasp.agent.sql;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;

/** Enclose both the entry policy check and the original JDBC implementation. */
public final class JdbcObservationAdvice extends ScopedMethodAdvice {
  private static final Type SCOPE = Type.getType(JdbcObservation.class);

  private final boolean isStatic;

  public JdbcObservationAdvice(MethodVisitor mv, int access, String name, String descriptor) {
    super(Opcodes.ASM9, mv, access, name, descriptor, true);
    isStatic = (access & Opcodes.ACC_STATIC) != 0;
  }

  @Override protected void enterDispatch() {
    if (isStatic) visitInsn(Opcodes.ACONST_NULL);
    else loadThis();
    loadArg(0);
    invokeStatic(SCOPE, Method.getMethod("Object enter(Object, String)"));
  }

  @Override protected void exitDispatch() {
    loadToken();
    invokeStatic(SCOPE, Method.getMethod("void exit(Object)"));
  }
}
