package io.ohmyrasp.agent.rules.product.activemq;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Check the constructor OpenWire actually chose for its exception slot. */
public final class OpenWireThrowableVisitor {
  private static final String PREFIX = "org/apache/activemq/openwire/v";
  private static final String SUFFIX = "/BaseDataStreamMarshaller";
  private OpenWireThrowableVisitor() {}

  public static boolean matches(String name) {
    if (name == null || !name.startsWith(PREFIX) || !name.endsWith(SUFFIX)) return false;
    int end = name.length() - SUFFIX.length();
    for (int i = PREFIX.length(); i < end; i++) {
      if (name.charAt(i) < '0' || name.charAt(i) > '9') return false;
    }
    return end > PREFIX.length();
  }

  public static MethodVisitor wrap(MethodVisitor mv, String name, String desc, final String hooks) {
    if (!"createThrowable".equals(name) || !"(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Throwable;".equals(desc))
      return mv;
    return new MethodVisitor(Opcodes.ASM9, mv) {
      @Override public void visitMethodInsn(int op, String owner, String target, String signature, boolean itf) {
        if (op == Opcodes.INVOKEVIRTUAL && "java/lang/reflect/Constructor".equals(owner)
            && "newInstance".equals(target) && "([Ljava/lang/Object;)Ljava/lang/Object;".equals(signature)) {
          // Preserve the constructor and original argument array. Never resolve the wire name again.
          mv.visitInsn(Opcodes.DUP2);
          mv.visitInsn(Opcodes.POP);
          mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, owner, "getDeclaringClass", "()Ljava/lang/Class;", false);
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "beforeOpenWireThrowable", "(Ljava/lang/Class;)V", false);
        }
        super.visitMethodInsn(op, owner, target, signature, itf);
      }
    };
  }
}
