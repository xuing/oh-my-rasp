package io.ohmyrasp.agent.rules.product.activemq;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

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

  public static MethodVisitor wrap(final MethodVisitor delegate, int access, String name, String desc, final String hooks) {
    if (!"createThrowable".equals(name) || !"(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Throwable;".equals(desc))
      return delegate;
    return new MethodNode(Opcodes.ASM9, access, name, desc, null, null) {
      @Override public void visitEnd() {
        for (AbstractInsnNode insn : instructions.toArray()) {
          if (insn.getOpcode() != Opcodes.INVOKEVIRTUAL) continue;
          MethodInsnNode call = (MethodInsnNode)insn;
          if (!"java/lang/reflect/Constructor".equals(call.owner) || !"newInstance".equals(call.name)
              || !"([Ljava/lang/Object;)Ljava/lang/Object;".equals(call.desc)) continue;
          AbstractInsnNode use = call.getNext();
          while (use != null && use.getOpcode() < 0) use = use.getNext();
          if (!(use instanceof TypeInsnNode) || use.getOpcode() != Opcodes.CHECKCAST
              || !"java/lang/Throwable".equals(((TypeInsnNode)use).desc)) continue;

          // Keep the constructor and arguments on the original stack. Its result occupies the Throwable slot.
          InsnList guard = new InsnList();
          guard.add(new InsnNode(Opcodes.DUP2));
          guard.add(new InsnNode(Opcodes.POP));
          guard.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, call.owner, "getDeclaringClass", "()Ljava/lang/Class;", false));
          guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, hooks, "beforeOpenWireThrowable", "(Ljava/lang/Class;)V", false));
          instructions.insertBefore(call, guard);
        }
        accept(delegate);
      }
    };
  }
}
