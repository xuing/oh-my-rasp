package io.ohmyrasp.agent.jmx;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

/** Repair the legacy display conversion only when its result supplies the restored JMX field. */
public final class JmxAttributeReadVisitor {
  public static final String OWNER = "javax/management/BadAttributeValueExpException";

  private JmxAttributeReadVisitor() {}

  public static MethodVisitor wrap(MethodVisitor visitor, int access, String name, String descriptor, String hooks) {
    if (visitor == null || !"readObject".equals(name) || !"(Ljava/io/ObjectInputStream;)V".equals(descriptor)) return visitor;
    return new MethodNode(Opcodes.ASM9, access, name, descriptor, null, null) {
      @Override public void visitEnd() {
        super.visitEnd();
        for (AbstractInsnNode node : instructions.toArray()) {
          if (node.getOpcode() != Opcodes.PUTFIELD) continue;
          FieldInsnNode field = (FieldInsnNode) node;
          if (!OWNER.equals(field.owner) || !"val".equals(field.name)) continue;
          AbstractInsnNode producer = node.getPrevious();
          while (producer != null && producer.getOpcode() < 0) producer = producer.getPrevious();
          if (!(producer instanceof MethodInsnNode) || producer.getOpcode() != Opcodes.INVOKEVIRTUAL) continue;
          MethodInsnNode call = (MethodInsnNode) producer;
          if ("java/lang/Object".equals(call.owner) && "toString".equals(call.name) && "()Ljava/lang/String;".equals(call.desc)) {
            instructions.insertBefore(call, new MethodInsnNode(Opcodes.INVOKESTATIC, hooks,
                "jmxAttributeDisplayReceiver", "(Ljava/lang/Object;)Ljava/lang/Object;", false));
          }
        }
        accept(visitor);
      }
    };
  }
}
