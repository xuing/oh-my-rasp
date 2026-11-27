package io.ohmyrasp.agent.jmx;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

/** Observe the JDK's resolved DynamicMBean call, after lookup and access checks. */
public final class JmxDispatchVisitor {
  public static final String TARGET = "com/sun/jmx/interceptor/DefaultMBeanServerInterceptor";
  private static final String INVOKE = "(Ljava/lang/String;[Ljava/lang/Object;[Ljava/lang/String;)Ljava/lang/Object;";
  private static final String SERVER_INVOKE = "(Ljavax/management/ObjectName;Ljava/lang/String;[Ljava/lang/Object;[Ljava/lang/String;)Ljava/lang/Object;";

  private JmxDispatchVisitor() {}

  public static MethodVisitor wrap(final MethodVisitor visitor, int access, String name, String descriptor, final Type hooks) {
    if (visitor == null || !"invoke".equals(name) || !SERVER_INVOKE.equals(descriptor)) return visitor;
    return new MethodNode(Opcodes.ASM9, access, name, descriptor, null, null) {
      @Override public void visitEnd() {
        super.visitEnd();
        for (AbstractInsnNode node : instructions.toArray()) {
          if (!(node instanceof MethodInsnNode) || node.getOpcode() != Opcodes.INVOKEINTERFACE) continue;
          MethodInsnNode call = (MethodInsnNode) node;
          if (!"javax/management/DynamicMBean".equals(call.owner) || !"invoke".equals(call.name) || !INVOKE.equals(call.desc)) continue;
          // The receiver, operation, arguments and signature are local reference loads on supported JDKs.
          VarInsnNode signature = precedingLoad(call);
          VarInsnNode arguments = precedingLoad(signature);
          VarInsnNode operation = precedingLoad(arguments);
          VarInsnNode receiver = precedingLoad(operation);
          if (receiver == null) continue;
          LabelNode dispatch = new LabelNode();
          int callIndex = instructions.indexOf(call);
          java.util.Set<AbstractInsnNode> handlers = new java.util.HashSet<AbstractInsnNode>();
          for (TryCatchBlockNode range : tryCatchBlocks) {
            if (instructions.indexOf(range.start) <= callIndex && callIndex < instructions.indexOf(range.end)) {
              AbstractInsnNode handler = range.handler;
              while (handler != null && handler.getOpcode() < 0) handler = handler.getNext();
              if (handler != null) handlers.add(handler);
            }
            AbstractInsnNode first = range.start;
            while (first != null && first.getOpcode() < 0) first = first.getNext();
            // Only the managed operation's exceptions are subject to JMX exception wrapping.
            if (first == receiver) range.start = dispatch;
          }
          InsnList guard = new InsnList();
          guard.add(new VarInsnNode(Opcodes.ALOAD, 1));
          guard.add(new VarInsnNode(Opcodes.ALOAD, operation.var));
          guard.add(new VarInsnNode(Opcodes.ALOAD, arguments.var));
          guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, hooks.getInternalName(), "beforeResolvedJmxInvoke",
              "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;)V", false));
          guard.add(dispatch);
          instructions.insertBefore(receiver, guard);
          instructions.insert(call, clearArguments());
          // The JDK can call application exception-formatting code after the delegate throws.
          for (AbstractInsnNode handler : handlers) instructions.insertBefore(handler, clearArguments());
        }
        accept(new ScopedMethodAdvice(Opcodes.ASM9, visitor, access, name, desc, true) {
          @Override protected void enterDispatch() {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, Type.getInternalName(JmxWriteScope.class), "enter",
                "()Ljava/lang/Object;", false);
          }
          @Override protected void exitDispatch() {
            loadToken();
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, Type.getInternalName(JmxWriteScope.class), "exit",
                "(Ljava/lang/Object;)V", false);
          }
        });
      }
    };
  }

  private static MethodInsnNode clearArguments() {
    return new MethodInsnNode(Opcodes.INVOKESTATIC, Type.getInternalName(JmxWriteScope.class), "clearArguments", "()V", false);
  }

  private static VarInsnNode precedingLoad(AbstractInsnNode node) {
    if (node == null) return null;
    do { node = node.getPrevious(); } while (node != null && node.getOpcode() < 0);
    return node != null && node.getOpcode() == Opcodes.ALOAD ? (VarInsnNode) node : null;
  }
}
