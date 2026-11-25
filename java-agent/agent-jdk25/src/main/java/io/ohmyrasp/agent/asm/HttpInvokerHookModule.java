package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** The base exporter reads the selected stream before checking the resulting invocation. */
final class HttpInvokerHookModule implements HookModule {
  @Override public boolean matchesClass(String owner) {
    return "org/springframework/remoting/rmi/RemoteInvocationSerializingExporter".equals(owner);
  }

  @Override public MethodVisitor visitMethod(String owner, MethodVisitor delegate, int access, String name, String desc) {
    if (!"doReadRemoteInvocation".equals(name)
        || !"(Ljava/io/ObjectInputStream;)Lorg/springframework/remoting/support/RemoteInvocation;".equals(desc)) return delegate;
    return new MethodVisitor(Opcodes.ASM9, delegate) {
      @Override public void visitMethodInsn(int op, String target, String method, String signature, boolean itf) {
        if (op == Opcodes.INVOKEVIRTUAL && "java/io/ObjectInputStream".equals(target)
            && "readObject".equals(method) && "()Ljava/lang/Object;".equals(signature)) {
          mv.visitVarInsn(Opcodes.ALOAD, 0);
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, "io/ohmyrasp/agent/hook/OhMyRaspHooks",
              "beforeHttpInvokerRead", "(Ljava/lang/Object;)V", false);
        }
        super.visitMethodInsn(op, target, method, signature, itf);
      }
    };
  }
}
