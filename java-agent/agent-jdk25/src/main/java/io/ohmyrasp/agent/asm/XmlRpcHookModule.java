package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.hook.XmlRpcReadScope;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;
import org.objectweb.asm.Opcodes;

final class XmlRpcHookModule implements HookModule {
  @Override public boolean matchesClass(String owner) {
    return "org/apache/xmlrpc/parser/SerializableParser".equals(owner);
  }

  @Override public MethodVisitor visitMethod(String owner, MethodVisitor delegate, int access, String name, String desc) {
    if (!"getResult".equals(name) || !"()Ljava/lang/Object;".equals(desc)) return delegate;
    return new ScopedMethodAdvice(Opcodes.ASM9, delegate, access, name, desc, true) {
      @Override protected void enterDispatch() {
        invokeStatic(Type.getType(XmlRpcReadScope.class), Method.getMethod("Object enter()"));
      }

      @Override protected void exitDispatch() {
        loadToken();
        invokeStatic(Type.getType(XmlRpcReadScope.class), Method.getMethod("void exit(Object)"));
      }

      @Override public void visitMethodInsn(int op, String target, String method, String signature, boolean itf) {
        if (op == Opcodes.INVOKEVIRTUAL && "java/io/ObjectInputStream".equals(target)
            && "readObject".equals(method) && "()Ljava/lang/Object;".equals(signature)) {
          dup();
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, "io/ohmyrasp/agent/hook/OhMyRaspHooks",
              "beforeXmlRpcObjectRead", "(Ljava/io/ObjectInputStream;)V", false);
        }
        super.visitMethodInsn(op, target, method, signature, itf);
      }
    };
  }
}
