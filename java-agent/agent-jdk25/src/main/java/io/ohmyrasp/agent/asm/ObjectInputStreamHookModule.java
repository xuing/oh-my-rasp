package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class ObjectInputStreamHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("java/io/ObjectInputStream");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if ("filterCheck".equals(methodName) && "(Ljava/lang/Class;I)V".equals(descriptor)) {
      return new MethodVisitor(Opcodes.ASM9, methodVisitor) {
        private static final String GUARD = "io/ohmyrasp/agent/hook/DeserializationGuard";
        private static final String FILTER = "Ljava/io/ObjectInputFilter;";
        private static final String CHECK = "(Ljava/io/ObjectInputFilter$FilterInfo;)Ljava/io/ObjectInputFilter$Status;";

        @Override public void visitFieldInsn(int opcode, String owner, String name, String desc) {
          super.visitFieldInsn(opcode, owner, name, desc);
          if (opcode == Opcodes.GETFIELD && className.equals(owner) && "serialFilter".equals(name) && FILTER.equals(desc)) {
            super.visitMethodInsn(Opcodes.INVOKESTATIC, GUARD, "filterOrGuard", "(" + FILTER + ")" + FILTER, false);
          }
        }

        @Override public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
          if (opcode == Opcodes.INVOKEINTERFACE && "java/io/ObjectInputFilter".equals(owner)
              && "checkInput".equals(name) && CHECK.equals(desc)) {
            mv.visitVarInsn(Opcodes.ALOAD, 0);
            super.visitMethodInsn(Opcodes.INVOKESTATIC, GUARD, name,
                "(" + FILTER + "Ljava/io/ObjectInputFilter$FilterInfo;Ljava/io/ObjectInputStream;)Ljava/io/ObjectInputFilter$Status;", false);
          } else {
            super.visitMethodInsn(opcode, owner, name, desc, itf);
          }
        }
      };
    }
    if (methodName.equals("<init>") && descriptor.equals("(Ljava/io/InputStream;)V")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override protected void onMethodEnter() {}
        @Override protected void onMethodExit(int opcode) {
          if (opcode == RETURN) {
            loadThis();
            loadArg(0);
            invokeHook("afterObjectInputStreamConstruction", "(Ljava/io/ObjectInputStream;Ljava/lang/Object;)V");
          }
        }
      };
    }
    if (!methodName.equals("readObject") && !methodName.equals("readUnshared")) return methodVisitor;
    return new MethodVisitor(Opcodes.ASM9, methodVisitor) {
      @Override public void visitMethodInsn(int op, String owner, String name, String desc, boolean itf) {
        if (className.equals(owner) && "readObject0".equals(name)
            && "(Ljava/lang/Class;Z)Ljava/lang/Object;".equals(desc)) {
          mv.visitVarInsn(Opcodes.ALOAD, 0);
          mv.visitMethodInsn(Opcodes.INVOKESTATIC, "io/ohmyrasp/agent/hook/OhMyRaspHooks",
              "beforeServletObjectRead", "(Ljava/io/ObjectInputStream;)V", false);
        }
        super.visitMethodInsn(op, owner, name, desc, itf);
      }
    };
  }
}
