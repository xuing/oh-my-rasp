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
            super.visitMethodInsn(Opcodes.INVOKESTATIC, GUARD, name, "(" + FILTER + CHECK.substring(1), false);
          } else {
            super.visitMethodInsn(opcode, owner, name, desc, itf);
          }
        }
      };
    }
    if (!methodName.equals("<init>") || !descriptor.equals("(Ljava/io/InputStream;)V")) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        loadArg(0);
        invokeHook("beforeObjectInputStream", "(Ljava/lang/Object;)V");
      }
    };
  }
}
