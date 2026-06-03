package io.ohmyrasp.agent.asm;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class SqlCallsiteClassVisitor extends ClassVisitor {
  SqlCallsiteClassVisitor(ClassVisitor delegate) {
    super(OhMyRaspTransformer.api(), delegate);
  }

  @Override
  public MethodVisitor visitMethod(
      int access, String name, String descriptor, String signature, String[] exceptions) {
    MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
    if (methodVisitor == null) {
      return null;
    }
    return new MethodVisitor(OhMyRaspTransformer.api(), methodVisitor) {
      @Override
      public void visitMethodInsn(
          int opcode, String owner, String methodName, String methodDescriptor, boolean isInterface) {
        if (isJavaCompilerGetTaskCall(opcode, owner, methodName, methodDescriptor)) {
          super.visitInsn(Opcodes.DUP);
          super.visitMethodInsn(
              Opcodes.INVOKESTATIC,
              "io/ohmyrasp/agent/hook/OhMyRaspHooks",
              "beforeJavaCompilationUnits",
              "(Ljava/lang/Object;)V",
              false);
        }
        if (isSqlStringCall(opcode, owner, methodName, methodDescriptor)) {
          super.visitInsn(Opcodes.DUP);
          super.visitMethodInsn(
              Opcodes.INVOKESTATIC,
              "io/ohmyrasp/agent/hook/OhMyRaspHooks",
              "beforeSql",
              "(Ljava/lang/String;)V",
              false);
        }
        super.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface);
      }
    };
  }

  private static boolean isJavaCompilerGetTaskCall(
      int opcode, String owner, String name, String descriptor) {
    if (name == null || !name.equals("getTask")) {
      return false;
    }
    if (opcode != Opcodes.INVOKEINTERFACE && opcode != Opcodes.INVOKEVIRTUAL) {
      return false;
    }
    if (!descriptor.equals(
        "(Ljava/io/Writer;Ljavax/tools/JavaFileManager;Ljavax/tools/DiagnosticListener;Ljava/lang/Iterable;Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljavax/tools/JavaCompiler$CompilationTask;")
        && !descriptor.equals(
            "(Ljava/io/Writer;Ljavax/tools/JavaFileManager;Ljavax/tools/DiagnosticListener;Ljava/lang/Iterable;Ljava/lang/Iterable;Ljava/lang/Iterable;)Lcom/sun/source/util/JavacTask;")) {
      return false;
    }
    return owner.equals("javax/tools/JavaCompiler")
        || owner.equals("com/sun/tools/javac/api/JavacTool");
  }

  private static boolean isSqlStringCall(
      int opcode, String owner, String name, String descriptor) {
    if (opcode != Opcodes.INVOKEINTERFACE && opcode != Opcodes.INVOKEVIRTUAL) {
      return false;
    }
    if (owner.equals("java/sql/Statement") && descriptor.startsWith("(Ljava/lang/String;")) {
      return name.equals("execute")
          || name.equals("executeQuery")
          || name.equals("executeUpdate")
          || name.equals("executeLargeUpdate")
          || name.equals("addBatch");
    }
    if (owner.equals("java/sql/Connection")
        && descriptor.equals("(Ljava/lang/String;)Ljava/sql/PreparedStatement;")) {
      return name.equals("prepareStatement") || name.equals("prepareCall") || name.equals("nativeSQL");
    }
    return false;
  }
}
