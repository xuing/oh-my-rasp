package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import java.util.HashMap;
import java.util.Map;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

final class SqlCallsiteClassVisitor extends ClassVisitor {
  private final ClassReader original;
  private Map<String, Integer> localLimits;

  SqlCallsiteClassVisitor(ClassReader original, ClassVisitor delegate) {
    super(OhMyRaspTransformer.api(), delegate);
    this.original = original;
  }

  // Only classes calling a multi-argument JDBC overload need scratch space.
  // Read the original limits once and append temporary slots after application locals.
  private int optionBase(String name, String descriptor) {
    if (localLimits == null) {
      localLimits = new HashMap<>();
      original.accept(new ClassVisitor(api) {
        @Override
        public MethodVisitor visitMethod(int access, String n, String desc, String sig, String[] exceptions) {
          return new MethodVisitor(api) {
            @Override
            public void visitMaxs(int maxStack, int maxLocals) {
              localLimits.put(n + desc, maxLocals);
            }
          };
        }
      }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    }
    return localLimits.get(name + descriptor);
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
          Type[] args = Type.getArgumentTypes(methodDescriptor);
          int base = args.length == 1 ? 0 : optionBase(name, descriptor);
          if (base + args.length - 1 > 65535) {
            super.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface);
            return;
          }
          for (int i = args.length - 1; i > 0; i--) {
            mv.visitVarInsn(args[i].getOpcode(Opcodes.ISTORE), base + i - 1);
          }
          super.visitInsn(Opcodes.DUP2);
          super.visitMethodInsn(
              Opcodes.INVOKESTATIC,
              "io/ohmyrasp/agent/hook/OhMyRaspHooks",
              "beforeSql",
              "(Ljava/lang/Object;Ljava/lang/String;)V",
              false);
          for (int i = 1; i < args.length; i++) {
            mv.visitVarInsn(args[i].getOpcode(Opcodes.ILOAD), base + i - 1);
          }
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
    if (owner.equals("java/sql/Connection")) return JdbcSqlMethod.preparesSql(name, descriptor);
    return owner.equals("java/sql/Statement") && JdbcSqlMethod.executesSql(name, descriptor);
  }
}
