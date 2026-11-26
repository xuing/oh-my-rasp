package io.ohmyrasp.agent.sql;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

/** Observes the token result and the copies MyBatis itself makes while composing a JDBC template. */
public final class MyBatisSqlVisitor {
  private static final String PARSER = "org/apache/ibatis/parsing/GenericTokenParser";
  private static final String HANDLER = "org/apache/ibatis/parsing/TokenHandler";
  private static final String CONTEXT = "org/apache/ibatis/scripting/xmltags/DynamicContext";
  private static final String TRIM = "org/apache/ibatis/scripting/xmltags/TrimSqlNode$FilteredDynamicContext";
  private static final String PAGE_DIALECT = "com/github/pagehelper/dialect/";
  private static final String SQL_SOURCE = "org/apache/ibatis/builder/SqlSourceBuilder";
  private static final String BASE_HANDLER = "org/apache/ibatis/executor/statement/BaseStatementHandler";
  private static final String SIMPLE_HANDLER = "org/apache/ibatis/executor/statement/SimpleStatementHandler";
  private static final String BOUND = "org/apache/ibatis/mapping/BoundSql";
  private static final String BUILDER = "java/lang/StringBuilder";
  private static final String TRACE = Type.getInternalName(MyBatisSqlTrace.class);

  private MyBatisSqlVisitor() {}

  public static boolean matches(String owner) {
    return PARSER.equals(owner) || CONTEXT.equals(owner) || TRIM.equals(owner) || BOUND.equals(owner)
        || SQL_SOURCE.equals(owner) || BASE_HANDLER.equals(owner) || SIMPLE_HANDLER.equals(owner)
        || owner.startsWith(PAGE_DIALECT);
  }

  public static MethodVisitor wrap(final String owner, MethodVisitor delegate, int access,
      String name, String desc, final String hooks) {
    if ((BASE_HANDLER.equals(owner) && name.equals("prepare")
          && desc.equals("(Ljava/sql/Connection;Ljava/lang/Integer;)Ljava/sql/Statement;"))
        || (SIMPLE_HANDLER.equals(owner) && desc.startsWith("(Ljava/sql/Statement;")
          && (name.equals("batch") || name.equals("query") || name.equals("queryCursor") || name.equals("update")))) {
      return new ScopedMethodAdvice(Opcodes.ASM9, delegate, access, name, desc) {
        @Override protected void enterDispatch() {
          loadThis();
          getField(Type.getObjectType(BASE_HANDLER), "boundSql", Type.getObjectType(BOUND));
          mv.visitMethodInsn(INVOKESTATIC, TRACE, "enterStatement", "(Ljava/lang/Object;)V", false);
        }
        @Override protected void exitDispatch() {
          mv.visitMethodInsn(INVOKESTATIC, TRACE, "exitStatement", "()V", false);
        }
      };
    }
    final boolean compact = SQL_SOURCE.equals(owner) && name.equals("removeExtraWhitespaces")
        && desc.equals("(Ljava/lang/String;)Ljava/lang/String;");
    final boolean parse = PARSER.equals(owner) && name.equals("parse") && desc.equals("(Ljava/lang/String;)Ljava/lang/String;");
    final boolean append = CONTEXT.equals(owner) && name.equals("appendSql") && desc.equals("(Ljava/lang/String;)V");
    final boolean sql = CONTEXT.equals(owner) && name.equals("getSql") && desc.equals("()Ljava/lang/String;");
    final boolean page = owner.startsWith(PAGE_DIALECT) && name.equals("getPageSql")
        && (desc.equals("(Ljava/lang/String;Lcom/github/pagehelper/Page;Lorg/apache/ibatis/cache/CacheKey;)Ljava/lang/String;")
            || desc.equals("(Ljava/lang/String;Lorg/apache/ibatis/session/RowBounds;Lorg/apache/ibatis/cache/CacheKey;)Ljava/lang/String;")
            // PageHelper 4.2.x: the dialects are com.github.pagehelper.dialect.*Dialect and take both.
            || desc.equals("(Ljava/lang/String;Lcom/github/pagehelper/Page;Lorg/apache/ibatis/session/RowBounds;Lorg/apache/ibatis/cache/CacheKey;)Ljava/lang/String;"));
    final boolean trim = TRIM.equals(owner) && !name.equals("<init>");
    final boolean returned = BOUND.equals(owner) && name.equals("getSql") && desc.equals("()Ljava/lang/String;");
    final boolean compiled = BOUND.equals(owner) && name.equals("<init>") && desc.equals(
        "(Lorg/apache/ibatis/session/Configuration;Ljava/lang/String;Ljava/util/List;Ljava/lang/Object;)V");
    if (!parse && !append && !sql && !compiled && !trim && !returned && !compact && !page) return delegate;
    MethodVisitor copies = new AdviceAdapter(Opcodes.ASM9, delegate, access, name, desc) {
      @Override
      public void visitMethodInsn(int opcode, String target, String method, String descriptor, boolean itf) {
        if (parse && opcode == INVOKEVIRTUAL && BUILDER.equals(target) && method.equals("append")
            && descriptor.equals("([CII)Ljava/lang/StringBuilder;")) {
          mv.visitMethodInsn(INVOKESTATIC, TRACE, "appendSlice",
              "(Ljava/lang/StringBuilder;[CII)Ljava/lang/StringBuilder;", false);
          return;
        }
        if ((append || trim || page) && opcode == INVOKEVIRTUAL && BUILDER.equals(target) && method.equals("append")
            && descriptor.equals("(Ljava/lang/String;)Ljava/lang/StringBuilder;")) {
          mv.visitMethodInsn(INVOKESTATIC, TRACE, "appendPiece",
              "(Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
          return;
        }
        if (append && opcode == INVOKEVIRTUAL && target.equals("java/util/StringJoiner") && method.equals("add")
            && descriptor.equals("(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;")) {
          mv.visitMethodInsn(INVOKESTATIC, TRACE, "joinPiece",
              "(Ljava/util/StringJoiner;Ljava/lang/CharSequence;)Ljava/util/StringJoiner;", false);
          return;
        }
        if (parse && opcode == INVOKEVIRTUAL && target.equals("java/lang/String") && method.equals("toCharArray")
            && descriptor.equals("()[C")) {
          dup();
          super.visitMethodInsn(opcode, target, method, descriptor, itf);
          dupX1();
          mv.visitMethodInsn(INVOKESTATIC, TRACE, "characters", "(Ljava/lang/String;[C)V", false);
          return;
        }
        if ((trim || page) && BUILDER.equals(target)) {
          if (opcode == INVOKESPECIAL && method.equals("<init>") && descriptor.equals("(Ljava/lang/String;)V")) {
            int builder = newLocalMapping(Type.getObjectType(BUILDER));
            int text = newLocalMapping(Type.getType(String.class));
            dup2();
            mv.visitVarInsn(ASTORE, text);
            mv.visitVarInsn(ASTORE, builder);
            super.visitMethodInsn(opcode, target, method, descriptor, itf);
            mv.visitVarInsn(ALOAD, builder);
            mv.visitVarInsn(ALOAD, text);
            mv.visitMethodInsn(INVOKESTATIC, TRACE, "initialized", "(Ljava/lang/StringBuilder;Ljava/lang/String;)V", false);
            return;
          }
          if (opcode == INVOKEVIRTUAL && method.equals("delete") && descriptor.equals("(II)Ljava/lang/StringBuilder;")) {
            mv.visitMethodInsn(INVOKESTATIC, TRACE, method, "(Ljava/lang/StringBuilder;II)Ljava/lang/StringBuilder;", false);
            return;
          }
          if (opcode == INVOKEVIRTUAL && method.equals("insert") && descriptor.equals("(ILjava/lang/String;)Ljava/lang/StringBuilder;")) {
            mv.visitMethodInsn(INVOKESTATIC, TRACE, method, "(Ljava/lang/StringBuilder;ILjava/lang/String;)Ljava/lang/StringBuilder;", false);
            return;
          }
        }
        boolean built = (parse || sql || trim || page) && (BUILDER.equals(target) || "java/util/StringJoiner".equals(target))
            && method.equals("toString");
        boolean trimmed = (sql || trim) && target.equals("java/lang/String") && method.equals("trim");
        if ((built || trimmed) && opcode == INVOKEVIRTUAL && descriptor.equals("()Ljava/lang/String;")) {
          dup();
          super.visitMethodInsn(opcode, target, method, descriptor, itf);
          dupX1();
          mv.visitMethodInsn(INVOKESTATIC, TRACE, built ? "built" : "trimmed",
              built ? "(Ljava/lang/Object;Ljava/lang/String;)V" : "(Ljava/lang/String;Ljava/lang/String;)V", false);
          return;
        }
        super.visitMethodInsn(opcode, target, method, descriptor, itf);
      }

      @Override protected void onMethodExit(int opcode) {
        if (compiled && opcode == RETURN) {
          loadThis();
          loadArg(1);
          mv.visitMethodInsn(INVOKESTATIC, TRACE, "compiled", "(Ljava/lang/Object;Ljava/lang/String;)V", false);
        } else if (compact && opcode == ARETURN) {
          dup();
          loadArg(0);
          swap();
          mv.visitMethodInsn(INVOKESTATIC, TRACE, "compacted", "(Ljava/lang/String;Ljava/lang/String;)V", false);
        } else if (returned && opcode == ARETURN) {
          dup();
          loadThis();
          swap();
          mv.visitMethodInsn(INVOKESTATIC, TRACE, "returnedSql", "(Ljava/lang/Object;Ljava/lang/String;)V", false);
        }
      }
    };
    if (!parse) return copies;
    // Require the verified stack shape: the handler result is immediately
    // appended to the builder. Other parser implementations pass unchanged.
    return new MethodNode(Opcodes.ASM9, access, name, desc, null, null) {
      @Override public void visitEnd() {
        int handlerSlot = maxLocals;
        if (handlerSlot <= 65532) {
          for (AbstractInsnNode insn : instructions.toArray()) {
            if (!call(insn, Opcodes.INVOKEINTERFACE, HANDLER, "handleToken", "(Ljava/lang/String;)Ljava/lang/String;")
                || !call(insn.getNext(), Opcodes.INVOKEVIRTUAL, BUILDER, "append",
                    "(Ljava/lang/String;)Ljava/lang/StringBuilder;")) continue;
            AbstractInsnNode appendCall = insn.getNext();
            InsnList save = new InsnList();
            save.add(new InsnNode(Opcodes.DUP2));
            save.add(new VarInsnNode(Opcodes.ASTORE, handlerSlot + 1));
            save.add(new VarInsnNode(Opcodes.ASTORE, handlerSlot));
            instructions.insertBefore(insn, save);
            InsnList keepValue = new InsnList();
            keepValue.add(new InsnNode(Opcodes.DUP));
            keepValue.add(new VarInsnNode(Opcodes.ASTORE, handlerSlot + 2));
            instructions.insert(insn, keepValue);
            InsnList observe = new InsnList();
            observe.add(new InsnNode(Opcodes.DUP));
            observe.add(new VarInsnNode(Opcodes.ALOAD, handlerSlot + 2));
            observe.add(new VarInsnNode(Opcodes.ALOAD, handlerSlot));
            observe.add(new VarInsnNode(Opcodes.ALOAD, handlerSlot + 1));
            observe.add(new MethodInsnNode(Opcodes.INVOKESTATIC, hooks, "observeMyBatisSubstitution",
                "(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;)V", false));
            instructions.insert(appendCall, observe);
            maxLocals = handlerSlot + 3;
          }
        }
        accept(copies);
      }
    };
  }

  private static boolean call(AbstractInsnNode node, int opcode, String owner, String method, String desc) {
    if (!(node instanceof MethodInsnNode) || node.getOpcode() != opcode) return false;
    MethodInsnNode invocation = (MethodInsnNode) node;
    return owner.equals(invocation.owner) && method.equals(invocation.name) && desc.equals(invocation.desc);
  }
}
