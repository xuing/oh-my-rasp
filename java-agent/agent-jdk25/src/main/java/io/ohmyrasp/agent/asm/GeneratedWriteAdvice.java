package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;

/** Observe the text the JDK materialized and the iterable elements it actually consumed. */
final class GeneratedWriteAdvice extends EntryAdvice {
  private static final String BYTES = "(Ljava/nio/file/Path;[B[Ljava/nio/file/OpenOption;)Ljava/nio/file/Path;";
  private static final Type STRING = Type.getType(String.class);
  private static final Type LINES = Type.getObjectType("io/ohmyrasp/agent/hook/GeneratedLineWrite");
  private final boolean lines;
  private int captured;

  private GeneratedWriteAdvice(MethodVisitor visitor, int access, String name, String desc, boolean lines) {
    super(visitor, access, name, desc);
    this.lines = lines;
  }

  static MethodVisitor wrap(MethodVisitor visitor, int access, String name, String desc) {
    boolean text = "writeString".equals(name) && desc.startsWith("(Ljava/nio/file/Path;Ljava/lang/CharSequence;Ljava/nio/charset/Charset;");
    boolean lines = "write".equals(name) && desc.startsWith("(Ljava/nio/file/Path;Ljava/lang/Iterable;Ljava/nio/charset/Charset;");
    return text || lines ? new GeneratedWriteAdvice(visitor, access, name, desc, lines) : visitor;
  }

  @Override protected void onMethodEnter() {
    captured = newLocal(lines ? LINES : STRING);
    if (lines) {
      loadArg(0);
      invokeHook("beginGeneratedLines", "(Ljava/lang/Object;)Lio/ohmyrasp/agent/hook/GeneratedLineWrite;");
    } else {
      visitInsn(ACONST_NULL);
    }
    storeLocal(captured);
  }

  @Override public void visitMethodInsn(int op, String owner, String name, String desc, boolean itf) {
    if (!lines && op == INVOKESTATIC && owner.equals("java/nio/file/Files") && name.equals("write") && desc.equals(BYTES)) {
      // The original stack holds path, encoded bytes and options. Keep all three intact.
      dup2(); pop();
      loadArg(0); loadLocal(captured); loadArg(2);
      invokeHook("beforeEncodedScriptWrite", "([BLjava/lang/Object;Ljava/lang/String;Ljava/nio/charset/Charset;)V");
    }
    if (lines && op == INVOKEVIRTUAL && owner.equals("java/io/BufferedWriter") && name.equals("append")
        && desc.equals("(Ljava/lang/CharSequence;)Ljava/io/Writer;")) {
      // Writer.append(CharSequence) writes String.valueOf(line). Preserve the one application conversion
      // and its exact text, including the distinction between a null line and an invalid null toString result.
      invokeStatic(STRING, Method.getMethod("String valueOf(Object)"));
      dup(); loadLocal(captured);
      invokeHook("beforeGeneratedLine", "(Ljava/lang/String;Lio/ohmyrasp/agent/hook/GeneratedLineWrite;)V");
      dup2();
      invokeVirtual(Type.getType(java.io.BufferedWriter.class), Method.getMethod("void write(String)"));
      pop(); // leave the original writer, as append does
      return;
    }
    super.visitMethodInsn(op, owner, name, desc, itf);
    if (!lines && op == Opcodes.INVOKESTATIC && owner.equals("java/lang/String") && name.equals("valueOf")
        && desc.equals("(Ljava/lang/Object;)Ljava/lang/String;")) {
      dup(); storeLocal(captured);
    }
  }
}
