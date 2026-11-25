package io.ohmyrasp.agent.file;

import io.ohmyrasp.agent.rules.general.PlotWrite;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** Capture the private open result and inspect the bytes submitted to FileOutputStream's native write. */
public final class PlotWriteVisitor {
  public static final String OWNER = "java/io/FileOutputStream";
  private static final Type STATE = Type.getType(PlotWrite.class);
  private static final Method INSPECT = Method.getMethod("void inspectPlotWrite(io.ohmyrasp.agent.rules.general.PlotWrite)");

  private PlotWriteVisitor() {}

  public static MethodVisitor wrap(MethodVisitor visitor, int access, String name, String desc, final Type hooks) {
    boolean open = "open".equals(name) && "(Ljava/lang/String;Z)V".equals(desc);
    boolean close = "close".equals(name) && "()V".equals(desc);
    boolean expose = ("getFD".equals(name) && "()Ljava/io/FileDescriptor;".equals(desc))
        || ("getChannel".equals(name) && "()Ljava/nio/channels/FileChannel;".equals(desc));
    if (open || close || expose) {
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, desc) {
        @Override protected void onMethodEnter() {
          if (close || expose) {
            loadThis(); invokeStatic(STATE, Method.getMethod(close ? "void closed(Object)" : "void exposed(Object)"));
          }
        }
        @Override protected void onMethodExit(int opcode) {
          if (open && opcode == RETURN) {
            loadThis(); loadArg(0); loadArg(1); invokeStatic(STATE, Method.getMethod("void opened(Object,String,boolean)"));
          }
        }
      };
    }
    if (!"write".equals(name) || !(desc.equals("([B)V") || desc.equals("([BII)V") || desc.equals("(I)V"))) return visitor;
    return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, desc) {
      private int pending;
      private final Label body = new Label();
      @Override protected void onMethodEnter() {
        pending = newLocal(STATE);
        visitInsn(ACONST_NULL); checkCast(STATE); storeLocal(pending); mark(body);
      }

      @Override public void visitMethodInsn(int opcode, String target, String method, String descriptor, boolean itf) {
        boolean single = "write".equals(method) && "(IZ)V".equals(descriptor);
        boolean bytes = "writeBytes".equals(method) && "([BIIZ)V".equals(descriptor);
        if (!OWNER.equals(target) || !(single || bytes)) {
          super.visitMethodInsn(opcode, target, method, descriptor, itf);
          return;
        }
        // Preserve the actual operands on the native call, including the JDK's slice bounds.
        int append = save(Type.BOOLEAN_TYPE);
        int length = bytes ? save(Type.INT_TYPE) : -1;
        int offset = bytes ? save(Type.INT_TYPE) : -1;
        int data = save(bytes ? Type.getType(byte[].class) : Type.INT_TYPE);
        dup(); loadLocal(data);
        if (single) {
          invokeStatic(STATE, Method.getMethod("io.ohmyrasp.agent.rules.general.PlotWrite single(Object,int)"));
        } else {
          loadLocal(offset); loadLocal(length);
          invokeStatic(STATE, Method.getMethod("io.ohmyrasp.agent.rules.general.PlotWrite bytes(Object,byte[],int,int)"));
        }
        dup(); invokeStatic(hooks, INSPECT); storeLocal(pending);
        loadLocal(data);
        if (bytes) { loadLocal(offset); loadLocal(length); }
        loadLocal(append);
        super.visitMethodInsn(opcode, target, method, descriptor, itf);
        finish(true);
        visitInsn(ACONST_NULL); checkCast(STATE); storeLocal(pending);
      }

      private int save(Type type) {
        int local = newLocal(type);
        storeLocal(local);
        return local;
      }

      private void finish(boolean success) {
        loadLocal(pending); push(success);
        invokeStatic(STATE, Method.getMethod("void finished(io.ohmyrasp.agent.rules.general.PlotWrite,boolean)"));
      }

      @Override public void visitMaxs(int maxStack, int maxLocals) {
        // Allow the JDK's own native-call cleanup to run first.
        Label end = mark();
        catchException(body, end, Type.getType(Throwable.class));
        finish(false);
        throwException();
        super.visitMaxs(maxStack, maxLocals);
      }
    };
  }
}
