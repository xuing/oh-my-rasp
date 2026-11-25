package io.ohmyrasp.agent.http;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Propagate a multipart collection through the element accesses the application itself performs. */
public final class MultipartCollectionVisitor extends ClassVisitor {
  private final String hooks;
  private boolean changed;

  public MultipartCollectionVisitor(ClassVisitor delegate, Type hooks) {
    super(Opcodes.ASM9, delegate);
    this.hooks = hooks.getInternalName();
  }

  public boolean changed() { return changed; }

  @Override public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exceptions) {
    MethodVisitor next = super.visitMethod(access, name, desc, sig, exceptions);
    if (next == null) return null;
    return new MethodVisitor(Opcodes.ASM9, next) {
      @Override public void visitMethodInsn(int op, String owner, String method, String descriptor, boolean itf) {
        boolean iterator = ("iterator".equals(method) && "()Ljava/util/Iterator;".equals(descriptor))
            || ("listIterator".equals(method) && "()Ljava/util/ListIterator;".equals(descriptor));
        boolean element = ("next".equals(method) || "previous".equals(method)) && "()Ljava/lang/Object;".equals(descriptor);
        boolean indexed = "get".equals(method) && "(I)Ljava/lang/Object;".equals(descriptor);
        if ((op != Opcodes.INVOKEVIRTUAL && op != Opcodes.INVOKEINTERFACE) || !(iterator || element || indexed)) {
          super.visitMethodInsn(op, owner, method, descriptor, itf);
          return;
        }
        changed = true;
        // Preserve the receiver for the receipt. No extra get, next, equals or iterator call.
        mv.visitInsn(indexed ? Opcodes.DUP2 : Opcodes.DUP);
        super.visitMethodInsn(op, owner, method, descriptor, itf);
        if (indexed) { mv.visitInsn(Opcodes.SWAP); mv.visitInsn(Opcodes.POP); }
        mv.visitInsn(Opcodes.DUP_X1);
        mv.visitInsn(iterator ? Opcodes.ICONST_1 : Opcodes.ICONST_0);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, hooks, "afterMultipartAccess", "(Ljava/lang/Object;Ljava/lang/Object;Z)V", false);
      }
    };
  }
}
