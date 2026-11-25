package io.ohmyrasp.agent.file;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;

/** One portable Files entry can delegate to other entries and finally to the native channel. */
public final class FacadeReadVisitor {
  private FacadeReadVisitor() {}
  public static MethodVisitor wrap(MethodVisitor visitor, int access, String name, String descriptor,
      final Type hooks, final boolean channel) {
    return new ScopedMethodAdvice(Opcodes.ASM9, visitor, access, name, descriptor) {
      @Override protected void enterDispatch() {
        loadArg(0);
        if (channel) {
          loadArg(1);
          invokeStatic(hooks, Method.getMethod("void beginNioChannel(Object, Object)"));
        } else {
          invokeStatic(hooks, Method.getMethod("void beginNioRead(Object)"));
        }
      }
      @Override protected void exitDispatch() {
        invokeStatic(Type.getType(HostReadPath.class), Method.getMethod("void endFacade()"));
      }
    };
  }
}
