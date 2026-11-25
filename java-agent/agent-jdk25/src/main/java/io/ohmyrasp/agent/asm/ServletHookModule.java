package io.ohmyrasp.agent.asm;

import io.ohmyrasp.agent.hook.OhMyRaspHooks;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;

final class ServletHookModule implements HookModule {
  private static final String JAKARTA_SERVICE =
      "(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V";
  private static final String JAVAX_SERVICE =
      "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V";
  private static final String JAKARTA_GENERIC_SERVICE =
      "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V";
  private static final String JAVAX_GENERIC_SERVICE =
      "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V";

  @Override
  public boolean matchesClass(String className) {
    return className.equals("jakarta/servlet/http/HttpServlet")
        || className.equals("javax/servlet/http/HttpServlet");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (methodName.equals("service")
        && (descriptor.equals(JAKARTA_SERVICE)
            || descriptor.equals(JAVAX_SERVICE)
            || descriptor.equals(JAKARTA_GENERIC_SERVICE)
            || descriptor.equals(JAVAX_GENERIC_SERVICE))) {
      return new ServletDispatchAdvice(OhMyRaspTransformer.api(), methodVisitor, access, methodName, descriptor) {
        @Override
        protected void enterDispatch() {
          loadArg(0);
          loadArg(1);
          push(descriptor.equals(JAKARTA_GENERIC_SERVICE) || descriptor.equals(JAVAX_GENERIC_SERVICE));
          invokeStatic(Type.getType(OhMyRaspHooks.class),
              new Method("admitServletRequest", "(Ljava/lang/Object;Ljava/lang/Object;Z)Z"));
          var admitted = newLabel();
          ifZCmp(NE, admitted);
          // Denied entry already restored the parent dispatch. Skip normal method-exit cleanup.
          mv.visitInsn(RETURN);
          mark(admitted);
          Type[] args = Type.getArgumentTypes(descriptor);
          mv.visitFrame(F_NEW, 3, new Object[]{className, args[0].getInternalName(), args[1].getInternalName()}, 0, null);
        }

        @Override
        protected void exitDispatch() {
          invokeStatic(Type.getType(OhMyRaspHooks.class), new Method("exitHttpRequest", "()V"));
        }
      };
    }
    return methodVisitor;
  }
}
