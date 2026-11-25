package io.ohmyrasp.agent.naming;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** Observe the exact string the JDK uses to choose a URL scheme, without invoking Name methods. */
public final class JndiLookupVisitor {
  public static final String INITIAL = "javax/naming/InitialContext";
  public static final String LOGIN_MODULE = "com/sun/security/auth/module/JndiLoginModule";
  public static final String URL_CONTEXT = "com/sun/jndi/toolkit/url/GenericURLContext";
  private static final Type ROUTE = Type.getType(LookupRoute.class);
  private static final String STRING = "Ljava/lang/String;";
  private JndiLookupVisitor() {}

  public static boolean target(String owner) { return INITIAL.equals(owner) || URL_CONTEXT.equals(owner) || LOGIN_MODULE.equals(owner); }

  public static MethodVisitor wrap(String owner, MethodVisitor mv, int access, final String name, String desc, final Type hooks) {
    if (LOGIN_MODULE.equals(owner) && "attemptAuthentication".equals(name) && "(Z)V".equals(desc)) {
      return new MethodVisitor(Opcodes.ASM9, mv) {
        @Override public void visitMethodInsn(int op, String callee, String method, String signature, boolean itf) {
          if (op == Opcodes.INVOKEVIRTUAL && INITIAL.equals(callee) && "lookup".equals(method)
              && "(Ljava/lang/String;)Ljava/lang/Object;".equals(signature)) {
            super.visitMethodInsn(Opcodes.INVOKESTATIC, ROUTE.getInternalName(), "loginLookup",
                "(Ljavax/naming/InitialContext;Ljava/lang/String;)Ljava/lang/Object;", false);
          } else {
            super.visitMethodInsn(op, callee, method, signature, itf);
          }
        }
      };
    }
    boolean lookup = "lookup".equals(name) || "lookupLink".equals(name);
    boolean string = desc.startsWith("(" + STRING + ")");
    boolean named = desc.startsWith("(Ljavax/naming/Name;)");
    if (INITIAL.equals(owner) && lookup && (string || named) && desc.endsWith(")Ljava/lang/Object;")) {
      return new ScopedMethodAdvice(Opcodes.ASM9, mv, access, name, desc) {
        @Override protected void enterDispatch() {
          loadThis(); loadArg(0); push("InitialContext." + name);
          invokeStatic(ROUTE, Method.getMethod("void enter(Object, Object, String)"));
        }
        @Override protected void exitDispatch() { invokeStatic(ROUTE, Method.getMethod("void exit()")); }
        @Override public void visitMethodInsn(int op, String callee, String method, String signature, boolean itf) {
          if (op == INVOKEINTERFACE && "javax/naming/Context".equals(callee) && name.equals(method) && desc.equals(signature)) {
            dup2();
            invokeStatic(ROUTE, Method.getMethod("void dispatch(Object, Object)"));
          }
          super.visitMethodInsn(op, callee, method, signature, itf);
        }
      };
    }
    if (INITIAL.equals(owner) && "getURLOrDefaultInitCtx".equals(name) && (string || named)
        && desc.endsWith(")Ljavax/naming/Context;")) {
      return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
        @Override public void visitMethodInsn(int op, String callee, String method, String signature, boolean itf) {
          if (op == INVOKESTATIC && INITIAL.equals(callee) && "getURLScheme".equals(method)
              && "(Ljava/lang/String;)Ljava/lang/String;".equals(signature)) {
            dup(); dup();
            super.visitMethodInsn(op, callee, method, signature, itf);
            // Leave the computed scheme on the application stack and pass the original component to the hook.
            dupX2();
            loadThis(); loadArg(0);
            invokeStatic(ROUTE, Method.getMethod("String selecting(String, String, Object, Object)"));
            invokeStatic(hooks, Method.getMethod("void onJndiRoute(String, String)"));
            return;
          }
          super.visitMethodInsn(op, callee, method, signature, itf);
        }
      };
    }
    if (URL_CONTEXT.equals(owner) && lookup && string && desc.endsWith(")Ljava/lang/Object;")) {
      return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
        @Override public void visitMethodInsn(int op, String callee, String method, String signature, boolean itf) {
          if (op == INVOKEVIRTUAL && URL_CONTEXT.equals(callee) && "getRootURLContext".equals(method)
              && "(Ljava/lang/String;Ljava/util/Hashtable;)Ljavax/naming/spi/ResolveResult;".equals(signature)) {
            dup2(); pop(); loadThis(); push("URLContext." + name);
            invokeStatic(hooks, Method.getMethod("void beforeJndiProviderLookup(String, Object, String)"));
          }
          super.visitMethodInsn(op, callee, method, signature, itf);
        }
      };
    }
    return mv;
  }
}
