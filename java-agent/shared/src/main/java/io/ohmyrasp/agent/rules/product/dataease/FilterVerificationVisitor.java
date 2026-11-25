package io.ohmyrasp.agent.rules.product.dataease;

import java.util.HashSet;
import java.util.Set;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** Observe credential selection, verifier results and downstream dispatch in the product filter. */
public final class FilterVerificationVisitor extends AdviceAdapter {
  public static final String OWNER = "io/dataease/auth/filter/CommunityTokenFilter";
  private static final Type STATE = Type.getType(FilterVerification.class);
  private static final String DECODED = "Lcom/auth0/jwt/interfaces/DecodedJWT;";
  private final Set<Label> handlers = new HashSet<Label>();
  private final Type hooks;
  private final String chainType;
  private final String dispatch;
  private int state, input, request, response;
  private boolean atHandler;

  public static MethodVisitor wrap(MethodVisitor mv, int access, String name, String desc, Type hooks) {
    if (mv == null || (access & (ACC_ABSTRACT | ACC_NATIVE | ACC_STATIC)) != 0 || !"doFilter".equals(name)) return mv;
    for (String namespace : new String[]{"jakarta/servlet/", "javax/servlet/"}) {
      String args = "(L" + namespace + "ServletRequest;L" + namespace + "ServletResponse;";
      String chain = namespace + "FilterChain";
      if ((args + "L" + chain + ";)V").equals(desc))
        return new FilterVerificationVisitor(mv, access, name, desc, hooks, chain, args + ")V");
    }
    return mv;
  }

  private FilterVerificationVisitor(MethodVisitor mv, int access, String name, String desc,
      Type hooks, String chainType, String dispatch) {
    super(Opcodes.ASM9, mv, access, name, desc);
    this.hooks = hooks;
    this.chainType = chainType;
    this.dispatch = dispatch;
  }

  @Override protected void onMethodEnter() {
    newInstance(STATE);
    dup();
    loadArg(0);
    loadArg(2);
    invokeConstructor(STATE, Method.getMethod("void <init>(Object, Object)"));
    state = newLocal(STATE);
    storeLocal(state);
    Type[] args = Type.getArgumentTypes(dispatch);
    input = nullableLocal(Type.getType(String.class));
    request = nullableLocal(args[0]);
    response = nullableLocal(args[1]);
  }

  private int nullableLocal(Type type) {
    int slot = newLocal(type);
    visitInsn(ACONST_NULL);
    storeLocal(slot);
    return slot;
  }

  @Override public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
    handlers.add(handler);
    super.visitTryCatchBlock(start, end, handler, type);
  }

  @Override public void visitLabel(Label label) {
    super.visitLabel(label);
    atHandler = handlers.contains(label);
  }

  @Override public void visitFrame(int type, int locals, Object[] local, int stack, Object[] types) {
    super.visitFrame(type, locals, local, stack, types);
    if (atHandler && stack == 1) {
      dup();
      loadLocal(state);
      swap();
      invokeVirtual(STATE, Method.getMethod("void caught(Throwable)"));
    }
    atHandler = false;
  }

  private static boolean verifiesCredential(int op, String owner, String name, String desc) {
    if (!"verify".equals(name) || (op != INVOKEINTERFACE && op != INVOKEVIRTUAL)) return false;
    if ("com/auth0/jwt/algorithms/Algorithm".equals(owner)) return ("(" + DECODED + ")V").equals(desc);
    if (!"com/auth0/jwt/JWTVerifier".equals(owner) && !"com/auth0/jwt/interfaces/JWTVerifier".equals(owner)) return false;
    return ("(Ljava/lang/String;)" + DECODED).equals(desc) || ("(" + DECODED + ")" + DECODED).equals(desc);
  }

  @Override public void visitMethodInsn(int op, String owner, String name, String desc, boolean itf) {
    if (op == INVOKESTATIC && "io/dataease/utils/ServletUtils".equals(owner) && "getToken".equals(name)
        && "()Ljava/lang/String;".equals(desc)) {
      super.visitMethodInsn(op, owner, name, desc, itf);
      dup();
      loadLocal(state);
      swap();
      invokeVirtual(STATE, Method.getMethod("void selected(String)"));
    } else if (op == INVOKESTATIC && "com/auth0/jwt/JWT".equals(owner) && "decode".equals(name)
        && ("(Ljava/lang/String;)" + DECODED).equals(desc)) {
      dup();
      storeLocal(input);
      super.visitMethodInsn(op, owner, name, desc, itf);
      // Leave the decoder result on the application's stack and bind its identity to the input string.
      dup();
      loadLocal(state);
      swap();
      loadLocal(input);
      swap();
      invokeVirtual(STATE, Method.getMethod("void decoded(String, Object)"));
    } else if (verifiesCredential(op, owner, name, desc)) {
      dup();
      loadLocal(state);
      swap();
      invokeVirtual(STATE, Method.getMethod("void verifying(Object)"));
      super.visitMethodInsn(op, owner, name, desc, itf);
      loadLocal(state);
      invokeVirtual(STATE, Method.getMethod("void verified()"));
    } else if (op == INVOKEINTERFACE && chainType.equals(owner) && "doFilter".equals(name) && dispatch.equals(desc)) {
      storeLocal(response);
      storeLocal(request);
      // Preserve the original receiver and arguments for the interface invocation.
      dup();
      loadLocal(state);
      swap();
      loadLocal(request);
      invokeVirtual(STATE, Method.getMethod("String continuing(Object, Object)"));
      loadLocal(request);
      invokeStatic(hooks, Method.getMethod("void beforeDataEaseFilterContinuation(String, Object)"));
      loadLocal(request);
      loadLocal(response);
      super.visitMethodInsn(op, owner, name, desc, itf);
    } else {
      super.visitMethodInsn(op, owner, name, desc, itf);
    }
  }
}
