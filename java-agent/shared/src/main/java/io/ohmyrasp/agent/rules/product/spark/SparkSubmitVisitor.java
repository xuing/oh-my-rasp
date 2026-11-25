package io.ohmyrasp.agent.rules.product.spark;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** The servlet passes its parsed, validated message to the virtual submission handler here. */
public final class SparkSubmitVisitor {
  public static final String OWNER = "org/apache/spark/deploy/rest/SubmitRequestServlet";
  private static final String REST = "org/apache/spark/deploy/rest/";
  private SparkSubmitVisitor() {}

  public static MethodVisitor wrap(MethodVisitor mv, int access, String name, String desc, Type hooks) {
    if (mv == null || !"doPost".equals(name) || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_STATIC)) != 0) return mv;
    for (String namespace : new String[]{"javax", "jakarta"}) {
      String http = namespace + "/servlet/http/HttpServlet";
      String response = "L" + http + "Response;";
      if (!("(L" + http + "Request;" + response + ")V").equals(desc)) continue;
      String submit = "(Ljava/lang/String;L" + REST + "SubmitRestProtocolMessage;" + response + ")L"
          + REST + "SubmitRestProtocolResponse;";
      return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
        @Override public void visitMethodInsn(int op, String owner, String method, String signature, boolean itf) {
          if (op == INVOKEVIRTUAL && OWNER.equals(owner) && "handleSubmit".equals(method) && submit.equals(signature)) {
            // The top pair is the parsed message and response. Preserve the original invocation operands.
            dup2();
            pop();
            instanceOf(Type.getObjectType(REST + "CreateSubmissionRequest"));
            loadArg(0);
            push(Type.getObjectType(http + "Request"));
            invokeStatic(hooks, Method.getMethod("void beforeSparkSubmitDispatch(boolean, Object, Class)"));
          }
          super.visitMethodInsn(op, owner, method, signature, itf);
        }
      };
    }
    return mv;
  }
}
