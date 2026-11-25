package io.ohmyrasp.agent.rules.product.yarn;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** Check the submitting request only once the ResourceManager has prepared its internal request. */
public final class YarnSubmitVisitor {
  public static final String OWNER = "org/apache/hadoop/yarn/server/resourcemanager/webapp/RMWebServices";
  private static final String INFO = "Lorg/apache/hadoop/yarn/server/resourcemanager/webapp/dao/ApplicationSubmissionContextInfo;";
  private static final String REQUEST = "org/apache/hadoop/yarn/api/protocolrecords/SubmitApplicationRequest";
  private static final String FACTORY = "(Lorg/apache/hadoop/yarn/api/records/ApplicationSubmissionContext;)L" + REQUEST + ";";

  private YarnSubmitVisitor() {}

  public static MethodVisitor wrap(MethodVisitor mv, int access, String name, String desc, Type hooks) {
    if (mv == null || !"submitApplication".equals(name) || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_STATIC)) != 0) return mv;
    for (String namespace : new String[]{"javax", "jakarta"}) {
      String servletType = namespace + "/servlet/http/HttpServletRequest";
      if (!("(" + INFO + "L" + servletType + ";)L" + namespace + "/ws/rs/core/Response;").equals(desc)) continue;
      return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
        @Override public void visitMethodInsn(int op, String owner, String method, String signature, boolean itf) {
          super.visitMethodInsn(op, owner, method, signature, itf);
          if (op == INVOKESTATIC && REQUEST.equals(owner) && "newInstance".equals(method) && FACTORY.equals(signature)) {
            dup();
            loadArg(1);
            push(Type.getObjectType(servletType));
            invokeStatic(hooks, Method.getMethod("void afterYarnSubmitPrepared(Object, Object, Class)"));
          }
        }
      };
    }
    return mv;
  }
}
