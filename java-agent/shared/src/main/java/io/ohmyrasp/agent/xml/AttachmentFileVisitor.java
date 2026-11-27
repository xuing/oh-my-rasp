package io.ohmyrasp.agent.xml;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

public final class AttachmentFileVisitor {
  private static final String READER = "org/apache/cxf/aegis/type/mtom/AttachmentUtil";
  private static final Type OBSERVER = Type.getType(AttachmentFileRead.class);

  private AttachmentFileVisitor() {}

  public static boolean matches(String owner) {
    return READER.equals(owner) || "javax/activation/URLDataSource".equals(owner)
        || "jakarta/activation/URLDataSource".equals(owner);
  }

  public static MethodVisitor wrap(String owner, MethodVisitor visitor, int access, String name, String descriptor, final Type hooks) {
    final boolean reader = READER.equals(owner);
    if (reader && !(name.equals("getAttachment")
        && descriptor.equals("(Ljava/lang/String;Ljava/util/Collection;)Lorg/apache/cxf/message/Attachment;"))) return visitor;
    if (!reader && name.equals("<init>") && descriptor.equals("(Ljava/net/URL;)V")) {
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        @Override protected void onMethodExit(int opcode) {
          if (opcode == RETURN) {
            loadThis();
            loadArg(0);
            invokeStatic(OBSERVER, Method.getMethod("void created(Object, java.net.URL)"));
          }
        }
      };
    }
    if (!reader && !(name.equals("getInputStream") && descriptor.equals("()Ljava/io/InputStream;"))) return visitor;
    return new ScopedMethodAdvice(Opcodes.ASM9, visitor, access, name, descriptor, true) {
      @Override protected void enterDispatch() {
        if (reader) {
          loadArg(0);
          invokeStatic(hooks, Method.getMethod("Object beginAttachmentReference(String)"));
        } else {
          loadThis();
          invokeStatic(OBSERVER, Method.getMethod("Object beginRead(Object)"));
        }
      }
      @Override protected void exitDispatch() {
        loadToken();
        invokeStatic(OBSERVER, Method.getMethod(reader ? "void endReference(Object)" : "void endRead(Object)"));
      }
    };
  }
}
