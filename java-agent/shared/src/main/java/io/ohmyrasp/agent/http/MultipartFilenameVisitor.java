package io.ohmyrasp.agent.http;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;

public final class MultipartFilenameVisitor {
  private static final String PART_NAME = "getSubmittedFileName";
  private static final String SPRING_NAME = "getOriginalFilename";
  private static final String[] NAMES = {PART_NAME, SPRING_NAME, "getPart", "getParts", "getFile", "getFiles"};
  private static final Type SCOPE = Type.getType(MultipartFilename.class);
  private MultipartFilenameVisitor() {}

  public static boolean known(String owner, boolean backport) {
    return requestWrapper(owner) || owner.equals("javax/servlet/http/Part") || owner.equals("jakarta/servlet/http/Part")
        || owner.equals("org/apache/catalina/core/ApplicationPart") || owner.equals("io/undertow/servlet/spec/PartImpl")
        || owner.equals("org/apache/commons/fileupload/disk/DiskFileItem")
        || owner.equals("org/eclipse/jetty/util/MultiPartInputStreamParser$MultiPart")
        || owner.equals("org/eclipse/jetty/server/MultiPartFormInputStream$MultiPart")
        // Jetty 12 moved the servlet layer out of jetty-server: ee8, ee9 and ee10/ee11 each carry their own.
        || owner.equals("org/eclipse/jetty/ee8/nested/MultiPartFormInputStream$MultiPart")
        || owner.equals("org/eclipse/jetty/ee8/nested/MultiPartInputStreamLegacyParser$MultiPart")
        || owner.equals("org/eclipse/jetty/ee9/nested/MultiPartFormInputStream$MultiPart")
        || owner.equals("org/eclipse/jetty/ee9/nested/MultiPartInputStreamLegacyParser$MultiPart")
        || owner.equals("org/eclipse/jetty/ee10/servlet/ServletMultiPartFormData$ServletPart")
        || owner.equals("org/eclipse/jetty/ee11/servlet/ServletMultiPartFormData$ServletPart")
        || (backport && (owner.equals("org/glassfish/jersey/media/multipart/ContentDisposition")
            || owner.equals("org/springframework/web/multipart/MultipartFile")
            || owner.equals("org/springframework/web/multipart/commons/CommonsMultipartFile")
            || owner.equals("org/springframework/web/multipart/support/StandardMultipartHttpServletRequest$StandardMultipartFile")
            || owner.equals("org/springframework/mock/web/MockMultipartFile")));
  }

  private static boolean requestWrapper(String owner) {
    return owner.equals("javax/servlet/ServletRequestWrapper") || owner.equals("jakarta/servlet/ServletRequestWrapper");
  }

  private static int lookup(String name, String descriptor) {
    // Concrete implementations can return a covariant part or collection. The runtime
    // checks the source contract and the result before it records the handoff.
    if (name.equals("getPart") && descriptor.startsWith("(Ljava/lang/String;)L")) return MultipartFilename.SERVLET_REQUEST;
    if (name.equals("getParts") && descriptor.startsWith("()L")) return MultipartFilename.SERVLET_REQUEST;
    if (name.equals("getFile") && descriptor.startsWith("(Ljava/lang/String;)L")) return MultipartFilename.SPRING_REQUEST;
    if (name.equals("getFiles") && descriptor.startsWith("(Ljava/lang/String;)L")) return MultipartFilename.SPRING_REQUEST;
    return 0;
  }

  public static boolean specificGetter(String name, String descriptor) {
    return ("()Ljava/lang/String;".equals(descriptor) && (PART_NAME.equals(name) || SPRING_NAME.equals(name)))
        || lookup(name, descriptor) != 0;
  }

  /** Check UTF-8 constants without decoding application classes or resolving their dependencies. */
  public static boolean mentionsGetter(ClassReader reader) {
    for (int i = 1; i < reader.getItemCount(); i++) {
      int entry = reader.getItem(i);
      if (entry == 0 || reader.readByte(entry - 1) != 1) continue;
      int size = reader.readUnsignedShort(entry);
      for (String name : NAMES) {
        if (size != name.length()) continue;
        int j = 0;
        while (j < size && reader.readByte(entry + 2 + j) == name.charAt(j)) j++;
        if (j == size) return true;
      }
    }
    return false;
  }

  /** Only multipart-aware callers need collection receipt instrumentation. */
  public static boolean multipartCaller(ClassReader reader) {
    for (int i = 1; i < reader.getItemCount(); i++) {
      int entry = reader.getItem(i);
      if (entry == 0 || reader.readByte(entry - 1) != 1) continue;
      int length = reader.readUnsignedShort(entry);
      for (String type : CALLER_TYPES) {
        if (length != type.length()) continue;
        int j = 0;
        while (j < length && reader.readByte(entry + 2 + j) == type.charAt(j)) j++;
        if (j == length) return true;
      }
    }
    return false;
  }

  private static final String[] CALLER_TYPES = {
      "javax/servlet/http/Part", "jakarta/servlet/http/Part", "org/springframework/web/multipart/MultipartFile",
      "getParts", "getSubmittedFileName", "getOriginalFilename", "org/springframework/web/multipart/MultipartRequest"
  };

  public static MethodVisitor wrap(String owner, MethodVisitor visitor, int access, String name, String descriptor,
      final Type hooks, boolean backport) {
    if ((access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_STATIC)) != 0) return visitor;
    if (requestWrapper(owner) && (name.equals("<init>") || name.equals("setRequest"))) {
      return new MethodVisitor(Opcodes.ASM9, visitor) {
        @Override public void visitFieldInsn(int op, String fieldOwner, String field, String desc) {
          if (op == Opcodes.PUTFIELD && owner.equals(fieldOwner)
              && ("Ljavax/servlet/ServletRequest;".equals(desc) || "Ljakarta/servlet/ServletRequest;".equals(desc))) {
            mv.visitInsn(Opcodes.DUP2);
            super.visitFieldInsn(op, fieldOwner, field, desc);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, SCOPE.getInternalName(), "wrapped", "(Ljava/lang/Object;Ljava/lang/Object;)V", false);
          } else super.visitFieldInsn(op, fieldOwner, field, desc);
        }
      };
    }
    final int source = lookup(name, descriptor);
    if (source != 0) {
      final boolean bulk = name.equals("getParts") || name.equals("getFiles");
      return new org.objectweb.asm.commons.AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        @Override protected void onMethodExit(int op) {
          if (op == ARETURN) {
            dup(); loadThis(); push(source); push(bulk);
            invokeStatic(hooks, Method.getMethod("void afterMultipartLookup(Object, Object, int, boolean)"));
          }
        }
      };
    }
    if (!"()Ljava/lang/String;".equals(descriptor)) return visitor;
    boolean known = known(owner, backport);
    final int kind;
    if (PART_NAME.equals(name)) kind = MultipartFilename.PART;
    else if (SPRING_NAME.equals(name)) kind = MultipartFilename.SPRING;
    else if ((owner.equals("org/apache/commons/fileupload/disk/DiskFileItem") && name.equals("getName"))
        || (backport && owner.equals("org/glassfish/jersey/media/multipart/ContentDisposition") && name.equals("getFileName"))) {
      kind = MultipartFilename.KNOWN;
    } else return visitor;
    // New implementation coverage is limited to archive authorization, which has an explicit deployment policy.
    final boolean archiveOnly = !known || (!backport && kind == MultipartFilename.SPRING);
    return new ScopedMethodAdvice(Opcodes.ASM9, visitor, access, name, descriptor, true) {
      @Override protected void enterDispatch() {
        loadThis(); push(kind);
        invokeStatic(SCOPE, Method.getMethod("Object enter(Object, int)"));
      }
      @Override public void visitInsn(int opcode) {
        if (opcode == ARETURN) {
          dup(); push(archiveOnly);
          invokeStatic(hooks, Method.getMethod("void inspectMultipartFilename(String, boolean)"));
        }
        super.visitInsn(opcode);
      }
      @Override protected void exitDispatch() {
        loadToken();
        invokeStatic(SCOPE, Method.getMethod("void exit(Object)"));
      }
    };
  }
}
