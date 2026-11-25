package io.ohmyrasp.agent.xml;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

/** Instruments Xerces' own transport open after reader/stream selection and URI expansion. */
public final class XmlEntityOpenVisitor {
  private static final String JDK = "com/sun/org/apache/xerces/internal/";
  private static final String APACHE = "org/apache/xerces/";
  private static final String ENTITY_MANAGER = "impl/XMLEntityManager";
  private static final String INPUT_SOURCE = "xni/parser/XMLInputSource";

  static boolean isResolver(String name) {
    return (JDK + "util/EntityResolverWrapper").equals(name) || (JDK + "util/EntityResolver2Wrapper").equals(name)
        || (APACHE + "util/EntityResolverWrapper").equals(name) || (APACHE + "util/EntityResolver2Wrapper").equals(name);
  }

  static boolean isManager(String name) {
    return (JDK + ENTITY_MANAGER).equals(name) || (APACHE + ENTITY_MANAGER).equals(name);
  }

  public static boolean matches(String name) {
    return isManager(name) || isResolver(name);
  }

  private static final String CATALOG = Type.getInternalName(XmlCatalogResolution.class);
  private static final String ENTER = "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;";

  private XmlEntityOpenVisitor() {}

  public static MethodVisitor wrap(String className, MethodVisitor visitor, int access, String name, String descriptor, String hooks) {
    if (visitor == null || (access & Opcodes.ACC_STATIC) != 0) {
      return visitor;
    }
    if (isResolver(className) && "resolveEntity".equals(name) && (descriptor.equals("(L" + JDK + "xni/XMLResourceIdentifier;)L" + JDK + INPUT_SOURCE + ";")
        || descriptor.equals("(L" + APACHE + "xni/XMLResourceIdentifier;)L" + APACHE + INPUT_SOURCE + ";"))) {
      return resolver(visitor, access, name, descriptor);
    }
    if (isManager(className) && (("endEntity".equals(name) && "()V".equals(descriptor))
        || "reset".equals(name))) {
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        protected void onMethodEnter() {
          loadThis();
          visitInsn(ACONST_NULL);
          super.visitMethodInsn(INVOKESTATIC, CATALOG, "enter", ENTER, false);
          pop();
        }
      };
    }
    if (!"setupCurrentEntity".equals(name)) {
      return visitor;
    }
    Type[] args = Type.getArgumentTypes(descriptor);
    int nameIndex = args.length > 0 && Type.BOOLEAN_TYPE.equals(args[0]) ? 1 : 0;
    if (args.length < nameIndex + 2 || !Type.getType(String.class).equals(args[nameIndex])) {
      return visitor;
    }
    String source = args[nameIndex + 1].getDescriptor();
    if (!("L" + JDK + INPUT_SOURCE + ";").equals(source) && !("L" + APACHE + INPUT_SOURCE + ";").equals(source)) {
      return visitor;
    }
    return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
      private int root;
      private int literal;
      private int url;

      @Override
      protected void onMethodEnter() {
        root = newLocal(Type.getType(Object.class));
        literal = newLocal(Type.getType(String.class));
        url = newLocal(Type.getType(java.net.URL.class));
        loadThis();
        loadArg(nameIndex);
        super.visitMethodInsn(INVOKESTATIC, CATALOG, "enter", ENTER, false);
        storeLocal(root);
        visitInsn(ACONST_NULL);
        storeLocal(literal);
        visitInsn(ACONST_NULL);
        storeLocal(url);
      }

      @Override
      public void visitMethodInsn(int opcode, String owner, String method, String desc, boolean isInterface) {
        if (opcode == INVOKEVIRTUAL && owner.equals(args[nameIndex + 1].getInternalName())
            && "getSystemId".equals(method) && "()Ljava/lang/String;".equals(desc)) {
          super.visitMethodInsn(opcode, owner, method, desc, isInterface);
          dup();
          storeLocal(literal);
          return;
        }
        if (opcode == INVOKEVIRTUAL && "java/net/URL".equals(owner)
            && "openConnection".equals(method) && "()Ljava/net/URLConnection;".equals(desc)) {
          dup();
          storeLocal(url);
          dup();
          loadArg(nameIndex);
          loadArg(nameIndex + 1);
          loadLocal(root);
          loadLocal(literal);
          super.visitMethodInsn(INVOKESTATIC, hooks, "beforeXmlEntityOpen",
              "(Ljava/net/URL;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V", false);
          super.visitMethodInsn(opcode, owner, method, desc, isInterface);
          loadThis();
          loadArg(nameIndex);
          loadLocal(url);
          super.visitMethodInsn(INVOKESTATIC, CATALOG, "opened", "(Ljava/lang/Object;Ljava/lang/String;Ljava/net/URL;)V", false);
          return;
        }
        super.visitMethodInsn(opcode, owner, method, desc, isInterface);
      }
    };
  }

  private static MethodVisitor resolver(MethodVisitor visitor, int access, String name, String descriptor) {
    return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
      private int requestedId;
      private int baseId;

      @Override
      protected void onMethodEnter() {
        requestedId = newLocal(Type.getType(String.class));
        baseId = newLocal(Type.getType(String.class));
        visitInsn(ACONST_NULL);
        storeLocal(requestedId);
        visitInsn(ACONST_NULL);
        storeLocal(baseId);
      }

      @Override
      public void visitMethodInsn(int opcode, String owner, String method, String desc, boolean isInterface) {
        if (opcode == INVOKEINTERFACE && "resolveEntity".equals(method)) {
          if ("org/xml/sax/EntityResolver".equals(owner)
              && "(Ljava/lang/String;Ljava/lang/String;)Lorg/xml/sax/InputSource;".equals(desc)) {
            dup();
            storeLocal(requestedId);
          } else if ("org/xml/sax/ext/EntityResolver2".equals(owner)
              && ("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)"
                  + "Lorg/xml/sax/InputSource;").equals(desc)) {
            // SAX2 can supply a relative identifier alongside the document base.
            dup2();
            storeLocal(requestedId);
            storeLocal(baseId);
          }
        }
        super.visitMethodInsn(opcode, owner, method, desc, isInterface);
      }

      @Override
      protected void onMethodExit(int opcode) {
        if (opcode == ARETURN) {
          dup();
          loadLocal(requestedId);
          loadLocal(baseId);
          super.visitMethodInsn(INVOKESTATIC, CATALOG, "resolved",
              "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V", false);
        }
      }
    };
  }
}
