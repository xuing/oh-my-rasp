package io.ohmyrasp.agent.rules.product.spring;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** Use the original resource, stream and bean operands from the Spring lifecycle. */
public final class SpringProcessVisitor {
  private static final String RESOURCE = "org/springframework/core/io/UrlResource";
  private static final String READER = "org/springframework/beans/factory/xml/XmlBeanDefinitionReader";
  private static final String PARSER = "org/springframework/beans/factory/xml/BeanDefinitionParserDelegate";
  private static final String DEFINITION = "org/springframework/beans/factory/support/AbstractBeanDefinition";
  private static final String FACTORY = "org/springframework/beans/factory/support/AbstractAutowireCapableBeanFactory";
  private static final Type TRACE = Type.getType(SpringProcessInit.class);
  private SpringProcessVisitor() {}

  public static boolean matches(String owner) {
    return RESOURCE.equals(owner) || READER.equals(owner) || PARSER.equals(owner) || DEFINITION.equals(owner)
        || FACTORY.equals(owner) || owner.startsWith(FACTORY + "$");
  }

  public static MethodVisitor wrap(String owner, MethodVisitor mv, int access, String name, String desc) {
    if (RESOURCE.equals(owner) && "getInputStream".equals(name) && "()Ljava/io/InputStream;".equals(desc)) {
      return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
        @Override public void visitMethodInsn(int op, String callee, String method, String signature, boolean itf) {
          if (op == INVOKEVIRTUAL && "java/net/URLConnection".equals(callee)
              && "getInputStream".equals(method) && "()Ljava/io/InputStream;".equals(signature)) {
            dup();
            super.visitMethodInsn(op, callee, method, signature, itf);
            dupX1();
            loadThis();
            invokeStatic(TRACE, Method.getMethod("void opened(java.net.URLConnection,java.io.InputStream,Object)"));
          } else {
            super.visitMethodInsn(op, callee, method, signature, itf);
          }
        }
      };
    }
    if (PARSER.equals(owner) && ("parseBeanDefinitionAttributes".equals(name) || "parseBeanDefinitionElement".equals(name))) {
      return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
        @Override public void visitMethodInsn(int op, String callee, String target, String signature, boolean itf) {
          boolean declared = "setInitMethodName".equals(target) && "(Ljava/lang/String;)V".equals(signature);
          boolean assigned = "setResource".equals(target) && "(Lorg/springframework/core/io/Resource;)V".equals(signature);
          if (op == INVOKEVIRTUAL && DEFINITION.equals(callee) && (declared || assigned)) {
            dup2();
            super.visitMethodInsn(op, callee, target, signature, itf);
            invokeStatic(TRACE, Method.getMethod(declared ? "void declared(Object,String)" : "void assigned(Object,Object)"));
          } else {
            super.visitMethodInsn(op, callee, target, signature, itf);
          }
        }
      };
    }
    final boolean parse = READER.equals(owner) && "doLoadBeanDefinitions".equals(name)
        && "(Lorg/xml/sax/InputSource;Lorg/springframework/core/io/Resource;)I".equals(desc);
    boolean init = FACTORY.equals(owner) && "invokeCustomInitMethod".equals(name)
        && desc.startsWith("(Ljava/lang/String;Ljava/lang/Object;Lorg/springframework/beans/factory/support/RootBeanDefinition;")
        && desc.endsWith(")V");
    // Older Spring versions dispatch inside a privileged callback. The outer custom-init scope
    // supplies the definition and receiver in both cases.
    if (init || (FACTORY.equals(owner) && name.startsWith("lambda$invokeCustomInitMethod$"))
        || (owner.startsWith(FACTORY + "$") && "run".equals(name))) {
      mv = new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
        @Override public void visitMethodInsn(int op, String callee, String target, String signature, boolean itf) {
          if (op == INVOKEVIRTUAL && "java/lang/reflect/Method".equals(callee) && "invoke".equals(target)
              && "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;".equals(signature)) {
            // Keep the original Method.invoke in its original caller.
            dupX2();
            pop();
            dup2X1();
            invokeStatic(TRACE, Method.getMethod("void dispatch(java.lang.reflect.Method,Object)"));
          }
          super.visitMethodInsn(op, callee, target, signature, itf);
        }
      };
    }
    if (parse || init) {
      return new ScopedMethodAdvice(Opcodes.ASM9, mv, access, name, desc) {
        @Override protected void enterDispatch() {
          loadArg(parse ? 0 : 1);
          loadArg(parse ? 1 : 2);
          invokeStatic(TRACE, Method.getMethod(parse ? "void enterParse(org.xml.sax.InputSource,Object)" : "void enterInit(Object,Object)"));
        }
        @Override protected void exitDispatch() {
          invokeStatic(TRACE, Method.getMethod(parse ? "void exitParse()" : "void exitInit()"));
        }
      };
    }
    if (!DEFINITION.equals(owner)) return mv;
    boolean copy = ("<init>".equals(name) || "overrideFrom".equals(name))
        && "(Lorg/springframework/beans/factory/config/BeanDefinition;)V".equals(desc);
    boolean names = ("setInitMethodName".equals(name) && "(Ljava/lang/String;)V".equals(desc))
        || ("setInitMethodNames".equals(name) && "([Ljava/lang/String;)V".equals(desc));
    if (!copy && !names) return mv;
    return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
      @Override protected void onMethodExit(int op) {
        if (op == RETURN) {
          loadThis();
          if (copy) loadArg(0);
          invokeStatic(TRACE, Method.getMethod(copy ? "void copied(Object,Object)" : "void replaced(Object)"));
        }
      }
    };
  }
}
