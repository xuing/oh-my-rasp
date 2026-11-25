package io.ohmyrasp.agent.loading;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** Inspect the resource supplied to URLClassLoader definition and the JDK RMI codebase-loader branch. */
public final class CodebaseVisitor {
  public static final String RMI_ROUTER = "sun/rmi/server/LoaderHandler";
  private static final String URL_LOADER = "java/net/URLClassLoader";

  private CodebaseVisitor() {}

  public static boolean target(String owner) {
    return URL_LOADER.equals(owner) || RMI_ROUTER.equals(owner) || directoryResource(owner);
  }

  public static boolean directoryResource(String owner) {
    return owner.startsWith("jdk/internal/loader/URLClassPath$Loader$") || owner.startsWith("sun/misc/URLClassPath$Loader$");
  }

  public static MethodVisitor wrap(String owner, MethodVisitor mv, int access, String name, String desc, final Type hooks) {
    if (directoryResource(owner) && "getInputStream".equals(name) && "()Ljava/io/InputStream;".equals(desc)) {
      return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
        @Override public void visitMethodInsn(int op, String callee, String target, String signature, boolean itf) {
          if (op == INVOKEVIRTUAL && "java/net/URLConnection".equals(callee)
              && "getInputStream".equals(target) && "()Ljava/io/InputStream;".equals(signature)) {
            dup();
            super.visitMethodInsn(op, callee, target, signature, itf);
            swap();
            loadThis();
            invokeStatic(hooks, Method.getMethod("void onClassResourceRead(java.net.URLConnection,Object)"));
            return;
          }
          super.visitMethodInsn(op, callee, target, signature, itf);
        }
      };
    }
    if (URL_LOADER.equals(owner) && "defineClass".equals(name)
        && ("(Ljava/lang/String;Lsun/misc/Resource;)Ljava/lang/Class;".equals(desc)
            || "(Ljava/lang/String;Ljdk/internal/loader/Resource;)Ljava/lang/Class;".equals(desc))) {
      return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
        @Override public void visitMethodInsn(int op, String callee, String target, String signature, boolean itf) {
          if (op == INVOKEVIRTUAL && URL_LOADER.equals(callee) && "defineClass".equals(target)
              && ("(Ljava/lang/String;[BIILjava/security/CodeSource;)Ljava/lang/Class;".equals(signature)
                  || "(Ljava/lang/String;Ljava/nio/ByteBuffer;Ljava/security/CodeSource;)Ljava/lang/Class;".equals(signature))) {
            // CodeSource is the final argument to both VM handoffs. URLClassLoader and URL share the java.net package.
            dup();
            invokeVirtual(Type.getType(java.security.CodeSource.class), Method.getMethod("java.net.URL getLocation()"));
            dup();
            getField(Type.getType(java.net.URL.class), "handler", Type.getType(java.net.URLStreamHandler.class));
            loadArg(1);
            invokeStatic(hooks, Method.getMethod("void beforeClassDefinition(java.net.URL,Object,Object)"));
          }
          super.visitMethodInsn(op, callee, target, signature, itf);
        }
      };
    }
    final Method hook;
    if (RMI_ROUTER.equals(owner) && "lookupLoader".equals(name) && (access & Opcodes.ACC_STATIC) != 0
        && "([Ljava/net/URL;Ljava/lang/ClassLoader;)Lsun/rmi/server/LoaderHandler$Loader;".equals(desc)) {
      hook = Method.getMethod("void beforeRmiCodebaseLoader(java.net.URL[])");
    } else {
      return mv;
    }
    return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
      @Override protected void onMethodEnter() {
        loadArg(0);
        invokeStatic(hooks, hook);
      }
    };
  }
}
