package io.ohmyrasp.agent.loading;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** Observe URL classpath configuration and the JDK RMI provider's codebase-loader branch. */
public final class CodebaseVisitor {
  public static final String RMI_ROUTER = "sun/rmi/server/LoaderHandler";
  private static final String URL_LOADER = "java/net/URLClassLoader";

  private CodebaseVisitor() {}

  public static boolean target(String owner) {
    return URL_LOADER.equals(owner) || RMI_ROUTER.equals(owner);
  }

  public static MethodVisitor wrap(String owner, MethodVisitor mv, int access, String name, String desc, final Type hooks) {
    final Method hook;
    if (URL_LOADER.equals(owner) && "<init>".equals(name) && desc.startsWith("([Ljava/net/URL;")) {
      hook = Method.getMethod("void beforeClassLoaderUrls(Object)");
    } else if (URL_LOADER.equals(owner) && "addURL".equals(name) && "(Ljava/net/URL;)V".equals(desc)) {
      hook = Method.getMethod("void beforeClassLoaderUrl(Object)");
    } else if (RMI_ROUTER.equals(owner) && "lookupLoader".equals(name) && (access & Opcodes.ACC_STATIC) != 0
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
