package io.ohmyrasp.agent.file;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;

/**
 * Wraps Tomcat's WAR unpack ({@code ExpandWar.expand(Host, URL, String)}) and Jasper's JSP compile
 * ({@code Compiler.compile(boolean, boolean)}, which {@code JDTCompiler} inherits) in a {@link ContainerDeployment}
 * scope, entered with the method's own class and the objects that say where it writes, and left on every way out.
 * The backport lines apply it in their file transformers, the primary in {@code ContainerDeploymentHookModule}.
 */
public final class ContainerDeploymentVisitor {
  public static final String EXPAND_WAR = "org/apache/catalina/startup/ExpandWar";
  public static final String COMPILER = "org/apache/jasper/compiler/Compiler";
  private static final String EXPAND = "(Lorg/apache/catalina/Host;Ljava/net/URL;Ljava/lang/String;)Ljava/lang/String;";
  private static final String COMPILE = "(ZZ)V";
  private static final Type OBSERVER = Type.getType(ContainerDeployment.class);

  private ContainerDeploymentVisitor() {}

  public static boolean matches(String owner) {
    return EXPAND_WAR.equals(owner) || COMPILER.equals(owner);
  }

  public static MethodVisitor wrap(String owner, MethodVisitor visitor, int access, String name, String descriptor) {
    if (visitor == null || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
      return visitor;
    }
    boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;
    final boolean war = EXPAND_WAR.equals(owner) && "expand".equals(name) && EXPAND.equals(descriptor) && isStatic;
    boolean jsp = COMPILER.equals(owner) && "compile".equals(name) && COMPILE.equals(descriptor) && !isStatic;
    if (!war && !jsp) {
      return visitor;
    }
    final Type ownerType = Type.getObjectType(owner);
    return new ScopedMethodAdvice(Opcodes.ASM9, visitor, access, name, descriptor) {
      @Override protected void enterDispatch() {
        push(ownerType);
        if (war) {
          loadArg(0);
          loadArg(2);
          invokeStatic(OBSERVER, Method.getMethod("void enterWarExpand(Class, Object, String)"));
        } else {
          loadThis();
          invokeStatic(OBSERVER, Method.getMethod("void enterJspCompile(Class, Object)"));
        }
      }

      @Override protected void exitDispatch() {
        invokeStatic(OBSERVER, Method.getMethod("void exit()"));
      }
    };
  }
}
