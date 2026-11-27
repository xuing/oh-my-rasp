package io.ohmyrasp.agent.process;

import io.ohmyrasp.agent.asm.ScopedMethodAdvice;
import io.ohmyrasp.agent.rules.product.spring.SpringProcessVisitor;
import java.io.IOException;
import java.io.InputStream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

public final class ProcessLaunchVisitor {
  private static final String START = "([Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;[Ljava/lang/ProcessBuilder$Redirect;Z)Ljava/lang/Process;";
  private static final String EXEC_TAIL = "[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;";
  private static final Type SCOPE = Type.getType(ProcessLaunch.class);
  private static final boolean PLATFORM_HANDOFF = hasPlatformHandoff();
  private ProcessLaunchVisitor() {}

  private static boolean hasPlatformHandoff() {
    // Read the bootstrap class resource without forcing ProcessImpl to load before instrumentation.
    try (InputStream bytes = Object.class.getResourceAsStream("/java/lang/ProcessImpl.class")) {
      if (bytes == null) return false;
      final boolean[] found = {false};
      new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
          if ("start".equals(name) && START.equals(descriptor) && (access & Opcodes.ACC_STATIC) != 0
              && (access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) == 0) found[0] = true;
          return null;
        }
      }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
      return found[0];
    } catch (IOException | RuntimeException unavailable) {
      return false;
    }
  }

  public static boolean platformHandoff() { return PLATFORM_HANDOFF; }

  public static boolean matches(String owner) {
    return "java/lang/Runtime".equals(owner) || "java/lang/ProcessBuilder".equals(owner)
        || (PLATFORM_HANDOFF && "java/lang/ProcessImpl".equals(owner)) || SpringProcessVisitor.matches(owner);
  }

  public static MethodVisitor wrap(String owner, MethodVisitor visitor, int access, String name,
      String descriptor, final Type hooks) {
    if (SpringProcessVisitor.matches(owner)) return SpringProcessVisitor.wrap(owner, visitor, access, name, descriptor);
    if (PLATFORM_HANDOFF && "java/lang/ProcessBuilder".equals(owner) && "start".equals(name)
        && (access & Opcodes.ACC_STATIC) == 0) {
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        @Override public void visitMethodInsn(int op, String callee, String method, String desc, boolean itf) {
          if (op == INVOKESTATIC && "java/lang/ProcessImpl".equals(callee) && "start".equals(method) && START.equals(desc)) {
            loadThis();
            invokeStatic(hooks, Method.getMethod("void beforeSpringProcessStart(java.lang.ProcessBuilder)"));
          }
          super.visitMethodInsn(op, callee, method, desc, itf);
        }
      };
    }
    if (!PLATFORM_HANDOFF) {
      final Method fallback;
      final boolean builder = "java/lang/ProcessBuilder".equals(owner);
      if (builder && "start".equals(name) && "()Ljava/lang/Process;".equals(descriptor)) {
        fallback = Method.getMethod("void beforeProcessBuilderStart(java.lang.ProcessBuilder)");
      } else if ("java/lang/Runtime".equals(owner) && "exec".equals(name) && descriptor.startsWith("(Ljava/lang/String;")) {
        fallback = Method.getMethod("void beforeRuntimeExecString(String)");
      } else if ("java/lang/Runtime".equals(owner) && "exec".equals(name) && descriptor.startsWith("([Ljava/lang/String;")) {
        fallback = Method.getMethod("void beforeRuntimeExecArray(String[])");
      } else {
        return visitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        @Override protected void onMethodEnter() {
          if (builder) loadThis(); else loadArg(0);
          invokeStatic(hooks, fallback);
        }
      };
    }
    if ("java/lang/ProcessImpl".equals(owner) && "start".equals(name) && START.equals(descriptor)
        && (access & Opcodes.ACC_STATIC) != 0) {
      return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
        @Override protected void onMethodEnter() {
          loadArg(0);
          invokeStatic(hooks, Method.getMethod("void beforeProcessLaunch(String[])"));
        }
      };
    }
    final boolean stringMethod = ("(Ljava/lang/String;" + EXEC_TAIL).equals(descriptor);
    if ("java/lang/Runtime".equals(owner) && "exec".equals(name)
        && (stringMethod || ("([Ljava/lang/String;" + EXEC_TAIL).equals(descriptor))) {
      return new ScopedMethodAdvice(Opcodes.ASM9, visitor, access, name, descriptor, true) {
        @Override protected void enterDispatch() {
          push(stringMethod);
          invokeStatic(SCOPE, Method.getMethod("Object enter(boolean)"));
        }
        @Override protected void exitDispatch() {
          loadToken();
          invokeStatic(SCOPE, Method.getMethod("void exit(Object)"));
        }
      };
    }
    return visitor;
  }
}
