package io.ohmyrasp.agent.java11;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

public final class Java11ScriptEngineTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java11RaspHooks.class);
  private static final Method BEFORE_SCRIPT_EVAL =
      Method.getMethod("void beforeScriptEval(java.lang.String)");

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (className == null || classfileBuffer == null || !isTarget(className)) {
      return null;
    }
    try {
      ClassReader reader = new ClassReader(classfileBuffer);
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      reader.accept(new ScriptEngineClassVisitor(writer, className), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println(
            "[OHMYRASP-JAVA11] script engine transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "javax/script/AbstractScriptEngine".equals(className)
        || "jdk/nashorn/api/scripting/NashornScriptEngine".equals(className)
        || "org/mozilla/javascript/Context".equals(className)
        || className.endsWith("ScriptEngineImpl");
  }

  private static final class ScriptEngineClassVisitor extends ClassVisitor {
    private final String className;

    ScriptEngineClassVisitor(ClassVisitor delegate, String className) {
      super(Opcodes.ASM9, delegate);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      int scriptArg = scriptSourceArg(className, name, descriptor);
      if (methodVisitor == null || (access & Opcodes.ACC_ABSTRACT) != 0 || scriptArg < 0) {
        return methodVisitor;
      }
      return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
        @Override
        protected void onMethodEnter() {
          loadArg(scriptArg);
          invokeStatic(HOOKS, BEFORE_SCRIPT_EVAL);
        }
      };
    }

    private static int scriptSourceArg(String className, String name, String descriptor) {
      if ("org/mozilla/javascript/Context".equals(className)) {
        if ("evaluateString".equals(name)
            && descriptor.startsWith("(Lorg/mozilla/javascript/Scriptable;Ljava/lang/String;")) {
          return 1;
        }
        if ("compileFunction".equals(name)
            && descriptor.startsWith("(Lorg/mozilla/javascript/Scriptable;Ljava/lang/String;")) {
          return 1;
        }
        if ("compileString".equals(name) && descriptor.startsWith("(Ljava/lang/String;")) {
          return 0;
        }
        return -1;
      }
      return ("eval".equals(name) || "compile".equals(name)) && descriptor.startsWith("(Ljava/lang/String;")
          ? 0
          : -1;
    }
  }
}
