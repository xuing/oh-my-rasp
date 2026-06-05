package io.ohmyrasp.agent.java17;

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

public final class Java17JavaCompilationTransformer implements ClassFileTransformer {
  private static final Type HOOKS = Type.getType(Java17RaspHooks.class);
  private static final Method BEFORE_JAVA_COMPILATION_UNITS =
      Method.getMethod("void beforeJavaCompilationUnits(java.lang.String, java.lang.Object)");
  private static final Method BEFORE_JAVA_COMPILATION_SOURCE =
      Method.getMethod("void beforeJavaCompilationSource(java.lang.String, java.lang.Object)");

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
      reader.accept(new JavaCompilationClassVisitor(className, writer), ClassReader.EXPAND_FRAMES);
      return writer.toByteArray();
    } catch (Throwable throwable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println(
            "[OHMYRASP-JAVA17] Java compilation transform failed for " + className + ": " + throwable);
      }
      return null;
    }
  }

  private static boolean isTarget(String className) {
    return "com/sun/tools/javac/api/JavacTool".equals(className)
        || "org/codehaus/janino/Cookable".equals(className)
        || "org/codehaus/janino/SimpleCompiler".equals(className)
        || "org/codehaus/janino/ScriptEvaluator".equals(className)
        || "org/codehaus/janino/ExpressionEvaluator".equals(className)
        || "org/codehaus/janino/ClassBodyEvaluator".equals(className);
  }

  private static final class JavaCompilationClassVisitor extends ClassVisitor {
    private final String className;

    JavaCompilationClassVisitor(String className, ClassVisitor delegate) {
      super(Opcodes.ASM9, delegate);
      this.className = className;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (methodVisitor == null || (access & Opcodes.ACC_ABSTRACT) != 0) {
        return methodVisitor;
      }
      if ("com/sun/tools/javac/api/JavacTool".equals(className) && "getTask".equals(name)) {
        int unitsArg = javacCompilationUnitsArgument(descriptor);
        if (unitsArg >= 0) {
          return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
            @Override
            protected void onMethodEnter() {
              push("javac");
              loadArg(unitsArg);
              invokeStatic(HOOKS, BEFORE_JAVA_COMPILATION_UNITS);
            }
          };
        }
      }
      if (className.startsWith("org/codehaus/janino/") && isJaninoSourceMethod(name)) {
        int sourceArg = firstStringArgument(descriptor);
        if (sourceArg >= 0) {
          return new AdviceAdapter(Opcodes.ASM9, methodVisitor, access, name, descriptor) {
            @Override
            protected void onMethodEnter() {
              push("janino");
              loadArg(sourceArg);
              invokeStatic(HOOKS, BEFORE_JAVA_COMPILATION_SOURCE);
            }
          };
        }
      }
      return methodVisitor;
    }

    private static boolean isJaninoSourceMethod(String name) {
      String normalized = name.toLowerCase(java.util.Locale.ROOT);
      return "cook".equals(normalized) || normalized.startsWith("compile");
    }

    private static int javacCompilationUnitsArgument(String descriptor) {
      Type[] arguments;
      try {
        arguments = Type.getArgumentTypes(descriptor);
      } catch (RuntimeException e) {
        return -1;
      }
      if (arguments.length < 6) {
        return -1;
      }
      Type argument = arguments[5];
      return argument.getSort() == Type.OBJECT
              && "java/lang/Iterable".equals(argument.getInternalName())
          ? 5
          : -1;
    }

    private static int firstStringArgument(String descriptor) {
      Type[] arguments;
      try {
        arguments = Type.getArgumentTypes(descriptor);
      } catch (RuntimeException e) {
        return -1;
      }
      for (int index = 0; index < arguments.length; index++) {
        Type argument = arguments[index];
        if (argument.getSort() == Type.OBJECT && "java/lang/String".equals(argument.getInternalName())) {
          return index;
        }
      }
      return -1;
    }
  }
}
