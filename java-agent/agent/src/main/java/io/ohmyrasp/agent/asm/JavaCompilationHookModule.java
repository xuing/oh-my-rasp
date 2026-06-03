package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class JavaCompilationHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("com/sun/tools/javac/api/JavacTool")
        || className.equals("org/codehaus/janino/Cookable")
        || className.equals("org/codehaus/janino/SimpleCompiler")
        || className.equals("org/codehaus/janino/ScriptEvaluator")
        || className.equals("org/codehaus/janino/ExpressionEvaluator")
        || className.equals("org/codehaus/janino/ClassBodyEvaluator");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (className.equals("com/sun/tools/javac/api/JavacTool")
        && methodName.equals("getTask")) {
      int unitsArg = javacCompilationUnitsArgument(descriptor);
      if (unitsArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("javac");
            loadArg(unitsArg);
            invokeHook("beforeJavaCompilationUnits", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (isJaninoCompiler(className) && isJaninoSourceMethod(methodName)) {
      int sourceArg = firstStringArgument(descriptor);
      if (sourceArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("janino");
            loadArg(sourceArg);
            invokeHook("beforeJavaCompilationSource", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    return methodVisitor;
  }

  private static boolean isJaninoCompiler(String className) {
    return className.startsWith("org/codehaus/janino/");
  }

  private static boolean isJaninoSourceMethod(String methodName) {
    String normalized = methodName.toLowerCase(java.util.Locale.ROOT);
    return normalized.equals("cook") || normalized.startsWith("compile");
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
            && argument.getInternalName().equals("java/lang/Iterable")
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
      if (argument.getSort() == Type.OBJECT
          && argument.getInternalName().equals("java/lang/String")) {
        return index;
      }
    }
    return -1;
  }
}
