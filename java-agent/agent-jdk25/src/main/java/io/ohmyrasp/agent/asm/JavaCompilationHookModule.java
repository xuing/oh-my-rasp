package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class JavaCompilationHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("com/sun/tools/javac/api/JavacTool")
        || className.equals("org/codehaus/commons/compiler/Cookable");
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
    if (className.equals("org/codehaus/commons/compiler/Cookable")
        && methodName.equals("cook")
        && descriptor.equals("(Ljava/lang/String;Ljava/lang/String;)V")) {
      // Janino 2.7 and later keep the base class in commons-compiler (2.7.8, 3.0.16 and 3.1.12 checked).
      // cook(String source) calls cook(String fileName, String source), which wraps the text in a
      // StringReader for cook(String fileName, Reader). That is the one level every String source
      // passes through and still holds as text, so it is the only one hooked: one compilation, one
      // report, and no file name read as source. The Reader and InputStream overloads, cookFile and
      // the evaluators' own cook(String fileName, Reader) are not hooked; a source that exists only
      // as a Reader or stream is not inspected (docs/detection.md, Runtime Java compilation).
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          push("janino");
          loadArg(1);
          invokeHook("beforeJavaCompilationSource", "(Ljava/lang/String;Ljava/lang/Object;)V");
        }
      };
    }
    return methodVisitor;
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
}
