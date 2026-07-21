package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class PolymorphicDeserializationHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("com/alibaba/fastjson/util/TypeUtils")
        || className.equals("com/alibaba/fastjson/parser/ParserConfig")
        || className.equals("com/alibaba/fastjson2/util/TypeUtils")
        || className.equals("com/alibaba/fastjson2/reader/ObjectReaderProvider")
        || className.equals("com/fasterxml/jackson/databind/jsontype/impl/ClassNameIdResolver")
        || className.startsWith("com/thoughtworks/xstream/mapper/")
        || className.equals("org/yaml/snakeyaml/constructor/Constructor")
        || className.startsWith("org/snakeyaml/engine/v2/constructor/");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    String parser = parserFor(className, methodName);
    if (parser.isBlank()) {
      return methodVisitor;
    }
    int stringArg = firstStringArgument(descriptor);
    if (stringArg < 0) {
      return methodVisitor;
    }
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        push(parser);
        loadArg(stringArg);
        invokeHook("beforePolymorphicType", "(Ljava/lang/String;Ljava/lang/String;)V");
      }

      @Override
      public void visitMethodInsn(
          int opcode, String owner, String name, String methodDescriptor, boolean isInterface) {
        if (isFastjsonClassResourceLookup(
            className, methodName, owner, name, methodDescriptor)) {
          // Stack before the original call is [ClassLoader, resource]. Keep the
          // original resource for getResourceAsStream and inspect one copy
          // immediately before any URL-aware ClassLoader can dereference it.
          dup();
          invokeHook("beforeFastjsonClassResource", "(Ljava/lang/String;)V");
        }
        super.visitMethodInsn(opcode, owner, name, methodDescriptor, isInterface);
      }
    };
  }

  private static boolean isFastjsonClassResourceLookup(
      String className,
      String methodName,
      String owner,
      String invokedName,
      String invokedDescriptor) {
    return className.equals("com/alibaba/fastjson/parser/ParserConfig")
        && methodName.equals("checkAutoType")
        && owner.equals("java/lang/ClassLoader")
        && invokedName.equals("getResourceAsStream")
        && invokedDescriptor.equals("(Ljava/lang/String;)Ljava/io/InputStream;");
  }

  private static String parserFor(String className, String methodName) {
    if ((className.equals("com/alibaba/fastjson/util/TypeUtils")
            || className.equals("com/alibaba/fastjson/parser/ParserConfig")
            || className.equals("com/alibaba/fastjson2/util/TypeUtils")
            || className.equals("com/alibaba/fastjson2/reader/ObjectReaderProvider"))
        && (methodName.equals("loadClass") || methodName.equals("checkAutoType"))) {
      return "fastjson";
    }
    if (className.equals("com/fasterxml/jackson/databind/jsontype/impl/ClassNameIdResolver")
        && methodName.toLowerCase(java.util.Locale.ROOT).contains("typefromid")) {
      return "jackson";
    }
    if (className.startsWith("com/thoughtworks/xstream/mapper/")
        && methodName.equals("realClass")) {
      return "xstream";
    }
    if (className.equals("org/yaml/snakeyaml/constructor/Constructor")
        && methodName.equals("getClassForName")) {
      return "snakeyaml";
    }
    if (className.startsWith("org/snakeyaml/engine/v2/constructor/")
        && methodName.equals("getClassForName")) {
      return "snakeyaml";
    }
    return "";
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
