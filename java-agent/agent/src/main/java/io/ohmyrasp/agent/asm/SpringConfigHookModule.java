package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class SpringConfigHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("org/springframework/context/support/ClassPathXmlApplicationContext")
        || className.equals("org/springframework/context/support/FileSystemXmlApplicationContext")
        || className.equals("org/springframework/context/support/AbstractRefreshableConfigApplicationContext")
        || className.equals("org/springframework/beans/factory/support/AbstractBeanDefinitionReader")
        || className.equals("org/springframework/beans/factory/xml/XmlBeanDefinitionReader")
        || className.equals("org/apache/xbean/spring/context/ResourceXmlApplicationContext");
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if (methodName.equals("<init>") || methodName.equals("setConfigLocation")) {
      int arg = firstConfigArgument(descriptor);
      if (arg >= 0) {
        return configAdvice(methodVisitor, access, methodName, descriptor, arg);
      }
    }
    if ((methodName.equals("setConfigLocations")
            || methodName.equals("loadBeanDefinitions")
            || methodName.equals("loadBeanDefinition"))
        && descriptor.startsWith("([Ljava/lang/String;")) {
      return configAdvice(methodVisitor, access, methodName, descriptor, 0);
    }
    if ((methodName.equals("setConfigLocations")
            || methodName.equals("loadBeanDefinitions")
            || methodName.equals("loadBeanDefinition"))
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return configAdvice(methodVisitor, access, methodName, descriptor, 0);
    }
    if (className.equals("org/springframework/beans/factory/xml/XmlBeanDefinitionReader")
        && methodName.equals("loadBeanDefinitions")
        && descriptor.startsWith("(Lorg/springframework/core/io/Resource;")) {
      return configAdvice(methodVisitor, access, methodName, descriptor, 0);
    }
    return methodVisitor;
  }

  private static MethodVisitor configAdvice(
      MethodVisitor methodVisitor, int access, String methodName, String descriptor, int arg) {
    return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
      @Override
      protected void onMethodEnter() {
        loadArg(arg);
        invokeHook("beforeSpringConfigLocations", "(Ljava/lang/Object;)V");
      }
    };
  }

  private static int firstConfigArgument(String descriptor) {
    Type[] arguments;
    try {
      arguments = Type.getArgumentTypes(descriptor);
    } catch (RuntimeException e) {
      return -1;
    }
    for (int index = 0; index < arguments.length; index++) {
      Type argument = arguments[index];
      if (argument.getSort() == Type.ARRAY
          && argument.getElementType().getSort() == Type.OBJECT
          && argument.getElementType().getInternalName().equals("java/lang/String")) {
        return index;
      }
      if (argument.getSort() == Type.OBJECT
          && (argument.getInternalName().equals("java/lang/String")
              || argument.getInternalName().equals("org/springframework/core/io/Resource"))) {
        return index;
      }
    }
    return -1;
  }
}
