package io.ohmyrasp.agent.asm;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

final class ExpressionHookModule implements HookModule {
  @Override
  public boolean matchesClass(String className) {
    return className.equals("org/springframework/expression/spel/standard/SpelExpression")
        || className.equals("ognl/Ognl")
        || className.equals("org/apache/commons/ognl/Ognl")
        || className.equals("com/opensymphony/xwork2/ognl/OgnlUtil")
        || className.equals("org/apache/velocity/app/VelocityEngine")
        || className.equals("org/apache/velocity/app/Velocity")
        || className.equals("org/apache/velocity/runtime/RuntimeInstance")
        || className.equals("org/mvel2/MVEL")
        || className.equals("groovy/lang/GroovyShell")
        || className.equals("org/mozilla/javascript/Context")
        || isJiffleImplementation(className)
        || isJexlImplementation(className)
        || isElImplementation(className)
        || isXPathImplementation(className)
        || isScriptEngineImplementation(className);
  }

  @Override
  public MethodVisitor visitMethod(
      String className,
      MethodVisitor methodVisitor,
      int access,
      String methodName,
      String descriptor) {
    if ((access & org.objectweb.asm.Opcodes.ACC_ABSTRACT) != 0) {
      return methodVisitor;
    }
    if (className.equals("org/springframework/expression/spel/standard/SpelExpression")
        && (methodName.equals("getValue") || methodName.equals("setValue"))) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          push("spel");
          loadThis();
          invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
        }
      };
    }
    if ((className.equals("ognl/Ognl") || className.equals("org/apache/commons/ognl/Ognl"))
        && (methodName.equals("getValue")
            || methodName.equals("setValue")
            || methodName.equals("parseExpression"))
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          push("ognl");
          loadArg(0);
          invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
        }
      };
    }
    if (className.equals("com/opensymphony/xwork2/ognl/OgnlUtil")
        && (methodName.equals("getValue") || methodName.equals("setValue"))
        && descriptor.startsWith("(Ljava/lang/String;")) {
      return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
        @Override
        protected void onMethodEnter() {
          push("ognl");
          loadArg(0);
          invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
        }
      };
    }
    if ((className.equals("org/apache/velocity/app/VelocityEngine")
            || className.equals("org/apache/velocity/app/Velocity")
            || className.equals("org/apache/velocity/runtime/RuntimeInstance"))
        && methodName.equals("evaluate")) {
      int templateArg = lastStringArgument(descriptor);
      if (templateArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("template");
            loadArg(templateArg);
            invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (isJexlImplementation(className) && isJexlExpressionMethod(methodName)) {
      int expressionArg = firstStringArgument(descriptor);
      if (expressionArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("jexl");
            loadArg(expressionArg);
            invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (isElImplementation(className) && isElExpressionMethod(methodName)) {
      int expressionArg = firstStringArgument(descriptor);
      if (expressionArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("el");
            loadArg(expressionArg);
            invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (isXPathImplementation(className)
        && isXPathEvaluationMethod(methodName)) {
      int expressionArg = firstStringArgument(descriptor);
      if (expressionArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("xpath");
            loadArg(expressionArg);
            invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (isScriptEngineImplementation(className) && methodName.equals("eval")) {
      int scriptArg = firstStringArgument(descriptor);
      if (scriptArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push(engineForScriptClass(className));
            loadArg(scriptArg);
            invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (className.equals("org/mozilla/javascript/Context")
        && isRhinoSourceMethod(methodName)) {
      int scriptArg = firstStringArgument(descriptor);
      if (scriptArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("javascript");
            loadArg(scriptArg);
            invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (className.equals("groovy/lang/GroovyShell")
        && (methodName.equals("evaluate") || methodName.equals("parse"))) {
      int scriptArg = firstStringArgument(descriptor);
      if (scriptArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("groovy");
            loadArg(scriptArg);
            invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (isJiffleImplementation(className) && isJiffleScriptMethod(methodName)) {
      int scriptArg = firstStringArgument(descriptor);
      if (scriptArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("jiffle");
            loadArg(scriptArg);
            invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    if (className.equals("org/mvel2/MVEL")
        && (methodName.toLowerCase(java.util.Locale.ROOT).contains("eval")
            || methodName.startsWith("compile"))) {
      int scriptArg = firstStringArgument(descriptor);
      if (scriptArg >= 0) {
        return new EntryAdvice(methodVisitor, access, methodName, descriptor) {
          @Override
          protected void onMethodEnter() {
            push("mvel");
            loadArg(scriptArg);
            invokeHook("beforeExpressionEvaluation", "(Ljava/lang/String;Ljava/lang/Object;)V");
          }
        };
      }
    }
    return methodVisitor;
  }

  private static boolean isRhinoSourceMethod(String methodName) {
    return methodName.equals("evaluateString")
        || methodName.equals("compileString")
        || methodName.equals("compileFunction");
  }

  private static boolean isJiffleImplementation(String className) {
    return className.equals("it/geosolutions/jaiext/jiffle/Jiffle")
        || className.equals("it/geosolutions/jaiext/jiffle/JiffleBuilder");
  }

  private static boolean isJiffleScriptMethod(String methodName) {
    return methodName.equals("<init>") || methodName.equals("setScript") || methodName.equals("script");
  }

  private static boolean isJexlImplementation(String className) {
    return className.equals("org/apache/commons/jexl/ExpressionFactory")
        || className.equals("org/apache/commons/jexl/ScriptFactory")
        || className.equals("org/apache/commons/jexl2/JexlEngine")
        || className.equals("org/apache/commons/jexl2/UnifiedJEXL")
        || className.startsWith("org/apache/commons/jexl2/internal/")
        || className.equals("org/apache/commons/jexl3/JexlEngine")
        || className.startsWith("org/apache/commons/jexl3/internal/");
  }

  private static boolean isJexlExpressionMethod(String methodName) {
    return methodName.equals("createExpression")
        || methodName.equals("createScript")
        || methodName.equals("createTemplate")
        || methodName.equals("compile")
        || methodName.equals("parse")
        || methodName.equals("evaluate")
        || methodName.equals("execute")
        || methodName.equals("<init>");
  }

  private static boolean isElImplementation(String className) {
    return className.equals("javax/el/ExpressionFactory")
        || className.equals("jakarta/el/ExpressionFactory")
        || className.equals("javax/el/ELProcessor")
        || className.equals("jakarta/el/ELProcessor")
        || (className.endsWith("/ExpressionFactoryImpl") && className.contains("/el/"))
        || (className.endsWith("/ExpressionBuilder") && className.contains("/el/"));
  }

  private static boolean isElExpressionMethod(String methodName) {
    return methodName.equals("createValueExpression")
        || methodName.equals("createMethodExpression")
        || methodName.equals("eval")
        || methodName.equals("getValue")
        || methodName.equals("setValue")
        || methodName.equals("createNode")
        || methodName.equals("build")
        || methodName.equals("<init>");
  }

  private static boolean isScriptEngineImplementation(String className) {
    return className.equals("jdk/nashorn/api/scripting/NashornScriptEngine")
        || className.equals("org/codehaus/groovy/jsr223/GroovyScriptEngineImpl")
        || className.endsWith("ScriptEngineImpl");
  }

  private static boolean isXPathImplementation(String className) {
    return className.equals("com/sun/org/apache/xpath/internal/jaxp/XPathImpl")
        || className.equals("com/sun/org/apache/xpath/internal/jaxp/XPathExpressionImpl")
        || className.equals("org/apache/xpath/jaxp/XPathImpl")
        || className.equals("org/apache/xpath/jaxp/XPathExpressionImpl")
        || className.equals("org/jaxen/BaseXPath")
        || className.equals("org/apache/commons/jxpath/JXPathContext")
        || className.equals("org/apache/commons/jxpath/ri/JXPathContextReferenceImpl")
        || className.equals("org/apache/commons/jxpath/ri/JXPathCompiledExpression");
  }

  private static boolean isXPathEvaluationMethod(String methodName) {
    return methodName.equals("evaluate")
        || methodName.equals("compile")
        || methodName.equals("<init>")
        || methodName.equals("getValue")
        || methodName.equals("setValue")
        || methodName.equals("iterate")
        || methodName.equals("selectNodes")
        || methodName.equals("selectSingleNode")
        || methodName.equals("removePath")
        || methodName.equals("createPath")
        || methodName.equals("createPathAndSetValue");
  }

  private static String engineForScriptClass(String className) {
    String normalized = className.toLowerCase(java.util.Locale.ROOT);
    if (normalized.contains("groovy")) {
      return "groovy";
    }
    if (normalized.contains("javascript") || normalized.contains("nashorn") || normalized.contains("rhino")) {
      return "javascript";
    }
    return "script";
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

  private static int lastStringArgument(String descriptor) {
    Type[] arguments;
    try {
      arguments = Type.getArgumentTypes(descriptor);
    } catch (RuntimeException e) {
      return -1;
    }
    for (int index = arguments.length - 1; index >= 0; index--) {
      Type argument = arguments[index];
      if (argument.getSort() == Type.OBJECT
          && argument.getInternalName().equals("java/lang/String")) {
        return index;
      }
    }
    return -1;
  }
}
