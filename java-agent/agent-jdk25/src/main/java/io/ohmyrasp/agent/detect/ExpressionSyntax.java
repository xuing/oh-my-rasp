package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.lower;

import java.util.regex.Pattern;

/** Runtime execution indicators shared by expressions and script configuration. */
final class ExpressionSyntax {
  private static final Pattern SCRIPT_LITERAL_EXECUTE =
      Pattern.compile("(?is)['\"][^'\"]{1,120}['\"]\\s*\\.\\s*execute\\s*\\(");

  private static final Pattern SCRIPT_COMMAND_VARIABLE_EXECUTE =
      Pattern.compile(
          "(?is)\\b(?:cmd|command)\\s*=\\s*['\"][^'\"]{1,120}['\"].{0,240}\\b(?:cmd|command)\\s*\\.\\s*execute\\s*\\(");

  private ExpressionSyntax() {}

  private static boolean isScriptEngine(String engine) {
    return "mvel".equals(engine)
        || "groovy".equals(engine)
        || "javascript".equals(engine)
        || "script".equals(engine);
  }

  static boolean looksLikeScriptCommandExecution(String expression) {
    return SCRIPT_LITERAL_EXECUTE.matcher(expression).find()
        || SCRIPT_COMMAND_VARIABLE_EXECUTE.matcher(expression).find();
  }

  static boolean containsRuntimeExpressionPrimitive(String engine, String expression) {
    String compactExpression = lower(expression).replaceAll("\\s+", "");
    boolean runtimeExec =
        compactExpression.contains("runtime")
            && compactExpression.contains("getruntime")
            && compactExpression.contains("exec");
    boolean reflectiveRuntimeExec =
        compactExpression.contains("java.lang.runtime")
            && (compactExpression.contains("getmethods") || compactExpression.contains("getmethod"))
            && compactExpression.contains("invoke")
            && compactExpression.contains("exec");
    boolean processBuilderStart =
        compactExpression.contains("processbuilder")
            && (compactExpression.contains(".start")
                || compactExpression.contains("newprocessbuilder")
                || compactExpression.contains("newjava.lang.processbuilder"));
    boolean reflectiveProcessBuilderStart =
        compactExpression.contains("processbuilder")
            && (compactExpression.contains("getmethod(\"start\"")
                || compactExpression.contains("getmethod('start'"))
            && compactExpression.contains("invoke");
    boolean scriptEngineEval =
        compactExpression.contains("scriptenginemanager") && compactExpression.contains(".eval");
    boolean scriptCommandExecute = isScriptEngine(lower(engine)) && looksLikeScriptCommandExecution(expression);
    boolean freemarkerExecute =
        compactExpression.contains("freemarker.template.utility.execute")
            && compactExpression.contains(".exec(");
    return runtimeExec
        || reflectiveRuntimeExec
        || processBuilderStart
        || reflectiveProcessBuilderStart
        || scriptEngineEval
        || freemarkerExecute
        || scriptCommandExecute;
  }
}
