package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.ExpressionSyntax.containsRuntimeExpressionPrimitive;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Dynamic code: expression engines, OGNL, Java compilation, eval, callable selection and native library loads. */
public final class CodeExecutionDetector {
  private CodeExecutionDetector() {}

  private static final Set<String> OGNL_BLACKLIST =
      Set.of(
          "ognl.OgnlContext",
          "ognl.TypeConverter",
          "ognl.MemberAccess",
          "_memberAccess",
          "ognl.ClassResolver",
          "java.lang.Runtime",
          "java.lang.Class",
          "java.lang.ClassLoader",
          "java.lang.System",
          "java.lang.ProcessBuilder",
          "java.lang.Object",
          "java.lang.Shutdown",
          "java.io.File",
          "javax.script.ScriptEngineManager",
          "excludedClasses",
          "excludedPackageNamePatterns",
          "excludedPackageNames",
          "com.opensymphony.xwork2.ActionContext");

  private static final Set<String> EXPRESSION_ENGINES =
      Set.of(
          "spel",
          "ognl",
          "mvel",
          "xpath",
          "template",
          "javascript",
          "jiffle",
          "groovy",
          "script",
          "jexl",
          "el",
          "expression");

  private static final Set<String> WEBSHELL_CALLABLES =
      Set.of("system", "exec", "passthru", "proc_open", "shell_exec", "popen", "pcntl_exec", "assert");

  public static Optional<Detection> detectOgnl(String expression, RequestContext request) {
    if (expression == null || expression.isBlank()) {
      return Optional.empty();
    }
    for (String item : OGNL_BLACKLIST) {
      if (expression.contains(item)) {
        return Optional.of(
            Detection.log(
                "ognl",
                "ognl_blacklist",
                100,
                "OGNL expression contains a dangerous class or object reference",
                request,
                Map.of("match", item, "expression", abbreviate(expression))));
      }
    }
    if (expression.length() > 400) {
      return Optional.of(
          Detection.log(
              "ognl",
              "ognl_length_limit",
              100,
              "OGNL expression length is unusual: " + expression.length(),
              request,
              Map.of("length", String.valueOf(expression.length()))));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectExpression(
      String engine, String expression, RequestContext request) {
    if (expression == null || expression.isBlank()) {
      return Optional.empty();
    }
    String normalizedEngine = lower(engine);
    if ("ognl".equals(normalizedEngine)) {
      return detectOgnl(expression, request);
    }
    if (!containsRuntimeExpressionPrimitive(normalizedEngine, expression)) {
      return Optional.empty();
    }
    String hook = EXPRESSION_ENGINES.contains(normalizedEngine) ? normalizedEngine : "expression";
    String algorithm =
        switch (hook) {
          case "spel" -> "spel_runtime";
          case "template" -> "template_runtime";
          case "javascript" -> "javascript_runtime";
          case "xpath" -> "xpath_runtime";
          case "jiffle" -> "jiffle_runtime";
          case "jexl" -> "jexl_runtime";
          case "el" -> "el_runtime";
          case "mvel", "groovy", "script" -> "script_runtime";
          default -> "expression_runtime";
        };
    int confidence = request.hasParameterIn(expression) ? 100 : 85;
    Map<String, String> details =
        "jiffle".equals(hook)
            ? Map.of(
                "engine", hook,
                "expressionLength", String.valueOf(expression.length()),
                "requestControlled", String.valueOf(request.hasParameterIn(expression)))
            : Map.of(
                "engine", hook,
                "expression", abbreviate(expression),
                "requestControlled", String.valueOf(request.hasParameterIn(expression)));
    return Optional.of(
        Detection.log(
            hook,
            algorithm,
            confidence,
            "Dynamic expression evaluates a runtime execution capability",
            request,
            details));
  }

  public static Optional<Detection> detectJavaCompilation(
      String compiler, String source, RequestContext request) {
    if (source == null || source.isBlank()) {
      return Optional.empty();
    }
    boolean requestControlled = request.hasParameterIn(source);
    if (!requestControlled && !request.active()) {
      return Optional.empty();
    }
    String normalized = lower(source);
    String compact = normalized.replaceAll("\\s+", "");
    boolean runtimeExec =
        compact.contains("runtime.getruntime().exec")
            || (compact.contains("java.lang.runtime")
                && compact.contains("getruntime")
                && compact.contains(".exec"));
    boolean processBuilderStart =
        compact.contains("processbuilder")
            && (compact.contains(".start(") || compact.contains("getmethod(\"start\""));
    boolean scriptEngineEval =
        compact.contains("scriptenginemanager") && compact.contains(".eval(");
    if (!runtimeExec && !processBuilderStart && !scriptEngineEval) {
      return Optional.empty();
    }
    return Optional.of(
        Detection.log(
            "java_compile",
            "java_compile_runtime",
            requestControlled ? 100 : 85,
            "Java source compilation includes a runtime execution primitive",
            request,
            Map.of(
                "compiler", compiler == null || compiler.isBlank() ? "java" : compiler,
                "source", abbreviate(source),
                "requestControlled", String.valueOf(requestControlled))));
  }

  public static Optional<Detection> detectEval(String function, String code, RequestContext request) {
    if (code == null || code.isBlank()) {
      return Optional.empty();
    }
    if (Pattern.compile("(?is)base64_decode|gzuncompress|create_function").matcher(code).find()) {
      return Optional.of(
          Detection.log(
              "eval",
              "eval_regex",
              60,
              "Dynamic code matched eval regex policy",
              request,
              Map.of("function", String.valueOf(function), "code", abbreviate(code))));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectLoadLibrary(
      String function, String path, boolean windows, RequestContext request) {
    if (!windows || path == null || path.isBlank()) {
      return Optional.empty();
    }
    if (path.startsWith("\\\\") || path.startsWith("//")) {
      return Optional.of(
          Detection.log(
              "loadLibrary",
              "loadLibrary_unc",
              60,
              "Native library load used a UNC path",
              request,
              Map.of("function", String.valueOf(function), "path", abbreviate(path))));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectWebshellEval(
      String function, String code, RequestContext request) {
    String normalizedFunction = lower(function);
    if ((normalizedFunction.equals("eval") || normalizedFunction.equals("assert"))
        && request.hasParameterIn(code)) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_eval",
              95,
              "Dynamic code execution is controlled by request input",
              request,
              Map.of("function", String.valueOf(function), "code", abbreviate(code))));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectWebshellCallable(String function, RequestContext request) {
    String normalized = lower(function);
    if (WEBSHELL_CALLABLES.contains(normalized)) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_callable",
              90,
              "Dangerous callable function selected",
              request,
              Map.of("function", normalized)));
    }
    return Optional.empty();
  }
}
