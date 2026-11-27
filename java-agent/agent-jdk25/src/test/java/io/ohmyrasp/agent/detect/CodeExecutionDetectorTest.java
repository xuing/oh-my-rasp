package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** CodeExecutionDetector: Expression engines, OGNL, Java compilation, eval, callable selection and native library loads. */
final class CodeExecutionDetectorTest {
  @Test
  void detectsOgnlBlacklist() {
    var result = CodeExecutionDetector.detectOgnl("@java.lang.Runtime@getRuntime().exec('id')", request());

    assertAlgorithm(result, "ognl_blacklist");
  }

  @Test
  void detectsOgnlLengthLimit() {
    var result = CodeExecutionDetector.detectOgnl("a".repeat(401), request());

    assertAlgorithm(result, "ognl_length_limit");
  }

  @Test
  void detectsSpringExpressionRuntimeExecution() {
    var expression = "T(java.lang.Runtime).getRuntime().exec('id')";
    var result =
        CodeExecutionDetector.detectExpression(
            "spel",
            expression,
            request(Map.of("spring.cloud.function.routing-expression", List.of(expression))));

    assertAlgorithm(result, "spel_runtime");
  }

  @Test
  void detectsTemplateRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "template",
            "#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('id'))",
            request());

    assertAlgorithm(result, "template_runtime");
  }

  @Test
  void detectsJexlRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "jexl",
            "233.class.forName('java.lang.Runtime').getRuntime().exec('touch /tmp/success')",
            request());

    assertAlgorithm(result, "jexl_runtime");
  }

  @Test
  void detectsElReflectiveRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "el",
            "${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('id')}",
            request());

    assertAlgorithm(result, "el_runtime");
  }

  @Test
  void detectsJavascriptRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "javascript",
            "function(){ java.lang.Runtime.getRuntime().exec('id'); }",
            request());

    assertAlgorithm(result, "javascript_runtime");
  }

  @Test
  void detectsJiffleRuntimeExecutionWithoutLoggingRawScript() {
    String expression =
        "dest = y() - 500; // */ public class Double { static { "
            + "java.lang.Runtime.getRuntime().exec(\"id\"); } } /**";
    var result =
        CodeExecutionDetector.detectExpression("jiffle", expression, request(Map.of("script", List.of(expression))));

    assertAlgorithm(result, "jiffle_runtime");
    assertEquals("jiffle", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertTrue(!result.orElseThrow().details().containsKey("expression"));
  }

  @Test
  void detectsGeoServerCve202224816WpsJiffleRuntimeExecutionFromXmlBody() {
    String expression =
        "dest = y() - 500; // */ public class Double { static { "
            + "java.lang.Runtime.getRuntime().exec(\"id\"); } } /**";
    String body =
        """
        <wps:Execute service="WPS" version="1.0.0"
            xmlns:wps="http://www.opengis.net/wps/1.0.0"
            xmlns:ows="http://www.opengis.net/ows/1.1">
          <wps:DataInputs>
            <wps:Input>
              <ows:Identifier>script</ows:Identifier>
              <wps:Data><wps:LiteralData>%s</wps:LiteralData></wps:Data>
            </wps:Input>
          </wps:DataInputs>
        </wps:Execute>
        """
            .formatted(expression);
    RequestContext context =
        new RequestContext(
            "POST",
            "/geoserver/wms",
            "",
            Map.of(),
            Map.of("content-type", "application/xml"),
            body);

    var result = CodeExecutionDetector.detectExpression("jiffle", expression, context);

    assertAlgorithm(result, "jiffle_runtime");
    assertEquals("/geoserver/wms", result.orElseThrow().request().uri());
    assertEquals("true", result.orElseThrow().details().get("requestControlled"));
    assertEquals(String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertTrue(!result.orElseThrow().details().containsKey("expression"));
  }

  @Test
  void detectsMvelRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "mvel",
            "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream())",
            request());

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsGroovyStringCommandExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "groovy",
            "def command='id';def res=command.execute().text;res",
            request());

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsXpathRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "xpath", "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success')", request());

    assertAlgorithm(result, "xpath_runtime");
  }

  @Test
  void detectsXpathProcessBuilderExecution() {
    var result =
        CodeExecutionDetector.detectExpression(
            "xpath", "new java.lang.ProcessBuilder('id').start()", request());

    assertAlgorithm(result, "xpath_runtime");
  }

  @Test
  void ignoresHarmlessXpathExpression() {
    var result = CodeExecutionDetector.detectExpression("xpath", "/root/name/text()", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessJexlExpression() {
    var result = CodeExecutionDetector.detectExpression("jexl", "user.name ?: 'guest'", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessElExpression() {
    var result = CodeExecutionDetector.detectExpression("el", "${user.name}", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessJiffleExpression() {
    var result = CodeExecutionDetector.detectExpression("jiffle", "dest = x() + y();", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRequestTimeJavaCompilationRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectJavaCompilation(
            "javac",
            """
            public class Demo {
              static void run() throws Exception {
                java.lang.Runtime.getRuntime().exec("id");
              }
            }
            """,
            request());

    assertAlgorithm(result, "java_compile_runtime");
  }

  @Test
  void detectsJavaCompilationProcessBuilderExecution() {
    var result =
        CodeExecutionDetector.detectJavaCompilation(
            "janino",
            "class Demo { void run() throws Exception { new ProcessBuilder(\"id\").start(); } }",
            request());

    assertAlgorithm(result, "java_compile_runtime");
  }

  @Test
  void ignoresHarmlessJavaCompilation() {
    var result =
        CodeExecutionDetector.detectJavaCompilation(
            "javac", "public class Demo { int add(int a, int b) { return a + b; } }", request());

    assertTrue(result.isEmpty());
  }

  /** Outside a request the rule decides as the backport lines do. */
  @Test
  void detectsBackgroundJavaCompilationRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectJavaCompilation(
            "javac",
            "public class Demo { void run() throws Exception { Runtime.getRuntime().exec(\"id\"); } }",
            RequestContext.empty());

    assertEquals("java_compile_runtime", result.orElseThrow().algorithm());
    assertEquals("false", result.orElseThrow().details().get("requestControlled"));
  }

  @Test
  void ignoresBackgroundJavaCompilationWithoutRuntimeExecution() {
    var result =
        CodeExecutionDetector.detectJavaCompilation(
            "javac", "public class Demo { int add(int a, int b) { return a + b; } }", RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessSpringExpression() {
    var result = CodeExecutionDetector.detectExpression("spel", "T(java.lang.Math).abs(-1)", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresHarmlessGroovyScript() {
    var result = CodeExecutionDetector.detectExpression("groovy", "def total = 1 + 2; total", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsEvalRegex() {
    var result = CodeExecutionDetector.detectEval("eval", "return base64_decode($x);", request());

    assertAlgorithm(result, "eval_regex");
  }

  @Test
  void detectsLoadLibraryUnc() {
    var result = CodeExecutionDetector.detectLoadLibrary("System.load", "\\\\server\\share\\evil.dll", true, request());

    assertAlgorithm(result, "loadLibrary_unc");
  }

  @Test
  void detectsWebshellEval() {
    var result =
        CodeExecutionDetector.detectWebshellEval("assert", "system('id')", request(Map.of("code", List.of("system('id')"))));

    assertAlgorithm(result, "webshell_eval");
  }

  @Test
  void detectsWebshellCallable() {
    var result = CodeExecutionDetector.detectWebshellCallable("system", request());

    assertAlgorithm(result, "webshell_callable");
  }
}
