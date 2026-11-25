package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.RequestValues.bodyHasSinkValue;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.process.PosixShellCommand;
import io.ohmyrasp.agent.process.ProcessLaunchIndicators;
import io.ohmyrasp.agent.rules.general.RequestShellSyntax;
import io.ohmyrasp.agent.rules.product.rocketmq.RocketMqFilterServer;
import io.ohmyrasp.agent.rules.product.solr.SolrExecutableListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Process launches and command features, including direct runtime callers. */
final class ProcessDetector {
  private ProcessDetector() {}

  private static final Set<String> FILE_READERS = Set.of("cat");
  private static final Set<String> SENSITIVE_PATHS = Set.of("/etc/passwd");

  private static final Pattern COMMAND_COMMON =
      Pattern.compile(
          "(?is)(?:cat\\s+/etc/passwd|nc\\b.{0,40}\\s-e\\s+/bin/(?:ba)?sh|bash\\s+-i\\b|/dev/tcp/|curl\\b.{0,80}\\|\\s*(?:sh|bash)|wget\\b.{0,80}\\|\\s*(?:sh|bash)|\\{echo,.{10,400}\\}\\|\\{base64,-d\\})");

  private static final Pattern WINDOWS_SHELL =
      Pattern.compile("(?i)(?:.*[/\\\\])?(?:cmd|pwsh|powershell)(?:\\.exe)?");

  private static final Pattern COMMAND_META = Pattern.compile("[;&|`$<>]|\\$\\{?IFS\\}?");

  private static final Pattern COMMAND_SENSITIVE_AFTER_JOIN =
      Pattern.compile("(?is)(?:;|&&|\\|\\|?|`)\\s*(?:cat|bash|sh|nc|curl|wget|python|perl|php)\\b");

  private static final Pattern REMOTE_JOB_SHELL_COMMAND =
      Pattern.compile("(?is)(?:^|\\W)(?:bash|sh|cmd|powershell|pwsh|nc|curl|wget)\\b");

  static Optional<Detection> detectCommand(List<String> command, RequestContext request) {
    return detectCommand(command, request, List.of());
  }

  static Optional<Detection> detectCommand(
      List<String> command, RequestContext request, List<String> stackClassNames) {
    return detectCommand(command, request, stackClassNames, false);
  }

  static Optional<Detection> detectCommand(List<String> command, RequestContext request,
      List<String> stackClassNames, boolean reflectionPolicy) {
    String joined = command == null ? "" : String.join(" ", command);
    if (joined.isBlank()) {
      return Optional.empty();
    }
    String expressionEngine = expressionEngineFromStack(stackClassNames);
    if (!expressionEngine.isBlank()) {
      String algorithm = expressionRuntimeAlgorithm(expressionEngine);
      return Optional.of(
          Detection.log(
              expressionEngine,
              algorithm,
              95,
              "Command execution reached from dynamic expression evaluation",
              request,
              Map.of("command", abbreviate(joined))));
    }
    String executableListener = SolrExecutableListener.frame(stackClassNames);
    if (executableListener != null) {
      return Optional.of(
          Detection.log(
              "command",
              "command_config_listener",
              90,
              "Command execution reached from a server-configured executable listener",
              request,
              Map.of(
                  "command", abbreviate(joined),
                  "listener", abbreviate(executableListener))));
    }
    String configLauncher = RocketMqFilterServer.directOwner(stackClassNames);
    if (configLauncher != null) {
      return Optional.of(
          Detection.log(
              "command",
              "command_config_injection",
              90,
              "Command execution reached from mutable runtime configuration",
              request,
              Map.of(
                  "command", abbreviate(joined),
                  "launcher", abbreviate(configLauncher))));
    }
    PosixShellCommand shell = PosixShellCommand.from(command);
    boolean windowsShell = java.io.File.separatorChar == '\\'
        || (command.get(0) != null && WINDOWS_SHELL.matcher(command.get(0)).matches());
    boolean requestSyntax = shell != null && shell.hasOperator()
        && (request.parameters().values().stream().anyMatch(values -> RequestShellSyntax.matches(shell, values))
            || bodyHasSinkValue(request, shell.source()));
    if (requestSyntax || (windowsShell && request.hasParameterIn(joined) && COMMAND_META.matcher(joined).find())) {
      return Optional.of(
          Detection.log(
              "command",
              "command_userinput",
              95,
              "Command contains request input and shell metacharacters",
              request,
              Map.of("command", abbreviate(joined))));
    }
    if (ProcessLaunchIndicators.matches(command, shell, COMMAND_COMMON, FILE_READERS, SENSITIVE_PATHS)) {
      return Optional.of(
          Detection.log(
              "command",
              "command_common",
              95,
              "Potentially dangerous command execution detected",
              request,
              Map.of("command", abbreviate(joined))));
    }
    String callbackHost = CommandDestination.callbackHost(command);
    if (callbackHost != null) {
      return Optional.of(
          Detection.log(
              "command",
              "command_dnslog",
              95,
              "Network tool has a callback domain as a destination argument",
              request,
              Map.of("command", abbreviate(joined), "host", callbackHost)));
    }
    boolean syntaxError = windowsShell
        ? hasUnbalancedQuotes(joined) || COMMAND_SENSITIVE_AFTER_JOIN.matcher(joined).find()
            || joined.contains("$IFS") || joined.contains("${IFS}")
        : shell != null && shell.hasUnclosedQuote();
    if (syntaxError) {
      return Optional.of(
          Detection.log(
              "command",
              "command_error",
              75,
              "Command contains suspicious shell syntax",
              request,
              Map.of("command", abbreviate(joined))));
    }
    if (reflectionPolicy && processInvokedReflectively(stackClassNames)) {
      return Optional.of(Detection.log("command", "command_reflect", 70,
          "Reflection dispatched the process API selected by policy", request,
          Map.of("command", abbreviate(joined), "decision_basis", "process_dispatch")));
    }
    return Optional.empty();
  }

  static Optional<Detection> detectWebshellCommand(
      List<String> command, RequestContext request) {
    String joined = command == null ? "" : String.join(" ", command);
    if (!joined.isBlank() && request.hasParameterIn(joined)) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_command",
              95,
              "Command execution is controlled by request input",
              request,
              Map.of("command", abbreviate(joined))));
    }
    return Optional.empty();
  }

  private static boolean hasUnbalancedQuotes(String value) {
    long single = value.chars().filter(ch -> ch == '\'').count();
    long doubleQuote = value.chars().filter(ch -> ch == '"').count();
    long backtick = value.chars().filter(ch -> ch == '`').count();
    return single % 2 != 0 || doubleQuote % 2 != 0 || backtick % 2 != 0;
  }

  private static boolean processInvokedReflectively(List<String> stack) {
    if (stack == null || stack.isEmpty()) return false;
    int caller = 0;
    for (int i = 0; i < stack.size(); i++) {
      String frame = stack.get(i);
      if ("java.lang.ProcessImpl".equals(frame) || "java.lang.ProcessBuilder".equals(frame) || "java.lang.Runtime".equals(frame)) {
        caller = i + 1;
        while (caller < stack.size() && ("java.lang.ProcessBuilder".equals(stack.get(caller))
            || "java.lang.Runtime".equals(stack.get(caller)))) caller++;
        break;
      }
    }
    if (caller == stack.size()) return false;
    String frame = stack.get(caller);
    return frame != null && (frame.startsWith("java.lang.reflect.") || frame.startsWith("jdk.internal.reflect.")
        || frame.startsWith("sun.reflect."));
  }

  private static String expressionEngineFromStack(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return "";
    }
    for (String frame : stackClassNames) {
      if (frame == null) continue;
      if (frame.startsWith("org.springframework.expression.") || frame.startsWith("org.springframework.webflow.expression.")) return "spel";
      if (frame.startsWith("org.apache.velocity.") || frame.startsWith("freemarker.")) return "template";
      if (frame.startsWith("org.mozilla.javascript.") || frame.startsWith("jdk.nashorn.")
          || frame.startsWith("org.openjdk.nashorn.") || frame.startsWith("com.oracle.truffle.js.")) return "javascript";
      if (frame.startsWith("org.apache.commons.jxpath.") || frame.startsWith("javax.xml.xpath.")
          || frame.startsWith("org.apache.xpath.") || frame.startsWith("com.sun.org.apache.xpath.internal.")
          || frame.startsWith("net.sf.saxon.xpath.")) return "xpath";
      if (frame.startsWith("org.apache.commons.jexl.") || frame.startsWith("org.apache.commons.jexl2.")
          || frame.startsWith("org.apache.commons.jexl3.")) return "jexl";
      if (frame.startsWith("javax.el.") || frame.startsWith("jakarta.el.") || frame.startsWith("org.apache.el.")) return "el";
      if (frame.startsWith("groovy.") || frame.startsWith("org.codehaus.groovy.") || frame.startsWith("org.apache.groovy.")
          || frame.startsWith("org.apache.tinkerpop.gremlin.groovy.")
          || frame.startsWith("org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.")) return "groovy";
      if (frame.startsWith("javax.script.")) return "script";
      if (frame.startsWith("ognl.") || frame.startsWith("org.apache.commons.ognl.")
          || frame.startsWith("com.opensymphony.xwork2.ognl.")) return "ognl";
      if (frame.startsWith("org.mvel.") || frame.startsWith("org.mvel2.")
          || frame.startsWith("org.elasticsearch.common.mvel2.")) return "mvel";
    }
    return "";
  }

  private static String expressionRuntimeAlgorithm(String engine) {
    return switch (engine) {
      case "spel" -> "spel_runtime";
      case "template" -> "template_runtime";
      case "javascript" -> "javascript_runtime";
      case "xpath" -> "xpath_runtime";
      case "jexl" -> "jexl_runtime";
      case "el" -> "el_runtime";
      case "mvel", "groovy", "script" -> "script_runtime";
      default -> engine + "_runtime";
    };
  }

  static boolean dangerousRemoteJobCommand(String command) {
    if (command == null || command.isBlank()) {
      return false;
    }
    String normalized = command.trim();
    return COMMAND_COMMON.matcher(normalized).find()
        || (COMMAND_META.matcher(normalized).find()
            && REMOTE_JOB_SHELL_COMMAND.matcher(normalized).find());
  }

  static List<String> commandFromObject(Object command) {
    if (command instanceof List<?> list) {
      var values = new ArrayList<String>();
      for (Object item : list) {
        values.add(String.valueOf(item));
      }
      return values;
    }
    return List.of(String.valueOf(command));
  }
}
