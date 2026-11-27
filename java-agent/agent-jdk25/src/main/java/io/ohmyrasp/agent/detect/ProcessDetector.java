package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.RequestValues.bodyHasSinkValue;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.process.PosixShellCommand;
import io.ohmyrasp.agent.process.WindowsShellCommand;
import io.ohmyrasp.agent.process.ProcessLaunchIndicators;
import io.ohmyrasp.agent.rules.general.RequestShellSyntax;
import io.ohmyrasp.agent.rules.product.rocketmq.RocketMqFilterServer;
import io.ohmyrasp.agent.rules.product.solr.SolrExecutableListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Process launches and command features, including direct runtime callers. */
public final class ProcessDetector {
  private ProcessDetector() {}

  private static final Set<String> FILE_READERS = Set.of("cat");
  private static final Set<String> SENSITIVE_PATHS = Set.of("/etc/passwd");

  private static final Pattern COMMAND_COMMON =
      Pattern.compile(
          "(?is)(?:cat\\s+/etc/passwd|nc\\b.{0,40}\\s-e\\s+/bin/(?:ba)?sh|bash\\s+-i\\b|/dev/tcp/|curl\\b.{0,80}\\|\\s*(?:sh|bash)|wget\\b.{0,80}\\|\\s*(?:sh|bash)|\\{echo,.{10,400}\\}\\|\\{base64,-d\\})");

  private static final Pattern COMMAND_META = Pattern.compile("[;&|`$<>]|\\$\\{?IFS\\}?");

  private static final Pattern REMOTE_JOB_SHELL_COMMAND =
      Pattern.compile("(?is)(?:^|\\W)(?:bash|sh|cmd|powershell|pwsh|nc|curl|wget)\\b");

  private static final Set<String> WEBSHELL_ENV =
      Set.of("LD_PRELOAD", "LD_AUDIT", "GCONV_PATH");

  public static Optional<Detection> detectCommand(List<String> command, RequestContext request) {
    return detectCommand(command, request, List.of());
  }

  public static Optional<Detection> detectCommand(
      List<String> command, RequestContext request, List<String> stackClassNames) {
    return detectCommand(command, request, stackClassNames, false);
  }

  public static Optional<Detection> detectCommand(List<String> command, RequestContext request,
      List<String> stackClassNames, boolean reflectionPolicy) {
    String joined = command == null ? "" : String.join(" ", command);
    if (joined.isBlank()) {
      return Optional.empty();
    }
    // Stack evidence first. An expression language reaching the process API is intrinsic and decides at once; a
    // general-purpose script engine or Solr's configured listener starts processes on purpose too and follows
    // outside_request, so it is held while the intrinsic checks below run: one of them on the same launch (shell
    // operators in RocketMQ's launcher, exploit-shaped arguments) wins, and log only cannot let it through.
    String expressionEngine = expressionEngineFromStack(stackClassNames, false);
    Optional<Detection> held = Optional.empty();
    if (!expressionEngine.isBlank()) {
      // The backports' bases for the same evidence: an expression language reaching the process API is expression
      // injection (intrinsic); a general-purpose script engine starts processes on purpose too (follows the setting).
      if (!isScriptEngine(expressionEngine)) {
        return Optional.of(expressionFinding(expressionEngine, joined, request));
      }
      // A script engine nearer the sink than an expression language that drove it: the language decides.
      String language = expressionEngineFromStack(stackClassNames, true);
      if (!language.isBlank()) {
        return Optional.of(expressionFinding(language, joined, request));
      }
      held = Optional.of(expressionFinding(expressionEngine, joined, request));
    }
    String executableListener = held.isPresent() ? null : SolrExecutableListener.frame(stackClassNames);
    if (executableListener != null) {
      held = Optional.of(
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
    PosixShellCommand shell = PosixShellCommand.from(command);
    WindowsShellCommand windows = WindowsShellCommand.from(command);
    String configLauncher = RocketMqFilterServer.directOwner(stackClassNames);
    // Shell operators in the program the filter-server manager launches, as on the backports: its own start command
    // (sh <home>/bin/startfsrv.sh ...) has none, an injected rocketmqHome (CVE-2023-33246) does.
    if (configLauncher != null && shell != null && shell.hasOperator()) {
      return Optional.of(
          Detection.log(
              "command",
              "command_config_injection",
              90,
              "Command execution reached from mutable runtime configuration",
              request,
              Map.of(
                  "command", abbreviate(joined),
                  "launcher", abbreviate(configLauncher),
                  "decision_basis", "configuration_launcher")));
    }
    if (held.isPresent()) {
      return ProcessLaunchIndicators.matches(command, shell, windows, COMMAND_COMMON, FILE_READERS, SENSITIVE_PATHS)
          ? Optional.of(commandCommon(joined, request)) : held;
    }
    boolean requestSyntax = shell != null && shell.hasOperator()
        && (request.inputParameters().values().stream().anyMatch(values -> RequestShellSyntax.matches(shell, values))
            || bodyHasSinkValue(request, shell.source()));
    boolean windowsSyntax = windows != null && windows.hasControl()
        && (request.inputParameters().values().stream().anyMatch(windows::controlsFrom) || bodyHasSinkValue(request, windows.source()));
    if (requestSyntax || windowsSyntax) {
      return Optional.of(
          Detection.log(
              "command",
              "command_userinput",
              95,
              "Request input matches control syntax in the inline shell program",
              request,
              Map.of("command", abbreviate(joined), "decision_basis", "request_shell_syntax")));
    }
    if (ProcessLaunchIndicators.matches(command, shell, windows, COMMAND_COMMON, FILE_READERS, SENSITIVE_PATHS)) {
      return Optional.of(commandCommon(joined, request));
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
    if (shell != null && shell.hasUnclosedQuote()) {
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

  private static Detection commandCommon(String joined, RequestContext request) {
    return Detection.log("command", "command_common", 95, "Potentially dangerous command execution detected", request,
        Map.of("command", abbreviate(joined)));
  }

  private static boolean isScriptEngine(String engine) {
    return "groovy".equals(engine) || "javascript".equals(engine) || "script".equals(engine);
  }

  private static Detection expressionFinding(String engine, String joined, RequestContext request) {
    return Detection.log(engine, expressionRuntimeAlgorithm(engine), 95,
        "Command execution reached from dynamic expression evaluation", request,
        Map.of("command", abbreviate(joined),
            "decision_basis", isScriptEngine(engine) ? "script_evaluation" : "expression_evaluation"));
  }

  public static Optional<Detection> detectWebshellCommand(
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

  /**
   * The engine of the first frame (nearest the sink) that belongs to one; with {@code languagesOnly}, the first that
   * is an expression language and not a general-purpose script engine.
   */
  private static String expressionEngineFromStack(List<String> stackClassNames, boolean languagesOnly) {
    if (stackClassNames == null) {
      return "";
    }
    for (String frame : stackClassNames) {
      if (frame == null) continue;
      String engine = engineOf(frame);
      if (!engine.isEmpty() && !(languagesOnly && isScriptEngine(engine))) return engine;
    }
    return "";
  }

  private static String engineOf(String frame) {
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

  public static Optional<Detection> detectWebshellLdPreload(
      String name, String value, RequestContext request) {
    String normalized = name == null ? "" : name.toUpperCase(Locale.ROOT);
    if (WEBSHELL_ENV.contains(normalized)) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_ld_preload",
              90,
              "Dangerous dynamic loader environment variable selected",
              request,
              Map.of("name", normalized, "value", abbreviate(value))));
    }
    return Optional.empty();
  }
}
