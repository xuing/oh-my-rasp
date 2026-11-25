package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.DetectorStrings.protocolOf;
import static io.ohmyrasp.agent.detect.ExpressionSyntax.containsRuntimeExpressionPrimitive;
import static io.ohmyrasp.agent.detect.ExpressionSyntax.looksLikeScriptCommandExecution;
import static io.ohmyrasp.agent.detect.JdbcDetector.h2JdbcInitConfig;
import static io.ohmyrasp.agent.detect.RemoteResourceDetector.JNDI_LOOKUP_PROTOCOLS;
import static io.ohmyrasp.agent.detect.RemoteResourceDetector.remoteConfigScheme;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodeJavaUnicodeEscapes;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodedVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.stripWrappingQuotes;
import static io.ohmyrasp.agent.detect.RequestExpressionDetector.dangerousRequestExpressionValue;
import static io.ohmyrasp.agent.detect.RequestExpressionDetector.requestExpressionParameterEngine;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;
import static io.ohmyrasp.agent.detect.RequestJson.parseJsonString;
import static io.ohmyrasp.agent.detect.RequestValues.firstNonBlankParameter;
import static io.ohmyrasp.agent.detect.RequestValues.jsonBodyParameter;
import static io.ohmyrasp.agent.detect.RequestValues.redactBodyRequest;
import static io.ohmyrasp.agent.serialization.StreamTypeNames.CONFIG_CONTEXT_TYPES;

import io.ohmyrasp.agent.detect.RequestJson.JsonStringField;
import io.ohmyrasp.agent.detect.RequestJson.JsonStringToken;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Scheduler, dynamic configuration, selector and JNDI request rules. */
final class RequestConfigurationDetector {
  private static final Pattern BASE64_CONFIG_VALUE =
      Pattern.compile("(?is)^[A-Za-z0-9+/=_-]{32,8192}$");

  private static final Pattern REQUEST_JNDI_LOOKUP =
      Pattern.compile("(?is)\\$\\{[^\\r\\n]{0,512}?jndi\\s*:\\s*([a-z][a-z0-9.+-]{0,20})://");

  private static final Pattern SCHEDULER_JOB_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:run|execute|trigger|executor|executors|job|jobs|scheduler|schedule|task|tasks)(?:[;/]|/|$)");

  private static final Pattern DYNAMIC_SCRIPT_CONFIG_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:actuator/gateway(?:/routes)?|api/setup/validate|setup/validate|h2-console/login\\.do|datasource/validate|connection/validate|context\\.json|dataimport|sampler|verification|checkscript|programexport|gremlin|console|_search|_scripts|config|configs|settings)(?:[;/]|/|$)");

  private static final Pattern MESSAGE_SELECTOR_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:websocket|sockjs|stomp|message|messages|topic|queue|gs-guide-websocket)(?:[;/]|/|$)");

  private static final Pattern STOMP_COMMAND =
      Pattern.compile("(?im)(?:^|[\\r\\n])(?:CONNECT|SUBSCRIBE|SEND|MESSAGE|UNSUBSCRIBE)\\b");

  private static final Pattern STOMP_SELECTOR_HEADER =
      Pattern.compile("(?im)(?:^|[\\r\\n])selector\\s*:\\s*([^\\r\\n\\u0000]{1,1000})");

  private static final Pattern JAVA_CONFIG_CONSTRUCTOR_ARGUMENT =
      Pattern.compile("(?s)[\"']([^\"']{1,2048})[\"']");

  private static final Set<String> JNDI_DRIVER_PARAMETER_NAMES =
      Set.of("driver", "driverclass", "driverclassname", "jdbcdriver", "jdbcdriverclass");

  private static final Set<String> JNDI_REMOTE_URL_PARAMETER_NAMES =
      Set.of(
          "url",
          "jdbcurl",
          "jndiurl",
          "providerurl",
          "javanamingproviderurl",
          "connectionurl",
          "datasourceurl");

  private static final Set<String> SCHEDULER_JOB_TYPE_PARAMETERS =
      Set.of("gluetype", "scripttype", "jobtype", "commandtype", "tasktype", "executortype");

  private static final Set<String> SCHEDULER_JOB_SOURCE_PARAMETERS =
      Set.of(
          "gluesource",
          "script",
          "source",
          "command",
          "commandline",
          "shell",
          "code",
          "payload");

  private static final Set<String> SCHEDULER_JOB_CONTEXT_PARAMETERS =
      Set.of(
          "jobid",
          "logid",
          "logdatetime",
          "executorhandler",
          "executorparams",
          "executorblockstrategy",
          "broadcastindex",
          "broadcasttotal",
          "glueupdatetime",
          "gluetype",
          "gluesource");

  private static final Set<String> DEBUG_PROCESS_LAUNCH_PARAMETERS =
      Set.of("exepath", "executable", "executablepath", "command", "commandline", "cmd");

  private static final Set<String> DYNAMIC_SCRIPT_CONFIG_PARAMETERS =
      Set.of(
          "dataconfig",
          "routeconfig",
          "routedefinition",
          "gatewayroute",
          "filterconfig",
          "scriptfields",
          "scriptfield",
          "scriptconfig",
          "validationrules",
          "groovyprogram");

  private RequestConfigurationDetector() {}

  static Optional<Detection> configuration(RequestContext request) {
    Optional<SchedulerShellJobMatch> schedulerJob = schedulerShellJobDispatch(request);
    if (schedulerJob.isPresent()) {
      SchedulerShellJobMatch match = schedulerJob.orElseThrow();
      RequestContext redactedRequest = redactSchedulerShellJobRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_scheduler_shell_job",
              90,
              "Request dispatches a scheduler job with shell-backed source",
              redactedRequest,
              Map.of(
                  "typeParameter", match.typeParameter(),
                  "typeValue", abbreviate(match.typeValue()),
                  "sourceParameter", match.sourceParameter(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<DebugProcessLaunchMatch> debugProcess = debugProcessLaunch(request);
    if (debugProcess.isPresent()) {
      DebugProcessLaunchMatch match = debugProcess.orElseThrow();
      RequestContext redactedRequest = redactDebugProcessLaunchRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_debug_process_launch",
              88,
              "Request invokes a debug process launch endpoint with an executable parameter",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "commandLength", String.valueOf(match.commandLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<DynamicScriptConfigMatch> dynamicConfig = dynamicScriptConfig(request);
    if (dynamicConfig.isPresent()) {
      DynamicScriptConfigMatch match = dynamicConfig.orElseThrow();
      RequestContext redactedRequest = redactDynamicScriptConfigRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_dynamic_script_config",
              90,
              "Request submits dynamic script configuration with runtime execution",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  static Optional<Detection> messageSelector(RequestContext request) {
    Optional<MessageSelectorExpressionMatch> messageSelectorExpression =
        messageSelectorExpression(request);
    if (messageSelectorExpression.isPresent()) {
      MessageSelectorExpressionMatch match = messageSelectorExpression.orElseThrow();
      RequestContext redactedRequest = redactBodyRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_message_selector_expression",
              92,
              "Request message selector carries a runtime expression",
              redactedRequest,
              Map.of(
                  "engine", match.engine(),
                  "selectorLength", String.valueOf(match.selectorLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  static Optional<Detection> naming(RequestContext request) {
    Optional<RequestJndiLookupMatch> jndiLookup = requestJndiLookup(request);
    if (jndiLookup.isPresent()) {
      RequestJndiLookupMatch match = jndiLookup.orElseThrow();
      RequestContext redactedRequest = redactJndiLookupRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_jndi_lookup",
              95,
              "Request carries a JNDI lookup payload",
              redactedRequest,
              Map.of(
                  "source", match.source(),
                  "name", match.name(),
                  "protocol", match.protocol(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  private record SchedulerShellJobMatch(
      String typeParameter, String typeValue, String sourceParameter, int sourceLength) {}

  private record DebugProcessLaunchMatch(String parameter, int commandLength) {}

  private record DynamicScriptConfigMatch(String parameter, String engine, int sourceLength) {}

  private record DynamicScriptConfigValue(String value, int sourceLength) {}

  private record MessageSelectorExpressionMatch(String engine, int selectorLength) {}

  private record RequestJndiLookupMatch(
      String source, String name, String protocol, int valueLength) {}

  private static Optional<SchedulerShellJobMatch> schedulerShellJobDispatch(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    boolean schedulerPath =
        SCHEDULER_JOB_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find();
    Optional<SchedulerShellJobMatch> parameterMatch =
        schedulerShellJobParameterDispatch(request.parameters(), schedulerPath);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    List<JsonStringField> fields = jsonStringFields(request.body());
    Optional<JsonStringField> type =
        firstJsonFieldValueMatching(
            fields, SCHEDULER_JOB_TYPE_PARAMETERS, RequestConfigurationDetector::isShellSchedulerType);
    if (type.isEmpty()) {
      return Optional.empty();
    }
    Optional<JsonStringField> source = firstNonBlankJsonField(fields, SCHEDULER_JOB_SOURCE_PARAMETERS);
    if (source.isEmpty()) {
      return Optional.empty();
    }
    if (!schedulerPath && schedulerContextSignalCount(fields) < 3) {
      return Optional.empty();
    }
    JsonStringField typeField = type.orElseThrow();
    JsonStringField sourceField = source.orElseThrow();
    return Optional.of(
        new SchedulerShellJobMatch(
            jsonBodyParameter(typeField.name()),
            typeField.value(),
            jsonBodyParameter(sourceField.name()),
            sourceField.value().length()));
  }

  private static Optional<SchedulerShellJobMatch> schedulerShellJobParameterDispatch(
      Map<String, List<String>> parameters, boolean schedulerPath) {
    if (parameters == null || parameters.isEmpty()) {
      return Optional.empty();
    }
    Optional<Map.Entry<String, String>> type =
        firstParameterValueMatching(
            parameters,
            SCHEDULER_JOB_TYPE_PARAMETERS,
            RequestConfigurationDetector::isShellSchedulerType);
    if (type.isEmpty()) {
      return Optional.empty();
    }
    Optional<Map.Entry<String, String>> source =
        firstNonBlankParameter(parameters, SCHEDULER_JOB_SOURCE_PARAMETERS);
    if (source.isEmpty()) {
      return Optional.empty();
    }
    if (!schedulerPath && schedulerContextSignalCount(parameters) < 3) {
      return Optional.empty();
    }
    Map.Entry<String, String> typeEntry = type.orElseThrow();
    Map.Entry<String, String> sourceEntry = source.orElseThrow();
    return Optional.of(
        new SchedulerShellJobMatch(
            typeEntry.getKey(),
            typeEntry.getValue(),
            sourceEntry.getKey(),
            sourceEntry.getValue().length()));
  }

  private static Optional<Map.Entry<String, String>> firstParameterValueMatching(
      Map<String, List<String>> parameters,
      Set<String> candidateNames,
      java.util.function.Predicate<String> valuePredicate) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!candidateNames.contains(normalizeParameterName(entry.getKey()))) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (value != null && valuePredicate.test(value)) {
          return Optional.of(Map.entry(entry.getKey(), value));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<JsonStringField> firstJsonFieldValueMatching(
      List<JsonStringField> fields,
      Set<String> candidateNames,
      java.util.function.Predicate<String> valuePredicate) {
    for (JsonStringField field : fields == null ? List.<JsonStringField>of() : fields) {
      if (!candidateNames.contains(normalizeParameterName(field.name()))) {
        continue;
      }
      if (field.value() != null && valuePredicate.test(field.value())) {
        return Optional.of(field);
      }
    }
    return Optional.empty();
  }

  private static Optional<JsonStringField> firstNonBlankJsonField(
      List<JsonStringField> fields, Set<String> candidateNames) {
    for (JsonStringField field : fields == null ? List.<JsonStringField>of() : fields) {
      if (!candidateNames.contains(normalizeParameterName(field.name()))) {
        continue;
      }
      if (field.value() != null && !field.value().isBlank()) {
        return Optional.of(field);
      }
    }
    return Optional.empty();
  }

  private static boolean isShellSchedulerType(String value) {
    String normalized = value == null ? "" : value.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
    return normalized.equals("glueshell")
        || normalized.equals("shell")
        || normalized.equals("bash")
        || normalized.equals("sh")
        || normalized.equals("cmd")
        || normalized.equals("powershell")
        || normalized.equals("pwsh")
        || normalized.equals("shellscript");
  }

  private static int schedulerContextSignalCount(Map<String, List<String>> parameters) {
    int count = 0;
    for (String name : parameters.keySet()) {
      if (SCHEDULER_JOB_CONTEXT_PARAMETERS.contains(normalizeParameterName(name))) {
        count++;
      }
    }
    return count;
  }

  private static int schedulerContextSignalCount(List<JsonStringField> fields) {
    int count = 0;
    var seen = new LinkedHashSet<String>();
    for (JsonStringField field : fields == null ? List.<JsonStringField>of() : fields) {
      String normalized = normalizeParameterName(field.name());
      if (SCHEDULER_JOB_CONTEXT_PARAMETERS.contains(normalized) && seen.add(normalized)) {
        count++;
      }
    }
    return count;
  }

  private static RequestContext redactSchedulerShellJobRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    SCHEDULER_JOB_SOURCE_PARAMETERS.contains(normalizeParameterName(name))
                            && value != null
                            && !value.isBlank()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactSchedulerShellJobQuery(request.query()),
        parameters,
        request.headers(),
        request.body());
  }

  private static String redactSchedulerShellJobQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = percentDecode(parts[i].substring(0, separator));
      if (SCHEDULER_JOB_SOURCE_PARAMETERS.contains(normalizeParameterName(name))) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<DebugProcessLaunchMatch> debugProcessLaunch(RequestContext request) {
    if (request == null || !request.active() || !debugProcessLaunchContext(request)) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!DEBUG_PROCESS_LAUNCH_PARAMETERS.contains(normalizeParameterName(entry.getKey()))) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value != null && !value.isBlank()) {
          return Optional.of(new DebugProcessLaunchMatch(entry.getKey(), value.length()));
        }
      }
    }
    if (jsonConfigBody(request)) {
      for (JsonStringField field : jsonStringFields(request.body())) {
        if (DEBUG_PROCESS_LAUNCH_PARAMETERS.contains(normalizeParameterName(field.name()))
            && field.value() != null
            && !field.value().isBlank()) {
          return Optional.of(
              new DebugProcessLaunchMatch("body." + field.name(), field.value().length()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean debugProcessLaunchContext(RequestContext request) {
    String method = lower(request.method()).replaceAll("[^a-z]", "");
    if (!Set.of("post", "put", "patch").contains(method)) {
      return false;
    }
    String uri = lower(percentDecode(request.uri() == null ? "" : request.uri())).replace('\\', '/');
    return (uri.contains("/debug/") || uri.endsWith("/debug"))
        && (uri.contains("/process") || uri.contains("/processes"));
  }

  private static RequestContext redactDebugProcessLaunchRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (DEBUG_PROCESS_LAUNCH_PARAMETERS.contains(normalizeParameterName(name))) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactDebugProcessLaunchQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactDebugProcessLaunchQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String rawName = parts[i].substring(0, separator);
      String name = percentDecode(rawName);
      if (DEBUG_PROCESS_LAUNCH_PARAMETERS.contains(normalizeParameterName(name))) {
        parts[i] = rawName + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<DynamicScriptConfigMatch> dynamicScriptConfig(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    boolean controlPath =
        DYNAMIC_SCRIPT_CONFIG_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
            .find();
    Optional<DynamicScriptConfigMatch> parameterMatch =
        dynamicScriptConfigParameters(request, controlPath);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    return dynamicScriptConfigBody(request, controlPath);
  }

  private static Optional<DynamicScriptConfigMatch> dynamicScriptConfigParameters(
      RequestContext request, boolean controlPath) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue()) {
        Optional<DynamicScriptConfigValue> dangerousValue =
            dangerousDynamicScriptConfigValue(request, entry.getKey(), value, controlPath);
        if (dangerousValue.isPresent()) {
          DynamicScriptConfigValue inspected = dangerousValue.orElseThrow();
          String engine = dynamicScriptConfigEngine(request.uri(), entry.getKey(), inspected.value());
          return Optional.of(
              new DynamicScriptConfigMatch(
                  entry.getKey(),
                  engine.isBlank() ? "script" : engine,
                  inspected.sourceLength()));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<DynamicScriptConfigValue> dangerousDynamicScriptConfigValue(
      RequestContext request, String name, String value, boolean controlPath) {
    String normalizedName = normalizeParameterName(name);
    boolean configParameter = DYNAMIC_SCRIPT_CONFIG_PARAMETERS.contains(normalizedName);
    if (!controlPath && !configParameter) {
      return Optional.empty();
    }
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (DynamicScriptConfigValue inspected : dynamicScriptConfigValues(value)) {
      String engine = dynamicScriptConfigEngine(request.uri(), name, inspected.value());
      if (containsRuntimeExpressionPrimitive(engine, inspected.value())
          || looksLikeScriptCommandExecution(inspected.value())
          || h2JdbcInitConfig(inspected.value())
          || dangerousJavaConfigConstructor(inspected.value())) {
        return Optional.of(inspected);
      }
    }
    return Optional.empty();
  }

  private static List<DynamicScriptConfigValue> dynamicScriptConfigValues(String value) {
    var values = new ArrayList<DynamicScriptConfigValue>();
    values.add(new DynamicScriptConfigValue(value, value.length()));
    String unicodeDecoded = decodeJavaUnicodeEscapes(value);
    if (!unicodeDecoded.equals(value)) {
      values.add(new DynamicScriptConfigValue(unicodeDecoded, unicodeDecoded.length()));
    }
    decodedBase64ConfigValue(value)
        .ifPresent(decoded -> values.add(new DynamicScriptConfigValue(decoded, decoded.length())));
    return List.copyOf(values);
  }

  private static Optional<String> decodedBase64ConfigValue(String value) {
    if (value == null) {
      return Optional.empty();
    }
    String compact = value.replaceAll("\\s+", "");
    if (!BASE64_CONFIG_VALUE.matcher(compact).matches()) {
      return Optional.empty();
    }
    Optional<String> decoded = base64DecodeUtf8(compact);
    if (decoded.isEmpty()) {
      return Optional.empty();
    }
    String text = decoded.orElseThrow();
    return lower(text).contains("jdbc:h2:") ? Optional.of(text) : Optional.empty();
  }

  private static Optional<String> base64DecodeUtf8(String value) {
    try {
      return Optional.of(new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8));
    } catch (IllegalArgumentException first) {
      try {
        return Optional.of(
            new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8));
      } catch (IllegalArgumentException second) {
        return Optional.empty();
      }
    }
  }

  private static boolean dangerousJavaConfigConstructor(String value) {
    for (String variant : decodedVariants(value)) {
      String normalized = lower(variant).replace('/', '.');
      for (String type : CONFIG_CONTEXT_TYPES) {
        String normalizedType = lower(type);
        int classIndex = normalized.indexOf(normalizedType);
        if (classIndex < 0) {
          continue;
        }
        int openParen = normalized.indexOf('(', classIndex + normalizedType.length());
        if (openParen < 0) {
          continue;
        }
        String arguments = variant.substring(Math.min(openParen + 1, variant.length()));
        var matcher = JAVA_CONFIG_CONSTRUCTOR_ARGUMENT.matcher(arguments);
        while (matcher.find()) {
          if (remoteConfigScheme(matcher.group(1)).isPresent()) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private static Optional<DynamicScriptConfigMatch> dynamicScriptConfigBody(
      RequestContext request, boolean controlPath) {
    if (!dynamicScriptJsonConfigBody(request, controlPath)) {
      return Optional.empty();
    }
    List<JsonStringField> fields = jsonStringFields(request.body());
    String bodyEngine = dynamicScriptBodyEngineSignal(fields);
    for (JsonStringField field : fields) {
      String normalizedName = normalizeParameterName(field.name());
      boolean configField = DYNAMIC_SCRIPT_CONFIG_PARAMETERS.contains(normalizedName);
      if (!controlPath && !configField) {
        continue;
      }
      String value = field.value();
      if (value == null || value.isBlank()) {
        continue;
      }
      String engine = dynamicScriptConfigEngine(request.uri(), field.name(), value);
      if (!bodyEngine.isBlank() && isDynamicScriptSourceField(field.name())) {
        engine = bodyEngine;
      }
      Optional<DynamicScriptConfigValue> dangerousValue =
          dangerousDynamicScriptConfigValue(request, field.name(), value, controlPath);
      if (dangerousValue.isPresent()) {
        DynamicScriptConfigValue inspected = dangerousValue.orElseThrow();
        engine = dynamicScriptConfigEngine(request.uri(), field.name(), inspected.value());
        if (!bodyEngine.isBlank() && isDynamicScriptSourceField(field.name())) {
          engine = bodyEngine;
        }
        return Optional.of(
            new DynamicScriptConfigMatch(
                jsonBodyParameter(field.name()),
                engine.isBlank() ? "script" : engine,
                inspected.sourceLength()));
      }
    }
    return Optional.empty();
  }

  private static boolean dynamicScriptJsonConfigBody(RequestContext request, boolean controlPath) {
    if (jsonConfigBody(request)) {
      return true;
    }
    if (!controlPath || request == null || request.body().isBlank()) {
      return false;
    }
    String method = lower(request.method());
    if (!method.equals("post") && !method.equals("put") && !method.equals("patch")) {
      return false;
    }
    String trimmed = request.body().trim();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
      return false;
    }
    String contentType = lower(request.header("content-type").orElse(""));
    return contentType.contains("text") || contentType.contains("x-www-form-urlencoded");
  }

  private static String dynamicScriptBodyEngineSignal(List<JsonStringField> fields) {
    for (JsonStringField field : fields) {
      String normalizedName = normalizeParameterName(field.name());
      if (!normalizedName.equals("lang")
          && !normalizedName.equals("language")
          && !normalizedName.endsWith("lang")
          && !normalizedName.endsWith("language")) {
        continue;
      }
      String engine = dynamicScriptLanguageEngineName(field.value());
      if (!engine.isBlank()) {
        return engine;
      }
    }
    return "";
  }

  private static String dynamicScriptLanguageEngineName(String value) {
    String normalized = normalizeParameterName(value);
    if (normalized.equals("mvel")) {
      return "mvel";
    }
    if (normalized.equals("groovy") || normalized.equals("gremlingroovy")) {
      return "groovy";
    }
    if (normalized.equals("javascript") || normalized.equals("js")) {
      return "javascript";
    }
    if (normalized.equals("spel") || normalized.equals("springel")) {
      return "spel";
    }
    if (normalized.equals("ognl")) {
      return "ognl";
    }
    return "";
  }

  private static boolean isDynamicScriptSourceField(String name) {
    String normalized = normalizeParameterName(name);
    return normalized.equals("script")
        || normalized.equals("source")
        || normalized.equals("code")
        || normalized.equals("expression")
        || normalized.endsWith("script")
        || normalized.endsWith("source")
        || normalized.endsWith("code")
        || normalized.endsWith("expression");
  }

  private static RequestContext redactDynamicScriptConfigRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    boolean controlPath =
        DYNAMIC_SCRIPT_CONFIG_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
            .find();
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    dangerousDynamicScriptConfigValue(request, name, value, controlPath).isPresent()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactDynamicScriptConfigQuery(request, controlPath),
        parameters,
        request.headers());
  }

  private static String redactDynamicScriptConfigQuery(RequestContext request, boolean controlPath) {
    String query = request.query();
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String rawName = parts[i].substring(0, separator);
      String name = percentDecode(rawName);
      String value = percentDecode(parts[i].substring(separator + 1));
      if (dangerousDynamicScriptConfigValue(request, name, value, controlPath).isPresent()) {
        parts[i] = rawName + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<MessageSelectorExpressionMatch> messageSelectorExpression(
      RequestContext request) {
    if (request == null || !request.active() || request.body().isBlank()) {
      return Optional.empty();
    }
    for (String frame : messageSelectorFrames(request)) {
      if (!stompSelectorContext(request, frame)) {
        continue;
      }
      var matcher = STOMP_SELECTOR_HEADER.matcher(frame);
      while (matcher.find()) {
        String selector = matcher.group(1).trim();
        if (selector.isBlank()) {
          continue;
        }
        String engine = messageSelectorEngine(selector);
        if (!engine.isBlank() && dangerousRequestExpressionValue(engine, selector)) {
          return Optional.of(new MessageSelectorExpressionMatch(engine, selector.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static List<String> messageSelectorFrames(RequestContext request) {
    String body = request.body();
    var frames = new ArrayList<String>();
    frames.add(body);
    if (body.trim().startsWith("[")) {
      int index = 0;
      while (index < body.length()) {
        int quote = body.indexOf('"', index);
        if (quote < 0) {
          break;
        }
        Optional<JsonStringToken> token = parseJsonString(body, quote);
        if (token.isEmpty()) {
          index = quote + 1;
          continue;
        }
        frames.add(token.orElseThrow().value());
        index = token.orElseThrow().nextIndex();
      }
    }
    return List.copyOf(frames);
  }

  private static boolean stompSelectorContext(RequestContext request, String frame) {
    if (frame == null || frame.isBlank()) {
      return false;
    }
    String uri = request.uri() == null ? "" : request.uri();
    boolean messagePath = MESSAGE_SELECTOR_CONTROL_PATH.matcher(uri).find();
    boolean stompFrame =
        STOMP_COMMAND.matcher(frame).find()
            && lower(frame).contains("destination:")
            && lower(frame).contains("selector:");
    return stompFrame && (messagePath || lower(request.header("content-type").orElse("")).contains("json"));
  }

  private static String messageSelectorEngine(String selector) {
    String expressionEngine = requestExpressionParameterEngine(selector);
    if (!expressionEngine.isBlank()) {
      return expressionEngine;
    }
    String normalized = lower(selector);
    if (normalized.contains("t(java.lang.") || normalized.contains("springframework.expression")) {
      return "spel";
    }
    if (normalized.contains("java.lang.runtime") || normalized.contains("processbuilder")) {
      return "expression";
    }
    return "";
  }

  private static String dynamicScriptConfigEngine(String uri, String parameter, String value) {
    String normalizedUri = lower(uri);
    String normalizedParameter = normalizeParameterName(parameter);
    String normalizedValue = lower(value);
    if (normalizedValue.contains("jdbc:h2:")) {
      return "h2";
    }
    if (normalizedValue.contains("filesystemxmlapplicationcontext")
        || normalizedValue.contains("classpathxmlapplicationcontext")
        || normalizedValue.contains("resourcexmlapplicationcontext")) {
      return "spring";
    }
    if (normalizedValue.contains("shellsession")) {
      return "mvel";
    }
    if (normalizedUri.contains("/actuator/gateway")
        || normalizedValue.contains("#{")
        || normalizedValue.contains("t(java.lang.")) {
      return "spel";
    }
    String compactValue = normalizedValue.replaceAll("\\s+", "");
    if (normalizedValue.contains("script::") || normalizedParameter.contains("mvel")) {
      return "mvel";
    }
    if (normalizedUri.contains("groovy")
        || normalizedParameter.contains("groovy")
        || normalizedUri.contains("gremlin")
        || normalizedParameter.equals("gremlin")
        || normalizedValue.contains("gremlin-groovy")) {
      return "groovy";
    }
    if (compactValue.contains("#runtimeclass")
        || (compactValue.contains("#this")
            && compactValue.contains("getdeclaredmethods")
            && compactValue.contains("invoke"))) {
      return "ognl";
    }
    if (normalizedUri.contains("dataimport")
        || normalizedParameter.equals("dataconfig")
        || normalizedParameter.equals("validationrules")
        || normalizedParameter.equals("function")
        || normalizedValue.contains("function")
        || normalizedValue.contains("//javascript")
        || normalizedValue.contains("<script")
        || normalizedValue.contains("transformer=\"script:")) {
      return "javascript";
    }
    if (normalizedUri.contains("_search")
        || normalizedParameter.equals("scriptfields")
        || normalizedParameter.equals("scriptfield")) {
      return "mvel";
    }
    return "script";
  }

  private static Optional<RequestJndiLookupMatch> requestJndiLookup(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    boolean jndiDriverSelector = requestHasJndiDriverSelector(request);
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        String protocol = jndiParameterProtocol(entry.getKey(), value, jndiDriverSelector);
        if (!protocol.isBlank()) {
          return Optional.of(
              new RequestJndiLookupMatch(
                  "parameter", entry.getKey(), protocol, value == null ? 0 : value.length()));
        }
      }
    }
    for (Map.Entry<String, String> entry : request.headers().entrySet()) {
      String protocol = jndiLookupProtocol(entry.getValue());
      if (!protocol.isBlank()) {
        return Optional.of(
            new RequestJndiLookupMatch(
                "header",
                entry.getKey(),
                protocol,
                entry.getValue() == null ? 0 : entry.getValue().length()));
      }
    }
    return Optional.empty();
  }

  private static String jndiLookupProtocol(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    var variants = new ArrayList<String>();
    variants.add(value);
    String decoded = percentDecode(value);
    variants.add(decoded);
    variants.add(percentDecode(decoded));
    variants.add(deobfuscateLog4jLookup(decoded));
    for (String variant : variants) {
      var matcher = REQUEST_JNDI_LOOKUP.matcher(variant);
      while (matcher.find()) {
        String protocol = lower(matcher.group(1));
        if (JNDI_LOOKUP_PROTOCOLS.contains(protocol)) {
          return protocol;
        }
      }
    }
    return "";
  }

  private static String jndiParameterProtocol(
      String name, String value, boolean jndiDriverSelector) {
    String protocol = jndiLookupProtocol(value);
    if (!protocol.isBlank()) {
      return protocol;
    }
    if (jndiDriverSelector && isJndiRemoteUrlParameter(name)) {
      return directJndiUrlProtocol(value);
    }
    return "";
  }

  private static boolean requestHasJndiDriverSelector(RequestContext request) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isJndiDriverParameter(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (isJndiDriverClass(value)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean isJndiDriverParameter(String name) {
    return JNDI_DRIVER_PARAMETER_NAMES.contains(normalizeDottedParameterName(name));
  }

  private static boolean isJndiRemoteUrlParameter(String name) {
    return JNDI_REMOTE_URL_PARAMETER_NAMES.contains(normalizeDottedParameterName(name));
  }

  private static String normalizeDottedParameterName(String name) {
    return normalizeParameterName(name).replace(".", "");
  }

  private static boolean isJndiDriverClass(String value) {
    for (String variant : decodedVariants(value)) {
      String normalized = lower(variant).replace('/', '.').trim();
      if (normalized.equals("javax.naming.initialcontext")
          || normalized.equals("javax.naming.ldap.initialldapcontext")
          || normalized.startsWith("com.sun.jndi.")) {
        return true;
      }
    }
    return false;
  }

  private static String directJndiUrlProtocol(String value) {
    for (String variant : decodedVariants(value)) {
      String protocol = protocolOf(stripWrappingQuotes(variant.trim()));
      if (JNDI_LOOKUP_PROTOCOLS.contains(protocol)) {
        return protocol;
      }
    }
    return "";
  }

  private static String deobfuscateLog4jLookup(String value) {
    String normalized = lower(value);
    for (int i = 0; i < 3; i++) {
      normalized =
          normalized.replaceAll("\\$\\{\\s*::-\\s*([a-z0-9])\\s*}", "$1");
      normalized =
          normalized.replaceAll("\\$\\{\\s*(?:lower|upper)\\s*:\\s*([a-z0-9])\\s*}", "$1");
      normalized =
          normalized.replaceAll(
              "\\$\\{\\s*env\\s*:[^}:]{1,80}\\s*:-\\s*([a-z0-9])\\s*}", "$1");
    }
    return normalized;
  }

  private static RequestContext redactJndiLookupRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    boolean jndiDriverSelector = requestHasJndiDriverSelector(request);
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    jndiParameterProtocol(name, value, jndiDriverSelector).isBlank()
                        ? value
                        : "[redacted]");
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    var headers = new LinkedHashMap<String, String>();
    request
        .headers()
        .forEach(
            (name, value) ->
                headers.put(name, jndiLookupProtocol(value).isBlank() ? value : "[redacted]"));
    return new RequestContext(
        request.method(),
        request.uri(),
        redactJndiLookupQuery(request.query(), jndiDriverSelector),
        parameters,
        headers);
  }

  private static String redactJndiLookupQuery(String query, boolean jndiDriverSelector) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = percentDecode(parts[i].substring(0, separator));
      String value = percentDecode(parts[i].substring(separator + 1));
      if (!jndiParameterProtocol(name, value, jndiDriverSelector).isBlank()) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }
}
