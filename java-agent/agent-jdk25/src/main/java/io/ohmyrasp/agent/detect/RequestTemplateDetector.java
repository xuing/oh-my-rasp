package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.ExpressionSyntax.containsRuntimeExpressionPrimitive;
import static io.ohmyrasp.agent.detect.ExpressionSyntax.looksLikeScriptCommandExecution;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodedVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.pathVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.protectedWebappResource;
import static io.ohmyrasp.agent.detect.RequestDecoding.stripWrappingQuotes;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;
import static io.ohmyrasp.agent.detect.RequestValues.jsonBodyParameter;

import io.ohmyrasp.agent.detect.RequestJson.JsonStringField;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Template loader, parameter and source-path request rules. */
final class RequestTemplateDetector {
  private static final Pattern TEMPLATE_PARAMETER_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:select|query|queryfield|queryfieldbysql|search|render|report|template|templates|velocity|view|views)(?:[;/]|/|$)");

  private static final Pattern TEMPLATE_LOADER_ENABLE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|config|configs|settings|schema|template|templates|velocity)(?:[;/]|/|$)");

  private static final Pattern TEMPLATE_PARAMETER_MESSAGE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:contactadministrators|contact|support|feedback|message|messages|mail|email)(?:[!.;/]|/|$)");

  private static final Pattern TEMPLATE_SOURCE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|administrator|adminapi|ajax|cfc|control|filemanager|include|includes|macro|preview|render|resource|resources|template|templates|tinymce|view|views)(?:[!;/]|/|$)");

  private static final Pattern TEMPLATE_SOURCE_SENSITIVE_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:web\\.xml|server\\.xml|context\\.xml|confluence\\.cfg\\.xml|database\\.properties|application\\.properties|password\\.properties|proc/self/environ|passwd|shadow|[^/]*(?:access|application|coldfusion-out|error|server)\\.log)(?:$|[?#])");

  private static final Pattern TEMPLATE_PARAMETER_LOADER_ENABLE =
      Pattern.compile(
          "(?is)[\"']?\\s*((?:params?|parameters?|request)\\s*[._-]?\\s*resource\\s*[._-]?\\s*loader\\s*[._-]?\\s*enabled)\\s*[\"']?\\s*[:=]\\s*[\"']?\\s*(?:true|1|yes|on)\\b");

  private static final Set<String> TEMPLATE_PARAMETER_NAMES =
      Set.of(
          "template",
          "templatebody",
          "templatecontent",
          "templatesource",
          "templatepayload",
          "templatecustom",
          "v.template.custom",
          "vtemplatecustom",
          "velocitytemplate",
          "freemarkertemplate",
          "ftltemplate",
          "thymeleaftemplate");

  private static final Set<String> TEMPLATE_ENGINE_PARAMETER_NAMES =
      Set.of("wt", "engine", "renderer", "renderengine", "templateengine", "viewengine");

  private static final Set<String> TEMPLATE_ENGINE_VALUES =
      Set.of("velocity", "freemarker", "ftl", "thymeleaf", "mustache", "pebble", "template");

  private static final Set<String> TEMPLATE_MESSAGE_PARAMETER_NAMES =
      Set.of("body", "comment", "content", "description", "details", "message", "subject", "text");

  private static final Set<String> TEMPLATE_SOURCE_PARAMETER_NAMES =
      Set.of(
          "class",
          "classname",
          "bundle",
          "bundlefile",
          "bundlepath",
          "javaclass",
          "locale",
          "localefile",
          "localepath",
          "messagebundle",
          "messagebundlepath",
          "resource",
          "resourcefile",
          "resourcepath",
          "resourceurl",
          "template",
          "templatepath",
          "templatefile",
          "templateurl",
          "templatesource",
          "templatesourceurl",
          "templatesourcepath");

  private RequestTemplateDetector() {}

  static Optional<Detection> loader(RequestContext request) {
    Optional<TemplateLoaderEnableMatch> templateLoaderEnable = templateLoaderEnable(request);
    if (templateLoaderEnable.isPresent()) {
      TemplateLoaderEnableMatch match = templateLoaderEnable.orElseThrow();
      RequestContext redactedRequest = redactTemplateLoaderEnableRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_template_loader_enable",
              88,
              "Request enables parameter-loaded template resources",
              redactedRequest,
              Map.of(
                  "source", match.source(),
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  static Optional<Detection> content(RequestContext request) {
    Optional<TemplateParameterMatch> templateParameter = templateParameter(request);
    if (templateParameter.isPresent()) {
      TemplateParameterMatch match = templateParameter.orElseThrow();
      RequestContext redactedRequest = redactTemplateParameterRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_template_parameter",
              90,
              "Request parameter carries a runtime template payload",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<TemplateSourceMatch> templateSource = templateSource(request);
    if (templateSource.isPresent()) {
      TemplateSourceMatch match = templateSource.orElseThrow();
      RequestContext redactedRequest = redactTemplateSourceRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_template_source",
              88,
              "Request selects an unsafe template source path or URL",
              redactedRequest,
              Map.of(
                  "source", match.source(),
                  "parameter", match.parameter(),
                  "targetType", match.targetType(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  private record TemplateLoaderEnableMatch(
      String source, String parameter, String engine, int sourceLength) {}

  private record TemplateParameterMatch(String parameter, String engine, int sourceLength) {}

  private record TemplateSourceMatch(
      String source, String parameter, String targetType, int valueLength) {}

  private static Optional<TemplateLoaderEnableMatch> templateLoaderEnable(
      RequestContext request) {
    if (request == null || !request.active() || !isMutatingHttpMethod(request.method())) {
      return Optional.empty();
    }
    if (!TEMPLATE_LOADER_ENABLE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
        .find()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<String> enabledName = templateParameterLoaderEnableName(value);
        if (enabledName.isEmpty()) {
          continue;
        }
        String engine = templateLoaderEnableEngine(request, value);
        if (!engine.isBlank()) {
          return Optional.of(
              new TemplateLoaderEnableMatch(
                  "parameter", entry.getKey(), engine, value == null ? 0 : value.length()));
        }
      }
    }
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    Optional<String> bodyField = templateParameterLoaderEnableField(request.body());
    if (bodyField.isEmpty()) {
      return Optional.empty();
    }
    String engine = templateLoaderEnableEngine(request, request.body());
    if (engine.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(
        new TemplateLoaderEnableMatch(
            "body", jsonBodyParameter(bodyField.orElseThrow()), engine, request.body().length()));
  }

  private static boolean isMutatingHttpMethod(String method) {
    String normalized = lower(method);
    return normalized.equals("post")
        || normalized.equals("put")
        || normalized.equals("patch")
        || normalized.equals("delete");
  }

  private static Optional<String> templateParameterLoaderEnableName(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (String variant : decodedVariants(value)) {
      var matcher = TEMPLATE_PARAMETER_LOADER_ENABLE.matcher(variant);
      if (matcher.find()) {
        return Optional.of(matcher.group(1).replaceAll("\\s+", ""));
      }
    }
    return Optional.empty();
  }

  private static Optional<String> templateParameterLoaderEnableField(String body) {
    for (JsonStringField field : jsonStringFields(body)) {
      if (isTemplateParameterLoaderEnableName(field.name()) && truthyConfigValue(field.value())) {
        return Optional.of(field.name());
      }
    }
    return templateParameterLoaderEnableName(body);
  }

  private static boolean isTemplateParameterLoaderEnableName(String name) {
    String normalized = normalizeParameterName(name).replace(".", "");
    return normalized.equals("paramresourceloaderenabled")
        || normalized.equals("paramsresourceloaderenabled")
        || normalized.equals("parameterresourceloaderenabled")
        || normalized.equals("parametersresourceloaderenabled")
        || normalized.equals("requestresourceloaderenabled");
  }

  private static boolean truthyConfigValue(String value) {
    String normalized =
        stripWrappingQuotes(lower(percentDecode(value == null ? "" : value)).trim());
    return normalized.equals("true")
        || normalized.equals("1")
        || normalized.equals("yes")
        || normalized.equals("on");
  }

  private static String templateLoaderEnableEngine(RequestContext request, String source) {
    String engine = templateEngineSignal(request.parameters());
    if (!engine.isBlank()) {
      return engine;
    }
    if (jsonConfigBody(request)) {
      engine = templateEngineSignal(jsonStringFields(request.body()));
      if (!engine.isBlank()) {
        return engine;
      }
    }
    String inspected =
        lower(
            percentDecode(
                (request.uri() == null ? "" : request.uri())
                    + "\n"
                    + (source == null ? "" : source)));
    if (inspected.contains("velocityresponsewriter")
        || inspected.contains("velocity")
        || inspected.contains("apache.velocity")) {
      return "velocity";
    }
    if (inspected.contains("freemarker") || inspected.contains("ftl")) {
      return "freemarker";
    }
    if (inspected.contains("thymeleaf")) {
      return "thymeleaf";
    }
    if (inspected.contains("template")) {
      return "template";
    }
    return "";
  }

  private static RequestContext redactTemplateLoaderEnableRequest(RequestContext request) {
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
                    templateParameterLoaderEnableName(value).isPresent()
                            && !templateLoaderEnableEngine(request, value).isBlank()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTemplateLoaderEnableQuery(request),
        parameters,
        request.headers());
  }

  private static String redactTemplateLoaderEnableQuery(RequestContext request) {
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
      String value = percentDecode(parts[i].substring(separator + 1));
      if (templateParameterLoaderEnableName(value).isPresent()
          && !templateLoaderEnableEngine(request, value).isBlank()) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<TemplateParameterMatch> templateParameter(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String uri = request.uri() == null ? "" : request.uri();
    boolean controlPath =
        TEMPLATE_PARAMETER_CONTROL_PATH.matcher(uri).find();
    boolean messageControlPath = TEMPLATE_PARAMETER_MESSAGE_CONTROL_PATH.matcher(uri).find();
    boolean engineSignal = hasTemplateEngineSignal(request.parameters());
    Optional<TemplateParameterMatch> parameterMatch =
        templateParameterParameters(request, controlPath, messageControlPath, engineSignal);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    return templateParameterBody(request, controlPath, engineSignal);
  }

  private static Optional<TemplateParameterMatch> templateParameterParameters(
      RequestContext request, boolean controlPath, boolean messageControlPath, boolean engineSignal) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      boolean strongName = isTemplateParameterName(entry.getKey());
      boolean weakMessageName =
          !strongName && messageControlPath && isTemplateMessageParameterName(entry.getKey());
      if (!strongName && !weakMessageName) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (value == null || value.isBlank()) {
          continue;
        }
        String engine = templateParameterEngine(request, entry.getKey(), value);
        boolean strongTemplateContext =
            strongName && (controlPath || engineSignal || !engine.equals("template"));
        if ((strongTemplateContext || weakMessageName)
            && isDangerousTemplateParameterValue(engine, value, weakMessageName)) {
          return Optional.of(new TemplateParameterMatch(entry.getKey(), engine, value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<TemplateParameterMatch> templateParameterBody(
      RequestContext request, boolean controlPath, boolean engineSignal) {
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    boolean bodyEngineSignal = engineSignal || hasTemplateEngineSignal(jsonStringFields(request.body()));
    for (JsonStringField field : jsonStringFields(request.body())) {
      boolean strongField = isTemplateParameterName(field.name());
      if (!strongField && !isWeakTemplateBodyFieldName(field.name())) {
        continue;
      }
      String value = field.value();
      if (value == null || value.isBlank()) {
        continue;
      }
      String engine = templateParameterEngine(request, field.name(), value);
      if ((controlPath || bodyEngineSignal || strongField)
          && isDangerousTemplateParameterValue(engine, value)) {
        return Optional.of(new TemplateParameterMatch("body." + field.name(), engine, value.length()));
      }
    }
    return Optional.empty();
  }

  private static boolean isTemplateParameterName(String name) {
    String normalized = normalizeParameterName(name);
    return TEMPLATE_PARAMETER_NAMES.contains(normalized)
        || normalized.startsWith("v.template.")
        || normalized.endsWith(".template")
        || (normalized.contains("template")
            && (normalized.contains("body")
                || normalized.contains("content")
                || normalized.contains("source")
                || normalized.contains("payload")
                || normalized.contains("custom")))
        || normalized.contains("velocitytemplate")
        || normalized.contains("freemarkertemplate");
  }

  private static boolean isWeakTemplateBodyFieldName(String name) {
    String normalized = normalizeParameterName(name);
    return normalized.equals("sql")
        || normalized.equals("query")
        || normalized.equals("body")
        || normalized.equals("content")
        || normalized.equals("text")
        || normalized.equals("message");
  }

  private static boolean isTemplateMessageParameterName(String name) {
    return TEMPLATE_MESSAGE_PARAMETER_NAMES.contains(normalizeParameterName(name));
  }

  static String templateParameterEngine(
      RequestContext request, String parameter, String value) {
    String normalizedParameter = normalizeParameterName(parameter);
    String normalizedValue = lower(value);
    String engineSignal =
        templateEngineSignal(request == null ? Map.<String, List<String>>of() : request.parameters());
    if (normalizedParameter.startsWith("v.template")
        || normalizedParameter.contains("velocity")
        || looksLikeVelocityTemplateSyntax(value)
        || engineSignal.equals("velocity")) {
      return "velocity";
    }
    if (normalizedParameter.contains("freemarker")
        || normalizedParameter.contains("ftl")
        || normalizedValue.contains("freemarker.template")
        || engineSignal.equals("freemarker")) {
      return "freemarker";
    }
    if (normalizedParameter.contains("thymeleaf")
        || normalizedValue.contains("org.thymeleaf")
        || engineSignal.equals("thymeleaf")) {
      return "thymeleaf";
    }
    return "template";
  }

  static boolean isDangerousTemplateParameterValue(String engine, String value) {
    return containsRuntimeExpressionPrimitive(engine, value)
        || looksLikeScriptCommandExecution(value)
        || looksLikeTemplateCommandExecution(engine, value);
  }

  static boolean isDangerousTemplateParameterValue(
      String engine, String value, boolean weakMessageName) {
    if (!isDangerousTemplateParameterValue(engine, value)) {
      return false;
    }
    return !weakMessageName || looksLikeTemplateRuntimeSyntax(value);
  }

  private static boolean looksLikeTemplateCommandExecution(String engine, String value) {
    String normalizedEngine = lower(engine);
    String normalizedValue = lower(value);
    if (!normalizedEngine.equals("freemarker") && !normalizedValue.contains("freemarker.template")) {
      return false;
    }
    return normalizedValue.contains("freemarker.template.utility.execute")
        || normalizedValue.contains("template.utility.execute");
  }

  private static boolean looksLikeTemplateRuntimeSyntax(String value) {
    String normalized = lower(value);
    String compact = normalized.replaceAll("\\s+", "");
    return looksLikeVelocityTemplateSyntax(value)
        || normalized.contains("freemarker.template")
        || normalized.contains("<#")
        || compact.contains("${")
        || compact.contains("?new()");
  }

  private static boolean looksLikeVelocityTemplateSyntax(String value) {
    String compact = lower(value).replaceAll("\\s+", "");
    return compact.contains("#set(")
        || compact.contains("#if(")
        || compact.contains("#foreach(")
        || compact.contains("$i18n.")
        || compact.contains("$!i18n.")
        || (compact.contains("$") && compact.contains(".getclass().forname("));
  }

  private static boolean hasTemplateEngineSignal(Map<String, List<String>> parameters) {
    return !templateEngineSignal(parameters).isBlank();
  }

  private static boolean hasTemplateEngineSignal(List<JsonStringField> fields) {
    return !templateEngineSignal(fields).isBlank();
  }

  private static String templateEngineSignal(Map<String, List<String>> parameters) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      String normalizedName = normalizeParameterName(entry.getKey());
      if (!TEMPLATE_ENGINE_PARAMETER_NAMES.contains(normalizedName)
          && !normalizedName.contains("templateengine")) {
        continue;
      }
      for (String value : entry.getValue()) {
        String normalizedValue = lower(value).trim();
        if (TEMPLATE_ENGINE_VALUES.contains(normalizedValue)) {
          return normalizedValue.equals("ftl") ? "freemarker" : normalizedValue;
        }
      }
    }
    return "";
  }

  private static String templateEngineSignal(List<JsonStringField> fields) {
    for (JsonStringField field : fields) {
      String normalizedName = normalizeParameterName(field.name());
      if (!TEMPLATE_ENGINE_PARAMETER_NAMES.contains(normalizedName)
          && !normalizedName.contains("templateengine")) {
        continue;
      }
      String normalizedValue = lower(field.value()).trim();
      if (TEMPLATE_ENGINE_VALUES.contains(normalizedValue)) {
        return normalizedValue.equals("ftl") ? "freemarker" : normalizedValue;
      }
    }
    return "";
  }

  private static RequestContext redactTemplateParameterRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    boolean messageControlPath =
        TEMPLATE_PARAMETER_MESSAGE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              boolean strongName = isTemplateParameterName(name);
              boolean weakMessageName =
                  !strongName && messageControlPath && isTemplateMessageParameterName(name);
              if (!strongName && !weakMessageName) {
                parameters.put(name, values == null ? List.of() : values);
                return;
              }
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                String engine = templateParameterEngine(request, name, value);
                redactedValues.add(
                    value != null && isDangerousTemplateParameterValue(engine, value, weakMessageName)
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTemplateParameterQuery(request),
        parameters,
        request.headers());
  }

  private static String redactTemplateParameterQuery(RequestContext request) {
    String query = request.query();
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    boolean messageControlPath =
        TEMPLATE_PARAMETER_MESSAGE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find();
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      String value = percentDecode(parts[i].substring(separator + 1));
      String decodedName = percentDecode(name);
      boolean strongName = isTemplateParameterName(decodedName);
      boolean weakMessageName =
          !strongName && messageControlPath && isTemplateMessageParameterName(decodedName);
      if (!strongName && !weakMessageName) {
        continue;
      }
      String engine = templateParameterEngine(request, decodedName, value);
      if (isDangerousTemplateParameterValue(engine, value, weakMessageName)) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<TemplateSourceMatch> templateSource(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    if (!TEMPLATE_SOURCE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find()) {
      return Optional.empty();
    }
    Optional<TemplateSourceMatch> parameterMatch = templateSourceParameters(request);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    return templateSourceBody(request);
  }

  private static Optional<TemplateSourceMatch> templateSourceParameters(RequestContext request) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<TemplateSourceMatch> match = templateSourceParameterValue(entry.getKey(), value);
        if (match.isPresent()) {
          return match;
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<TemplateSourceMatch> templateSourceParameterValue(
      String parameter, String value) {
    if (isTemplateSourceName(parameter)) {
      String targetType = templateSourceTargetType(value);
      if (!targetType.isBlank()) {
        return Optional.of(
            new TemplateSourceMatch(
                "parameter", parameter, targetType, value == null ? 0 : value.length()));
      }
    }
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (JsonStringField field : jsonStringFields(value)) {
      if (!isTemplateSourceName(field.name())) {
        continue;
      }
      String targetType = templateSourceTargetType(field.value());
      if (!targetType.isBlank()) {
        return Optional.of(
            new TemplateSourceMatch(
                "parameter",
                parameter + "." + field.name(),
                targetType,
                field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static Optional<TemplateSourceMatch> templateSourceBody(RequestContext request) {
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    for (JsonStringField field : jsonStringFields(request.body())) {
      if (!isTemplateSourceName(field.name())) {
        continue;
      }
      String targetType = templateSourceTargetType(field.value());
      if (!targetType.isBlank()) {
        return Optional.of(
            new TemplateSourceMatch(
                "body", "body." + field.name(), targetType, field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static boolean isTemplateSourceName(String name) {
    String normalized = normalizeParameterName(name);
    return TEMPLATE_SOURCE_PARAMETER_NAMES.contains(normalized)
        || (normalized.contains("decorator") && normalized.contains("location"))
        || (normalized.contains("screen") && normalized.contains("location"))
        || (normalized.contains("template")
            && (normalized.contains("source")
                || normalized.contains("path")
                || normalized.contains("file")
                || normalized.contains("url")));
  }

  private static String templateSourceTargetType(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    String inspected = percentDecode(value.trim());
    URI uri;
    try {
      uri = URI.create(inspected);
    } catch (IllegalArgumentException e) {
      uri = null;
    }
    String scheme = uri == null ? "" : lower(uri.getScheme());
    if (Set.of("http", "https", "ftp", "ldap", "rmi").contains(scheme)) {
      return "remote-url";
    }
    if (Set.of("file", "jar", "netdoc").contains(scheme)) {
      return "local-url";
    }
    for (String variant : pathVariants(inspected)) {
      String normalized = normalizeTemplateSourcePath(variant);
      if (normalized.isBlank()) {
        continue;
      }
      if (pathHasTraversal(normalized)) {
        return "path-traversal";
      }
      if (protectedWebappResource(normalized).isPresent()) {
        return "protected-resource";
      }
      if (TEMPLATE_SOURCE_SENSITIVE_PATH.matcher(normalized).find()) {
        return "sensitive-file";
      }
    }
    return "";
  }

  private static String normalizeTemplateSourcePath(String value) {
    String normalized = value == null ? "" : value.trim().replace('\\', '/').toLowerCase(Locale.ROOT);
    while (normalized.startsWith(". ")) {
      normalized = normalized.substring(1).trim();
    }
    return normalized;
  }

  private static boolean pathHasTraversal(String normalizedPath) {
    return normalizedPath.equals("..")
        || normalizedPath.startsWith("../")
        || normalizedPath.contains("/../")
        || normalizedPath.endsWith("/..");
  }

  private static RequestContext redactTemplateSourceRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isTemplateSourceName(name)
                  || containsTemplateSourceParameterValue(name, values)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTemplateSourceQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactTemplateSourceQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      String value = percentDecode(parts[i].substring(separator + 1));
      if (isTemplateSourceName(percentDecode(name))
          || templateSourceParameterValue(percentDecode(name), value).isPresent()) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static boolean containsTemplateSourceParameterValue(String name, List<String> values) {
    for (String value : values == null ? List.<String>of() : values) {
      if (templateSourceParameterValue(name, value).isPresent()) {
        return true;
      }
    }
    return false;
  }
}
