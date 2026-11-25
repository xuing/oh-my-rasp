package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.ExpressionSyntax.containsRuntimeExpressionPrimitive;
import static io.ohmyrasp.agent.detect.ExpressionSyntax.looksLikeScriptCommandExecution;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodeJavaUnicodeEscapes;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodeUnicodeEscapes;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodeXmlCharacterReferences;
import static io.ohmyrasp.agent.detect.RequestDecoding.pathVariants;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;
import static io.ohmyrasp.agent.detect.RequestTemplateDetector.isDangerousTemplateParameterValue;
import static io.ohmyrasp.agent.detect.RequestTemplateDetector.templateParameterEngine;

import io.ohmyrasp.agent.detect.RequestJson.JsonStringField;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Expression-bearing parameters, headers, paths, patches and spatial filters. */
final class RequestExpressionDetector {
  private static final Pattern EXPRESSION_BODY_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:service/(?:rest|extdirect)|repository|repositories|groups?|roles?|users?|admin|manage|management|config|settings)(?:[;/]|/|$)");

  private static final Pattern OGC_XPATH_CONTROL_PATH =
      Pattern.compile("(?i)(?:^|/)(?:ows|wfs|wms|wps)(?:[;/]|/|$)");

  private static final Pattern OGC_XPATH_XML_TEXT_FIELD =
      Pattern.compile(
          "(?is)<\\s*(?:[A-Za-z0-9_.-]+:)?(valueReference|propertyName)\\b[^>]*>"
              + "(.*?)"
              + "<\\s*/\\s*(?:[A-Za-z0-9_.-]+:)?\\1\\s*>");

  private static final Pattern OGC_FILTER_SQL_INJECTION_VALUE =
      Pattern.compile(
          "(?is)(?:--|/\\*|\\bunion\\s+(?:all\\s+)?select\\b|\\bcast\\s*\\(\\s*\\(?\\s*\\(?\\s*select\\b|\\bselect\\b.{0,160}\\b(?:version|current_database|database|user)\\s*\\(|\\b(?:pg_sleep|sleep|benchmark)\\s*\\()");

  private static final Pattern OGNL_DELEGATED_PARAMETER_DOT =
      Pattern.compile(
          "(?is)\\.\\s*findValue\\s*\\(\\s*#parameters\\.([A-Za-z0-9_.-]{1,80})\\b");

  private static final Pattern OGNL_DELEGATED_PARAMETER_BRACKET =
      Pattern.compile(
          "(?is)\\.\\s*findValue\\s*\\(\\s*#parameters\\s*\\[\\s*['\"]([A-Za-z0-9_.-]{1,80})['\"]\\s*\\]");

  private static final Set<String> EXPRESSION_HEADER_NAMES =
      Set.of(
          "springcloudfunctionroutingexpression",
          "spring.cloud.function.routingexpression",
          "routingexpression",
          "expression",
          "spel",
          "script");

  private static final Set<String> EXPRESSION_PARSER_HEADER_NAMES =
      Set.of("contenttype", "contentdisposition");

  private static final Set<String> REQUEST_EXPRESSION_PARAMETER_NAMES =
      Set.of(
          "expression",
          "expr",
          "spel",
          "ognl",
          "routingexpression",
          "script",
          "valueexpression",
          "querystring",
          "responsetype");

  private static final Set<String> OGC_XPATH_EXPRESSION_PARAMETERS =
      Set.of("valuereference", "propertyname");

  private static final Set<String> OGC_FILTER_SQL_PARAMETERS =
      Set.of("cqlfilter", "ecqlfilter", "filter");

  private static final Set<String> OGC_XPATH_SERVICES = Set.of("wfs", "wms", "wps", "ows");

  private static final Set<String> OGC_XPATH_REQUESTS =
      Set.of(
          "getpropertyvalue",
          "getfeature",
          "getmap",
          "getfeatureinfo",
          "getlegendgraphic",
          "execute");

  private RequestExpressionDetector() {}

  static Optional<Detection> header(RequestContext request) {
    Optional<ExpressionHeaderMatch> expressionHeader = expressionHeader(request);
    if (expressionHeader.isPresent()) {
      ExpressionHeaderMatch match = expressionHeader.orElseThrow();
      RequestContext redactedRequest = redactExpressionHeaderRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_expression_header",
              90,
              "Request header carries a runtime expression payload",
              redactedRequest,
              Map.of(
                  "header", match.header(),
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  static Optional<Detection> parametersAndPath(RequestContext request) {
    Optional<RequestExpressionParameterMatch> expressionParameter =
        requestExpressionParameter(request);
    if (expressionParameter.isPresent()) {
      RequestExpressionParameterMatch match = expressionParameter.orElseThrow();
      RequestContext redactedRequest = redactExpressionParameterRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_expression_parameter",
              90,
              "Request parameter carries a runtime expression payload",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<JsonPatchExpressionMatch> jsonPatchExpression = jsonPatchExpression(request);
    if (jsonPatchExpression.isPresent()) {
      JsonPatchExpressionMatch match = jsonPatchExpression.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_json_patch_expression",
              90,
              "JSON Patch path carries a runtime expression payload",
              request,
              Map.of(
                  "field", "path",
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "bodyLength", String.valueOf(match.bodyLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RequestExpressionParameterNameMatch> expressionParameterName =
        requestExpressionParameterName(request);
    if (expressionParameterName.isPresent()) {
      RequestExpressionParameterNameMatch match = expressionParameterName.orElseThrow();
      RequestContext redactedRequest = redactExpressionParameterNameRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_expression_parameter_name",
              90,
              "Request parameter name carries a runtime expression payload",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RequestExpressionPathMatch> expressionPath = requestExpressionPath(request);
    if (expressionPath.isPresent()) {
      RequestExpressionPathMatch match = expressionPath.orElseThrow();
      RequestContext redactedRequest = redactExpressionPathRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_expression_path",
              90,
              "Request path carries a runtime expression payload",
              redactedRequest,
              Map.of(
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "uri", redactedRequest.uri(),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  static Optional<Detection> spatialFilter(RequestContext request) {
    Optional<OgcFilterSqlInjectionMatch> ogcFilterSqlInjection = ogcFilterSqlInjection(request);
    if (ogcFilterSqlInjection.isPresent()) {
      OgcFilterSqlInjectionMatch match = ogcFilterSqlInjection.orElseThrow();
      RequestContext redactedRequest = redactOgcFilterSqlInjectionRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_ogc_filter_sql_injection",
              90,
              "Request OGC filter carries a SQL control expression",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  private record ExpressionHeaderMatch(String header, String engine, int expressionLength) {}

  private record RequestExpressionParameterMatch(
      String parameter, String engine, int expressionLength) {}

  private record JsonPatchExpressionMatch(String engine, int expressionLength, int bodyLength) {}

  private record OgcFilterSqlInjectionMatch(String parameter, int valueLength) {}

  private record XmlTextField(String name, String value) {}

  private record RequestExpressionParameterNameMatch(
      String parameter, String engine, int expressionLength) {}

  private record RequestExpressionPathMatch(String engine, int expressionLength) {}

  private static Optional<ExpressionHeaderMatch> expressionHeader(RequestContext request) {
    if (request == null || !request.active() || request.headers().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, String> entry : request.headers().entrySet()) {
      String header = entry.getKey();
      String value = entry.getValue();
      if (!dangerousExpressionHeader(header, value)) {
        continue;
      }
      String engine = expressionHeaderEngine(header, value);
      return Optional.of(new ExpressionHeaderMatch(header, engine, value.length()));
    }
    return Optional.empty();
  }

  private static boolean isExpressionHeaderName(String name) {
    String normalized = normalizeHeaderName(name);
    return EXPRESSION_HEADER_NAMES.contains(normalized)
        || normalized.endsWith("expression")
        || normalized.endsWith("script")
        || normalized.contains("routingexpression");
  }

  private static boolean isParserExpressionHeaderName(String name) {
    return EXPRESSION_PARSER_HEADER_NAMES.contains(normalizeHeaderName(name));
  }

  private static String expressionHeaderEngine(String name, String value) {
    String normalizedName = normalizeHeaderName(name);
    String valueEngine = requestExpressionParameterEngine(value);
    if (!valueEngine.isBlank()) {
      return valueEngine;
    }
    String normalizedValue = lower(percentDecode(value));
    if (normalizedName.contains("spel")
        || normalizedName.contains("springcloudfunction")
        || normalizedValue.contains("t(java.lang.")) {
      return "spel";
    }
    if (normalizedName.contains("jexl")) {
      return "jexl";
    }
    if (normalizedName.contains("ognl")) {
      return "ognl";
    }
    if (normalizedName.contains("el")) {
      return "el";
    }
    if (normalizedName.contains("script")) {
      return "script";
    }
    return "expression";
  }

  private static boolean dangerousExpressionHeader(String name, String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    String engine = expressionHeaderEngine(name, value);
    if (isExpressionHeaderName(name)) {
      return containsRuntimeExpressionPrimitive(engine, percentDecode(value))
          || looksLikeScriptCommandExecution(percentDecode(value));
    }
    if (!isParserExpressionHeaderName(name) || engine.isBlank()) {
      return false;
    }
    String decoded = percentDecode(value);
    return dangerousRequestExpressionValue(engine, decoded)
        || dangerousParserHeaderExpression(engine, decoded);
  }

  static boolean dangerousParserHeaderExpression(String engine, String value) {
    String compact = lower(value).replaceAll("\\s+", "");
    return "ognl".equals(engine)
        && compact.contains("%{")
        && (compact.contains("#context")
            || compact.contains("_memberaccess")
            || compact.contains("@java.lang.")
            || compact.contains("@ognl.")
            || compact.contains("processbuilder")
            || compact.contains("runtime"));
  }

  private static RequestContext redactExpressionHeaderRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var headers = new LinkedHashMap<String, String>();
    request
        .headers()
        .forEach(
            (name, value) -> {
              if (dangerousExpressionHeader(name, value)) {
                headers.put(name, "[redacted]");
                return;
              }
              headers.put(name, value);
            });
    return new RequestContext(
        request.method(), request.uri(), request.query(), request.parameters(), headers);
  }

  private static String normalizeHeaderName(String name) {
    return name == null ? "" : name.replaceAll("[^A-Za-z0-9.]", "").toLowerCase(Locale.ROOT);
  }

  private static Optional<RequestExpressionParameterMatch> requestExpressionParameter(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    Optional<RequestExpressionParameterMatch> parameterMatch =
        requestExpressionParameterValues(request);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    Optional<RequestExpressionParameterMatch> delegatedParameterMatch =
        requestDelegatedExpressionParameterValues(request);
    if (delegatedParameterMatch.isPresent()) {
      return delegatedParameterMatch;
    }
    Optional<RequestExpressionParameterMatch> bodyMatch = requestExpressionBodyValues(request);
    if (bodyMatch.isPresent()) {
      return bodyMatch;
    }
    return requestExpressionXmlBodyValues(request);
  }

  private static Optional<RequestExpressionParameterMatch> requestExpressionParameterValues(
      RequestContext request) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value == null || value.isBlank()) {
          continue;
        }
        String engine = requestExpressionParameterEngine(value);
        if (!engine.isBlank()
            && isRequestExpressionParameterContext(request, entry.getKey(), engine)
            && dangerousRequestExpressionValue(engine, value)) {
          return Optional.of(
              new RequestExpressionParameterMatch(entry.getKey(), engine, value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<RequestExpressionParameterMatch> requestDelegatedExpressionParameterValues(
      RequestContext request) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value == null || value.isBlank()) {
          continue;
        }
        String engine = requestExpressionParameterEngine(value);
        if (!"ognl".equals(engine)) {
          continue;
        }
        Optional<String> delegatedTargetName = delegatedOgnlParameterName(value);
        if (delegatedTargetName.isEmpty()) {
          continue;
        }
        String targetName = delegatedTargetName.orElseThrow();
        if (!hasDangerousDelegatedExpressionTarget(request, targetName)) {
          continue;
        }
        return Optional.of(
            new RequestExpressionParameterMatch(entry.getKey(), engine, value.length()));
      }
    }
    return Optional.empty();
  }

  private static Optional<RequestExpressionParameterMatch> requestExpressionBodyValues(
      RequestContext request) {
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    boolean controlPath =
        EXPRESSION_BODY_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find();
    List<JsonStringField> fields = jsonStringFields(request.body());
    for (JsonStringField field : fields) {
      String value = field.value();
      if (value == null || value.isBlank()) {
        continue;
      }
      String engine = requestExpressionParameterEngine(value);
      if (!engine.isBlank()
          && isRequestExpressionBodyContext(request, field.name(), engine, controlPath)
          && dangerousRequestExpressionValue(engine, value)) {
        return Optional.of(
            new RequestExpressionParameterMatch(
                "body." + field.name(), engine, value.length()));
      }
    }
    if (!controlPath) {
      return Optional.empty();
    }
    String bodyEngine = requestExpressionBodyEngineSignal(fields);
    if (bodyEngine.isBlank()) {
      return Optional.empty();
    }
    for (JsonStringField field : fields) {
      if (!isExpressionBodyRuntimeValueField(field.name())) {
        continue;
      }
      String value = field.value();
      if (value == null || value.isBlank()) {
        continue;
      }
      if (dangerousRequestExpressionValue(bodyEngine, value)) {
        return Optional.of(
            new RequestExpressionParameterMatch(
                "body." + field.name(), bodyEngine, value.length()));
      }
    }
    return Optional.empty();
  }

  private static boolean isRequestExpressionBodyContext(
      RequestContext request, String name, String engine, boolean controlPath) {
    if ("xpath".equals(engine)) {
      return isRequestExpressionParameterContext(request, name, engine);
    }
    return controlPath || isRequestExpressionParameterContext(request, name, engine);
  }

  private static String requestExpressionBodyEngineSignal(List<JsonStringField> fields) {
    String fallback = "";
    boolean typeProperty = false;
    String valueEngine = "";
    for (JsonStringField field : fields) {
      String normalizedName = normalizeParameterName(field.name());
      String normalizedValue = normalizeParameterName(field.value());
      if (normalizedName.equals("type")
          || normalizedName.equals("engine")
          || normalizedName.endsWith("type")
          || normalizedName.endsWith("engine")) {
        String engine = expressionEngineName(normalizedValue);
        if (!engine.isBlank()) {
          return engine;
        }
      }
      if ((normalizedName.equals("property")
              || normalizedName.equals("name")
              || normalizedName.equals("field"))
          && (normalizedValue.equals("type") || normalizedValue.equals("engine"))) {
        typeProperty = true;
      }
      if (normalizedName.equals("value")) {
        String engine = expressionEngineName(normalizedValue);
        if (!engine.isBlank()) {
          valueEngine = engine;
        }
      }
      if ((normalizedName.equals("property")
              || normalizedName.equals("name")
              || normalizedName.equals("field"))
          && isExpressionBodyRuntimeValueField(normalizedValue)) {
        fallback = "expression";
      }
    }
    if (typeProperty && !valueEngine.isBlank()) {
      return valueEngine;
    }
    return fallback;
  }

  private static String expressionEngineName(String value) {
    String normalized = normalizeParameterName(value);
    if (normalized.equals("jexl") || normalized.equals("commonsjexl")) {
      return "jexl";
    }
    if (normalized.equals("el") || normalized.equals("javaxel") || normalized.equals("jakartael")) {
      return "el";
    }
    if (normalized.equals("spel") || normalized.equals("springel")) {
      return "spel";
    }
    if (normalized.equals("ognl")) {
      return "ognl";
    }
    if (normalized.equals("expression") || normalized.equals("script")) {
      return "expression";
    }
    return "";
  }

  private static boolean isExpressionBodyRuntimeValueField(String name) {
    String normalized = normalizeParameterName(name);
    return REQUEST_EXPRESSION_PARAMETER_NAMES.contains(normalized)
        || normalized.equals("value")
        || normalized.equals("payload")
        || normalized.endsWith("value")
        || normalized.endsWith("expression")
        || normalized.endsWith("script");
  }

  private static Optional<RequestExpressionParameterMatch> requestExpressionXmlBodyValues(
      RequestContext request) {
    if (!xmlRequestBody(request) || !ogcXPathRequestContext(request)) {
      return Optional.empty();
    }
    for (XmlTextField field : xmlTextFields(request.body())) {
      String engine = requestExpressionParameterEngine(field.value());
      if (!engine.isBlank()
          && isRequestExpressionParameterContext(request, field.name(), engine)
          && dangerousRequestExpressionValue(engine, field.value())) {
        return Optional.of(
            new RequestExpressionParameterMatch(
                "body." + field.name(), engine, field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static Optional<String> delegatedOgnlParameterName(String value) {
    String decoded = percentDecode(value);
    var dotMatcher = OGNL_DELEGATED_PARAMETER_DOT.matcher(decoded);
    if (dotMatcher.find()) {
      return Optional.of(dotMatcher.group(1));
    }
    var bracketMatcher = OGNL_DELEGATED_PARAMETER_BRACKET.matcher(decoded);
    if (bracketMatcher.find()) {
      return Optional.of(bracketMatcher.group(1));
    }
    return Optional.empty();
  }

  private static boolean hasDangerousDelegatedExpressionTarget(
      RequestContext request, String targetName) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!entry.getKey().equals(targetName)) {
        continue;
      }
      for (String targetValue : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (dangerousDelegatedExpressionTargetValue(request, targetName, targetValue)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean dangerousDelegatedExpressionTargetValue(
      RequestContext request, String targetName, String targetValue) {
    if (targetValue == null || targetValue.isBlank()) {
      return false;
    }
    String expressionEngine = requestExpressionParameterEngine(targetValue);
    if (!expressionEngine.isBlank()
        && dangerousRequestExpressionValue(expressionEngine, targetValue)) {
      return true;
    }
    String templateEngine = templateParameterEngine(request, targetName, targetValue);
    return isDangerousTemplateParameterValue(templateEngine, targetValue);
  }

  private static Optional<RequestExpressionParameterNameMatch> requestExpressionParameterName(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (String name : request.parameters().keySet()) {
      String engine = requestExpressionParameterEngine(name);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, name)) {
        return Optional.of(
            new RequestExpressionParameterNameMatch(
                safeExpressionParameterNamePrefix(name), engine, percentDecode(name).length()));
      }
    }
    return Optional.empty();
  }

  static String requestExpressionParameterEngine(String value) {
    String normalized = lower(expressionDecodedValue(value));
    String compact = normalized.replaceAll("\\s+", "");
    if (compact.contains("@java.lang.runtime@")
        || compact.contains("@java.lang.processbuilder@")
        || compact.contains("_memberaccess")
        || compact.contains("xwork.methodaccessor")
        || compact.contains("ognl.")
        || compact.contains("#context")
        || compact.contains("#parameters")
        || compact.contains("%{")) {
      return "ognl";
    }
    if (compact.contains("#{")
        || compact.contains("t(java.lang.")
        || (compact.contains("#this") && compact.contains("java.lang."))
        || springBindingExpressionName(compact)) {
      return "spel";
    }
    if (compact.contains("scriptenginemanager") && compact.contains(".eval")) {
      return "expression";
    }
    boolean escapedEl = escapedElExpression(compact);
    if ((compact.contains("${") || escapedEl) && compact.contains("java.lang.runtime")) {
      return "el";
    }
    if (compact.contains("${") || escapedEl || compact.contains("#{")) {
      return "expression";
    }
    if (xpathRuntimeExpression(compact)) {
      return "xpath";
    }
    return "";
  }

  private static String expressionDecodedValue(String value) {
    String decoded = percentDecode(value);
    decoded = decodeJavaUnicodeEscapes(decoded);
    return decodeUnicodeEscapes(decoded);
  }

  private static boolean xpathRuntimeExpression(String compactValue) {
    if (compactValue == null || compactValue.isBlank()) {
      return false;
    }
    boolean runtimeExec =
        compactValue.contains("java.lang.runtime")
            && compactValue.contains("getruntime")
            && compactValue.contains("exec");
    boolean processBuilderStart =
        compactValue.contains("processbuilder") && compactValue.contains(".start");
    return (runtimeExec || processBuilderStart) && compactValue.contains("(");
  }

  private static boolean escapedElExpression(String compactValue) {
    int marker = compactValue.indexOf("$\\");
    return marker >= 0
        && marker + 3 < compactValue.length()
        && compactValue.charAt(marker + 3) == '{';
  }

  private static boolean springBindingExpressionName(String compactValue) {
    return compactValue.startsWith("_(")
        && (compactValue.contains("newjava.lang.processbuilder")
            || compactValue.contains("java.lang.runtime")
            || compactValue.contains("runtime.getruntime")
            || compactValue.contains("scriptenginemanager"));
  }

  private static boolean isRequestExpressionParameterContext(String name, String engine) {
    return isRequestExpressionParameterContext(null, name, engine);
  }

  private static boolean isRequestExpressionParameterContext(
      RequestContext request, String name, String engine) {
    if ("xpath".equals(engine)) {
      return isOgcXPathExpressionContext(request, name);
    }
    if ("ognl".equals(engine)) {
      return true;
    }
    String normalized = normalizeParameterName(name);
    return REQUEST_EXPRESSION_PARAMETER_NAMES.contains(normalized)
        || normalized.endsWith("expression")
        || normalized.endsWith("script");
  }

  private static boolean isOgcXPathExpressionContext(RequestContext request, String name) {
    String normalizedName = normalizeParameterName(name);
    return OGC_XPATH_EXPRESSION_PARAMETERS.contains(normalizedName)
        && ogcXPathRequestContext(request);
  }

  private static boolean ogcXPathRequestContext(RequestContext request) {
    if (request == null || !request.active()) {
      return false;
    }
    String uri = request.uri() == null ? "" : request.uri();
    if (OGC_XPATH_CONTROL_PATH.matcher(uri).find()) {
      return true;
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      String normalizedName = normalizeParameterName(entry.getKey());
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        String normalizedValue = normalizeParameterName(value);
        if (normalizedName.equals("service") && OGC_XPATH_SERVICES.contains(normalizedValue)) {
          return true;
        }
        if (normalizedName.equals("request") && OGC_XPATH_REQUESTS.contains(normalizedValue)) {
          return true;
        }
      }
    }
    String body = lower(request.body());
    return body.contains("getpropertyvalue")
        || body.contains("valuereference")
        || body.contains("propertyname");
  }

  static boolean dangerousRequestExpressionValue(String engine, String value) {
    if (engine.isBlank()) {
      return false;
    }
    String decoded = expressionDecodedValue(value);
    return containsRuntimeExpressionPrimitive(engine, decoded)
        || looksLikeScriptCommandExecution(decoded);
  }

  private static Optional<OgcFilterSqlInjectionMatch> ogcFilterSqlInjection(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    if (!ogcXPathRequestContext(request)) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isOgcFilterSqlParameter(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (dangerousOgcFilterSqlValue(value)) {
          return Optional.of(new OgcFilterSqlInjectionMatch(entry.getKey(), value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean isOgcFilterSqlParameter(String name) {
    return OGC_FILTER_SQL_PARAMETERS.contains(normalizeParameterName(name));
  }

  private static boolean dangerousOgcFilterSqlValue(String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    String decoded = percentDecode(value);
    return OGC_FILTER_SQL_INJECTION_VALUE.matcher(decoded).find();
  }

  private static RequestContext redactOgcFilterSqlInjectionRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (!isOgcFilterSqlParameter(name)) {
                parameters.put(name, values == null ? List.of() : values);
                return;
              }
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    value != null && dangerousOgcFilterSqlValue(value) ? "[redacted]" : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactOgcFilterSqlInjectionQuery(request.query()),
        parameters,
        request.headers(),
        request.body());
  }

  private static String redactOgcFilterSqlInjectionQuery(String query) {
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
      if (isOgcFilterSqlParameter(percentDecode(name)) && dangerousOgcFilterSqlValue(value)) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<JsonPatchExpressionMatch> jsonPatchExpression(RequestContext request) {
    if (request == null || !request.active() || request.body().isBlank()) {
      return Optional.empty();
    }
    if (!"patch".equalsIgnoreCase(request.method())) {
      return Optional.empty();
    }
    String contentType = lower(request.header("content-type").orElse(""));
    if (!contentType.contains("application/json-patch+json")) {
      return Optional.empty();
    }
    String body = request.body();
    if (!body.trim().startsWith("[") || !body.contains("\"path\"")) {
      return Optional.empty();
    }
    for (String path : jsonStringFieldValues(body, "path")) {
      String engine = requestExpressionParameterEngine(path);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, path)) {
        return Optional.of(new JsonPatchExpressionMatch(engine, path.length(), body.length()));
      }
    }
    return Optional.empty();
  }

  private static List<String> jsonStringFieldValues(String json, String fieldName) {
    if (json == null || json.isBlank() || fieldName == null || fieldName.isBlank()) {
      return List.of();
    }
    var values = new ArrayList<String>();
    for (JsonStringField field : jsonStringFields(json)) {
      if (fieldName.equals(field.name())) {
        values.add(field.value());
      }
    }
    return values;
  }

  private static boolean xmlRequestBody(RequestContext request) {
    if (request == null || request.body().isBlank() || request.body().length() > 65536) {
      return false;
    }
    String contentType = lower(request.header("content-type").orElse(""));
    String trimmed = request.body().trim();
    return contentType.contains("xml") || trimmed.startsWith("<");
  }

  private static List<XmlTextField> xmlTextFields(String xml) {
    if (xml == null || xml.isBlank() || xml.length() > 65536) {
      return List.of();
    }
    var fields = new ArrayList<XmlTextField>();
    var matcher = OGC_XPATH_XML_TEXT_FIELD.matcher(xml);
    while (matcher.find()) {
      String name = matcher.group(1);
      String value = decodeXmlText(stripCdata(matcher.group(2)).replaceAll("(?is)<[^>]+>", ""));
      fields.add(new XmlTextField(name, value));
    }
    return List.copyOf(fields);
  }

  private static String stripCdata(String value) {
    if (value == null) {
      return "";
    }
    return value.replace("<![CDATA[", "").replace("]]>", "");
  }

  private static String decodeXmlText(String value) {
    String decoded = decodeXmlCharacterReferences(value);
    return decoded
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&");
  }

  private static RequestContext redactExpressionParameterRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    Set<String> delegatedExpressionParameters = delegatedExpressionParameterNames(request);
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                String engine = requestExpressionParameterEngine(value);
                redactedValues.add(
                    delegatedExpressionParameters.contains(name)
                            || (isRequestExpressionParameterContext(request, name, engine)
                                && dangerousRequestExpressionValue(engine, value))
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactExpressionParameterQuery(request, delegatedExpressionParameters),
        parameters,
        request.headers());
  }

  private static Set<String> delegatedExpressionParameterNames(RequestContext request) {
    if (request == null || request.parameters().isEmpty()) {
      return Set.of();
    }
    var names = new LinkedHashSet<String>();
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (!"ognl".equals(requestExpressionParameterEngine(value))) {
          continue;
        }
        Optional<String> delegatedTargetName = delegatedOgnlParameterName(value);
        if (delegatedTargetName.isEmpty()) {
          continue;
        }
        String targetName = delegatedTargetName.orElseThrow();
        if (!hasDangerousDelegatedExpressionTarget(request, targetName)) {
          continue;
        }
        names.add(entry.getKey());
        names.add(targetName);
      }
    }
    return Set.copyOf(names);
  }

  private static String redactExpressionParameterQuery(
      RequestContext request, Set<String> delegatedExpressionParameters) {
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
      String engine = requestExpressionParameterEngine(value);
      String name = percentDecode(parts[i].substring(0, separator));
      if (delegatedExpressionParameters.contains(name)
          || (isRequestExpressionParameterContext(request, name, engine)
              && dangerousRequestExpressionValue(engine, value))) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static RequestContext redactExpressionParameterNameRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              String engine = requestExpressionParameterEngine(name);
              String safeName =
                  !engine.isBlank() && dangerousRequestExpressionValue(engine, name)
                      ? safeExpressionParameterName(name)
                      : name;
              parameters.put(safeName, values == null ? List.of() : values);
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactExpressionParameterNameQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactExpressionParameterNameQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      String rawName = separator < 0 ? parts[i] : parts[i].substring(0, separator);
      String engine = requestExpressionParameterEngine(rawName);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, rawName)) {
        parts[i] = safeExpressionParameterName(rawName) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static String safeExpressionParameterName(String name) {
    String prefix = safeExpressionParameterNamePrefix(name);
    return prefix.isBlank() ? "[redacted]" : prefix + "[redacted]";
  }

  private static String safeExpressionParameterNamePrefix(String name) {
    String decoded = percentDecode(name);
    if (decoded.startsWith("_(")) {
      return "_";
    }
    int colon = decoded.indexOf(':');
    if (colon > 0) {
      String colonPrefix = decoded.substring(0, colon);
      if (colonPrefix.matches("[A-Za-z0-9_.-]{1,80}")) {
        return colonPrefix;
      }
    }
    int boundary = decoded.length();
    for (String marker : List.of("[", "%{", "#{", "${")) {
      int index = decoded.indexOf(marker);
      if (index >= 0 && index < boundary) {
        boundary = index;
      }
    }
    String prefix = decoded.substring(0, boundary).trim();
    if (prefix.endsWith(":")) {
      String colonPrefix = prefix.substring(0, prefix.length() - 1);
      if (colonPrefix.matches("[A-Za-z0-9_.-]{1,80}")) {
        return colonPrefix;
      }
    }
    return prefix.matches("[A-Za-z0-9_.-]{1,80}") ? prefix : "";
  }

  private static Optional<RequestExpressionPathMatch> requestExpressionPath(
      RequestContext request) {
    if (request == null || !request.active() || request.uri().isBlank()) {
      return Optional.empty();
    }
    for (String variant : pathVariants(request.uri())) {
      String engine = requestExpressionParameterEngine(variant);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, variant)) {
        return Optional.of(new RequestExpressionPathMatch(engine, variant.length()));
      }
    }
    return Optional.empty();
  }

  private static RequestContext redactExpressionPathRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    return new RequestContext(
        request.method(),
        redactExpressionPathUri(request.uri()),
        request.query(),
        request.parameters(),
        request.headers());
  }

  private static String redactExpressionPathUri(String uri) {
    if (uri == null || uri.isBlank()) {
      return uri == null ? "" : uri;
    }
    for (String variant : pathVariants(uri)) {
      String engine = requestExpressionParameterEngine(variant);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, variant)) {
        return "/[redacted]";
      }
    }
    return uri;
  }
}
