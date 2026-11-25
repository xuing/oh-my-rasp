package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DeserializationTypes.normalizeJavaTypeName;
import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizePath;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.FilePaths.WINDOWS_ABSOLUTE_PATH;
import static io.ohmyrasp.agent.detect.FilePaths.containsParentSegment;
import static io.ohmyrasp.agent.detect.RemoteResourceDetector.containsRemoteProtocol;
import static io.ohmyrasp.agent.detect.RequestDecoding.PROTECTED_WEBAPP_RESOURCE;
import static io.ohmyrasp.agent.detect.RequestDecoding.addLowByteVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.collapsePathDotSegments;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodeUnicodeEscapes;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodedPathVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodedVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.hasConfusingDotSegment;
import static io.ohmyrasp.agent.detect.RequestDecoding.pathVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.protectedWebappResource;
import static io.ohmyrasp.agent.detect.RequestDecoding.stripServletPathParameters;

import io.ohmyrasp.agent.jmx.JmxDispatch;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

public final class DetectorEngine {

  private static final Pattern SCRIPT_FILE_REQUEST_PATH =
      Pattern.compile(
          "(?is).+\\.(?:aspx?|jspx?|php[345]?|phar|phtml|sh|py|pl|rb|so|dll|dylib|ashx|cer|asa)(?:[;/\\\\].*|\\.*$)");

  private static final Pattern SENSITIVE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:auth|admin|user|users|role|roles|permission|permissions|ops|manage|management|console)(?:/|$)");

  private static final Pattern INTERNAL_FORWARD_JSP_SUFFIX =
      Pattern.compile("(?i);\\s*\\.jspx?(?:$|[/?#])");

  private static final Pattern INTERNAL_FORWARD_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:auth|admin|user|users|role|roles|permission|permissions|token|tokens|debug|config|ops|manage|management|console)(?:/|$)");

  private static final Pattern SETUP_STATE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:server-info\\.action|setup|install|bootstrap|setupadministrator\\.action|finishsetup\\.action)(?:[;/]|/|$)");

  // Syntax indicators for explicitly selected input policies and response observations.
  private static final Pattern XSS_INPUT =
      Pattern.compile(
          "(?is)<\\s*script\\b"
              + "|javascript\\s*:"
              + "|\\bon(?:error|load|click|dblclick|mouse[a-z]*|key[a-z]*|focus[a-z]*|blur"
              + "|change|submit|reset|select|input|toggle|scroll|wheel|contextmenu"
              + "|copy|cut|paste|drag[a-z]*|drop|animation[a-z]*|transition[a-z]*"
              + "|pointer[a-z]*|play[a-z]*|abort|unload|resize|show|begin|finish"
              + "|pageshow|pagehide|hashchange|popstate|message|storage|beforescriptexecute)"
              + "\\s*=");

  private static final Pattern STRUCTURED_RESPONSE = Pattern.compile(
      "(?i)(?:text/html|(?:application|text)/(?:json|xml)|[a-z0-9!#$%&'*+.^_`|~-]+/[a-z0-9!#$%&'*+.^_`|~-]+\\+(?:json|xml))");

  private static final Pattern CHINA_ID =
      Pattern.compile("(?<!\\d)\\d{10}(?:[01]\\d)(?:[0123]\\d)\\d{3}(?:\\d|x|X)(?!\\d)");

  private static final Pattern CHINA_MOBILE =
      Pattern.compile("(?<!\\w)(?:(?:00|\\+)?86 ?)?(1\\d{2})(?:[ -]?\\d){8}(?!\\w)");

  private static final Pattern BANK_CARD =
      Pattern.compile("(?<!\\d)(?:62|3|5[1-5]|4\\d)\\d{2}(?:[ -]?\\d{4}){3}(?!\\d)");

  private static final Set<String> SCANNER_MARKERS =
      Set.of(
          "sqlmap",
          "nikto",
          "nessus",
          "arachni",
          "webinspect",
          "acunetix",
          "appscan",
          "w3af",
          "masscan",
          "nmap",
          "zgrab",
          "dirbuster");

  private static final Set<String> INTERNAL_SERVICE_USER_AGENTS =
      Set.of("nacos-server");

  private static final Set<String> INTERNAL_FORWARD_PARAMETERS =
      Set.of(
          "jsp", "view", "viewname", "forward", "forwardto", "dispatch", "dispatcher", "template");

  private static final Set<String> BEAN_POLLUTION_TARGETS =
      Set.of(
          "resources.context.parent.pipeline",
          "protectiondomain.codesource.location",
          "ucp.path",
          "urlclassloader",
          "systemclassloader");

  private static final Set<String> WEBSHELL_ENV =
      Set.of("LD_PRELOAD", "LD_AUDIT", "GCONV_PATH");

  private static final Set<String> CHINA_MOBILE_PREFIXES =
      Set.of(
          "130", "131", "132", "133", "134", "135", "136", "137", "138", "139", "145",
          "146", "147", "148", "149", "150", "151", "152", "153", "155", "156", "157",
          "158", "159", "165", "166", "170", "173", "174", "175", "176", "177", "178",
          "180", "181", "182", "183", "184", "185", "186", "187", "188", "189", "198",
          "199");

  public Optional<Detection> detectRequest(RequestContext request) {
    String userAgent = request.header("user-agent").orElse("").toLowerCase(Locale.ROOT);
    if (looksLikeInternalIdentityBypass(userAgent, request)) {
      return Optional.of(
          Detection.log(
              "request",
              "request_internal_identity",
              90,
              "Request presents an internal service identity on a sensitive control path",
              request,
              Map.of(
                  "userAgent", userAgent,
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<Detection> jwtFinding = CredentialDetector.defaultSignedTokenFinding(request);
    if (jwtFinding.isPresent()) return jwtFinding;
    Optional<Detection> cookieFinding = CredentialDetector.defaultEncryptedCookieFinding(request);
    if (cookieFinding.isPresent()) return cookieFinding;
    Optional<Detection> stateFinding = SerializedRequestState.serializedClientStateFinding(request);
    if (stateFinding.isPresent()) return stateFinding;
    Optional<Detection> credentialFinding = CredentialDetector.defaultCredentialFinding(request);
    if (credentialFinding.isPresent()) return credentialFinding;
    Optional<Detection> emptyFinding = CredentialDetector.emptyCredentialFinding(request);
    if (emptyFinding.isPresent()) return emptyFinding;
    Optional<String> beanPollution = request.parameters().keySet().stream()
        .filter(DetectorEngine::looksLikeJavaBeanPollution)
        .findFirst();
    if (beanPollution.isPresent()) {
      RequestContext redactedRequest = redactJavaBeanPollutionRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_java_bean_pollution",
              95,
              "Request parameter attempts to bind Java classloader metadata",
              redactedRequest,
              Map.of("parameter", abbreviate(beanPollution.orElseThrow()))));
    }
    Optional<Detection> configurationFinding = RequestConfigurationDetector.configuration(request);
    if (configurationFinding.isPresent()) return configurationFinding;
    Optional<Detection> loaderFinding = RequestTemplateDetector.loader(request);
    if (loaderFinding.isPresent()) return loaderFinding;
    Optional<Detection> messageSelectorFinding = RequestConfigurationDetector.messageSelector(request);
    if (messageSelectorFinding.isPresent()) return messageSelectorFinding;
    Optional<Detection> headerFinding = RequestExpressionDetector.header(request);
    if (headerFinding.isPresent()) return headerFinding;
    Optional<Detection> namingFinding = RequestConfigurationDetector.naming(request);
    if (namingFinding.isPresent()) return namingFinding;
    Optional<Detection> contentFinding = RequestTemplateDetector.content(request);
    if (contentFinding.isPresent()) return contentFinding;
    Optional<Detection> parametersAndPathFinding = RequestExpressionDetector.parametersAndPath(request);
    if (parametersAndPathFinding.isPresent()) return parametersAndPathFinding;
    Optional<Detection> bindingFinding = RequestPayloadDetector.binding(request);
    if (bindingFinding.isPresent()) return bindingFinding;
    Optional<Detection> resourceFinding = RequestResourceDetector.resource(request);
    if (resourceFinding.isPresent()) return resourceFinding;
    Optional<Detection> spatialFilterFinding = RequestExpressionDetector.spatialFilter(request);
    if (spatialFilterFinding.isPresent()) return spatialFilterFinding;
    Optional<SetupStateResetMatch> setupStateReset = setupStateReset(request);
    if (setupStateReset.isPresent()) {
      SetupStateResetMatch match = setupStateReset.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_setup_state_reset",
              90,
              "Request parameter attempts to reset application setup completion state",
              request,
              Map.of(
                  "parameter", abbreviate(match.parameter()),
                  "value", match.value(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<ServerSideScriptPutMatch> scriptPut = serverSideScriptPut(request);
    if (scriptPut.isPresent()) {
      ServerSideScriptPutMatch match = scriptPut.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_server_side_script_put",
              90,
              "HTTP PUT targets a server-side script path",
              request,
              Map.of(
                  "path", abbreviate(match.path()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<UploadFilenameOverrideMatch> uploadFilenameOverride =
        uploadFilenameOverride(request);
    if (uploadFilenameOverride.isPresent()) {
      UploadFilenameOverrideMatch match = uploadFilenameOverride.orElseThrow();
      RequestContext redactedRequest = redactUploadFilenameOverrideRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_upload_filename_override",
              90,
              "Multipart request overrides upload filename binding with an unsafe path",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "targetType", match.targetType(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<Map.Entry<String, String>> internalForward = requestControlledInternalForward(request);
    if (internalForward.isPresent()) {
      Map.Entry<String, String> forward = internalForward.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_internal_forward",
              90,
              "Request parameter attempts internal forwarding to a sensitive control path",
              request,
              Map.of(
                  "parameter", forward.getKey(),
                  "target", abbreviate(forward.getValue()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<InternalResourceMatch> internalResource = protectedInternalResourceRequest(request);
    if (internalResource.isPresent()) {
      InternalResourceMatch match = internalResource.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_internal_resource",
              88,
              "Request target exposes a protected web application resource after decoding",
              request,
              Map.of(
                  "component", match.component(),
                  "resource", match.resource(),
                  "variant", match.variant(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<String> confusingPath = confusingRequestPath(request.uri());
    if (confusingPath.isPresent()) {
      return Optional.of(
          Detection.log(
              "request",
              "request_path_confusion",
              90,
              "Request URI contains path normalization confusion",
              request,
              Map.of(
                  "uri", abbreviate(request.uri()),
                  "decoded", abbreviate(confusingPath.orElseThrow()))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectMarkupParameter(RequestContext request) {
    for (String value : request.allParameterValues()) {
      if (value != null && XSS_INPUT.matcher(value).find()) {
        return Optional.of(
            Detection.log(
                "request",
                "xss_userinput",
                70,
                "XSS-like request parameter detected",
                request,
                Map.of("value", abbreviate(value))));
      }
    }
    return Optional.empty();
  }

  public Optional<Detection> detectScannerUserAgent(RequestContext request) {
    String userAgent = request.header("user-agent").orElse("").toLowerCase(Locale.ROOT);
    for (String marker : SCANNER_MARKERS) {
      if (userAgent.contains(marker)) {
        return Optional.of(
            Detection.log(
                "request",
                "request_scanner",
                90,
                "Scanner-like user agent detected: " + marker,
                request,
                Map.of("userAgent", userAgent)));
      }
    }
    return Optional.empty();
  }

  public static boolean isBase64TailUnderflowCandidate(
      byte[] src, int sp, int sl, boolean isURL, boolean isMIME) {
    if (isMIME || src == null || sp < 0 || sl < sp || sl > src.length) {
      return false;
    }
    int length = sl - sp;
    if (length < 65) {
      return false;
    }
    int remainder = length & 63;
    if (remainder < 1 || remainder > 3) {
      return false;
    }
    int padding = 0;
    while (padding < 3 && src[sl - 1 - padding] == '=') {
      padding++;
    }
    if (padding < 1 || padding > 2 || padding > remainder) {
      return false;
    }
    for (int i = sp; i < sl - padding; i++) {
      int c = src[i] & 0xff;
      if (!((c >= 'A' && c <= 'Z')
          || (c >= 'a' && c <= 'z')
          || (c >= '0' && c <= '9')
          || (isURL ? (c == '-' || c == '_') : (c == '+' || c == '/')))) {
        return false;
      }
    }
    return true;
  }

  public Optional<Detection> detectBase64Decode(
      byte[] src, int sp, int sl, boolean isURL, boolean isMIME, RequestContext request) {
    if (!isBase64TailUnderflowCandidate(src, sp, sl, isURL, isMIME)) {
      return Optional.empty();
    }
    int length = sl - sp;
    int remainder = length & 63;
    int padding = 0;
    while (padding < 3 && src[sl - 1 - padding] == '=') {
      padding++;
    }
    return Optional.of(
        Detection.log(
            "base64",
            "base64_avx512_tail_underflow",
            99,
            "Base64.Decoder.decode0 rejected x64 AVX-512 tail-underflow candidate (CVE-2026-114938)",
            request,
            Map.of(
                "length", String.valueOf(length),
                "padding", String.valueOf(padding),
                "remainder", String.valueOf(remainder),
                "alphabet", isURL ? "URL-safe" : "standard",
                "cve", "CVE-2026-114938")));
  }

  public Optional<Detection> detectJmxMBeanInvoke(
      String mbeanName, String operationName, List<String> arguments, RequestContext request) {
    if (operationName == null || operationName.isBlank() || !request.active()) {
      return Optional.empty();
    }
    List<String> safeArguments = arguments == null ? List.of() : arguments;
    Optional<String> remoteConfig =
        safeArguments.stream()
            .filter(argument -> argument != null && looksLikeRemoteJmxConfig(argument))
            .findFirst();
    if (!isMutatingJmxOperation(operationName)) {
      return Optional.empty();
    }
    if (remoteConfig.isPresent()) {
      String matched = remoteConfig.orElseThrow();
      int confidence = request.hasParameterIn(matched) ? 100 : 90;
      return Optional.of(
          Detection.log(
              "jmx",
              "jmx_remote_config",
              confidence,
              "Request-time MBean invocation passes a remote configuration source",
              request,
              Map.of(
                  "mbean", abbreviate(String.valueOf(mbeanName)),
                  "operation", operationName,
                  "argument", abbreviate(matched),
                  "requestControlled", String.valueOf(request.hasParameterIn(matched)))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectJaasConfig(
      String config, String mechanism, RequestContext request) {
    // Compatibility for declaration-only callers. Runtime policy uses the login module lookup.
    return Optional.empty();
  }

  public Optional<Detection> detectXmlDecoderExpression(
      String targetType,
      String methodName,
      List<String> arguments,
      RequestContext request,
      List<String> stackClassNames) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    if (!isXmlDecoderStack(stackClassNames)) {
      return Optional.empty();
    }
    String normalizedTarget = normalizeJavaTypeName(targetType);
    String normalizedMethod = lower(methodName);
    List<String> safeArguments = arguments == null ? List.of() : arguments;
    String joinedArguments = String.join(" ", safeArguments);

    boolean processBuilderStart =
        normalizedTarget.equals("java.lang.ProcessBuilder") && normalizedMethod.equals("start");
    boolean runtimeExec =
        normalizedTarget.equals("java.lang.Runtime") && normalizedMethod.startsWith("exec");
    boolean reflectiveInvoke =
        normalizedTarget.equals("java.lang.reflect.Method") && normalizedMethod.equals("invoke");
    if (processBuilderStart || runtimeExec || reflectiveInvoke) {
      return Optional.of(
          Detection.log(
              "deserialization",
              "xml_decoder_runtime",
              95,
              "XMLDecoder object graph invoked a runtime execution primitive",
              request,
              Map.of(
                  "target", normalizedTarget,
                  "method", String.valueOf(methodName),
                  "arguments", abbreviate(joinedArguments))));
    }

    boolean writerConstruction =
        (normalizedTarget.equals("java.io.PrintWriter")
                || normalizedTarget.equals("java.io.FileWriter")
                || normalizedTarget.equals("java.io.FileOutputStream"))
            && (normalizedMethod.equals("new") || normalizedMethod.equals("newinstance"));
    if (writerConstruction) {
      for (String argument : safeArguments) {
        String path = normalizePath(argument);
        if (HostFileMutationDetector.isScriptTarget(path)) {
          return Optional.of(
              Detection.log(
                  "deserialization",
                  "xml_decoder_webshell",
                  95,
                  "XMLDecoder object graph created a writer for a server-side script path",
                  request,
                  Map.of(
                      "target", normalizedTarget,
                      "method", String.valueOf(methodName),
                      "path", abbreviate(path))));
        }
      }
    }
    return Optional.empty();
  }

  public Optional<Detection> detectResponseDataLeak(
      String contentType, String content, RequestContext request) {
    if (contentType == null || content == null) return Optional.empty();
    int separator = contentType.indexOf(';');
    String mediaType = (separator < 0 ? contentType : contentType.substring(0, separator)).trim();
    if (!STRUCTURED_RESPONSE.matcher(mediaType).matches()) return Optional.empty();
    Optional<String> identityCard = firstValidIdentityCard(content);
    if (identityCard.isPresent()) {
      return dataLeak("Identity Card", identityCard.orElseThrow(), request);
    }
    Optional<String> mobileNumber = firstValidMobileNumber(content);
    if (mobileNumber.isPresent()) {
      return dataLeak("Mobile Number", mobileNumber.orElseThrow(), request);
    }
    Optional<String> bankCard = firstValidBankCard(content);
    if (bankCard.isPresent()) {
      return dataLeak("Bank Card", bankCard.orElseThrow(), request);
    }
    return Optional.empty();
  }

  public Optional<Detection> detectXssEcho(String content, RequestContext request) {
    if (content == null || content.isBlank()) {
      return Optional.empty();
    }
    for (String value : request.allParameterValues()) {
      if (value != null && !value.isBlank() && content.contains(value) && XSS_INPUT.matcher(value).find()) {
        return Optional.of(
            Detection.log(
                "response",
                "xss_echo",
                70,
                "Response echoes XSS-like request input",
                request,
                Map.of("value", abbreviate(value))));
      }
    }
    return Optional.empty();
  }

  public Optional<Detection> detectWebshellLdPreload(
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

  private static boolean looksLikeJavaBeanPollution(String parameterName) {
    if (parameterName == null || parameterName.isBlank()) {
      return false;
    }
    String normalized = normalizeBindingPath(parameterName);
    boolean reachesClassLoader =
        normalized.contains("class.module.classloader")
            || normalized.contains("class.classloader")
            || normalized.startsWith("classloader.")
            || normalized.contains(".classloader.");
    if (!reachesClassLoader) {
      return false;
    }
    for (String target : BEAN_POLLUTION_TARGETS) {
      if (normalized.contains(target)) {
        return true;
      }
    }
    return normalized.contains("pipeline.first.")
        && (normalized.endsWith(".pattern")
            || normalized.endsWith(".suffix")
            || normalized.endsWith(".directory")
            || normalized.endsWith(".prefix")
            || normalized.endsWith(".filedateformat"));
  }

  private static RequestContext redactJavaBeanPollutionRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request.parameters().forEach(
        (name, values) -> {
          if (!looksLikeJavaBeanPollution(name)) {
            parameters.put(name, values);
            return;
          }
          var redactedValues = new ArrayList<String>();
          for (int i = 0; i < values.size(); i++) {
            redactedValues.add("[redacted]");
          }
          parameters.put(name, List.copyOf(redactedValues));
        });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactJavaBeanPollutionQuery(request.query()),
        parameters,
        request.headers(),
        request.body());
  }

  private static String redactJavaBeanPollutionQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      String rawName = separator >= 0 ? parts[i].substring(0, separator) : parts[i];
      if (looksLikeJavaBeanPollution(percentDecode(rawName))) {
        parts[i] = rawName + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<SetupStateResetMatch> setupStateReset(RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    boolean setupContext = setupStateControlPath(request.uri());
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      String normalized = normalizeBindingPath(entry.getKey());
      if (!looksLikeSetupCompletionBinding(normalized, setupContext)) {
        continue;
      }
      Optional<String> resetValue = setupResetValue(entry.getValue());
      if (resetValue.isPresent()) {
        return Optional.of(new SetupStateResetMatch(entry.getKey(), resetValue.orElseThrow()));
      }
    }
    return Optional.empty();
  }

  private static boolean looksLikeSetupCompletionBinding(
      String normalizedParameterName, boolean setupContext) {
    if (!normalizedParameterName.equals("setupcomplete")
        && !normalizedParameterName.endsWith(".setupcomplete")) {
      return false;
    }
    boolean setupBindingChain =
        normalizedParameterName.contains("bootstrap")
            || normalizedParameterName.contains("statusprovider")
            || normalizedParameterName.contains("applicationconfig");
    return setupBindingChain || setupContext;
  }

  private static boolean setupStateControlPath(String uri) {
    String path = uri == null ? "" : uri.split("\\?", 2)[0];
    return SETUP_STATE_CONTROL_PATH.matcher(path).find();
  }

  private static Optional<String> setupResetValue(List<String> values) {
    for (String value : values == null ? List.<String>of() : values) {
      String normalized = lower(percentDecode(value)).trim();
      if (normalized.equals("false")
          || normalized.equals("0")
          || normalized.equals("off")
          || normalized.equals("no")) {
        return Optional.of(normalized);
      }
    }
    return Optional.empty();
  }

  private static String normalizeBindingPath(String parameterName) {
    String normalized =
        percentDecode(parameterName == null ? "" : parameterName)
            .toLowerCase(Locale.ROOT)
            .replace('[', '.')
            .replace(']', '.')
            .replace('/', '.')
            .replace('\\', '.');
    while (normalized.contains("..")) {
      normalized = normalized.replace("..", ".");
    }
    while (normalized.startsWith(".")) {
      normalized = normalized.substring(1);
    }
    while (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized;
  }

  private static Optional<ServerSideScriptPutMatch> serverSideScriptPut(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String method = lower(request.method()).replaceAll("[^a-z]", "");
    if (!method.equals("put")) {
      return Optional.empty();
    }
    String rawPath = request.uri() == null ? "" : request.uri().split("\\?", 2)[0];
    for (String variant : pathVariants(rawPath)) {
      String normalized = variant.replace('\\', '/').toLowerCase(Locale.ROOT);
      if (SCRIPT_FILE_REQUEST_PATH.matcher(normalized).matches()) {
        return Optional.of(new ServerSideScriptPutMatch(normalized));
      }
    }
    return Optional.empty();
  }

  private static Optional<UploadFilenameOverrideMatch> uploadFilenameOverride(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    if (!multipartUploadBindingContext(request)) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!uploadFilenameOverrideParameter(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<String> targetType = uploadFilenameOverrideTarget(value);
        if (targetType.isPresent()) {
          return Optional.of(
              new UploadFilenameOverrideMatch(
                  entry.getKey(), targetType.orElseThrow(), value == null ? 0 : value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean multipartUploadBindingContext(RequestContext request) {
    String method = lower(request.method()).replaceAll("[^a-z]", "");
    if (!Set.of("post", "put", "patch").contains(method)) {
      return false;
    }
    String contentType = lower(request.header("content-type").orElse(""));
    return contentType.contains("multipart/form-data");
  }

  private static boolean uploadFilenameOverrideParameter(String parameterName) {
    if (parameterName == null || parameterName.isBlank()) {
      return false;
    }
    String normalized = normalizeBindingPath(parameterName).replace("_", "").replace("-", "");
    return normalized.equals("filename")
        || normalized.endsWith(".filename")
        || normalized.endsWith("filename");
  }

  private static Optional<String> uploadFilenameOverrideTarget(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (String variant : decodedVariants(value)) {
      String normalized = variant.trim().replace('\\', '/');
      if (normalized.isBlank()) {
        continue;
      }
      if (normalized.indexOf('\0') >= 0 || containsParentSegment(normalized)) {
        return Optional.of("traversal");
      }
      if (normalized.startsWith("/")
          || normalized.startsWith("//")
          || WINDOWS_ABSOLUTE_PATH.matcher(normalized).matches()) {
        return Optional.of("absolute");
      }
    }
    return Optional.empty();
  }

  private static RequestContext redactUploadFilenameOverrideRequest(RequestContext request) {
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
                    uploadFilenameOverrideParameter(name)
                            && uploadFilenameOverrideTarget(value).isPresent()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactUploadFilenameOverrideQuery(request.query()),
        parameters,
        request.headers(),
        request.body());
  }

  private static String redactUploadFilenameOverrideQuery(String query) {
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
      if (uploadFilenameOverrideParameter(name)
          && uploadFilenameOverrideTarget(value).isPresent()) {
        parts[i] = rawName + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static boolean looksLikeInternalIdentityBypass(
      String userAgent, RequestContext request) {
    if (userAgent == null || userAgent.isBlank() || request == null) {
      return false;
    }
    String normalizedAgent = userAgent.trim().toLowerCase(Locale.ROOT);
    boolean internalIdentity =
        INTERNAL_SERVICE_USER_AGENTS.stream()
            .anyMatch(
                agent -> normalizedAgent.equals(agent) || normalizedAgent.startsWith(agent + "/"));
    if (!internalIdentity) {
      return false;
    }
    String uri = request.uri() == null ? "" : request.uri();
    if (isBenignInternalServicePath(uri)) {
      return false;
    }
    return SENSITIVE_CONTROL_PATH.matcher(uri).find();
  }

  private static boolean isBenignInternalServicePath(String uri) {
    String normalized = lower(uri == null ? "" : uri);
    return normalized.equals("/nacos/v1/cs/ops/data/removal")
        || normalized.startsWith("/nacos/v1/cs/ops/data/removal/");
  }

  private record SetupStateResetMatch(String parameter, String value) {}

  private record ServerSideScriptPutMatch(String path) {}

  private record UploadFilenameOverrideMatch(
      String parameter, String targetType, int valueLength) {}

  private record InternalResourceMatch(String component, String resource, String variant) {}

  private static Optional<Map.Entry<String, String>> requestControlledInternalForward(
      RequestContext request) {
    if (request == null || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!internalForwardParameter(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue()) {
        Optional<String> target = internalForwardTarget(value);
        if (target.isPresent()) {
          return Optional.of(Map.entry(entry.getKey(), target.orElseThrow()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean internalForwardParameter(String name) {
    if (name == null || name.isBlank()) {
      return false;
    }
    String normalized =
        name.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "").replace(".", "");
    return INTERNAL_FORWARD_PARAMETERS.contains(normalized);
  }

  private static Optional<String> internalForwardTarget(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (String variant : pathVariants(value.trim())) {
      String normalized = variant.trim().replace('\\', '/');
      if (!normalized.startsWith("/") || !INTERNAL_FORWARD_JSP_SUFFIX.matcher(normalized).find()) {
        continue;
      }
      String path = normalized.split("[?#]", 2)[0];
      String stripped = stripServletPathParameters(path);
      if (INTERNAL_FORWARD_CONTROL_PATH.matcher(stripped).find()) {
        return Optional.of(normalized);
      }
    }
    return Optional.empty();
  }

  private static Optional<InternalResourceMatch> protectedInternalResourceRequest(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    var candidates = new LinkedHashMap<String, String>();
    addCandidate(candidates, "uri", request.uri());
    if (looksLikeQueryResourceSpec(request.query())) {
      addCandidate(candidates, "query", request.query());
      addCandidate(candidates, "target", request.uri() + "?" + request.query());
    }
    for (Map.Entry<String, String> candidate : candidates.entrySet()) {
      String raw = normalizeRequestTarget(candidate.getValue());
      if (raw.isBlank()) {
        continue;
      }
      Optional<InternalResourceMatch> ambiguous =
          ambiguousProtectedInternalResource(candidate.getKey(), candidate.getValue(), raw);
      if (ambiguous.isPresent()) {
        return ambiguous;
      }
      if (protectedWebappResource(raw).isPresent()) {
        continue;
      }
      for (String variant : pathVariants(candidate.getValue())) {
        String normalized = normalizeRequestTarget(variant);
        if (normalized.equals(raw)) {
          continue;
        }
        Optional<String> resource = protectedWebappResource(normalized);
        if (resource.isPresent()) {
          return Optional.of(
              new InternalResourceMatch(
                  candidate.getKey(), resource.orElseThrow(), decodingVariant(candidate.getValue(), variant)));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<InternalResourceMatch> ambiguousProtectedInternalResource(
      String component, String value, String raw) {
    var matcher = PROTECTED_WEBAPP_RESOURCE.matcher(raw);
    if (!matcher.find()) {
      return Optional.empty();
    }
    String prefix = raw.substring(0, matcher.start(1));
    if (!ambiguousProtectedResourcePrefix(prefix)) {
      return Optional.empty();
    }
    return Optional.of(
        new InternalResourceMatch(
            component,
            matcher.group(1).toUpperCase(Locale.ROOT),
            protectedResourceAmbiguityVariant(value, prefix)));
  }

  private static boolean ambiguousProtectedResourcePrefix(String prefix) {
    String normalized = lower(prefix);
    if (normalized.contains("%2e") || normalized.contains("%252e") || normalized.contains("%u002e")) {
      return true;
    }
    String decoded = percentDecode(normalized);
    return (normalized.contains("%00") || decoded.indexOf('\0') >= 0)
        && (normalized.contains(".") || decoded.contains("."));
  }

  private static String protectedResourceAmbiguityVariant(String value, String prefix) {
    String normalized = lower(prefix);
    if (normalized.contains("%u002e")) {
      return "unicode-decoded";
    }
    if (normalized.contains("%252e")) {
      return "double-decoded";
    }
    if (normalized.contains("%2e")) {
      return "decoded";
    }
    if (normalized.contains("%00") || percentDecode(value).indexOf('\0') >= 0) {
      return "nul-segment";
    }
    return "ambiguous-path";
  }

  private static void addCandidate(Map<String, String> candidates, String component, String value) {
    if (value != null && !value.isBlank()) {
      candidates.put(component, value);
    }
  }

  private static String normalizeRequestTarget(String value) {
    return value == null ? "" : value.replace('\\', '/').toLowerCase(Locale.ROOT);
  }

  private static boolean looksLikeQueryResourceSpec(String query) {
    if (query == null || query.isBlank() || query.contains("=")) {
      return false;
    }
    String trimmed = query.trim();
    return trimmed.startsWith("/") || percentDecode(trimmed).startsWith("/");
  }

  private static String decodingVariant(String raw, String variant) {
    String once = percentDecode(raw);
    if (normalizeRequestTarget(variant).equals(normalizeRequestTarget(once))) {
      return "decoded";
    }
    String twice = percentDecode(once);
    if (normalizeRequestTarget(variant).equals(normalizeRequestTarget(twice))) {
      return "double-decoded";
    }
    String unicode = decodeUnicodeEscapes(once);
    if (normalizeRequestTarget(variant).equals(normalizeRequestTarget(unicode))) {
      return "unicode-decoded";
    }
    return "decoded";
  }

  private static Optional<String> confusingRequestPath(String uri) {
    if (uri == null || uri.isBlank()) {
      return Optional.empty();
    }
    String path = uri.split("\\?", 2)[0];
    boolean sensitiveControlPath = SENSITIVE_CONTROL_PATH.matcher(path).find();
    List<String> variants = decodedPathVariants(path);
    int decodedCount = variants.size();
    addLowByteVariants(variants, path);
    for (int i = 0; i < variants.size(); i++) {
      String normalized = variants.get(i).replace('\\', '/');
      if (hasConfusingDotSegment(normalized)
          || (sensitiveControlPath && i < decodedCount && hasPathControlCharacter(normalized))) {
        return Optional.of(normalized);
      }
      Optional<String> canonicalControlPath = canonicalSensitiveControlPath(normalized);
      if (canonicalControlPath.isPresent()) {
        return canonicalControlPath;
      }
    }
    return Optional.empty();
  }

  private static Optional<String> canonicalSensitiveControlPath(String path) {
    if (path == null || path.isBlank()) {
      return Optional.empty();
    }
    String normalized = stripServletPathParameters(path.replace('\\', '/'));
    if (!hasSingleDotSegment(normalized) && !hasDuplicateSlash(normalized)) {
      return Optional.empty();
    }
    String canonical = collapsePathDotSegments(normalized);
    if (canonical.equals(normalized) || !SENSITIVE_CONTROL_PATH.matcher(canonical).find()) {
      return Optional.empty();
    }
    return Optional.of(canonical);
  }

  private static boolean hasSingleDotSegment(String path) {
    for (String segment : path.split("/", -1)) {
      if (segment.equals(".")) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasDuplicateSlash(String path) {
    return path != null && path.contains("//");
  }

  private static boolean isMutatingJmxOperation(String operationName) {
    String normalized = lower(operationName);
    return normalized.startsWith("add")
        || normalized.startsWith("set")
        || normalized.startsWith("create")
        || normalized.startsWith("copy")
        || normalized.startsWith("load")
        || normalized.startsWith("reload")
        || normalized.startsWith("update")
        || normalized.startsWith("write")
        || normalized.startsWith("save")
        || normalized.startsWith("store")
        || normalized.startsWith("dump")
        || normalized.startsWith("install")
        || normalized.startsWith("deploy")
        || normalized.startsWith("import")
        || normalized.startsWith("start");
  }

  private static boolean looksLikeRemoteJmxConfig(String argument) {
    String normalized = lower(argument.trim());
    if (normalized.isBlank() || !containsRemoteProtocol(normalized) || !JmxDispatch.isLocationArgument(argument)) {
      return false;
    }
    return normalized.contains("brokerconfig=")
        || normalized.contains("xbean:")
        || normalized.contains("spring:")
        || (normalized.contains("config") && normalized.contains(".xml"));
  }

  private static boolean hasPathControlCharacter(String path) {
    for (int i = 0; i < path.length(); i++) {
      if (Character.isISOControl(path.charAt(i))) {
        return true;
      }
    }
    return false;
  }

  private static boolean isXmlDecoderStack(List<String> stackClassNames) {
    if (stackClassNames == null || stackClassNames.isEmpty()) {
      return false;
    }
    for (String className : stackClassNames) {
      if (className == null) {
        continue;
      }
      if (className.equals("java.beans.XMLDecoder")
          || className.startsWith("com.sun.beans.decoder.")) {
        return true;
      }
    }
    return false;
  }

  private static String archivePath(String path) {
    return path == null ? "" : path.trim().replace('\\', '/');
  }

  private static Optional<Detection> dataLeak(
      String kind, String matchedValue, RequestContext request) {
    return Optional.of(
        Detection.log(
            "response",
            "response_dataLeak",
            80,
            "PII leak detected: " + kind,
            request,
            Map.of("kind", kind, "match", matchedValue)));
  }

  private static Optional<String> firstValidIdentityCard(String content) {
    var matcher = CHINA_ID.matcher(content);
    int[] weights = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
    while (matcher.find()) {
      String id = matcher.group();
      if (id.charAt(0) == '0') {
        continue;
      }
      int sum = 0;
      for (int i = 0; i < weights.length; i++) {
        sum += Character.digit(id.charAt(i), 10) * weights[i];
      }
      char check = id.charAt(17);
      sum += (check == 'X' || check == 'x') ? 10 : Character.digit(check, 10);
      if (sum % 11 == 1) {
        return Optional.of(id);
      }
    }
    return Optional.empty();
  }

  private static Optional<String> firstValidMobileNumber(String content) {
    var matcher = CHINA_MOBILE.matcher(content);
    while (matcher.find()) {
      if (CHINA_MOBILE_PREFIXES.contains(matcher.group(1))) {
        return Optional.of(matcher.group());
      }
    }
    return Optional.empty();
  }

  private static Optional<String> firstValidBankCard(String content) {
    var matcher = BANK_CARD.matcher(content);
    while (matcher.find()) {
      String card = matcher.group().replace(" ", "").replace("-", "");
      if (luhn(card)) {
        return Optional.of(matcher.group());
      }
    }
    return Optional.empty();
  }

  private static boolean luhn(String digits) {
    int sum = 0;
    boolean doubleDigit = false;
    for (int i = digits.length() - 1; i >= 0; i--) {
      int value = Character.digit(digits.charAt(i), 10);
      if (value < 0) {
        return false;
      }
      if (doubleDigit) {
        value *= 2;
      }
      sum += value / 10 + value % 10;
      doubleDigit = !doubleDigit;
    }
    return sum % 10 == 0;
  }
}
