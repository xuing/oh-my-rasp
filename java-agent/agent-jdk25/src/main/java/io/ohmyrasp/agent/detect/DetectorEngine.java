package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.FilePaths.WINDOWS_ABSOLUTE_PATH;
import static io.ohmyrasp.agent.detect.FilePaths.containsParentSegment;
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

/**
 * The HTTP request chain. {@link #detectRequest} runs the request-level detectors in a fixed
 * first-match order that {@code DetectorEngineDispatchTest} pins; the checks below it are the
 * steps only this chain uses. Every other hook calls the detector class of its family directly.
 */
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

  public Optional<Detection> detectRequest(RequestContext request) {
    List<Detection> out = new ArrayList<>(1);
    requestChain(request, out, true);
    return out.isEmpty() ? Optional.empty() : Optional.of(out.get(0));
  }

  /**
   * Every finding of the request chain, in chain order: what {@link #detectRequest} would return first, then
   * what each later rule finds. For a decision that must not let an earlier finding hide a later one (the
   * request body's, where the first finding is often the request's own and already reported).
   */
  public List<Detection> requestChainFindings(RequestContext request) {
    List<Detection> out = new ArrayList<>(2);
    requestChain(request, out, false);
    return out;
  }

  /** Adds {@code finding}; true when the chain stops at it (first match only). */
  private static boolean add(List<Detection> out, boolean firstOnly, Detection finding) {
    out.add(finding);
    return firstOnly;
  }

  private void requestChain(RequestContext request, List<Detection> out, boolean firstOnly) {
    String userAgent = request.header("user-agent").orElse("").toLowerCase(Locale.ROOT);
    if (looksLikeInternalIdentityBypass(userAgent, request)) {
      if (add(out, firstOnly, 
          Detection.log(
              "request",
              "request_internal_identity",
              90,
              "Request presents an internal service identity on a sensitive control path",
              request,
              Map.of(
                  "userAgent", userAgent,
                  "uri", abbreviate(request.uri()),
                  "method", request.method())))) return;
    }
    Optional<Detection> jwtFinding = CredentialDetector.defaultSignedTokenFinding(request);
    if (jwtFinding.isPresent() && add(out, firstOnly, jwtFinding.orElseThrow())) return;
    Optional<Detection> cookieFinding = CredentialDetector.defaultEncryptedCookieFinding(request);
    if (cookieFinding.isPresent() && add(out, firstOnly, cookieFinding.orElseThrow())) return;
    Optional<Detection> stateFinding = SerializedRequestState.serializedClientStateFinding(request);
    if (stateFinding.isPresent() && add(out, firstOnly, stateFinding.orElseThrow())) return;
    Optional<Detection> credentialFinding = CredentialDetector.defaultCredentialFinding(request);
    if (credentialFinding.isPresent() && add(out, firstOnly, credentialFinding.orElseThrow())) return;
    Optional<Detection> emptyFinding = CredentialDetector.emptyCredentialFinding(request);
    if (emptyFinding.isPresent() && add(out, firstOnly, emptyFinding.orElseThrow())) return;
    Optional<String> beanPollution = request.parameters().keySet().stream()
        .filter(DetectorEngine::looksLikeJavaBeanPollution)
        .findFirst();
    if (beanPollution.isPresent()) {
      RequestContext redactedRequest = redactJavaBeanPollutionRequest(request);
      if (add(out, firstOnly, 
          Detection.log(
              "request",
              "request_java_bean_pollution",
              95,
              "Request parameter attempts to bind Java classloader metadata",
              redactedRequest,
              Map.of("parameter", abbreviate(beanPollution.orElseThrow()))))) return;
    }
    Optional<Detection> configurationFinding = RequestConfigurationDetector.configuration(request);
    if (configurationFinding.isPresent() && add(out, firstOnly, configurationFinding.orElseThrow())) return;
    Optional<Detection> loaderFinding = RequestTemplateDetector.loader(request);
    if (loaderFinding.isPresent() && add(out, firstOnly, loaderFinding.orElseThrow())) return;
    Optional<Detection> messageSelectorFinding = RequestConfigurationDetector.messageSelector(request);
    if (messageSelectorFinding.isPresent() && add(out, firstOnly, messageSelectorFinding.orElseThrow())) return;
    Optional<Detection> headerFinding = RequestExpressionDetector.header(request);
    if (headerFinding.isPresent() && add(out, firstOnly, headerFinding.orElseThrow())) return;
    Optional<Detection> namingFinding = RequestConfigurationDetector.naming(request);
    if (namingFinding.isPresent() && add(out, firstOnly, namingFinding.orElseThrow())) return;
    Optional<Detection> contentFinding = RequestTemplateDetector.content(request);
    if (contentFinding.isPresent() && add(out, firstOnly, contentFinding.orElseThrow())) return;
    Optional<Detection> parametersAndPathFinding = RequestExpressionDetector.parametersAndPath(request);
    if (parametersAndPathFinding.isPresent() && add(out, firstOnly, parametersAndPathFinding.orElseThrow())) return;
    Optional<Detection> bindingFinding = RequestPayloadDetector.binding(request);
    if (bindingFinding.isPresent() && add(out, firstOnly, bindingFinding.orElseThrow())) return;
    Optional<Detection> resourceFinding = RequestResourceDetector.resource(request);
    if (resourceFinding.isPresent() && add(out, firstOnly, resourceFinding.orElseThrow())) return;
    Optional<Detection> spatialFilterFinding = RequestExpressionDetector.spatialFilter(request);
    if (spatialFilterFinding.isPresent() && add(out, firstOnly, spatialFilterFinding.orElseThrow())) return;
    Optional<SetupStateResetMatch> setupStateReset = setupStateReset(request);
    if (setupStateReset.isPresent()) {
      SetupStateResetMatch match = setupStateReset.orElseThrow();
      if (add(out, firstOnly, 
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
                  "method", request.method())))) return;
    }
    Optional<ServerSideScriptPutMatch> scriptPut = serverSideScriptPut(request);
    if (scriptPut.isPresent()) {
      ServerSideScriptPutMatch match = scriptPut.orElseThrow();
      if (add(out, firstOnly, 
          Detection.log(
              "request",
              "request_server_side_script_put",
              90,
              "HTTP PUT targets a server-side script path",
              request,
              Map.of(
                  "path", abbreviate(match.path()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())))) return;
    }
    Optional<UploadFilenameOverrideMatch> uploadFilenameOverride =
        uploadFilenameOverride(request);
    if (uploadFilenameOverride.isPresent()) {
      UploadFilenameOverrideMatch match = uploadFilenameOverride.orElseThrow();
      RequestContext redactedRequest = redactUploadFilenameOverrideRequest(request);
      if (add(out, firstOnly, 
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
                  "method", request.method())))) return;
    }
    Optional<Map.Entry<String, String>> internalForward = requestControlledInternalForward(request);
    if (internalForward.isPresent()) {
      Map.Entry<String, String> forward = internalForward.orElseThrow();
      if (add(out, firstOnly, 
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
                  "method", request.method())))) return;
    }
    Optional<InternalResourceMatch> internalResource = protectedInternalResourceRequest(request);
    if (internalResource.isPresent()) {
      InternalResourceMatch match = internalResource.orElseThrow();
      if (add(out, firstOnly, 
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
                  "method", request.method())))) return;
    }
    Optional<String> confusingPath = confusingRequestPath(request.uri());
    if (confusingPath.isPresent()) {
      if (add(out, firstOnly, 
          Detection.log(
              "request",
              "request_path_confusion",
              90,
              "Request URI contains path normalization confusion",
              request,
              Map.of(
                  "uri", abbreviate(request.uri()),
                  "decoded", abbreviate(confusingPath.orElseThrow()))))) return;
    }
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

  private static boolean hasPathControlCharacter(String path) {
    for (int i = 0; i < path.length(); i++) {
      if (Character.isISOControl(path.charAt(i))) {
        return true;
      }
    }
    return false;
  }

  private static String archivePath(String path) {
    return path == null ? "" : path.trim().replace('\\', '/');
  }
}
