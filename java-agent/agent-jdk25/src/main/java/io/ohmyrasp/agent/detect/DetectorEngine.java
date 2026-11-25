package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DeserializationTypes.normalizeJavaTypeName;
import static io.ohmyrasp.agent.detect.DetectorStrings.containsPathToken;
import static io.ohmyrasp.agent.detect.DetectorStrings.extensionOf;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizePath;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.DetectorStrings.protocolOf;
import static io.ohmyrasp.agent.detect.ExpressionSyntax.containsRuntimeExpressionPrimitive;
import static io.ohmyrasp.agent.detect.HostFileMutationDetector.fileOperationFromDynamicCode;
import static io.ohmyrasp.agent.detect.HostFileMutationDetector.unsafeConfigPersistencePath;
import static io.ohmyrasp.agent.detect.RemoteResourceDetector.SSRF_PROTOCOLS;
import static io.ohmyrasp.agent.detect.RemoteResourceDetector.containsRemoteProtocol;
import static io.ohmyrasp.agent.detect.RequestDecoding.PROTECTED_WEBAPP_RESOURCE;
import static io.ohmyrasp.agent.detect.RequestDecoding.addLowByteVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.addVariant;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodeUnicodeEscapes;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodedPathVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodedVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.pathVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.protectedWebappResource;
import static io.ohmyrasp.agent.detect.RequestExpressionDetector.dangerousParserHeaderExpression;
import static io.ohmyrasp.agent.detect.RequestExpressionDetector.dangerousRequestExpressionValue;
import static io.ohmyrasp.agent.detect.RequestExpressionDetector.requestExpressionParameterEngine;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;
import static io.ohmyrasp.agent.detect.RequestValues.bodyHasSinkValue;

import io.ohmyrasp.agent.file.ArchiveEntryContext;
import io.ohmyrasp.agent.file.HostDelete;
import io.ohmyrasp.agent.file.HostDirectory;
import io.ohmyrasp.agent.file.HostReadPath;
import io.ohmyrasp.agent.file.WindowsDataStream;
import io.ohmyrasp.agent.http.ArchiveUploadPolicy;
import io.ohmyrasp.agent.jmx.JmxDispatch;
import io.ohmyrasp.agent.jmx.JmxWriteScope;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.net.HttpTransportObservation;
import io.ohmyrasp.agent.net.NetworkHost;
import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

public final class DetectorEngine {
  private static final String UNIX_READ_TARGET =
      "etc/(?:issue|passwd|shadow|apache2/apache2\\.conf)|proc/self/environ|root/\\.ssh|root/\\.bash_(?:history|profile)";

  private static final String WINDOWS_READ_TARGET = "windows/system32/(?:inetsrv/metabase\\.xml|drivers/etc/hosts)";

  private static final String PRIVATE_READ_NAME = "\\.bash_history|\\.zsh_history|\\.mysql_history|id_rsa";

  // Higher-level argument and URI detectors can receive a path fragment. Host opens have a native root.
  private static final Pattern DANGEROUS_FILE_READ = Pattern.compile("(?is)(?:^|/)(?:"
      + UNIX_READ_TARGET + "|" + WINDOWS_READ_TARGET + "|" + PRIVATE_READ_NAME + ")$");

  private static final Pattern SENSITIVE_HOST_READ = Pattern.compile("^(?:/(?:" + UNIX_READ_TARGET
      + ")|[a-z]:/" + WINDOWS_READ_TARGET + "|(?:.*/)?(?:" + PRIVATE_READ_NAME + "))$");

  private static final Pattern SCRIPT_FILE_REQUEST_PATH =
      Pattern.compile(
          "(?is).+\\.(?:aspx?|jspx?|php[345]?|phar|phtml|sh|py|pl|rb|so|dll|dylib|ashx|cer|asa)(?:[;/\\\\].*|\\.*$)");

  private static final Pattern CLEAN_FILE =
      Pattern.compile("(?is).+\\.(?:jpg|jpeg|png|gif|bmp|txt|rar|zip)$");

  private static final Pattern HTML_FILE = Pattern.compile("(?is).+\\.(?:htm|html|js)$");

  private static final Pattern EXECUTABLE_FILE =
      Pattern.compile("(?is).+\\.(?:exe|dll|scr|vbs|cmd|bat)$");

  private static final Pattern WINDOWS_ABSOLUTE_PATH = Pattern.compile("(?i)^[a-z]:/.*");

  private static final Pattern READ_SAFE_EXTENSION =
      Pattern.compile(
          "(?is).+\\.(?:docx?|dotx?|docm|dotm|xlsx?|xltx?|xlsm|xlsb|pptx?|ppsx?|ppsm|potx?|potm|7z|tar|gz|bz2|xz|rar|zip|jpe?g|png|gif|bmp|txt)$");

  private static final Pattern INTERNAL_ADMIN_PATH = Pattern.compile(
      "(?i)(?:^|/)(?:jolokia|manager|host-manager|admin|console|webtools|solr/admin|debug|server-status|actuator/(?:env|heapdump|shutdown))(?:[/;]|$)");

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

  private static final Set<String> INCLUDE_PROTOCOLS =
      Set.of(
          "file",
          "gopher",
          "jar",
          "netdoc",
          "http",
          "https",
          "dict",
          "php",
          "compress.zlib",
          "compress.bzip2",
          "zip",
          "rar");

  private static final Set<String> JAVA_ARCHIVE_UPLOAD_TERMS =
      Set.of(
          "plugin",
          "plugins",
          "extension",
          "extensions",
          "addon",
          "addons",
          "module",
          "modules",
          "connector",
          "connectors",
          "driver",
          "drivers",
          "jar",
          "jars",
          "job",
          "jobs",
          "udf",
          "udfs",
          "app",
          "apps",
          "application",
          "applications");

  private static final Set<String> JAVA_ARCHIVE_UPLOAD_ACTIONS =
      Set.of("upload", "add", "install", "deploy", "load", "import", "submit", "create");

  private static final Set<String> JAVA_ARCHIVE_UPLOAD_PARAMETERS =
      Set.of(
          "plugin",
          "pluginfile",
          "extension",
          "extensionfile",
          "jar",
          "jarfile",
          "jobjar",
          "driver",
          "driverjar",
          "connector",
          "module");

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

  private static final Set<String> BEAN_POLLUTION_TARGETS =
      Set.of(
          "resources.context.parent.pipeline",
          "protectiondomain.codesource.location",
          "ucp.path",
          "urlclassloader",
          "systemclassloader");

  private static final Set<String> WEBSHELL_CALLABLES =
      Set.of("system", "exec", "passthru", "proc_open", "shell_exec", "popen", "pcntl_exec", "assert");

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

  public Optional<Detection> detectServletIncludeAttributes(
      Map<String, String> attributes, RequestContext request, List<String> stackClassNames) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (attributes == null || attributes.isEmpty() || legitimateServletIncludeStack(stackClassNames)) {
      return Optional.empty();
    }
    for (Map.Entry<String, String> entry : attributes.entrySet()) {
      String attribute = entry.getKey() == null ? "" : entry.getKey();
      String value = entry.getValue() == null ? "" : entry.getValue();
      if (!isServletIncludeAttribute(attribute) || value.isBlank()) {
        continue;
      }
      Optional<IncludeAttributeTarget> target = suspiciousIncludeAttributeTarget(value);
      if (target.isEmpty()) {
        continue;
      }
      if (isKnownLiferayPortalInclude(safeRequest.uri(), value)) {
        continue;
      }
      IncludeAttributeTarget match = target.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_forged_include_attribute",
              92,
              "Top-level request carries forged servlet include attributes for a sensitive target",
              safeRequest,
              Map.of(
                  "attribute", abbreviate(attribute),
                  "targetType", match.type(),
                  "resource", match.resource(),
                  "source", "servlet-include-attribute",
                  "uri", abbreviate(safeRequest.uri()),
                  "method", safeRequest.method())));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectRemoteJobSubmission(
      String mechanism, String descriptor, RequestContext request) {
    return detectRemoteJobSubmission(mechanism, descriptor, request, false);
  }

  public Optional<Detection> detectRemoteJobSubmission(String mechanism, String descriptor,
      RequestContext request, boolean descriptorPolicy) {
    return RemoteJobDetector.detect(mechanism, descriptor, request, descriptorPolicy);
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

  public Optional<Detection> detectCommand(List<String> command, RequestContext request) {
    return ProcessDetector.detectCommand(command, request);
  }

  public Optional<Detection> detectCommand(
      List<String> command, RequestContext request, List<String> stackClassNames) {
    return ProcessDetector.detectCommand(command, request, stackClassNames);
  }

  public Optional<Detection> detectCommand(List<String> command, RequestContext request,
      List<String> stackClassNames, boolean reflectionPolicy) {
    return ProcessDetector.detectCommand(command, request, stackClassNames, reflectionPolicy);
  }

  public Optional<Detection> detectUrl(String rawUrl, RequestContext request) {
    return detectUrl(rawUrl, request, false);
  }

  public Optional<Detection> detectUrl(String rawUrl, RequestContext request, boolean includeDestinationPolicy) {
    if (rawUrl == null || rawUrl.isBlank()) {
      return Optional.empty();
    }
    URI uri;
    try {
      uri = URI.create(rawUrl);
    } catch (IllegalArgumentException e) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_obfuscate",
              70,
              "Malformed outbound URL detected",
              request,
              Map.of("url", abbreviate(rawUrl))));
    }
    String scheme = lower(uri.getScheme());
    String host = NetworkHost.normalize(uri.getHost());
    String path = lower(uri.getPath());
    if (scheme.equals("file") && (!request.active() || !fileUrlNeedsInspection(uri, rawUrl, request))) {
      return Optional.empty();
    }
    if (isLocalArchiveUrl(rawUrl, scheme)) {
      return Optional.empty();
    }
    if ("jar".equals(scheme)) {
      if (!request.active()) return Optional.empty();
      if (HttpTransportObservation.archiveAddress(rawUrl) != null) {
        if (!includeDestinationPolicy) return Optional.empty();
        return Optional.of(Detection.log("ssrf", "ssrf_protocol", 90, "HTTP archive URL opened",
            request, Map.of("url", abbreviate(rawUrl), "decision_basis", "archive_scheme_only")));
      }
    }
    if (SSRF_PROTOCOLS.contains(scheme)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_protocol",
              90,
              "Outbound request uses a dangerous protocol: " + scheme,
              request,
              Map.of("url", abbreviate(rawUrl))));
    }
    return classifyNetworkDestination(uri, rawUrl, host, path, request, includeDestinationPolicy, null, false);
  }

  public Optional<Detection> classifyHttpTransport(java.net.URL url, RequestContext request, boolean includeDestinationPolicy, String peer, boolean redirected) {
    String address = HttpTransportObservation.address(url);
    URI uri = HttpTransportObservation.comparisonUri(url, address);
    return classifyNetworkDestination(uri, address, NetworkHost.normalize(url.getHost()),
        lower(uri == null ? url.getPath() : uri.getPath()), request, includeDestinationPolicy, peer, redirected);
  }

  public Optional<Detection> classifyHttpTransport(URI uri, RequestContext request, boolean includeDestinationPolicy, String peer, boolean redirected) {
    return classifyNetworkDestination(uri, HttpTransportObservation.address(uri), NetworkHost.normalize(uri.getHost()),
        lower(uri.getPath()), request, includeDestinationPolicy, peer, redirected);
  }

  private Optional<Detection> classifyNetworkDestination(URI uri, String rawUrl, String host, String path,
      RequestContext request, boolean includeDestinationPolicy, String peer, boolean redirected) {
    if (NetworkHost.isMetadata(host) || (peer != null && NetworkHost.isMetadata(peer))) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_aws",
              100,
              "Outbound request targets cloud instance metadata",
              request,
              Map.of("url", abbreviate(rawUrl))));
    }
    boolean internal = NetworkHost.isInternal(host) || (peer != null && NetworkHost.isInternal(peer));
    boolean admin = internal && INTERNAL_ADMIN_PATH.matcher(path).find();
    boolean supplied = redirected || requestControlsUrl(uri, rawUrl, host, request);
    boolean http = uri == null || "http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme());
    if ((!http && (supplied || admin)) || (internal && (supplied || (admin && requestControlsAdminPath(uri, request))))) {
      return Optional.of(Detection.log("ssrf", "ssrf_userinput", 90,
          "Request input selects an internal HTTP destination", request,
          Map.of("url", abbreviate(rawUrl), "host", host)));
    }
    if (CallbackDomain.matches(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_common",
              90,
              "Outbound request targets a callback collection domain",
              request,
              Map.of("url", abbreviate(rawUrl), "host", host)));
    }
    if (looksObfuscatedHost(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_obfuscate",
              80,
              "Outbound request host appears obfuscated",
              request,
              Map.of("url", abbreviate(rawUrl), "host", host)));
    }
    if (includeDestinationPolicy && (admin || supplied)) {
      return Optional.of(Detection.log("ssrf", "ssrf_userinput", 80,
          "Outbound destination matches a managed egress policy candidate", request,
          Map.of("url", abbreviate(rawUrl), "host", host, "policy_basis", "destination_only")));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectXmlAttachmentReference(
      String mechanism, String rawHref, RequestContext request) {
    if (rawHref == null || rawHref.isBlank() || request == null || !request.active()) {
      return Optional.empty();
    }
    String hook = xmlAttachmentMechanism(mechanism);
    if (hook.isBlank()) {
      return Optional.empty();
    }
    String href = attachmentHref(rawHref);
    if (href.isBlank()) {
      return Optional.empty();
    }
    URI uri;
    try {
      uri = URI.create(href);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    String scheme = lower(uri.getScheme());
    String host = NetworkHost.normalize(uri.getHost());
    String path = lower(uri.getPath());
    if (isLocalArchiveUrl(href, scheme)) {
      return Optional.empty();
    }
    if (SSRF_PROTOCOLS.contains(scheme)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_protocol",
              95,
              "XML attachment reference uses a dangerous protocol: " + scheme,
              request,
              Map.of("mechanism", hook, "scheme", scheme, "href", abbreviate(href))));
    }
    if (!scheme.equals("http") && !scheme.equals("https")) {
      return Optional.empty();
    }
    if (NetworkHost.isMetadata(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_aws",
              100,
              "XML attachment reference targets cloud instance metadata",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    if (NetworkHost.isInternal(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_userinput",
              95,
              "XML attachment reference targets an internal address",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    if (CallbackDomain.matches(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_common",
              90,
              "XML attachment reference targets a callback collection domain",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    if (looksObfuscatedHost(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_obfuscate",
              85,
              "XML attachment reference host appears obfuscated",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectClassLoaderUrl(
      String rawUrl, String mechanism, RequestContext request) {
    return RemoteResourceDetector.detectClassLoaderUrl(rawUrl, mechanism, request);
  }

  public Optional<Detection> detectSpringConfigLocation(
      String location, String mechanism, RequestContext request) {
    return RemoteResourceDetector.detectSpringConfigLocation(location, mechanism, request);
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

  public Optional<Detection> detectJmxFileWrite(String path, JmxWriteScope scope,
      String api, RequestContext request) {
    return HostFileMutationDetector.detectJmxFileWrite(path, scope, api, request);
  }

  public Optional<Detection> detectArgumentFileExpansion(
      String parser, List<String> arguments, RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String normalizedParser = lower(parser);
    if (!normalizedParser.equals("args4j")) {
      return Optional.empty();
    }
    List<String> safeArguments = arguments == null ? List.of() : arguments;
    for (String argument : safeArguments) {
      Optional<String> target = argumentFileExpansionTarget(argument);
      if (target.isEmpty()) {
        continue;
      }
      String path = target.orElseThrow();
      if (!dangerousArgumentFilePath(path)) {
        continue;
      }
      String normalizedPath = normalizePath(path);
      int confidence =
          request.hasParameterIn(argument)
                  || request.hasParameterIn(path)
                  || request.hasParameterIn(normalizedPath)
              ? 100
              : 95;
      return Optional.of(
          Detection.log(
              "readFile",
              "readFile_argument_expansion",
              confidence,
              "Command argument parser expands an @file reference during a request",
              request,
              Map.of(
                  "parser", normalizedParser,
                  "argument", abbreviate(argument),
                  "path", abbreviate(normalizedPath))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectDns(String host, RequestContext request) {
    if (host == null || host.isBlank()) {
      return Optional.empty();
    }
    String normalized = NetworkHost.normalize(host);
    if (CallbackDomain.matches(normalized)) {
      return Optional.of(
          Detection.log(
              "dns",
              "dns_blacklist",
              95,
              "DNS lookup targets a callback collection domain",
              request,
              Map.of("host", normalized)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectFileRead(String path, RequestContext request, boolean xmlParserStack) {
    return detectFileRead(path, request, xmlParserStack, false);
  }

  public Optional<Detection> detectFileRead(String path, RequestContext request, boolean xmlParserStack,
      boolean includeLocationPolicy) {
    return detectFileRead(path, request, () -> xmlParserStack, includeLocationPolicy);
  }

  public Optional<Detection> detectFileRead(String path, RequestContext request,
      java.util.function.BooleanSupplier xmlParserStack, boolean includeLocationPolicy) {
    return detectFileRead(path, request, xmlParserStack, includeLocationPolicy, HostReadPath.OpenPolicy.PATH_ONLY);
  }

  public Optional<Detection> detectFileRead(String path, RequestContext request,
      java.util.function.BooleanSupplier xmlParserStack, boolean includeLocationPolicy, HostReadPath.OpenPolicy links) {
    if (path == null || path.isBlank()) return Optional.empty();
    String location = HostReadPath.location(path);
    boolean sensitive = SENSITIVE_HOST_READ.matcher(location).matches() && HostReadPath.confirmsLocation(path);
    if (sensitive && xmlParserStack.getAsBoolean()) {
      return Optional.of(
          Detection.log(
              "xxe",
              "xxe_file",
              90,
              "XML parser attempted to read a sensitive local file",
              request,
              Map.of("path", location)));
    }
    if (!request.active()) {
      return Optional.empty();
    }
    String protocol = protocolOf(path);
    boolean protectedSelection = sensitive || ((isSystemDirectory(location) || isProtectedRequestResource(location))
        && HostReadPath.confirmsLocation(path));
    if (requestControlsReadPath(path, request, protectedSelection, protectedSelection || !protocol.isEmpty())) {
      if (protocol.equals("http") || protocol.equals("https")) {
        return Optional.of(
            Detection.log(
                "readFile",
                "readFile_userinput_http",
                90,
                "File streaming function requested an HTTP resource from user input",
                request,
                Map.of("path", abbreviate(path))));
      }
      if (protocol.equals("file") || protocol.equals("php")) {
        return Optional.of(
            Detection.log(
                "readFile",
                "readFile_userinput_unwanted",
                90,
                "File read used an unwanted user-controlled protocol",
                request,
                Map.of("path", abbreviate(path), "protocol", protocol)));
      }
      return Optional.of(
          Detection.log(
              "readFile",
              "readFile_userinput",
              90,
              "File read path is controlled by request input",
              request,
              Map.of("path", location)));
    }
    if (sensitive && !HostReadPath.isHostsFile(location)) {
      return Optional.of(
          Detection.log(
              "readFile",
              "readFile_unwanted",
              85,
              "Sensitive local file read detected",
              request,
              Map.of("path", location)));
    }
    if ((includeLocationPolicy || links != HostReadPath.OpenPolicy.PATH_ONLY) && protocol.isEmpty()
        && (request.parameters().values().stream().anyMatch(values -> HostReadPath.selected(path, values))
        || (isAbsolutePathLike(path) && bodyHasSinkValue(request, path)))) {
      String resolved = links.resolvedLocation(path);
      if (!resolved.isEmpty() && !resolved.equals(location)
          && (SENSITIVE_HOST_READ.matcher(resolved).matches() || isProtectedRequestResource(resolved))) {
        return Optional.of(Detection.log("readFile", "readFile_userinput", 90,
            "Request-selected path resolves to a protected host file", request,
            Map.of("path", resolved, "decision_basis", "resolved_request_file")));
      }
      if (includeLocationPolicy) {
        return Optional.of(Detection.log("readFile", "readFile_userinput", 65,
            "Request supplied the path of an ordinary file", request,
            Map.of("path", location, "decision_basis", "requested_path_only")));
      }
    }
    if (includeLocationPolicy && isSystemDirectory(location) && HostReadPath.confirmsLocation(path)) {
      return Optional.of(Detection.log("readFile", "readFile_outsideWebroot", 65,
          "Local read targets a system directory covered by file access policy", request,
          Map.of("path", location, "decision_basis", "system_directory")));
    }
    return Optional.empty();
  }

  private static boolean isProtectedRequestResource(String path) {
    return HostReadPath.isHostsFile(path) || path.contains("/.ssh/") || looksLikeApplicationSecretPath(path)
        || PROTECTED_WEBAPP_RESOURCE.matcher(path).find();
  }

  private static boolean isSystemDirectory(String path) {
    return path.startsWith("/etc/") || path.startsWith("/proc/") || path.startsWith("/root/");
  }

  private static boolean requestControlsReadPath(String path, RequestContext request, boolean sensitive, boolean reportDirect) {
    String target = HostReadPath.inputName(path);
    for (List<String> values : request.parameters().values()) {
      for (String value : values) {
        String candidate = HostReadPath.inputName(value);
        if (candidate.isEmpty()) {
          continue;
        }
        if (isAbsolutePathLike(candidate) || !protocolOf(candidate).isEmpty()) {
          if (reportDirect && target.equals(candidate)) {
            return true;
          }
        } else if (((sensitive && candidate.contains("/")) || escapesRelativeRoot(candidate))
            && (target.equals(candidate) || target.endsWith("/" + candidate))) {
          return true;
        }
      }
    }
    return ((reportDirect && (isAbsolutePathLike(target) || !protocolOf(target).isEmpty()))
            || escapesRelativeRoot(target)) && bodyHasSinkValue(request, target);
  }

  private static boolean escapesRelativeRoot(String path) {
    if (!path.contains("..")) {
      return false;
    }
    int depth = 0;
    for (String segment : path.split("/+")) {
      if (segment.equals("..")) {
        if (--depth < 0) {
          return true;
        }
      } else if (!segment.isEmpty() && !segment.equals(".")) {
        depth++;
      }
    }
    return false;
  }

  public Optional<Detection> detectWindowsStreamWrite(WindowsDataStream stream, RequestContext request,
      List<String> stackClassNames, boolean namedStreamPolicy) {
    return HostFileMutationDetector.detectWindowsStreamWrite(stream, request, stackClassNames, namedStreamPolicy);
  }

  public Optional<Detection> detectFileWrite(String path, RequestContext request) {
    return HostFileMutationDetector.detectFileWrite(path, request);
  }

  public Optional<Detection> detectFileWrite(
      String path, RequestContext request, List<String> stackClassNames) {
    return HostFileMutationDetector.detectFileWrite(path, request, stackClassNames);
  }

  public Optional<Detection> detectArchiveExtraction(
      String entryName, String targetPath, RequestContext request) {
    return HostFileMutationDetector.detectArchiveExtraction(entryName, targetPath, request);
  }

  public Optional<Detection> detectArchiveExtraction(
      ArchiveEntryContext.ChannelWrite open, RequestContext request) {
    return HostFileMutationDetector.detectArchiveExtraction(open, request);
  }

  public Optional<Detection> detectFileDelete(String path, RequestContext request) {
    return HostFileMutationDetector.detectFileDelete(path, request);
  }

  public Optional<Detection> detectFileDelete(HostDelete entry, RequestContext request, boolean explicitPathPolicy) {
    return HostFileMutationDetector.detectFileDelete(entry, request, explicitPathPolicy);
  }

  public Optional<Detection> detectDirectoryList(String path, RequestContext request) {
    return detectDirectoryList(path, request, List.of());
  }

  public Optional<Detection> detectDirectoryList(
      String path, RequestContext request, List<String> stackClassNames) {
    return directoryListings(path, request, null, false, false, false, algorithm -> false, () -> stackClassNames)
        .stream().findFirst();
  }

  public boolean requestSelectsDirectory(String path, RequestContext request, boolean descriptorRelative) {
    return request.active() && (request.parameters().values().stream()
        .anyMatch(values -> HostDirectory.selected(path, values, descriptorRelative)) || bodyHasSinkValue(request, path));
  }

  public List<Detection> directoryListings(String path, RequestContext request, java.nio.file.DirectoryStream<?> opened,
      boolean descriptorRelative, boolean observed, boolean selectedWalk, java.util.function.Predicate<String> enabledPolicy,
      java.util.function.Supplier<List<String>> stack) {
    if (path == null || path.isEmpty()) return List.of();
    boolean selected = requestSelectsDirectory(path, request, descriptorRelative);
    boolean locationRule = enabledPolicy.test("directory_unwanted");
    boolean reflectiveRule = enabledPolicy.test("directory_reflect");
    if (!selected && !selectedWalk && !locationRule && !reflectiveRule) return List.of();

    String root = selected || selectedWalk || locationRule
        ? (observed ? HostDirectory.protectedRoot(path, opened, descriptorRelative) : HostDirectory.namedRoot(path)) : "";
    String display = root.isEmpty() ? path : root;
    List<Detection> findings = new java.util.ArrayList<>();
    if ((selected || selectedWalk) && !root.isEmpty()) {
      findings.add(Detection.log("directory", "directory_userinput", 90, "Request selected a protected directory listing",
          request, Map.of("path", root, "decision_basis", observed ? (selected ? "selected_directory" : "selected_directory_walk") : "directory_argument")));
    } else if (selected && enabledPolicy.test("directory_userinput")) {
      findings.add(Detection.log("directory", "directory_userinput", 65, "Request supplied an ordinary directory path",
          request, Map.of("path", display, "decision_basis", "requested_path_only")));
    }
    if (locationRule && !root.isEmpty()) {
      findings.add(Detection.log("directory", "directory_unwanted", 70, "Directory selected by location policy",
          request, Map.of("path", root, "decision_basis", "directory_location")));
    }
    if (reflectiveRule && fileOperationFromDynamicCode(stack.get(), true)) {
      findings.add(Detection.log("directory", "directory_reflect", 70, "Directory listed through dynamic dispatch",
          request, Map.of("path", display, "decision_basis", "directory_dispatch")));
    }
    return findings;
  }

  public Optional<Detection> detectInclude(
      String url, String realPath, String function, RequestContext request) {
    String target = url == null ? "" : url;
    if (target.isBlank()) {
      return Optional.empty();
    }
    if (request.hasParameterIn(target) || request.hasParameterIn(realPath)) {
      return Optional.of(
          Detection.log(
              "include",
              "include_userinput",
              100,
              "File inclusion target is controlled by request input",
              request,
              Map.of("url", abbreviate(target), "realPath", abbreviate(realPath))));
    }
    String protocol = protocolOf(target);
    if (INCLUDE_PROTOCOLS.contains(protocol)) {
      return Optional.of(
          Detection.log(
              "include",
              "include_protocol",
              90,
              "File inclusion used an unwanted protocol: " + protocol,
              request,
              Map.of("url", abbreviate(target), "function", String.valueOf(function))));
    }
    return Optional.empty();
  }

  public Optional<Detection> deniedArchiveUpload(String filename, RequestContext request, ArchiveUploadPolicy.Decision decision) {
    String basis = decision.denialBasis();
    if (basis == null || !ArchiveUploadPolicy.isArchive(filename)) return Optional.empty();
    return Optional.of(Detection.log("fileUpload", "fileUpload_java_archive", 90,
        "Java archive upload conflicts with the application's deployment policy", request,
        Map.of("filename", normalizePath(filename), "decision_basis", basis)));
  }

  public Optional<Detection> detectFileUpload(String filename, RequestContext request) {
    return detectFileUpload(filename, request, ArchiveUploadPolicy.Decision.UNSPECIFIED, false);
  }

  public Optional<Detection> detectFileUpload(
      String filename, RequestContext request, ArchiveUploadPolicy.Decision decision, boolean managedPolicy) {
    String normalized = normalizePath(filename);
    if (normalized.isBlank()) {
      return Optional.empty();
    }
    Optional<String> expressionEngine = dangerousUploadExpressionFilename(filename);
    if (expressionEngine.isPresent()) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_multipart_expression",
              95,
              "Multipart upload filename contains a dangerous expression payload",
              request,
              Map.of(
                  "engine", expressionEngine.orElseThrow(),
                  "filenameLength", String.valueOf(filename == null ? 0 : filename.length()))));
    }
    if (dangerousUploadFilename(filename)) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_path_traversal",
              95,
              "Multipart upload filename escapes the intended upload directory",
              request,
              Map.of("filename", abbreviate(filename))));
    }
    if (HostFileMutationDetector.isScriptTarget(normalized)
        || normalized.endsWith("/.htaccess")
        || normalized.endsWith("/.user.ini")
        || normalized.equals(".htaccess")
        || normalized.equals(".user.ini")) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_multipart_script",
              95,
              "Multipart upload contains a server-side script or config file",
              request,
              Map.of("filename", normalized)));
    }
    if (ArchiveUploadPolicy.isArchive(normalized)) {
      if (decision.denialBasis() != null) return deniedArchiveUpload(normalized, request, decision);
      if (managedPolicy) {
        // Existing centrally managed rules may explicitly select this metadata candidate.
        Optional<String> context = javaArchiveUploadContext(request);
        if (context.isPresent()) {
          return Optional.of(Detection.log("fileUpload", "fileUpload_java_archive", 90,
              "Java archive submitted on a deployment surface", request,
              Map.of("filename", normalized, "context", abbreviate(context.get()),
                  "decision_basis", "deployment_context")));
        }
      }
    }
    if (HTML_FILE.matcher(normalized).matches()) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_multipart_html",
              90,
              "Multipart upload contains an HTML or JavaScript file",
              request,
              Map.of("filename", normalized)));
    }
    if (EXECUTABLE_FILE.matcher(normalized).matches()) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_multipart_exe",
              90,
              "Multipart upload contains an executable file",
              request,
              Map.of("filename", normalized)));
    }
    return Optional.empty();
  }

  private static Optional<String> dangerousUploadExpressionFilename(String filename) {
    if (filename == null || filename.isBlank()) {
      return Optional.empty();
    }
    for (String variant : decodedVariants(filename)) {
      String engine = requestExpressionParameterEngine(variant);
      if (engine.isBlank()) {
        continue;
      }
      if (dangerousRequestExpressionValue(engine, variant)
          || dangerousParserHeaderExpression(engine, variant)) {
        return Optional.of(engine);
      }
    }
    return Optional.empty();
  }

  public Optional<Detection> detectWebdavUpload(
      String source, String destination, String method, RequestContext request) {
    if (!webdavMutationMethod(method)) {
      return Optional.empty();
    }
    String normalizedSource = normalizePath(source);
    String normalizedDestination = normalizePath(destination);
    String destinationPath = webdavDestinationPath(destination);
    if (!HostFileMutationDetector.isScriptTarget(normalizedSource)
        && (HostFileMutationDetector.isScriptTarget(normalizedDestination)
            || HostFileMutationDetector.isScriptTarget(destinationPath))) {
      return Optional.of(
          Detection.log(
              "webdav",
              "fileUpload_webdav",
              100,
              "WebDAV-style move produced a server-side script file",
              request,
              Map.of(
                  "source", normalizedSource,
                  "destination", normalizedDestination,
                  "destinationType", "server-side-script",
                  "method", String.valueOf(method))));
    }
    if (unsafeWebdavDestination(destination, destinationPath)) {
      return Optional.of(
          Detection.log(
              "webdav",
              "fileUpload_webdav",
              95,
              "WebDAV-style move writes to an unsafe filesystem destination",
              request,
              Map.of(
                  "source", normalizedSource,
                  "destination", normalizedDestination,
                  "destinationPath", destinationPath,
                  "destinationType", "unsafe-filesystem-path",
                  "method", String.valueOf(method))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectRename(String source, String destination, RequestContext request) {
    if (CLEAN_FILE.matcher(normalizePath(source)).matches()
        && HostFileMutationDetector.isScriptTarget(normalizePath(destination))) {
      return Optional.of(
          Detection.log(
              "rename",
              "rename_webshell",
              90,
              "Rename converted a non-script file into a server-side script",
              request,
              Map.of("source", normalizePath(source), "destination", normalizePath(destination))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectLink(
      String source, String destination, String type, RequestContext request) {
    if (CLEAN_FILE.matcher(normalizePath(source)).matches()
        && HostFileMutationDetector.isScriptTarget(normalizePath(destination))) {
      return Optional.of(
          Detection.log(
              "link",
              "link_webshell",
              90,
              "Link converted a non-script file into a server-side script",
              request,
              Map.of(
                  "source", normalizePath(source),
                  "destination", normalizePath(destination),
                  "type", String.valueOf(type))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectJndi(String name, RequestContext request) {
    return detectJndi(name, request, "declared_lookup");
  }

  public Optional<Detection> detectJndi(String name, RequestContext request, String operation) {
    return RemoteResourceDetector.detectJndi(name, request, operation);
  }

  public Optional<Detection> detectJaasConfig(
      String config, String mechanism, RequestContext request) {
    // Compatibility for declaration-only callers. Runtime policy uses the login module lookup.
    return Optional.empty();
  }

  public Optional<Detection> detectJwtVerificationFailure(
      String mechanism, String exceptionClass, String message, RequestContext request) {
    return CredentialDetector.detectJwtVerificationFailure(mechanism, exceptionClass, message, request);
  }

  public Optional<Detection> detectDeserialization(String className, RequestContext request) {
    return DeserializationDetector.detectDeserialization(className, request);
  }

  /**
   * Non-emitting predicate mirroring {@link #detectDeserialization}'s notion of a
   * dangerous gadget class. Exposed for the JVM serial-filter guard, which must
   * decide whether to reject a class without re-running (or double-recording)
   * the full detection pipeline.
   */
  public boolean isDangerousDeserializationType(String className) {
    return DeserializationDetector.isDangerousDeserializationType(className);
  }

  public Optional<Detection> detectDeserialization(
      String className, RequestContext request, List<String> stackClassNames) {
    return DeserializationDetector.detectDeserialization(className, request, stackClassNames);
  }

  public Optional<Detection> detectRmiRegistryBind(
      String operation,
      String bindingName,
      String remoteClassName,
      RequestContext request,
      List<String> stackClassNames) {
    return DeserializationDetector.detectRmiRegistryBind(operation, bindingName, remoteClassName, request, stackClassNames);
  }

  public Optional<Detection> detectSessionDeserialization(
      String sessionId, String mechanism, RequestContext request) {
    return DeserializationDetector.detectSessionDeserialization(sessionId, mechanism, request);
  }

  public Optional<Detection> detectPolymorphicType(
      String parser, String className, RequestContext request) {
    return DeserializationDetector.detectPolymorphicType(parser, className, request);
  }

  public Optional<Detection> detectFastjsonClassResource(
      String resource, RequestContext request) {
    return DeserializationDetector.detectFastjsonClassResource(resource, request);
  }

  public Optional<Detection> detectProtocolClassInstantiation(
      String protocol, String className, List<String> arguments, RequestContext request) {
    // Compatibility for declaration-only callers. No constructor has been selected.
    return Optional.empty();
  }

  /** OpenWire's exception slot is checked using the declaring class of its chosen constructor. */
  public Optional<Detection> detectProtocolClassInstantiation(Class<?> selected, RequestContext request) {
    return DeserializationDetector.detectOpenWireThrowable(selected, request);
  }

  public Optional<Detection> detectHttpInvokerDeserialization(
      String mechanism, RequestContext request) {
    return DeserializationDetector.detectHttpInvokerDeserialization(mechanism, request);
  }

  public Optional<Detection> detectHttpObjectStreamDeserialization(
      String streamClassName, RequestContext request, List<String> stackClassNames) {
    // Compatibility for metadata-only callers.
    return Optional.empty();
  }

  public Optional<Detection> detectHttpObjectStreamDeserialization(String source, RequestContext request) {
    return DeserializationDetector.detectHttpObjectStreamDeserialization(source, request);
  }

  public Optional<Detection> detectHessianType(String type, RequestContext request) {
    // Compatibility for declarations with no class allocation.
    return Optional.empty();
  }

  public Optional<Detection> detectHessianType(Class<?> selected, String basis, RequestContext request) {
    return DeserializationDetector.detectHessianAllocation(selected, basis, request);
  }

  public Optional<Detection> detectXmlRpcSerializableValue(
      String mechanism, RequestContext request) {
    return DeserializationDetector.detectXmlRpcSerializableValue(mechanism, request);
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

  public Optional<Detection> detectOgnl(String expression, RequestContext request) {
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

  public Optional<Detection> detectExpression(
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

  public Optional<Detection> detectJavaCompilation(
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

  public Optional<Detection> detectEval(String function, String code, RequestContext request) {
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

  public Optional<Detection> detectLoadLibrary(
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

  public Optional<Detection> detectWebshellEval(
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

  public Optional<Detection> detectWebshellCommand(
      List<String> command, RequestContext request) {
    return ProcessDetector.detectWebshellCommand(command, request);
  }

  public Optional<Detection> detectWebshellFileWrite(
      String path, String content, RequestContext request) {
    String normalized = normalizePath(path);
    if (HostFileMutationDetector.isScriptTarget(normalized)
        && (request.hasParameterIn(path) || request.hasParameterIn(content))) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_file_put_contents",
              95,
              "Request-controlled content is written to a server-side script",
              request,
              Map.of("path", normalized, "content", abbreviate(content))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectGeneratedScriptFileWrite(
      String path, String content, RequestContext request) {
    return HostFileMutationDetector.detectGeneratedScriptFileWrite(path, content, request);
  }

  public Optional<Detection> detectWebshellCallable(String function, RequestContext request) {
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

  public Optional<Detection> detectXxeEntity(String name, String systemId, RequestContext request) {
    return detectXxeEntity(name, systemId, request, false);
  }

  public Optional<Detection> detectXxeEntity(String name, String systemId, RequestContext request, boolean parserOpen) {
    if ("[xml]".equals(name) || systemId == null) {
      return Optional.empty();
    }
    boolean unc = systemId.startsWith("\\\\") || systemId.startsWith("//");
    int colon = systemId.indexOf(':');
    String protocol = colon < 0 ? "" : lower(systemId.substring(0, colon));
    if (!unc && !SSRF_PROTOCOLS.contains(protocol) && !"http".equals(protocol) && !"https".equals(protocol)) {
      return Optional.empty();
    }
    return Optional.of(Detection.log(
        "xxe", "xxe_protocol", unc ? 100 : 90,
        unc ? "XML external entity uses SMB/UNC path" : "XML external entity uses protocol " + protocol,
        request, Map.of("name", String.valueOf(name), "systemId", abbreviate(systemId),
            "decision_basis", parserOpen ? "parser_url_open" : "declared_identifier")));
  }

  private static boolean unsafeWebdavDestination(String destination, String destinationPath) {
    return absoluteFilesystemDestination(destination) && unsafeConfigPersistencePath(destinationPath);
  }

  private static boolean webdavMutationMethod(String method) {
    String normalized = lower(method).replaceAll("[^a-z]", "");
    return normalized.equals("move") || normalized.equals("copy");
  }

  private static boolean absoluteFilesystemDestination(String destination) {
    String decoded = percentDecode(destination == null ? "" : destination).trim().replace('\\', '/');
    String normalized = lower(decoded);
    return normalized.startsWith("file:")
        || decoded.startsWith("/")
        || (decoded.length() > 2
            && Character.isLetter(decoded.charAt(0))
            && decoded.charAt(1) == ':'
            && decoded.charAt(2) == '/');
  }

  private static String webdavDestinationPath(String destination) {
    String decoded = percentDecode(destination == null ? "" : destination).trim().replace('\\', '/');
    if (decoded.isBlank()) {
      return "";
    }
    try {
      URI uri = URI.create(decoded);
      if (lower(uri.getScheme()).equals("file")) {
        String path = uri.getPath();
        if (path != null && !path.isBlank()) {
          return normalizePath(path);
        }
      }
    } catch (RuntimeException ignored) {
      // Fall through to plain filesystem-path normalization.
    }
    return normalizePath(decoded);
  }

  /** An untyped temporary file can also be data. Require a copied operation in code position,
   * or a complete request-supplied operand to that operation. Never search unrelated fields for authority. */
  public boolean generatedScriptCandidate(String path) {
    return HostFileMutationDetector.generatedScriptCandidate(path);
  }

  public boolean requestSuppliesHttpUrl(URI uri, String address, String host, RequestContext request) {
    return requestControlsUrl(uri, address, NetworkHost.normalize(host), request);
  }

  private static boolean requestControlsAdminPath(URI destination, RequestContext request) {
    if (request == null || !request.active() || destination == null) return false;
    String path = destination.getRawPath();
    if (path == null || !path.startsWith("/")) return false;
    return request.parameters().values().stream().anyMatch(values -> values.contains(path))
        || bodyHasSinkValue(request, path);
  }

  private static boolean requestControlsUrl(URI destination, String rawUrl, String host, RequestContext request) {
    if (request == null || !request.active() || (host.isEmpty() && (destination == null || destination.getRawAuthority() == null))) {
      return false;
    }
    for (var parameter : request.parameters().entrySet()) {
      for (String value : parameter.getValue()) {
        if (value == null || value.isBlank()) {
          continue;
        }
        if (value.equals(rawUrl) || matchesHttpArchive(value, destination)) {
          return true;
        }
        if (!host.isEmpty()
            && ("host".equalsIgnoreCase(parameter.getKey()) || "hostname".equalsIgnoreCase(parameter.getKey()))
            && NetworkHost.destinationKey(value).equals(NetworkHost.destinationKey(host))) {
          return true;
        }
        if (destination != null && matchesUrlBase(value, destination)) {
          return true;
        }
      }
    }
    if (bodyHasSinkValue(request, rawUrl) || matchesHttpArchive(request.body().trim(), destination)) return true;
    if ((request.body().contains("!/") || request.body().indexOf('\\') >= 0) && jsonConfigBody(request)) {
      for (var field : jsonStringFields(request.body())) {
        if (matchesHttpArchive(field.value(), destination)) return true;
      }
    }
    return false;
  }

  private static boolean matchesHttpArchive(String value, URI destination) {
    String archive = HttpTransportObservation.archiveAddress(value);
    if (archive == null || destination == null) return false;
    try {
      URI supplied = URI.create(archive);
      String path = supplied.getRawPath();
      return supplied.getHost() != null && supplied.getScheme().equalsIgnoreCase(destination.getScheme())
          && NetworkHost.destinationKey(supplied.getHost()).equals(NetworkHost.destinationKey(destination.getHost()))
          && effectivePort(supplied) == effectivePort(destination)
          && (path.isEmpty() ? "/" : path).equals(destination.getRawPath())
          && java.util.Objects.equals(supplied.getRawQuery(), destination.getRawQuery());
    } catch (IllegalArgumentException invalid) {
      return false;
    }
  }

  private static boolean matchesUrlBase(String value, URI destination) {
    if (!value.regionMatches(true, 0, "https://", 0, 8)
        && !value.regionMatches(true, 0, "http://", 0, 7)) {
      return false;
    }
    URI supplied;
    try {
      supplied = URI.create(value);
    } catch (IllegalArgumentException ignored) {
      return false;
    }
    if (supplied.getHost() == null || !supplied.getScheme().equalsIgnoreCase(destination.getScheme())
        || !NetworkHost.destinationKey(supplied.getHost()).equals(NetworkHost.destinationKey(destination.getHost()))
        || effectivePort(supplied) != effectivePort(destination)) {
      return false;
    }
    String query = supplied.getRawQuery();
    String base = supplied.getRawPath();
    String path = destination.getRawPath();
    return (query == null || query.equals(destination.getRawQuery()))
        && (path.equals(base) || path.startsWith(base.endsWith("/") ? base : base + "/"));
  }

  private static int effectivePort(URI uri) {
    return uri.getPort() >= 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
  }

  private static boolean looksObfuscatedHost(String host) {
    if (host == null || host.isBlank()) {
      return false;
    }
    // URI.getHost retains the zone identifier of a scoped IPv6 address.
    if (host.indexOf(':') >= 0) {
      return false;
    }
    return host.matches("0x[0-9a-f]+")
        || host.matches("\\d+")
        || host.matches(".*%[0-9a-fA-F]{2}.*")
        || host.matches(".*[。｡．].*");
  }

  private static boolean isLocalArchiveUrl(String rawUrl, String scheme) {
    String normalized = lower(rawUrl);
    return "jar".equals(scheme)
        && (normalized.startsWith("jar:file:") || normalized.startsWith("jar:nested:"));
  }

  private static boolean fileUrlNeedsInspection(URI uri, String rawUrl, RequestContext request) {
    String path = uri.getPath();
    if (path == null || !path.startsWith("/") || path.startsWith("//")
        || path.indexOf('\\') >= 0 || path.indexOf('\0') >= 0 || uri.getRawAuthority() != null) {
      return true;
    }
    String normalized = normalizePath(path);
    boolean sensitive = sensitiveFileLocation(normalized);
    boolean deploymentResource = PROTECTED_WEBAPP_RESOURCE.matcher(normalized).find();
    if (sensitive || requestControlsReadPath(path, request, deploymentResource,
        deploymentResource || !READ_SAFE_EXTENSION.matcher(normalized).matches() || !protocolOf(path).isEmpty())
        || bodyHasSinkValue(request, rawUrl)) {
      return true;
    }
    // A fixed application path can be opened by URL APIs during a request.
    // Check whether a request value actually supplies the local URL or base.
    for (List<String> values : request.parameters().values()) {
      for (String value : values) {
        if (value == null || !value.regionMatches(true, 0, "file:", 0, 5)) {
          continue;
        }
        try {
          URI supplied = URI.create(value);
          String base = supplied.getPath();
          if (supplied.getRawAuthority() == null && base != null && !base.isEmpty()
              && (path.equals(base) || path.startsWith(base.endsWith("/") ? base : base + "/"))) {
            return true;
          }
        } catch (IllegalArgumentException ignored) {
          // Ordinary text can start with a URI scheme.
        }
      }
    }
    return false;
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

  private record IncludeAttributeTarget(String type, String resource) {}

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

  private static String stripServletPathParameters(String path) {
    String[] segments = path.split("/", -1);
    StringBuilder builder = new StringBuilder(path.length());
    for (int i = 0; i < segments.length; i++) {
      if (i > 0) {
        builder.append('/');
      }
      String segment = segments[i];
      int semicolon = segment.indexOf(';');
      builder.append(semicolon >= 0 ? segment.substring(0, semicolon) : segment);
    }
    return builder.toString();
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

  private static boolean isServletIncludeAttribute(String name) {
    String normalized = lower(name);
    return normalized.startsWith("javax.servlet.include.")
        || normalized.startsWith("jakarta.servlet.include.");
  }

  private static Optional<IncludeAttributeTarget> suspiciousIncludeAttributeTarget(String value) {
    for (String variant : pathVariants(value)) {
      String normalized = normalizePath(variant);
      if (normalized.isBlank()) {
        continue;
      }
      Optional<String> resource = protectedWebappResource(normalized);
      if (resource.isPresent()) {
        return Optional.of(new IncludeAttributeTarget("protected-resource", resource.orElseThrow()));
      }
      if (HostFileMutationDetector.isScriptTarget(normalized)) {
        return Optional.of(new IncludeAttributeTarget("server-side-script", extensionOf(normalized)));
      }
      if (hasConfusingDotSegment(normalized)) {
        return Optional.of(new IncludeAttributeTarget("path-traversal", "dot-segment"));
      }
    }
    return Optional.empty();
  }

  private static boolean isKnownLiferayPortalInclude(String uri, String value) {
    String normalizedUri = normalizePath(uri == null ? "" : uri);
    if (!("/".equals(normalizedUri)
        || normalizedUri.startsWith("/c/portal/")
        || normalizedUri.startsWith("/o/"))) {
      return false;
    }
    for (String variant : pathVariants(value)) {
      String normalized = normalizePath(stripServletPathParameters(variant));
      if (isKnownLiferayInternalIncludePath(normalizedUri, normalized)) {
        return true;
      }
      String canonical = collapsePathDotSegments(normalized);
      if (isKnownLiferayInternalIncludePath(normalizedUri, canonical)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isKnownLiferayInternalIncludePath(String uri, String path) {
    if (path == null) {
      return false;
    }
    if (path.startsWith("/html/portal/")
        || path.startsWith("/html/common/")
        || path.startsWith("/html/taglib/")) {
      return true;
    }
    if (uri != null
        && uri.startsWith("/c/portal/")
        && path.startsWith("/dynamic_include/")) {
      return true;
    }
    return uri != null
        && uri.startsWith("/o/")
        && ("/view.jsp".equals(path)
            || path.endsWith("/view.jsp")
            || path.startsWith("/search/bar/"));
  }

  private static boolean legitimateServletIncludeStack(List<String> stackClassNames) {
    if (stackClassNames == null || stackClassNames.isEmpty()) {
      return false;
    }
    for (String className : stackClassNames) {
      String normalized = lower(className).replace('/', '.');
      if (normalized.endsWith(".applicationdispatcher")
          || normalized.contains(".applicationdispatcher.")
          || normalized.endsWith(".requestdispatcher")
          || normalized.contains(".requestdispatcher.")) {
        return true;
      }
    }
    return false;
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

  private static String collapsePathDotSegments(String path) {
    boolean absolute = path.startsWith("/");
    var segments = new ArrayList<String>();
    for (String segment : path.split("/+", -1)) {
      if (segment.isBlank() || segment.equals(".")) {
        continue;
      }
      if (segment.equals("..")) {
        if (!segments.isEmpty()) {
          segments.remove(segments.size() - 1);
        }
        continue;
      }
      segments.add(segment);
    }
    String collapsed = String.join("/", segments);
    if (absolute) {
      collapsed = "/" + collapsed;
    }
    return collapsed.isBlank() ? "/" : collapsed;
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

  private static String xmlAttachmentMechanism(String mechanism) {
    String normalized = lower(mechanism).replace('_', '-');
    if (normalized.equals("cxf-aegis-xop") || normalized.equals("cxf-aegis-mtom")) {
      return "cxf-aegis-xop";
    }
    return "";
  }

  private static String attachmentHref(String href) {
    String value = href == null ? "" : href.trim();
    int cid = lower(value).indexOf("cid:");
    if (cid >= 0) {
      value = value.substring(cid + 4).trim();
    }
    return value;
  }

  private static boolean hasConfusingDotSegment(String path) {
    for (String rawSegment : path.split("/+")) {
      if (rawSegment.isBlank()) {
        continue;
      }
      String segment = rawSegment;
      int semicolon = segment.indexOf(';');
      if (semicolon >= 0) {
        segment = segment.substring(0, semicolon);
      }
      if (segment.equals("..")) {
        return true;
      }
    }
    return false;
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

  private static Optional<String> argumentFileExpansionTarget(String argument) {
    if (argument == null || argument.isBlank()) {
      return Optional.empty();
    }
    String trimmed = argument.trim();
    if (!trimmed.startsWith("@") || trimmed.length() == 1) {
      return Optional.empty();
    }
    String target = trimmed.substring(1).trim();
    if (target.length() >= 2) {
      char first = target.charAt(0);
      char last = target.charAt(target.length() - 1);
      if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
        target = target.substring(1, target.length() - 1).trim();
      }
    }
    return target.isBlank() ? Optional.empty() : Optional.of(target);
  }

  private static boolean dangerousArgumentFilePath(String path) {
    String normalized = normalizePath(path);
    if (normalized.isBlank()) {
      return false;
    }
    String pathShape = path == null ? "" : path.trim().replace('\\', '/');
    if (!isAbsolutePathLike(pathShape) && !containsParentSegment(pathShape)) {
      return false;
    }
    return sensitiveFileLocation(normalized);
  }

  private static boolean sensitiveFileLocation(String normalized) {
    if (DANGEROUS_FILE_READ.matcher(normalized).find()) {
      return true;
    }
    if (normalized.startsWith("/proc/")
        || normalized.startsWith("/etc/")
        || normalized.startsWith("/root/")
        || normalized.contains("/.ssh/")) {
      return true;
    }
    return looksLikeApplicationSecretPath(normalized);
  }

  private static boolean isAbsolutePathLike(String path) {
    return path.startsWith("/") || WINDOWS_ABSOLUTE_PATH.matcher(path).matches();
  }

  private static boolean looksLikeApplicationSecretPath(String path) {
    if (path.endsWith("/secret.key")
        || path.endsWith("/master.key")
        || path.endsWith("/credentials.xml")
        || path.endsWith("/identity.key.enc")
        || path.endsWith("/hudson.util.secret")) {
      return true;
    }
    return path.contains("/secrets/")
        && (path.endsWith(".key")
            || path.endsWith(".key.enc")
            || path.endsWith(".secret")
            || path.endsWith(".credentials"));
  }

  private static String archivePath(String path) {
    return path == null ? "" : path.trim().replace('\\', '/');
  }

  private static boolean dangerousUploadFilename(String filename) {
    if (filename == null || filename.isBlank()) {
      return false;
    }
    List<String> variants = new ArrayList<>();
    addVariant(variants, filename);
    addVariant(variants, percentDecode(filename));
    addVariant(variants, percentDecode(percentDecode(filename)));
    addVariant(variants, decodeUnicodeEscapes(filename));
    for (String variant : variants) {
      String normalized = variant.trim().replace('\\', '/');
      if (normalized.indexOf('\0') >= 0
          || normalized.startsWith("/")
          || normalized.startsWith("//")
          || containsParentSegment(normalized)) {
        return true;
      }
    }
    return false;
  }

  private static Optional<String> javaArchiveUploadContext(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String uri = lower(request.uri());
    boolean term = containsPathToken(uri, JAVA_ARCHIVE_UPLOAD_TERMS);
    boolean action = containsPathToken(uri, JAVA_ARCHIVE_UPLOAD_ACTIONS);
    if (term && action) {
      return Optional.of("uri:" + abbreviate(request.uri()));
    }
    if (uri.contains("/jars/") || uri.endsWith("/jars") || uri.contains("/plugin/")) {
      return Optional.of("uri:" + abbreviate(request.uri()));
    }
    for (String name : request.parameters().keySet()) {
      String normalized = normalizeParameterName(name);
      if (JAVA_ARCHIVE_UPLOAD_PARAMETERS.contains(normalized)) {
        return Optional.of("parameter:" + abbreviate(name));
      }
    }
    return Optional.empty();
  }

  private static boolean containsParentSegment(String path) {
    for (String segment : path.split("/+")) {
      if (segment.equals("..")) {
        return true;
      }
    }
    return false;
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

  public static String abbreviate(String value) {
    return DetectorStrings.abbreviate(value);
  }

  public static List<String> commandFromObject(Object command) {
    return ProcessDetector.commandFromObject(command);
  }
}
