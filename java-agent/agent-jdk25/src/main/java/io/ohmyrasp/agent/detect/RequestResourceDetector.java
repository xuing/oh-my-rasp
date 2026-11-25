package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizePath;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.RemoteResourceDetector.SSRF_PROTOCOLS;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodedVariants;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;

import io.ohmyrasp.agent.detect.RequestJson.JsonStringField;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.net.NetworkHost;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Request-selected remote resources, output paths and script writes. */
final class RequestResourceDetector {
  private static final Pattern SCRIPT_FILE_TOKEN =
      Pattern.compile("(?is)(?:[a-z]:)?(?:[./][^\\s\"'<>;,)]*)?[^\\s\"'<>;,)]*\\.(?:aspx?|jspx?|php[345]?|phar|phtml|sh|py|pl|rb|so|dll|dylib|ashx|cer|asa)\\.?");

  private static final Pattern REMOTE_CONTENT_STREAM_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|config|configs|settings|debug|dump|select|stream|streams|content)(?:[;/]|/|$)");

  private static final Pattern REMOTE_CONTENT_STREAM_ENABLE =
      Pattern.compile(
          "(?is)(?:request\\s*dispatcher\\s*\\.\\s*request\\s*parsers\\s*\\.\\s*enable\\s*remote\\s*streaming|requestdispatcher\\.requestparsers\\.enableremotestreaming|enable\\s*remote\\s*streaming|enableremotestreaming|remote[_-]?streaming)\\s*[\"']?\\s*[:=]\\s*(?:true|1|yes)\\b");

  private static final Pattern REMOTE_IMPORT_SCRIPT_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|control|dataimport|datafile|import|imports|load|loads|manage|management|upload|viewdatafile|webtools)(?:[;/]|/|$)");

  private static final Pattern REPOSITORY_WEBROOT_WRITE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:_snapshot|snapshot|snapshots|backup|backups|repository|repositories|repo)(?:[;/]|/|$)");

  private static final Pattern PLOT_COMMAND_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:q|graph|graphs|plot|plots|chart|charts|render|query)(?:[;/]|/|$)");

  private static final Set<String> REMOTE_CONTENT_STREAM_URL_PARAMETERS =
      Set.of(
          "stream.url",
          "streamurl",
          "streamsource",
          "streamsourceurl",
          "contentstreamurl",
          "content.stream.url",
          "resource.stream.url");

  private static final Set<String> REMOTE_CONTENT_STREAM_CONFIG_PARAMETERS =
      Set.of("config", "body", "payload", "json", "data", "settings", "setproperty", "property");

  private static final Set<String> REMOTE_IMPORT_SOURCE_PARAMETERS =
      Set.of(
          "datafilelocation",
          "definitionlocation",
          "schemalocation",
          "templateurl",
          "templateuri",
          "template",
          "sourceurl",
          "sourceuri",
          "remoteurl",
          "dataurl",
          "fileurl",
          "url");

  private static final Set<String> REMOTE_IMPORT_TARGET_PARAMETERS =
      Set.of(
          "datafilesave",
          "savepath",
          "savefile",
          "targetpath",
          "targetfile",
          "outputpath",
          "outputfile",
          "destination",
          "dest",
          "path");

  private static final Set<String> REMOTE_IMPORT_URL_FLAG_PARAMETERS =
      Set.of("datafileisurl", "definitionisurl", "isurl", "remote", "fromurl", "urlinput");

  private static final Set<String> PLOT_COMMAND_PARAMETERS =
      Set.of("yrange", "y2range", "xrange", "x2range", "key");

  private static final Set<String> PLOT_CONTEXT_PARAMETERS =
      Set.of(
          "m",
          "start",
          "end",
          "wxh",
          "style",
          "grid",
          "json",
          "yrange",
          "y2range",
          "xrange",
          "x2range",
          "key");

  private RequestResourceDetector() {}

  static Optional<Detection> resource(RequestContext request) {
    Optional<RemoteContentStreamMatch> remoteContentStream = remoteContentStream(request);
    if (remoteContentStream.isPresent()) {
      RemoteContentStreamMatch match = remoteContentStream.orElseThrow();
      RequestContext redactedRequest = redactRemoteContentStreamRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_remote_content_stream",
              88,
              "Request enables or uses unsafe remote content streaming",
              redactedRequest,
              Map.of(
                  "mode", match.mode(),
                  "parameter", match.parameter(),
                  "scheme", match.scheme(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RemoteImportScriptWriteMatch> remoteImportScriptWrite =
        remoteImportScriptWrite(request);
    if (remoteImportScriptWrite.isPresent()) {
      RemoteImportScriptWriteMatch match = remoteImportScriptWrite.orElseThrow();
      RequestContext redactedRequest = redactRemoteImportScriptWriteRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_remote_import_script_write",
              90,
              "Request imports remote content into a server-side script target",
              redactedRequest,
              Map.of(
                  "sourceParameter", match.sourceParameter(),
                  "targetParameter", match.targetParameter(),
                  "targetType", match.targetType(),
                  "remoteSourceCount", String.valueOf(match.remoteSourceCount()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RepositoryWebrootWriteMatch> repositoryWebrootWrite =
        repositoryWebrootWrite(request);
    if (repositoryWebrootWrite.isPresent()) {
      RepositoryWebrootWriteMatch match = repositoryWebrootWrite.orElseThrow();
      RequestContext redactedRequest = redactRepositoryWebrootWriteRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_repository_webroot_write",
              90,
              "Request configures repository persistence into a web-executable location",
              redactedRequest,
              Map.of(
                  "targetParameter", match.targetParameter(),
                  "targetType", match.targetType(),
                  "locationType", match.locationType(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<PlotCommandInjectionMatch> plotCommandInjection = plotCommandInjection(request);
    if (plotCommandInjection.isPresent()) {
      PlotCommandInjectionMatch match = plotCommandInjection.orElseThrow();
      RequestContext redactedRequest = redactPlotCommandInjectionRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_plot_command_injection",
              90,
              "Request plotting parameter carries an interpreter command directive",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  private record RemoteContentStreamMatch(
      String mode, String parameter, String scheme, int sourceLength) {}

  private record RemoteImportScriptWriteMatch(
      String sourceParameter, String targetParameter, String targetType, int remoteSourceCount) {}

  private record RepositoryWebrootWriteMatch(
      String targetParameter, String targetType, String locationType, int valueLength) {}

  private record PlotCommandInjectionMatch(String parameter, int valueLength) {}

  private static Optional<RemoteContentStreamMatch> remoteContentStream(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    if (!request.parameters().isEmpty()) {
      for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
        if (!REMOTE_CONTENT_STREAM_URL_PARAMETERS.contains(normalizeParameterName(entry.getKey()))) {
          continue;
        }
        for (String value : entry.getValue()) {
          String scheme = unsafeContentStreamScheme(value);
          if (!scheme.isBlank()) {
            return Optional.of(
                new RemoteContentStreamMatch(
                    "stream-url", entry.getKey(), scheme, value == null ? 0 : value.length()));
          }
        }
      }
    }
    boolean controlPath =
        REMOTE_CONTENT_STREAM_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
            .find();
    if (!controlPath) {
      return Optional.empty();
    }
    if (request.body() != null && REMOTE_CONTENT_STREAM_ENABLE.matcher(request.body()).find()) {
      return Optional.of(
          new RemoteContentStreamMatch(
              "enable-config", "body", "remote-streaming", request.body().length()));
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      String normalizedName = normalizeParameterName(entry.getKey());
      boolean configParameter =
          REMOTE_CONTENT_STREAM_CONFIG_PARAMETERS.contains(normalizedName)
              || normalizedName.contains("config")
              || normalizedName.contains("setting");
      if (!configParameter) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (value != null && REMOTE_CONTENT_STREAM_ENABLE.matcher(value).find()) {
          return Optional.of(
              new RemoteContentStreamMatch(
                  "enable-config", entry.getKey(), "remote-streaming", value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static String unsafeContentStreamScheme(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    String inspected = percentDecode(value.trim());
    URI uri;
    try {
      uri = URI.create(inspected);
    } catch (IllegalArgumentException e) {
      return "";
    }
    String scheme = lower(uri.getScheme());
    if (scheme.isBlank()) {
      return "";
    }
    if (SSRF_PROTOCOLS.contains(scheme)) {
      return scheme;
    }
    if ((scheme.equals("http") || scheme.equals("https")) && NetworkHost.isInternal(NetworkHost.normalize(uri.getHost()))) {
      return scheme;
    }
    return "";
  }

  private static RequestContext redactRemoteContentStreamRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isRemoteContentStreamUrlName(name)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactRemoteContentStreamQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactRemoteContentStreamQuery(String query) {
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
      if (isRemoteContentStreamUrlName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static boolean isRemoteContentStreamUrlName(String name) {
    return REMOTE_CONTENT_STREAM_URL_PARAMETERS.contains(normalizeParameterName(name));
  }

  private static Optional<RemoteImportScriptWriteMatch> remoteImportScriptWrite(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    List<Map.Entry<String, String>> sources = remoteImportSources(request.parameters());
    if (sources.isEmpty()) {
      return Optional.empty();
    }
    Optional<Map.Entry<String, String>> target = remoteImportScriptTarget(request.parameters());
    if (target.isEmpty()) {
      return Optional.empty();
    }
    if (!remoteImportControlPath(request) && !hasRemoteImportUrlFlag(request.parameters())) {
      return Optional.empty();
    }
    Map.Entry<String, String> targetEntry = target.orElseThrow();
    return Optional.of(
        new RemoteImportScriptWriteMatch(
            sources.get(0).getKey(),
            targetEntry.getKey(),
            scriptTargetType(targetEntry.getValue()),
            sources.size()));
  }

  private static List<Map.Entry<String, String>> remoteImportSources(
      Map<String, List<String>> parameters) {
    var sources = new ArrayList<Map.Entry<String, String>>();
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!isRemoteImportSourceName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (!remoteImportSourceScheme(value).isBlank()) {
          sources.add(Map.entry(entry.getKey(), value));
        }
      }
    }
    return sources;
  }

  private static Optional<Map.Entry<String, String>> remoteImportScriptTarget(
      Map<String, List<String>> parameters) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!isRemoteImportTargetName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue()) {
        String normalized = normalizePath(value);
        if (HostFileMutationDetector.isScriptTarget(normalized)) {
          return Optional.of(Map.entry(entry.getKey(), value));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean remoteImportControlPath(RequestContext request) {
    return REMOTE_IMPORT_SCRIPT_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
        .find();
  }

  private static Optional<RepositoryWebrootWriteMatch> repositoryWebrootWrite(
      RequestContext request) {
    if (request == null || !request.active() || !repositoryWebrootMutatingMethod(request)) {
      return Optional.empty();
    }
    if (!REPOSITORY_WEBROOT_WRITE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
        .find()) {
      return Optional.empty();
    }
    Optional<String> scriptType = repositoryWebrootScriptTargetType(request);
    if (scriptType.isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, String> target : repositoryWebrootLocationTargets(request)) {
      if (repositoryWebDeploymentPath(target.getValue())) {
        return Optional.of(
            new RepositoryWebrootWriteMatch(
                target.getKey(),
                scriptType.orElseThrow(),
                "webroot",
                target.getValue() == null ? 0 : target.getValue().length()));
      }
    }
    return Optional.empty();
  }

  private static boolean repositoryWebrootMutatingMethod(RequestContext request) {
    String method = lower(request.method()).replaceAll("[^a-z]", "");
    return method.equals("put") || method.equals("post") || method.equals("patch");
  }

  private static List<Map.Entry<String, String>> repositoryWebrootLocationTargets(
      RequestContext request) {
    var targets = new ArrayList<Map.Entry<String, String>>();
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isRepositoryLocationName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value != null && !value.isBlank()) {
          targets.add(Map.entry(entry.getKey(), value));
        }
      }
    }
    if (jsonConfigBody(request)) {
      for (JsonStringField field : jsonStringFields(request.body())) {
        if (isRepositoryLocationName(field.name())
            && field.value() != null
            && !field.value().isBlank()) {
          targets.add(Map.entry("body." + field.name(), field.value()));
        }
      }
    }
    return List.copyOf(targets);
  }

  private static boolean isRepositoryLocationName(String name) {
    String normalized = normalizeParameterName(name);
    return normalized.equals("location")
        || normalized.equals("path")
        || normalized.equals("repositorylocation")
        || normalized.equals("repositorypath")
        || normalized.equals("repopath")
        || normalized.equals("repodir")
        || normalized.equals("basedir")
        || normalized.endsWith("location")
        || normalized.endsWith("path");
  }

  private static Optional<String> repositoryWebrootScriptTargetType(RequestContext request) {
    Optional<String> uriType = scriptFileType(request.uri());
    if (uriType.isPresent()) {
      return uriType;
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      Optional<String> nameType = scriptFileType(entry.getKey());
      if (nameType.isPresent()) {
        return nameType;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<String> valueType = scriptFileType(value);
        if (valueType.isPresent()) {
          return valueType;
        }
      }
    }
    if (jsonConfigBody(request)) {
      for (JsonStringField field : jsonStringFields(request.body())) {
        Optional<String> valueType = scriptFileType(field.value());
        if (valueType.isPresent()) {
          return valueType;
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<String> scriptFileType(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (String variant : decodedVariants(value)) {
      var matcher = SCRIPT_FILE_TOKEN.matcher(normalizePath(variant));
      while (matcher.find()) {
        String target = matcher.group();
        if (HostFileMutationDetector.isScriptTarget(normalizePath(target))) {
          return Optional.of(scriptTargetType(target));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean repositoryWebDeploymentPath(String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    String normalized = normalizePath(percentDecode(value));
    return normalized.contains("/webapps/")
        || normalized.endsWith("/webapps")
        || normalized.contains("/webroot/")
        || normalized.endsWith("/webroot")
        || normalized.contains("/wwwroot/")
        || normalized.endsWith("/wwwroot")
        || normalized.contains("/htdocs/")
        || normalized.endsWith("/htdocs")
        || normalized.contains("/public_html/")
        || normalized.endsWith("/public_html")
        || normalized.contains("/var/www/")
        || normalized.equals("/var/www")
        || normalized.startsWith("/var/www/")
        || normalized.contains("/srv/www/")
        || normalized.equals("/srv/www")
        || normalized.startsWith("/srv/www/")
        || normalized.contains("/usr/share/nginx/html");
  }

  private static boolean hasRemoteImportUrlFlag(Map<String, List<String>> parameters) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!isRemoteImportUrlFlagName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (isTruthy(value)) {
          return true;
        }
      }
    }
    return false;
  }

  private static String remoteImportSourceScheme(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    URI uri;
    try {
      uri = URI.create(percentDecode(value.trim()));
    } catch (IllegalArgumentException e) {
      return "";
    }
    String scheme = lower(uri.getScheme());
    return (scheme.equals("http") || scheme.equals("https") || scheme.equals("ftp")) ? scheme : "";
  }

  private static String scriptTargetType(String value) {
    String normalized = normalizePath(value);
    int dot = normalized.lastIndexOf('.');
    if (dot < 0 || dot == normalized.length() - 1) {
      return "script";
    }
    return normalized.substring(dot + 1);
  }

  private static boolean isRemoteImportSourceName(String name) {
    String normalized = normalizeParameterName(name);
    if (isRemoteImportUrlFlagName(name)) {
      return false;
    }
    return REMOTE_IMPORT_SOURCE_PARAMETERS.contains(normalized)
        || normalized.endsWith("location")
        || normalized.endsWith("url")
        || normalized.endsWith("uri");
  }

  private static boolean isRemoteImportTargetName(String name) {
    String normalized = normalizeParameterName(name);
    return REMOTE_IMPORT_TARGET_PARAMETERS.contains(normalized)
        || normalized.contains("save")
        || normalized.contains("target")
        || normalized.contains("destination")
        || normalized.contains("output");
  }

  private static boolean isRemoteImportUrlFlagName(String name) {
    String normalized = normalizeParameterName(name);
    return REMOTE_IMPORT_URL_FLAG_PARAMETERS.contains(normalized) || normalized.endsWith("isurl");
  }

  private static boolean isRemoteImportSensitiveName(String name) {
    return isRemoteImportSourceName(name) || isRemoteImportTargetName(name);
  }

  private static boolean isTruthy(String value) {
    String normalized = lower(value).trim();
    return normalized.equals("true")
        || normalized.equals("1")
        || normalized.equals("yes")
        || normalized.equals("y")
        || normalized.equals("on");
  }

  private static RequestContext redactRemoteImportScriptWriteRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isRemoteImportSensitiveName(name)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactRemoteImportScriptWriteQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactRemoteImportScriptWriteQuery(String query) {
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
      if (isRemoteImportSensitiveName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static RequestContext redactRepositoryWebrootWriteRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isRepositoryLocationName(name)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactRepositoryWebrootWriteQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactRepositoryWebrootWriteQuery(String query) {
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
      if (isRepositoryLocationName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<PlotCommandInjectionMatch> plotCommandInjection(
      RequestContext request) {
    if (request == null
        || !request.active()
        || request.parameters().isEmpty()
        || !plotCommandContext(request)) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isPlotCommandParameterName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (dangerousPlotCommandValue(value)) {
          return Optional.of(
              new PlotCommandInjectionMatch(entry.getKey(), value == null ? 0 : value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean plotCommandContext(RequestContext request) {
    String uri = request.uri() == null ? "" : request.uri();
    if (!PLOT_COMMAND_CONTROL_PATH.matcher(uri).find()) {
      return false;
    }
    int contextMarkers = 0;
    for (String name : request.parameters().keySet()) {
      if (PLOT_CONTEXT_PARAMETERS.contains(normalizeParameterName(name))) {
        contextMarkers++;
      }
    }
    return contextMarkers >= 2;
  }

  private static boolean isPlotCommandParameterName(String name) {
    return PLOT_COMMAND_PARAMETERS.contains(normalizeParameterName(name));
  }

  private static boolean dangerousPlotCommandValue(String value) {
    if (value == null || value.isBlank() || value.length() > 4096) {
      return false;
    }
    return HostFileMutationDetector.containsGeneratedOperation(percentDecode(value));
  }

  private static RequestContext redactPlotCommandInjectionRequest(RequestContext request) {
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
                    isPlotCommandParameterName(name) && dangerousPlotCommandValue(value)
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactPlotCommandInjectionQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactPlotCommandInjectionQuery(String query) {
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
      if (isPlotCommandParameterName(name) && dangerousPlotCommandValue(value)) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }
}
