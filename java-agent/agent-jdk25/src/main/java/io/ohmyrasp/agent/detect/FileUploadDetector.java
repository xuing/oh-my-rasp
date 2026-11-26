package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.containsPathToken;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizePath;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.FilePaths.containsParentSegment;
import static io.ohmyrasp.agent.detect.HostFileMutationDetector.unsafeConfigPersistencePath;
import static io.ohmyrasp.agent.detect.RequestDecoding.addVariant;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodeUnicodeEscapes;
import static io.ohmyrasp.agent.detect.RequestDecoding.decodedVariants;
import static io.ohmyrasp.agent.detect.RequestExpressionDetector.dangerousParserHeaderExpression;
import static io.ohmyrasp.agent.detect.RequestExpressionDetector.dangerousRequestExpressionValue;
import static io.ohmyrasp.agent.detect.RequestExpressionDetector.requestExpressionParameterEngine;

import io.ohmyrasp.agent.http.ArchiveUploadPolicy;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Uploaded file names and WebDAV move or copy destinations. */
public final class FileUploadDetector {
  private FileUploadDetector() {}

  private static final Pattern HTML_FILE = Pattern.compile("(?is).+\\.(?:htm|html|js)$");

  private static final Pattern EXECUTABLE_FILE =
      Pattern.compile("(?is).+\\.(?:exe|dll|scr|vbs|cmd|bat)$");

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

  public static Optional<Detection> deniedArchiveUpload(String filename, RequestContext request, ArchiveUploadPolicy.Decision decision) {
    String basis = decision.denialBasis();
    if (basis == null || !ArchiveUploadPolicy.isArchive(filename)) return Optional.empty();
    return Optional.of(Detection.log("fileUpload", "fileUpload_java_archive", 90,
        "Java archive upload conflicts with the application's deployment policy", request,
        Map.of("filename", normalizePath(filename), "decision_basis", basis)));
  }

  public static Optional<Detection> detectFileUpload(String filename, RequestContext request) {
    return detectFileUpload(filename, request, ArchiveUploadPolicy.Decision.UNSPECIFIED, false);
  }

  public static Optional<Detection> detectFileUpload(
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

  public static Optional<Detection> detectWebdavUpload(
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
}
