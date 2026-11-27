package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.extensionOf;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizePath;
import static io.ohmyrasp.agent.detect.DetectorStrings.protocolOf;
import static io.ohmyrasp.agent.detect.FilePaths.PRIVATE_READ_NAME;
import static io.ohmyrasp.agent.detect.FilePaths.UNIX_READ_TARGET;
import static io.ohmyrasp.agent.detect.FilePaths.WINDOWS_READ_TARGET;
import static io.ohmyrasp.agent.detect.FilePaths.containsParentSegment;
import static io.ohmyrasp.agent.detect.FilePaths.isAbsolutePathLike;
import static io.ohmyrasp.agent.detect.FilePaths.looksLikeApplicationSecretPath;
import static io.ohmyrasp.agent.detect.FilePaths.requestControlsReadPath;
import static io.ohmyrasp.agent.detect.FilePaths.sensitiveFileLocation;
import static io.ohmyrasp.agent.detect.HostFileMutationDetector.fileOperationFromDynamicCode;
import static io.ohmyrasp.agent.detect.RequestDecoding.PROTECTED_WEBAPP_RESOURCE;
import static io.ohmyrasp.agent.detect.RequestDecoding.collapsePathDotSegments;
import static io.ohmyrasp.agent.detect.RequestDecoding.hasConfusingDotSegment;
import static io.ohmyrasp.agent.detect.RequestDecoding.pathVariants;
import static io.ohmyrasp.agent.detect.RequestDecoding.protectedWebappResource;
import static io.ohmyrasp.agent.detect.RequestDecoding.stripServletPathParameters;
import static io.ohmyrasp.agent.detect.RequestValues.bodyHasSinkValue;

import io.ohmyrasp.agent.file.HostDirectory;
import io.ohmyrasp.agent.file.HostReadPath;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Local file access: reads, directory listings, @file argument expansion, includes and forged include attributes. */
public final class FileAccessDetector {
  private FileAccessDetector() {}

  private static final Pattern SENSITIVE_HOST_READ = Pattern.compile("^(?:/(?:" + UNIX_READ_TARGET
      + ")|[a-z]:/" + WINDOWS_READ_TARGET + "|(?:.*/)?(?:" + PRIVATE_READ_NAME + "))$");

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

  public static Optional<Detection> detectServletIncludeAttributes(
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

  public static Optional<Detection> detectArgumentFileExpansion(
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

  public static Optional<Detection> detectFileRead(String path, RequestContext request, boolean xmlParserStack) {
    return detectFileRead(path, request, xmlParserStack, false);
  }

  public static Optional<Detection> detectFileRead(String path, RequestContext request, boolean xmlParserStack,
      boolean includeLocationPolicy) {
    return detectFileRead(path, request, () -> xmlParserStack, includeLocationPolicy);
  }

  public static Optional<Detection> detectFileRead(String path, RequestContext request,
      java.util.function.BooleanSupplier xmlParserStack, boolean includeLocationPolicy) {
    return detectFileRead(path, request, xmlParserStack, includeLocationPolicy, HostReadPath.OpenPolicy.PATH_ONLY);
  }

  public static Optional<Detection> detectFileRead(String path, RequestContext request,
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
      // Outside a request every line decides with the protected host files of the backport rule.
      if (HostReadPath.isProtectedHostFile(location) && HostReadPath.confirmsLocation(path)) {
        return Optional.of(Detection.log(
            "readFile", "readFile_unwanted", 85, "Sensitive local file read detected", request, Map.of("path", location)));
      }
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

  public static Optional<Detection> detectDirectoryList(String path, RequestContext request) {
    return detectDirectoryList(path, request, List.of());
  }

  public static Optional<Detection> detectDirectoryList(
      String path, RequestContext request, List<String> stackClassNames) {
    return directoryListings(path, request, null, false, false, false, algorithm -> false, () -> stackClassNames)
        .stream().findFirst();
  }

  public static boolean requestSelectsDirectory(String path, RequestContext request, boolean descriptorRelative) {
    return request.active() && (request.parameters().values().stream()
        .anyMatch(values -> HostDirectory.selected(path, values, descriptorRelative)) || bodyHasSinkValue(request, path));
  }

  public static List<Detection> directoryListings(String path, RequestContext request, java.nio.file.DirectoryStream<?> opened,
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

  public static Optional<Detection> detectInclude(
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

  private record IncludeAttributeTarget(String type, String resource) {}

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
}
