package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizePath;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;

import io.ohmyrasp.agent.detect.RequestJson.JsonStringField;
import io.ohmyrasp.agent.file.ArchiveEntryContext;
import io.ohmyrasp.agent.file.EscapingPath;
import io.ohmyrasp.agent.file.HostDelete;
import io.ohmyrasp.agent.file.WindowsDataStream;
import io.ohmyrasp.agent.jmx.JmxWriteScope;
import io.ohmyrasp.agent.file.ScriptFileWrite;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/** Decisions on host write targets, generated output, archive extraction and removal. */
public final class HostFileMutationDetector {
  private HostFileMutationDetector() {}

  private static final Pattern GENERATED_SCRIPT_EXTENSION =
      Pattern.compile("(?is).+\\.(?:gnuplot|gp|plt|plot|cmd|sh|bash|ps1)$");

  private static final Pattern GENERATED_SCRIPT_EXEC_PRIMITIVE =
      Pattern.compile("(?is)(?:^|[^\\w])(system\\s*(?:\\(|[\"'])|exec\\s*\\(|shell\\s*\\(|`[^`]{1,240}`)");

  private static final Pattern SCRIPT_FILE =
      Pattern.compile("(?is).+\\.(?:aspx?|jspx?|php[345]?|phar|phtml|sh|py|pl|rb|so|dll|dylib|ashx|cer|asa)\\.?$");

  private static final Pattern CLEAN_FILE =
      Pattern.compile("(?is).+\\.(?:jpg|jpeg|png|gif|bmp|txt|rar|zip)$");

  public static Optional<Detection> detectJmxFileWrite(String path, JmxWriteScope scope,
      String api, RequestContext request) {
    if (!request.active() || scope == null) return Optional.empty();
    WindowsDataStream stream = java.io.File.separatorChar == '\\' ? WindowsDataStream.parse(path) : null;
    if (stream != null && !stream.name().isEmpty()) return Optional.empty();
    String file = stream == null ? path : stream.file();
    if (!SCRIPT_FILE.matcher(normalizePath(file)).matches() || !(scope.selects(path) || (stream != null && scope.selects(file))))
      return Optional.empty();
    boolean controlled = request.hasParameterIn(path) || (stream != null && request.hasParameterIn(file));
    return Optional.of(Detection.log("jmx", "jmx_file_write", controlled ? 100 : 90,
        "A managed operation opens its selected script destination for writing", request,
        Map.of("path", abbreviate(path), "mbean", abbreviate(scope.bean()), "operation", scope.operation(),
            "file_operation", api, "decision_basis", "selected_write_open", "requestControlled", String.valueOf(controlled))));
  }

  public static Optional<Detection> detectWindowsStreamWrite(WindowsDataStream stream, RequestContext request,
      List<String> stackClassNames, boolean namedStreamPolicy) {
    if (stream.name().isEmpty()) return detectFileWrite(stream.file(), request, stackClassNames);
    if (!namedStreamPolicy) return Optional.empty();
    return Optional.of(Detection.log("writeFile", "writeFile_NTFS", 70, "Windows requested a named data stream for writing",
        request, Map.of("path", abbreviate(stream.file()), "stream", abbreviate(stream.name()),
            "decision_basis", "named_data_stream")));
  }

  public static Optional<Detection> detectFileWrite(String path, RequestContext request) {
    return detectFileWrite(path, request, List.of());
  }

  public static Optional<Detection> detectFileWrite(
      String path, RequestContext request, List<String> stackClassNames) {
    String normalized = normalizePath(path);
    if (normalized.isBlank()) {
      return Optional.empty();
    }
    if ((normalized.endsWith(".jsp") || normalized.endsWith(".jspx"))
        && fileOperationFromDynamicCode(stackClassNames)) {
      return Optional.of(
          Detection.log(
              "writeFile",
              "writeFile_reflect",
              85,
              "Reflective stack wrote a JSP file",
              request,
              Map.of("path", normalized)));
    }
    Optional<String> configPersistence = configPersistenceFrame(stackClassNames);
    if (configPersistence.isPresent() && unsafeConfigPersistencePath(normalized)) {
      return Optional.of(
          Detection.log(
              "writeFile",
              "writeFile_config_path",
              85,
              "Runtime configuration persistence wrote to an unsafe path",
              request,
              Map.of(
                  "path", normalized,
                  "persistence", abbreviate(configPersistence.orElseThrow()))));
    }
    // Outside a request every line decides with the script-write rule of the backports.
    if (request.active() ? SCRIPT_FILE.matcher(normalized).matches() : ScriptFileWrite.protectedWrite(path)) {
      return Optional.of(
          Detection.log(
              "writeFile",
              "writeFile_script",
              90,
              "Server-side script file write detected",
              request,
              Map.of("path", normalized)));
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectArchiveExtraction(
      String entryName, String targetPath, RequestContext request) {
    return classifyArchiveExtraction(entryName, targetPath, request, null);
  }

  public static Optional<Detection> detectArchiveExtraction(
      ArchiveEntryContext.ChannelWrite open, RequestContext request) {
    return classifyArchiveExtraction(open.member, open.target, request, open.basis);
  }

  private static Optional<Detection> classifyArchiveExtraction(String member, String target, RequestContext request, String basis) {
    if (!EscapingPath.matches(member, target)) return Optional.empty();
    Map<String, String> details = basis == null
        ? Map.of("entry", abbreviate(member), "target", abbreviate(target))
        : Map.of("entry", abbreviate(member), "target", abbreviate(target), "decision_basis", basis);
    return Optional.of(Detection.log("archive", "archive_traversal", 95,
        "Archive extraction target escapes the intended directory", request, details));
  }

  public static Optional<Detection> detectFileDelete(String path, RequestContext request) {
    if (path == null || path.isEmpty()) return Optional.empty();
    try {
      return detectFileDelete(new HostDelete(Path.of(path), -1, false, false), request, false);
    } catch (java.nio.file.InvalidPathException invalid) {
      return Optional.empty();
    }
  }

  public static Optional<Detection> detectFileDelete(HostDelete entry, RequestContext request, boolean explicitPathPolicy) {
    if (!request.active()) return Optional.empty();
    HostDelete.Basis basis = HostDelete.Basis.NONE;
    for (List<String> values : request.inputParameters().values()) {
      for (String value : values) {
        HostDelete.Basis match = entry.match(value);
        if (match.ordinal() > basis.ordinal()) basis = match;
      }
    }
    if (basis != HostDelete.Basis.ESCAPING_ENTRY && !request.body().isEmpty()) {
      if (jsonConfigBody(request)) {
        for (JsonStringField field : jsonStringFields(request.body())) {
          HostDelete.Basis match = entry.match(field.value());
          if (match.ordinal() > basis.ordinal()) basis = match;
        }
      } else {
        HostDelete.Basis match = entry.match(request.body().trim());
        if (match.ordinal() > basis.ordinal()) basis = match;
      }
    }
    if (basis == HostDelete.Basis.NONE || (basis == HostDelete.Basis.REQUESTED_PATH_ONLY && !explicitPathPolicy))
      return Optional.empty();
    return Optional.of(Detection.log("deleteFile", "deleteFile_userinput", 85,
        "Request selected an entry for removal", request, Map.of("path", abbreviate(entry.path()),
            "decision_basis", basis.name().toLowerCase(java.util.Locale.ROOT))));
  }

  public static Optional<Detection> detectGeneratedScriptFileWrite(
      String path, String content, RequestContext request) {
    String normalized = normalizePath(path);
    if (normalized.isBlank() || content == null || content.isBlank() || !request.active()) {
      return Optional.empty();
    }
    if (!generatedScriptPath(normalized)) return Optional.empty();
    if (GENERATED_SCRIPT_EXTENSION.matcher(normalized).matches() || content.startsWith("#!")) {
      if (!GENERATED_SCRIPT_EXEC_PRIMITIVE.matcher(content).find()
          || (!request.hasParameterIn(content) && !request.hasParameterIn(path))) return Optional.empty();
    } else if (!requestSuppliesGeneratedOperation(content, request)) {
      return Optional.empty();
    }
    return Optional.of(
        Detection.log(
            "writeFile",
            "writeFile_generated_script",
            90,
            "Request-controlled generated script contains an interpreter execution primitive",
            request,
            Map.of("path", normalized, "content", abbreviate(content))));
  }

  private static boolean fileOperationFromDynamicCode(List<String> stack) {
    return fileOperationFromDynamicCode(stack, false);
  }

  private static boolean directoryApiFrame(String name) {
    return "java.io.File".equals(name) || "java.nio.file.Files".equals(name)
        || "sun.nio.fs.UnixFileSystemProvider".equals(name) || "sun.nio.fs.WindowsFileSystemProvider".equals(name)
        || "sun.nio.fs.UnixSecureDirectoryStream".equals(name);
  }

  static boolean fileOperationFromDynamicCode(List<String> stack, boolean directory) {
    if (stack == null || stack.isEmpty()) {
      return false;
    }
    int caller = 0;
    for (int i = 0; i < stack.size(); i++) {
      String frame = stack.get(i);
      if ("java.io.File".equals(frame) || "java.io.FileOutputStream".equals(frame)
          || "java.nio.file.Files".equals(frame) || (directory && directoryApiFrame(frame))) {
        caller = i + 1;
        while (caller < stack.size() && (frame.equals(stack.get(caller)) || (directory && directoryApiFrame(stack.get(caller))))) {
          caller++;
        }
        break;
      }
    }
    // Bootstrap and lifecycle methods often use reflection above an ordinary
    // application caller. Attribute reflective dispatch only at the file API.
    if (caller < stack.size() && isReflectionFrame(lower(stack.get(caller)))) {
      return true;
    }
    return stack.stream().anyMatch(frame -> isEvaluatedCodeFrame(lower(frame)));
  }

  private static boolean isEvaluatedCodeFrame(String name) {
    return name.contains("javax.script") || name.contains("springframework.expression")
        || name.contains("ognl") || name.contains("mvel") || name.contains("templatesimpl");
  }

  private static boolean isReflectionFrame(String name) {
    return name.contains("java.lang.reflect") || name.contains("sun.reflect")
        || name.contains("jdk.internal.reflect") || name.contains("generatedmethodaccessor");
  }

  private static Optional<String> configPersistenceFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    for (String frame : stackClassNames) {
      if (frame == null || frame.isBlank()) {
        continue;
      }
      String normalized = lower(frame).replace('/', '.');
      if (normalized.equals("org.apache.rocketmq.remoting.configuration")
          || normalized.equals("org.apache.rocketmq.common.mixall")) {
        return Optional.of(frame);
      }
    }
    return Optional.empty();
  }

  static boolean unsafeConfigPersistencePath(String normalizedPath) {
    if (normalizedPath == null || normalizedPath.isBlank()) {
      return false;
    }
    String normalized = normalizedPath.replace('\\', '/');
    return normalized.startsWith("/tmp/")
        || normalized.startsWith("/var/tmp/")
        || normalized.startsWith("/dev/shm/")
        || normalized.contains("/../")
        || normalized.contains("/.ssh/")
        || normalized.contains("/cron.")
        || normalized.contains("/cron/")
        || normalized.contains("/systemd/")
        || SCRIPT_FILE.matcher(normalized).matches();
  }

  private static boolean requestSuppliesGeneratedOperation(String content, RequestContext request) {
    var operations = GENERATED_SCRIPT_EXEC_PRIMITIVE.matcher(content);
    int cursor = 0;
    char quote = 0;
    boolean escape = false, comment = false;
    while (operations.find()) {
      int start = operations.start(1), end = operations.end(1);
      while (cursor < start) {
        char c = content.charAt(cursor++);
        if (comment) {
          if (c == '\n') comment = false;
        } else if (escape) {
          escape = false;
        } else if (c == '\\') {
          escape = true;
        } else if (quote != 0) {
          if (c == quote) quote = 0;
        } else if (c == '"' || c == '\'') {
          quote = c;
        } else if (c == '#') {
          comment = true;
        }
      }
      if (quote != 0 || comment || escape) continue;
      String operation = content.substring(start, end);
      String argument = generatedOperationArgument(content, start, end);
      for (List<String> values : request.inputParameters().values()) {
        for (String value : values) {
          if (value == null || value.isBlank()) continue;
          if (value.equals(argument)) return true;
          for (int offset = value.indexOf(operation); offset >= 0; offset = value.indexOf(operation, offset + 1)) {
            if (start >= offset && content.startsWith(value, start - offset)) return true;
          }
        }
      }
    }
    return false;
  }

  private static String generatedOperationArgument(String content, int start, int end) {
    if (content.charAt(start) == '`') return content.substring(start + 1, end - 1);
    int first = end - 1;
    if (content.charAt(first) == '(') {
      first++;
      while (first < content.length() && Character.isWhitespace(content.charAt(first))) first++;
    }
    if (first == content.length()) return "";
    char delimiter = content.charAt(first);
    if (delimiter != '"' && delimiter != '\'') {
      int stop = first;
      while (stop < content.length() && !Character.isWhitespace(content.charAt(stop))
          && ",);".indexOf(content.charAt(stop)) < 0) stop++;
      return content.substring(first, stop);
    }
    for (int at = first + 1; at < content.length(); at++) {
      char c = content.charAt(at);
      if (c == '\\') at++;
      else if (c == delimiter) return content.substring(first + 1, at);
    }
    return "";
  }

  /** An untyped temporary file can also be data. Require a copied operation in code position,
   * or a complete request-supplied operand to that operation. Never search unrelated fields for authority. */
  public static boolean generatedScriptCandidate(String path) {
    return generatedScriptPath(normalizePath(path));
  }

  private static boolean generatedScriptPath(String normalizedPath) {
    if (normalizedPath == null || normalizedPath.isBlank()) {
      return false;
    }
    String normalized = normalizedPath.replace('\\', '/');
    return normalized.startsWith("/tmp/")
        || normalized.startsWith("/var/tmp/")
        || normalized.startsWith("/dev/shm/")
        || normalized.contains("/cache/")
        || GENERATED_SCRIPT_EXTENSION.matcher(normalized).matches();
  }

  static boolean isScriptTarget(String normalized) { return SCRIPT_FILE.matcher(normalized).matches(); }

  static boolean containsGeneratedOperation(String value) { return GENERATED_SCRIPT_EXEC_PRIMITIVE.matcher(value).find(); }

  public static Optional<Detection> detectRename(String source, String destination, RequestContext request) {
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

  public static Optional<Detection> detectLink(
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

  public static Optional<Detection> detectWebshellFileWrite(
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
}
