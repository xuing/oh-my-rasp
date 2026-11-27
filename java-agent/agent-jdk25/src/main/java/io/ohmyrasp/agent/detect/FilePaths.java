package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.protocolOf;
import static io.ohmyrasp.agent.detect.RequestValues.bodyHasSinkValue;

import io.ohmyrasp.agent.file.HostReadPath;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.regex.Pattern;

/** Local path shapes and sensitive host locations shared by the file, URL, upload and request detectors. */
final class FilePaths {
  private FilePaths() {}

  static final String UNIX_READ_TARGET =
      "etc/(?:issue|passwd|shadow|apache2/apache2\\.conf)|proc/self/environ|root/\\.ssh|root/\\.bash_(?:history|profile)";

  static final String WINDOWS_READ_TARGET = "windows/system32/(?:inetsrv/metabase\\.xml|drivers/etc/hosts)";

  static final String PRIVATE_READ_NAME = "\\.bash_history|\\.zsh_history|\\.mysql_history|id_rsa";

  // Higher-level argument and URI detectors can receive a path fragment. Host opens have a native root.
  private static final Pattern DANGEROUS_FILE_READ = Pattern.compile("(?is)(?:^|/)(?:"
      + UNIX_READ_TARGET + "|" + WINDOWS_READ_TARGET + "|" + PRIVATE_READ_NAME + ")$");

  static final Pattern WINDOWS_ABSOLUTE_PATH = Pattern.compile("(?i)^[a-z]:/.*");

  static boolean requestControlsReadPath(String path, RequestContext request, boolean sensitive, boolean reportDirect) {
    String target = HostReadPath.inputName(path);
    for (List<String> values : request.inputParameters().values()) {
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

  static boolean sensitiveFileLocation(String normalized) {
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

  static boolean isAbsolutePathLike(String path) {
    return path.startsWith("/") || WINDOWS_ABSOLUTE_PATH.matcher(path).matches();
  }

  static boolean looksLikeApplicationSecretPath(String path) {
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

  static boolean containsParentSegment(String path) {
    for (String segment : path.split("/+")) {
      if (segment.equals("..")) {
        return true;
      }
    }
    return false;
  }
}
