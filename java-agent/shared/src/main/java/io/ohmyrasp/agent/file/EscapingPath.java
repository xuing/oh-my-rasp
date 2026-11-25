package io.ohmyrasp.agent.file;

import java.io.File;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Matches an untrusted absolute or escaping relative path against a local filesystem sink. */
public final class EscapingPath {
  private EscapingPath() {}

  public static boolean mayEscape(String name) {
    if (name == null || name.isEmpty()) {
      return false;
    }
    char first = name.charAt(0);
    return first == '/' || first == '\\' || name.contains("..")
        || (File.separatorChar == '\\' && name.length() > 1 && name.charAt(1) == ':');
  }

  public static boolean matches(String name, String target) {
    if (!mayEscape(name) || target == null || target.isEmpty()) {
      return false;
    }
    try {
      Path output = Paths.get(target);
      if (matchesPath(Paths.get(name), output)) {
        return true;
      }
      // Some extractors translate archive separators. The actual sink must
      // exhibit that translation; on Unix a literal backslash can be filename data.
      return File.separatorChar == '/' && name.indexOf('\\') >= 0
          && matchesPath(Paths.get(name.replace('\\', '/')), output);
    } catch (InvalidPathException | SecurityException ignored) {
      return false;
    }
  }

  static boolean matchesPath(Path entry, Path output) {
    if (entry.isAbsolute()) {
      return output.equals(entry);
    }
    // Preserve the parent segments at the write so the extraction directory
    // and the corresponding member can still be distinguished.
    if (!entry.normalize().startsWith("..") || !output.endsWith(entry)) {
      return false;
    }
    Path absolute = output.toAbsolutePath();
    Path directory = absolute;
    for (int i = 0; i < entry.getNameCount() && directory != null; i++) {
      directory = directory.getParent();
    }
    return directory != null && !absolute.normalize().startsWith(directory.normalize());
  }
}
