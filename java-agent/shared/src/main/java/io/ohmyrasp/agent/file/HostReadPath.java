package io.ohmyrasp.agent.file;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;

/** Host file policy uses the default filesystem's namespace and path syntax. */
public final class HostReadPath {
  private static volatile FileSystem nativeProviderFileSystem;

  private static final ThreadLocal<Facade> FACADES = new ThreadLocal<Facade>();

  private static final class Facade {
    final String path;
    final Facade parent;
    String reported;
    boolean opened;
    Facade(String path, Facade parent) { this.path = path; this.parent = parent; }
  }

  public static void beginFacade(Object path) {
    Facade parent = FACADES.get();
    boolean fallback = needsFacadeRead(path);
    if (fallback || parent != null) {
      FACADES.set(new Facade(fallback ? String.valueOf(path) : null, parent));
    }
  }

  public static void endFacade() {
    Facade current = FACADES.get();
    if (current == null) return;
    if (current.parent == null) FACADES.remove();
    else FACADES.set(current.parent);
  }

  /** Only suppress a repeated log inside the same still-active facade operation. */
  private static Facade matchingFacade(String path) {
    Facade first = null;
    for (Facade scope = FACADES.get(); scope != null; scope = scope.parent) {
      if (path.equals(scope.path)) first = scope;
    }
    return first;
  }

  public static boolean repeated(String path, String algorithm) {
    Facade first = matchingFacade(path);
    if (first == null) return false;
    boolean repeat = algorithm.equals(first.reported);
    first.reported = algorithm;
    return repeat;
  }

  private HostReadPath() {}

  /** A callback from an executed native-channel hook confirms coverage for this filesystem. */
  public static boolean nativeRead(Path path, boolean read, int directoryFd) {
    FileSystem fs = path.getFileSystem();
    if (nativeProviderFileSystem != fs) nativeProviderFileSystem = fs;
    // A relative openat path is rooted at its directory descriptor, not the process working directory.
    if (!read || (directoryFd >= 0 && !path.isAbsolute())) return false;
    if (FACADES.get() != null) {
      Facade facade = matchingFacade(path.toString());
      if (facade != null) {
        if (facade.opened) facade.reported = null;
        facade.opened = true;
      }
    }
    return true;
  }

  public static boolean needsFacadeRead(Object value) {
    if (!(value instanceof Path)) return true;
    FileSystem fs = ((Path) value).getFileSystem();
    return fs == FileSystems.getDefault() && fs != nativeProviderFileSystem;
  }

  public static boolean isHostPath(Object value) {
    return HostFileSystem.contains(value);
  }

  public static String location(String path) {
    if (path == null || path.isEmpty()) return "";
    try {
      return policyName(Paths.get(path).toAbsolutePath().normalize());
    } catch (InvalidPathException | SecurityException invalid) {
      return "";
    }
  }

  private static String policyName(Path path) {
    String name = path.toString();
    return File.separatorChar == '\\' ? name.replace('\\', '/').toLowerCase(Locale.ROOT) : name;
  }

  /** Resolution applies only to an actual open after correlating the path with request input. */
  public enum OpenPolicy {
    PATH_ONLY, FOLLOW, NOFOLLOW_FINAL;

    public String resolvedLocation(String path) {
      if (this == PATH_ONLY) return "";
      try {
        Path opened = Paths.get(path);
        // NOFOLLOW_LINKS at open leaves symlinks in parent directories effective.
        if (this == NOFOLLOW_FINAL && Files.isSymbolicLink(opened)) return "";
        return policyName(opened.toRealPath());
      } catch (IOException | InvalidPathException | SecurityException unavailable) {
        return "";
      }
    }
  }

  public static String inputName(String name) {
    if (name == null) return "";
    return File.separatorChar == '\\' ? name.replace('\\', '/') : name;
  }

  /** Removing a parent component can change the target if the preceding component is a symlink.
   * Only check a path already selected for a location-based decision at the file operation. */
  public static boolean confirmsLocation(String path) {
    if (path == null || !path.contains("..")) return true;
    try {
      Path actual = Paths.get(path);
      return !hasParentComponent(actual) || Files.isSameFile(actual, actual.toAbsolutePath().normalize());
    } catch (IOException | InvalidPathException | SecurityException unavailable) {
      return false;
    }
  }

  private static boolean hasParentComponent(Path path) {
    for (Path component : path) {
      if (component.toString().equals("..")) return true;
    }
    return false;
  }

  private static final java.util.regex.Pattern PROTECTED_HOST_FILE =
      java.util.regex.Pattern.compile(
          "^/(?:etc/(?:passwd|shadow|issue)|proc/self/(?:environ|cmdline)|root/\\.ssh/(?:id_rsa|authorized_keys)|home/[^/]+/\\.ssh/id_rsa)$");

  /**
   * Whether {@code location} (a {@link #location}) is a host file every line blocks a read of, inside or outside an
   * HTTP request: account databases, the process environment and command line, SSH keys.
   */
  public static boolean isProtectedHostFile(String location) {
    return location != null && PROTECTED_HOST_FILE.matcher(location).matches();
  }

  public static boolean isHostsFile(String location) {
    if (File.separatorChar == '/') return "/etc/hosts".equals(location);
    if (!location.endsWith("/system32/drivers/etc/hosts")) return false;
    try {
      String systemRoot = System.getenv("SystemRoot");
      return systemRoot != null && location.equals(location(systemRoot) + "/system32/drivers/etc/hosts");
    } catch (SecurityException unavailable) {
      return false;
    }
  }

  public static boolean selected(String path, List<String> inputs) {
    if (inputs == null || inputs.isEmpty() || path == null || path.isEmpty()) return false;
    Path opened = null;
    for (String value : inputs) {
      if (!EscapingPath.mayEscape(value)) continue;
      try {
        if (opened == null) opened = Paths.get(path);
        Path supplied = Paths.get(value);
        if (supplied.isAbsolute()) {
          Path absolute = opened.toAbsolutePath();
          if (supplied.equals(absolute)) return true;
          // Only the opened path is ever inspected on disk. Parent components in the
          // supplied value cannot establish where a different spelling would resolve.
          if (!hasParentComponent(supplied) && absolute.normalize().equals(supplied.normalize())
              && confirmsLocation(path)) return true;
        } else if (supplied.normalize().startsWith("..") && opened.endsWith(supplied)) {
          return true;
        }
      } catch (InvalidPathException | SecurityException ignored) {
        // No verifiable native path match.
      }
    }
    return false;
  }
}
