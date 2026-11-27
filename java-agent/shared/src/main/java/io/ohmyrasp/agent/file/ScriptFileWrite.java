package io.ohmyrasp.agent.file;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The write of a server-side script or executable that every agent line blocks wherever it happens: a script,
 * archive or class file in a web root, or behind a {@code ../} segment. The backport lines decide every file write
 * with it; the primary decides with it the writes made outside an HTTP request (inside one it has its own rule).
 *
 * <p>Benign writes that match the shape are left alone: class files and JARs a deployment puts under
 * {@code WEB-INF/classes} or {@code WEB-INF/lib}, JARs a build tool stores in a local Maven repository, the
 * plugins TeamCity unpacks while it starts, the files Tomcat writes into a docBase while it unpacks the WAR there, and
 * the classes Jasper writes into a JSP's output directory while it compiles the JSP. Those two Tomcat exemptions rest on
 * the operation itself, observed as it runs, and on the directory it reports ({@link #isContainerDeploymentWrite}). The path these decisions read has its {@code .} and {@code ..} segments
 * resolved, so {@code WEB-INF/classes/../../shell.class} is not a deployment artifact.
 *
 * <p>Java 8 source with no lambdas: the backport lines call it from their hooks.
 */
public final class ScriptFileWrite {
  private static final Pattern SCRIPT_FILE =
      Pattern.compile(
          "(?i).+\\.(?:jsp|jspx|jspf|war|class|jar|php|asp|aspx|ashx|cer|asa|sh|bash|cmd|bat|ps1)$");
  private static final Pattern WEBROOT_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:webapps?|webroot|ROOT|www|wwwroot|htdocs|html|public|static|uploads?)(?:/|$)");

  private ScriptFileWrite() {}

  /** Whether {@code path} names a script, archive or class file (by its extension). */
  public static boolean isScriptFile(String path) {
    return path != null && SCRIPT_FILE.matcher(path).matches();
  }

  /** Whether writing {@code path} is a protected script write; {@code path} as the hook saw it. */
  public static boolean protectedWrite(String path) {
    String normalized = normalize(path);
    if (normalized.length() == 0 || !isScriptFile(normalized)) {
      return false;
    }
    String resolved = resolve(normalized);
    if (isWebInfDeploymentArtifact(resolved)
        || isTeamCityPluginStartupWrite(resolved)
        || isMavenRepositoryArtifactWrite(resolved)) {
      return false;
    }
    if (!WEBROOT_PATH.matcher(normalized).find() && normalized.indexOf("../") < 0) {
      return false;
    }
    return !isContainerDeploymentWrite(resolved);
  }

  /**
   * Tomcat unpacking a WAR into {@code resolved}'s docBase, or Jasper compiling a JSP's class into its output
   * directory, on this thread: the operation itself reports the directory it writes, read from the container's own
   * objects when it starts, and only a path under that directory is exempt ({@link ContainerDeployment}). Neither a
   * class name on the stack nor the container's base directory is evidence.
   */
  static boolean isContainerDeploymentWrite(String resolved) {
    return ContainerDeployment.covers(resolved);
  }

  /** {@code normalized} (slashes only) with its {@code .} and {@code ..} segments resolved, as text. */
  static String resolve(String normalized) {
    if (normalized.indexOf("/.") < 0 && !normalized.startsWith(".")) {
      return normalized;
    }
    boolean absolute = normalized.startsWith("/");
    String[] segments = normalized.split("/");
    String[] kept = new String[segments.length];
    int count = 0;
    int leadingParents = 0;
    for (int i = 0; i < segments.length; i++) {
      String segment = segments[i];
      if (segment.length() == 0 || ".".equals(segment)) {
        continue;
      }
      if ("..".equals(segment)) {
        if (count > leadingParents) {
          count--;
        } else if (!absolute) {
          kept[count++] = segment;
          leadingParents++;
        }
        continue;
      }
      kept[count++] = segment;
    }
    StringBuilder out = new StringBuilder(normalized.length());
    if (absolute) {
      out.append('/');
    }
    for (int i = 0; i < count; i++) {
      if (i > 0) {
        out.append('/');
      }
      out.append(kept[i]);
    }
    return out.toString();
  }

  /** {@code path} trimmed, with backslashes as slashes and no doubled slash. */
  public static String normalize(String path) {
    if (path == null) {
      return "";
    }
    String normalized = path.trim().replace('\\', '/');
    while (normalized.indexOf("//") >= 0) {
      normalized = normalized.replace("//", "/");
    }
    return normalized;
  }

  private static boolean isWebInfDeploymentArtifact(String normalized) {
    String lower = normalized.toLowerCase(Locale.ROOT);
    if (!(lower.indexOf("/web-inf/classes/") >= 0
        || lower.indexOf("/web-inf/cfclasses/") >= 0
        || lower.indexOf("/web-inf/lib/") >= 0)) {
      return false;
    }
    return lower.endsWith(".class") || lower.endsWith(".jar");
  }

  private static boolean isMavenRepositoryArtifactWrite(String normalized) {
    String lower = normalized.toLowerCase(Locale.ROOT);
    return lower.indexOf("/.m2/repository/") >= 0
        && lower.indexOf("../") < 0
        && lower.endsWith(".jar");
  }

  private static boolean isTeamCityPluginStartupWrite(String normalized) {
    String lowerPath = normalized.toLowerCase(Locale.ROOT);
    if (!isTeamCityPluginStartupWritePath(lowerPath)) {
      return false;
    }
    boolean startupStack = false;
    boolean bundledPluginUnpackStack = false;
    boolean pluginResourceUnpackStack = false;
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (StackTraceElement element : stack) {
      String className = element.getClassName();
      if ("jetbrains.buildServer.plugins.files.PluginFilesUtil".equals(className)
          || className.startsWith("jetbrains.buildServer.web.plugins.files.")) {
        bundledPluginUnpackStack = true;
      }
      if ("jetbrains.buildServer.util.ArchiveUtil".equals(className)
          || "jetbrains.buildServer.web.impl.Unpacker".equals(className)
          || "jetbrains.buildServer.web.impl.WatchingResourceUnpackerState".equals(className)
          || "jetbrains.buildServer.web.impl.InitializingResourceUnpacker".equals(className)
          || "jetbrains.buildServer.web.impl.WebResourcesUnpacker".equals(className)) {
        pluginResourceUnpackStack = true;
      }
      if ("jetbrains.buildServer.web.impl.BuildServerConfigurator".equals(className)
          || "jetbrains.buildServer.serverSide.impl.BuildServerLifecycleProcessor"
              .equals(className)
          || className.startsWith("jetbrains.buildServer.maintenance.StartupProcessor")) {
        startupStack = true;
      }
    }
    return startupStack && (bundledPluginUnpackStack || pluginResourceUnpackStack);
  }

  private static boolean isTeamCityPluginStartupWritePath(String lowerPath) {
    if (lowerPath.endsWith(".jar") && lowerPath.indexOf("/web-inf/plugins/.unpacked/") >= 0) {
      return true;
    }
    return lowerPath.indexOf("/webapps/root/plugins/") >= 0 && isScriptFile(lowerPath);
  }
}
