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
 * plugins TeamCity unpacks while it starts, the files Tomcat writes when it unpacks a WAR into its web root, and
 * the classes Tomcat's JSP compiler writes.
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
    if (isWebInfDeploymentArtifact(normalized)
        || isTeamCityPluginStartupWrite(normalized)
        || isMavenRepositoryArtifactWrite(normalized)) {
      return false;
    }
    if (!WEBROOT_PATH.matcher(normalized).find() && normalized.indexOf("../") < 0) {
      return false;
    }
    return !isTomcatDeploymentStack();
  }

  /** Tomcat unpacking a WAR ({@code ExpandWar}) or compiling a JSP (Jasper) on this thread. */
  private static boolean isTomcatDeploymentStack() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (int i = 0; i < stack.length; i++) {
      String className = stack[i].getClassName();
      if ("org.apache.catalina.startup.ExpandWar".equals(className)
          || "org.apache.jasper.compiler.Compiler".equals(className)
          || "org.apache.jasper.compiler.JDTCompiler".equals(className)) {
        return true;
      }
    }
    return false;
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
