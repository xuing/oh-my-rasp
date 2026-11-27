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
 * plugins TeamCity unpacks while it starts, the files Tomcat writes when it unpacks a WAR, and the classes Tomcat's
 * JSP compiler writes. Those two Tomcat exemptions rest on evidence an application cannot give by naming a class
 * ({@link #isContainerDeploymentWrite}). The path these decisions read has its {@code .} and {@code ..} segments
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

  // Tomcat's own classes: the operation that writes, and the container class that drives it.
  private static final String EXPAND_WAR = "org.apache.catalina.startup.ExpandWar";
  private static final String[] WAR_DEPLOYERS = {
    "org.apache.catalina.startup.HostConfig", "org.apache.catalina.startup.ContextConfig",
  };
  private static final String JASPER_COMPILER = "org.apache.jasper.compiler.Compiler";
  private static final String JASPER_JDT = "org.apache.jasper.compiler.JDTCompiler";
  private static final String[] JSP_DRIVERS = {
    "org.apache.jasper.JspCompilationContext", "org.apache.jasper.servlet.JspServletWrapper",
  };
  private static final String WEBAPP_LOADER = "org.apache.catalina.loader.WebappClassLoaderBase";

  /** The classes on this thread's stack, outermost last. */
  private static final class Frames extends SecurityManager {
    Class<?>[] classes() {
      return getClassContext();
    }
  }

  private static final Frames FRAMES = new Frames();

  /**
   * Tomcat unpacking a WAR or compiling a JSP on this thread, on evidence an application cannot fake by naming a
   * class:
   *
   * <ul>
   *   <li>the operation: a frame of {@code ExpandWar.expand} with {@code HostConfig} or {@code ContextConfig} below
   *       it; or Jasper's {@code Compiler.compile} or {@code JDTCompiler.generateClass} with
   *       {@code JspCompilationContext} or {@code JspServletWrapper} below it;
   *   <li>who defined it: every class of those names on the stack is defined by one class loader, the container's,
   *       which is not a web application's loader ({@code WebappClassLoaderBase}) and has none among its parents;
   *   <li>where it writes: {@code resolved} (no {@code .} or {@code ..} left) is under the container's base directory
   *       ({@code catalina.base}, which standalone and embedded Tomcat both set), and a JSP compile writes a
   *       {@code .class} under its {@code work} directory.
   * </ul>
   */
  static boolean isContainerDeploymentWrite(String resolved) {
    String base = containerBase();
    if (base == null || !resolved.startsWith(base)) {
      return false;
    }
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    boolean war = onStack(stack, EXPAND_WAR, "expand") && anyOnStack(stack, WAR_DEPLOYERS);
    boolean jsp = (onStack(stack, JASPER_COMPILER, "compile") || onStack(stack, JASPER_JDT, "generateClass"))
        && anyOnStack(stack, JSP_DRIVERS);
    if (jsp && !war && !(resolved.startsWith(base + "work/") && resolved.toLowerCase(Locale.ROOT).endsWith(".class"))) {
      return false;
    }
    if (!war && !jsp) {
      return false;
    }
    String[] names = war ? new String[] {EXPAND_WAR, WAR_DEPLOYERS[0], WAR_DEPLOYERS[1]}
        : new String[] {JASPER_COMPILER, JASPER_JDT, JSP_DRIVERS[0], JSP_DRIVERS[1]};
    return definedByOneContainerLoader(FRAMES.classes(), names);
  }

  /** {@code catalina.base} resolved, with a trailing slash; null when it is not set or not absolute. */
  private static String containerBase() {
    String base;
    try {
      base = System.getProperty("catalina.base");
    } catch (SecurityException denied) {
      return null;
    }
    if (base == null) {
      return null;
    }
    String resolved = resolve(normalize(base));
    if (!resolved.startsWith("/") && !(resolved.length() > 2 && resolved.charAt(1) == ':')) {
      return null;
    }
    return resolved.endsWith("/") ? resolved : resolved + "/";
  }

  private static boolean onStack(StackTraceElement[] stack, String className, String method) {
    for (int i = 0; i < stack.length; i++) {
      if (className.equals(stack[i].getClassName()) && method.equals(stack[i].getMethodName())) {
        return true;
      }
    }
    return false;
  }

  private static boolean anyOnStack(StackTraceElement[] stack, String[] classNames) {
    for (int i = 0; i < stack.length; i++) {
      for (int j = 0; j < classNames.length; j++) {
        if (classNames[j].equals(stack[i].getClassName())) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Whether every class on the stack named one of {@code names} is defined by the same loader, which is neither a web
   * application's loader nor below one. A class an application defines with one of those names, in its own loader or
   * in a loader it creates under its web application, does not pass.
   */
  private static boolean definedByOneContainerLoader(Class<?>[] classes, String[] names) {
    if (classes == null) {
      return false;
    }
    ClassLoader container = null;
    boolean found = false;
    for (int i = 0; i < classes.length; i++) {
      Class<?> type = classes[i];
      if (type == null || !contains(names, type.getName())) {
        continue;
      }
      ClassLoader loader = type.getClassLoader();
      if (loader == null || (found && loader != container)) {
        return false;
      }
      container = loader;
      found = true;
    }
    if (!found) {
      return false;
    }
    for (ClassLoader loader = container; loader != null; loader = loader.getParent()) {
      for (Class<?> type = loader.getClass(); type != null; type = type.getSuperclass()) {
        if (WEBAPP_LOADER.equals(type.getName())) {
          return false;
        }
      }
    }
    return true;
  }

  private static boolean contains(String[] values, String value) {
    for (int i = 0; i < values.length; i++) {
      if (values[i].equals(value)) {
        return true;
      }
    }
    return false;
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
