package io.ohmyrasp.agent.file;

import io.ohmyrasp.agent.hook.HookActivation;
import java.io.File;
import java.util.Locale;

/**
 * The directory a Tomcat deployment operation is writing, on the thread that runs it, as the container's own objects
 * report it. {@link ContainerDeploymentVisitor} makes two of Tomcat's methods enter a scope here on entry and leave it
 * on every way out:
 *
 * <ul>
 *   <li>{@code org.apache.catalina.startup.ExpandWar.expand(Host, URL, String)}, which unpacks a WAR into
 *       {@code new File(host.getAppBaseFile(), pathname)}: the scope's root is that docBase;
 *   <li>Jasper's {@code org.apache.jasper.compiler.Compiler.compile(boolean, boolean)}, which writes a JSP's
 *       generated source and classes into its context's output directory
 *       ({@code JspCompilationContext.getOutputDir()}): the scope's root is that directory, for {@code .class} and
 *       {@code .java} files only.
 * </ul>
 *
 * <p>The scope gets a root only when the call is the container's own operation: the instrumented class has its Tomcat
 * name and is defined by a class loader that is not a web application's ({@code WebappClassLoaderBase} or a subclass)
 * and has none among its parents; its frame is the one that entered the scope, and its caller is defined by the same
 * loader (Tomcat's {@code ContextConfig}, {@code JspCompilationContext} or {@code JspC}), so neither an application
 * calling this class nor one calling the container method directly gets a root; the {@code Host} or
 * {@code JspCompilationContext} it reads is an instance of that type as the instrumented class's own loader defines
 * it, with a class from a loader that passes the same test. Anything else, a reflection failure included, enters a
 * scope without a root, which also hides an outer scope's root while it runs. {@link ScriptFileWrite} reads only the
 * innermost scope of the current thread ({@link #covers}), so a thread the operation starts has no root.
 *
 * <p>The three entries injected code calls do nothing while the hooks are off ({@link HookActivation}), and
 * {@link #covers} then grants nothing. The hooks turn on once and off once: an operation that was running when
 * they turned off never pops its scope, and that scope is never read again.
 *
 * <p>Java 8 source with no lambdas: the backport lines carry it. No method throws.
 */
public final class ContainerDeployment {
  static final String EXPAND_WAR = "org.apache.catalina.startup.ExpandWar";
  static final String COMPILER = "org.apache.jasper.compiler.Compiler";
  private static final String HOST = "org.apache.catalina.Host";
  private static final String COMPILATION_CONTEXT = "org.apache.jasper.JspCompilationContext";
  private static final String WEBAPP_LOADER = "org.apache.catalina.loader.WebappClassLoaderBase";

  private static final ThreadLocal<Scope> SCOPES = new ThreadLocal<Scope>();
  private static final Frames FRAMES = frames();

  private ContainerDeployment() {}

  /** One entered operation: the roots it may write under (null when it was not verified) and its outer scope. */
  private static final class Scope {
    final String[] roots;
    final boolean classesOnly;
    final Scope parent;

    Scope(String[] roots, boolean classesOnly, Scope parent) {
      this.roots = roots;
      this.classesOnly = classesOnly;
      this.parent = parent;
    }
  }

  /** The classes of this thread's frames, innermost first. */
  private static final class Frames extends SecurityManager {
    Class<?>[] classes() {
      return getClassContext();
    }
  }

  private static Frames frames() {
    try {
      return new Frames();
    } catch (Throwable denied) {
      return null;
    }
  }

  /** On entry to {@code ExpandWar.expand(host, war, pathname)}; {@code owner} is the instrumented class. */
  public static void enterWarExpand(Class<?> owner, Object host, String pathname) {
    if (HookActivation.inactive()) return;
    String[] roots;
    try {
      roots = warRoots(owner, host, pathname);
    } catch (Throwable failure) {
      roots = null;
    }
    push(roots, false);
  }

  /** On entry to {@code Compiler.compile(boolean, boolean)}; {@code compiler} is its receiver. */
  public static void enterJspCompile(Class<?> owner, Object compiler) {
    if (HookActivation.inactive()) return;
    String[] roots;
    try {
      roots = compileRoots(owner, compiler);
    } catch (Throwable failure) {
      roots = null;
    }
    push(roots, true);
  }

  /** On every way out of an instrumented operation. */
  public static void exit() {
    if (HookActivation.inactive()) return;
    try {
      Scope top = SCOPES.get();
      if (top == null) {
        return;
      }
      if (top.parent == null) {
        SCOPES.remove();
      } else {
        SCOPES.set(top.parent);
      }
    } catch (Throwable ignored) {
      // never into the container
    }
  }

  /**
   * Whether this thread is inside a verified container operation that writes {@code resolved} (slashes only, no
   * {@code .} or {@code ..} segment left): a path strictly under the innermost scope's root, and for a JSP compile a
   * {@code .class} or {@code .java} file.
   */
  static boolean covers(String resolved) {
    if (HookActivation.inactive()) return false;
    Scope scope = SCOPES.get();
    if (scope == null || scope.roots == null || resolved == null) {
      return false;
    }
    if (scope.classesOnly) {
      String lower = resolved.toLowerCase(Locale.ROOT);
      if (!lower.endsWith(".class") && !lower.endsWith(".java")) {
        return false;
      }
    }
    for (int i = 0; i < scope.roots.length; i++) {
      String root = scope.roots[i];
      if (resolved.length() > root.length() && resolved.startsWith(root)) {
        return true;
      }
    }
    return false;
  }

  private static void push(String[] roots, boolean classesOnly) {
    try {
      Scope parent = SCOPES.get();
      // With nothing to hide and nothing to grant, an empty stack stays empty: its exit() then finds nothing to pop.
      if (roots != null || parent != null) {
        SCOPES.set(new Scope(roots, classesOnly, parent));
      }
    } catch (Throwable ignored) {
      // never into the container
    }
  }

  private static String[] warRoots(Class<?> owner, Object host, String pathname) throws Exception {
    if (owner == null || host == null || pathname == null || !EXPAND_WAR.equals(owner.getName())) {
      return null;
    }
    ClassLoader loader = owner.getClassLoader();
    if (!containerLoader(loader) || !containerLoader(host.getClass().getClassLoader()) || !calledByContainer(owner)) {
      return null;
    }
    Class<?> hostType = Class.forName(HOST, false, loader);
    if (!hostType.isInstance(host)) {
      return null;
    }
    Object appBase = hostType.getMethod("getAppBaseFile").invoke(host);
    if (!(appBase instanceof File) || !((File) appBase).isAbsolute()) {
      return null;
    }
    File docBase = new File((File) appBase, pathname);
    String canonical = docBase.getCanonicalPath();
    // The docBase Tomcat computes is a directory of the Host's appBase; a pathname that leaves it grants nothing.
    if (!canonical.startsWith(root(((File) appBase).getCanonicalPath()))) {
      return null;
    }
    return roots(docBase.getAbsolutePath(), canonical);
  }

  private static String[] compileRoots(Class<?> owner, Object compiler) throws Exception {
    if (owner == null || compiler == null || !COMPILER.equals(owner.getName()) || !owner.isInstance(compiler)) {
      return null;
    }
    ClassLoader loader = owner.getClassLoader();
    if (!containerLoader(loader) || !containerLoader(compiler.getClass().getClassLoader())
        || !calledByContainer(owner)) {
      return null;
    }
    Object context = owner.getMethod("getCompilationContext").invoke(compiler);
    Class<?> contextType = Class.forName(COMPILATION_CONTEXT, false, loader);
    if (!contextType.isInstance(context) || !containerLoader(context.getClass().getClassLoader())) {
      return null;
    }
    Object outputDir = contextType.getMethod("getOutputDir").invoke(context);
    if (!(outputDir instanceof String)) {
      return null;
    }
    File output = new File((String) outputDir);
    if (!output.isAbsolute()) {
      return null;
    }
    return roots(output.getAbsolutePath(), output.getCanonicalPath());
  }

  /**
   * Whether the frame below this class's is {@code owner}'s, and the first frame below {@code owner}'s run of frames
   * is defined by {@code owner}'s loader: the operation was entered by the instrumented method, called by the
   * container. Reflection frames are not in the list, so an application that calls the method reflectively is the
   * caller.
   */
  private static boolean calledByContainer(Class<?> owner) {
    Class<?>[] stack = FRAMES == null ? null : FRAMES.classes();
    if (stack == null) {
      return false;
    }
    int i = 0;
    while (i < stack.length && (stack[i] == Frames.class || stack[i] == ContainerDeployment.class)) {
      i++;
    }
    if (i >= stack.length || stack[i] != owner) {
      return false;
    }
    while (i < stack.length && stack[i] == owner) {
      i++;
    }
    return i < stack.length && stack[i] != null && stack[i].getClassLoader() == owner.getClassLoader();
  }

  /** Whether {@code loader} is neither a web application's loader nor below one. */
  private static boolean containerLoader(ClassLoader loader) {
    if (loader == null) {
      return false;
    }
    for (ClassLoader current = loader; current != null; current = current.getParent()) {
      for (Class<?> type = current.getClass(); type != null; type = type.getSuperclass()) {
        if (WEBAPP_LOADER.equals(type.getName())) {
          return false;
        }
      }
    }
    return true;
  }

  /** The directory as the script-write rule reads paths, and its canonical form, each with a trailing slash. */
  private static String[] roots(String absolute, String canonical) {
    String first = root(absolute);
    String second = root(canonical);
    return first.equals(second) ? new String[] {first} : new String[] {first, second};
  }

  private static String root(String directory) {
    String resolved = ScriptFileWrite.resolve(ScriptFileWrite.normalize(directory));
    return resolved.endsWith("/") ? resolved : resolved + "/";
  }
}
