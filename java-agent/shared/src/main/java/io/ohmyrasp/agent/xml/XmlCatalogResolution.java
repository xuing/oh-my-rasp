package io.ohmyrasp.agent.xml;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.concurrent.ConcurrentHashMap;

/** Parser-observed origins for packaged DTDs; no XML content is retained. */
public final class XmlCatalogResolution {
  private static final ThreadLocal<WeakReference<Object>> REMAPPED = new ThreadLocal<WeakReference<Object>>();
  private static final ReferenceQueue<Object> COLLECTED = new ReferenceQueue<Object>();
  private static final ConcurrentHashMap<ManagerKey, Entry> DOCUMENTS = new ConcurrentHashMap<ManagerKey, Entry>();

  private XmlCatalogResolution() {}

  private static final class ManagerKey extends WeakReference<Object> {
    final int hash;
    ManagerKey(Object manager, ReferenceQueue<Object> queue) {
      super(manager, queue);
      hash = System.identityHashCode(manager);
    }
    @Override public int hashCode() { return hash; }
    @Override public boolean equals(Object other) {
      if (this == other) return true;
      Object manager = get();
      return manager != null && other instanceof ManagerKey && ((ManagerKey) other).get() == manager;
    }
  }

  // Only the next external subset can use a root observation. A new document,
  // entity closure, parser reuse, or collection invalidates it.
  public static Object enter(Object manager, String name) {
    if (DOCUMENTS.isEmpty()) return null;
    ManagerKey key;
    while ((key = (ManagerKey) COLLECTED.poll()) != null) DOCUMENTS.remove(key);
    Entry root = DOCUMENTS.remove(new ManagerKey(manager, null));
    return "[dtd]".equals(name) ? root : null;
  }

  public static void opened(Object manager, String name, URL target) {
    if (!"[xml]".equals(name)) return;
    Entry root = entry(target);
    if (root != null && parserCaller("setupCurrentEntity")) {
      DOCUMENTS.put(new ManagerKey(manager, COLLECTED), root);
    }
  }

  public static void resolved(Object parserInput, String requestedId, String baseId) {
    if (parserInput != null && remoteIdentifier(requestedId, baseId) && parserCaller("resolveEntity")) {
      REMAPPED.set(new WeakReference<Object>(parserInput));
    } else {
      REMAPPED.remove();
    }
  }

  private static boolean remoteIdentifier(String requestedId, String baseId) {
    if (requestedId == null || requestedId.isEmpty()) {
      return false;
    }
    try {
      URI id = new URI(requestedId);
      if (!id.isAbsolute() && baseId != null) {
        id = new URI(baseId).resolve(id);
      }
      return id.getHost() != null && ("http".equalsIgnoreCase(id.getScheme()) || "https".equalsIgnoreCase(id.getScheme()));
    } catch (URISyntaxException invalid) {
      return false;
    }
  }

  private static boolean parserCaller(String method) {
    for (StackTraceElement frame : Thread.currentThread().getStackTrace()) {
      String owner = frame.getClassName();
      if (Thread.class.getName().equals(owner) || XmlCatalogResolution.class.getName().equals(owner)) continue;
      String name = owner.replace('.', '/');
      return method.equals(frame.getMethodName())
          && ("resolveEntity".equals(method) ? XmlEntityOpenVisitor.isResolver(name) : XmlEntityOpenVisitor.isManager(name));
    }
    return false;
  }

  public static boolean consumesPackagedDtd(String name, URL target, Object input, Object root, String literal) {
    WeakReference<Object> selected = REMAPPED.get();
    boolean remapped = selected != null && input != null && selected.get() == input;
    if (remapped) REMAPPED.remove();
    if (!"[dtd]".equals(name) || (!remapped && !(root instanceof Entry))) return false;
    Entry dest = entry(target);
    if (dest == null || !dest.path.getPath().endsWith(".dtd")) return false;
    if (!remapped && !((Entry) root).containsReference(literal, dest)) return false;
    try {
      for (ClassLoader loader = Thread.currentThread().getContextClassLoader(); loader != null; loader = loader.getParent()) {
        if (loader instanceof URLClassLoader) {
          for (URL location : ((URLClassLoader) loader).getURLs()) {
            if ("file".equals(location.getProtocol()) && dest.archive.equals(location.toURI())) return true;
          }
        } else if (SystemArchiveOrigins.contains(loader, dest.archive)) {
          return true;
        }
      }
    } catch (URISyntaxException | RuntimeException unavailable) {
      // An unrecognised location or inaccessible loader cannot establish provenance.
    }
    return false;
  }

  /** Describe the opened transport without invoking the URL handler or recording credentials and queries. */
  public static String transportId(URL target) {
    String scheme = target.getProtocol();
    if ("jar".equals(scheme)) {
      Entry local = entry(target);
      return local == null ? "jar:" : "jar:" + local.archive + "!/" + local.path;
    }
    String host = target.getHost();
    StringBuilder id = new StringBuilder(scheme).append(':');
    if (host != null && !host.isEmpty()) {
      id.append("//").append(host);
      if (target.getPort() >= 0) id.append(':').append(target.getPort());
    }
    if (target.getPath() != null) id.append(target.getPath());
    return id.toString();
  }

  private static Entry entry(URL target) {
    if (target == null || !"jar".equals(target.getProtocol()) || target.getQuery() != null || target.getRef() != null) return null;
    String path = target.getPath();
    int split = path == null ? -1 : path.indexOf("!/");
    if (split < 0 || path.indexOf("!/", split + 2) >= 0) return null;
    try {
      URI entryPath = new URI(path.substring(split + 2));
      URI archive = new URI(path.substring(0, split));
      if (!relativePath(entryPath) || !"file".equalsIgnoreCase(archive.getScheme()) || archive.isOpaque()
          || archive.getRawAuthority() != null || archive.getQuery() != null || archive.getFragment() != null
          || !archive.getPath().startsWith("/") || archive.getPath().startsWith("//")
          || !archive.equals(archive.normalize())) return null;
      return new Entry(archive, entryPath);
    } catch (URISyntaxException invalid) {
      return null;
    }
  }

  private static boolean relativePath(URI uri) {
    if (uri.isAbsolute() || uri.getRawAuthority() != null || uri.getPath().startsWith("/")
        || uri.getQuery() != null || uri.getFragment() != null) return false;
    for (String segment : uri.getPath().split("/", -1)) {
      if (segment.isEmpty() || "..".equals(segment)
          || segment.indexOf('\\') >= 0 || segment.indexOf('\0') >= 0) return false;
    }
    return true;
  }

  private static final class Entry {
    final URI archive;
    final URI path;
    Entry(URI archive, URI path) {
      this.archive = archive;
      this.path = path;
    }
    boolean containsReference(String literal, Entry dest) {
      if (literal == null || !archive.equals(dest.archive)) return false;
      try {
        URI relative = new URI(literal);
        return relativePath(relative) && path.resolve(relative).normalize().equals(dest.path);
      } catch (URISyntaxException invalid) {
        return false;
      }
    }
  }
}
