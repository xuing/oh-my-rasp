package io.ohmyrasp.agent.loading;

import java.net.HttpURLConnection;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

/** Bind a JDK directory resource to the connection supplying its bytes. */
public final class ClassDefinitionOrigin {
  private static final Map<Object, String> READS = Collections.synchronizedMap(new WeakHashMap<Object, String>());

  private ClassDefinitionOrigin() {}

  public static void read(URLConnection connection, Object resource) {
    Class<?> provider = connection.getClass();
    if (provider.getClassLoader() != null) return;
    URL url;
    if (connection instanceof HttpURLConnection || "sun.net.www.protocol.ftp.FtpURLConnection".equals(provider.getName())) {
      url = connection.getURL();
    } else if ("sun.net.www.protocol.jar.JarURLConnection".equals(provider.getName())) {
      url = ((JarURLConnection) connection).getJarFileURL();
    } else {
      return;
    }
    if (CodebaseUrls.remoteProtocol(url.getProtocol())) READS.put(resource, recordedAddress(url));
  }

  public static String selected(Object resource, URL origin, Object handler) {
    String type = resource.getClass().getName();
    if (type.startsWith("sun.misc.URLClassPath$Loader$") || type.startsWith("jdk.internal.loader.URLClassPath$Loader$"))
      return READS.remove(resource);
    // JarLoader uses the archive URL as the CodeSource, including for cached archives.
    if (!type.startsWith("sun.misc.URLClassPath$JarLoader$") && !type.startsWith("jdk.internal.loader.URLClassPath$JarLoader$"))
      return null;
    if (origin == null || !CodebaseUrls.remoteProtocol(origin.getProtocol()) || handler == null || handler.getClass().getClassLoader() != null
        || !handler.getClass().getName().equals("sun.net.www.protocol." + origin.getProtocol() + ".Handler")) return null;
    return recordedAddress(origin);
  }

  private static String recordedAddress(URL url) {
    String port = url.getPort() < 0 ? "" : ":" + url.getPort();
    return url.getProtocol() + "://" + url.getHost() + port + url.getPath();
  }
}
