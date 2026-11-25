package io.ohmyrasp.agent.loading;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/** A classpath element is one URL, including when its path contains spaces. */
public final class CodebaseUrls {
  private CodebaseUrls() {}

  public static List<String> elements(Object input) {
    List<String> sources = new ArrayList<String>();
    if (input instanceof URL[]) {
      for (URL item : (URL[]) input) add(sources, item);
    } else {
      add(sources, input);
    }
    return sources;
  }

  public static String remoteScheme(String url) {
    String source = url.trim();
    int start = source.regionMatches(true, 0, "jar:", 0, 4) ? 4 : 0;
    int colon = source.indexOf(':', start);
    if (colon <= start) return "";
    String scheme = source.substring(start, colon).toLowerCase(java.util.Locale.ROOT);
    return remoteProtocol(scheme) ? scheme : "";
  }

  static boolean remoteProtocol(String scheme) {
    return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme) || "ftp".equalsIgnoreCase(scheme)
        || "rmi".equalsIgnoreCase(scheme) || "ldap".equalsIgnoreCase(scheme);
  }

  private static void add(List<String> sources, Object value) {
    if (value instanceof URL) {
      URL url = (URL) value;
      // URL.toExternalForm() delegates to the application's URLStreamHandler.
      StringBuilder text = new StringBuilder(url.getProtocol()).append(':');
      String authority = url.getAuthority();
      if (authority != null && !authority.isEmpty()) text.append("//").append(authority);
      if (url.getFile() != null) text.append(url.getFile());
      if (url.getRef() != null) text.append('#').append(url.getRef());
      sources.add(text.toString());
    }
  }
}
