package io.ohmyrasp.agent.detect;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;

/** Text transformations shared by primary-agent detectors. */
final class DetectorStrings {
  private DetectorStrings() {}

  static String normalizeParameterName(String name) {
    return name == null ? "" : name.replace("_", "").replace("-", "").toLowerCase(Locale.ROOT);
  }

  static String percentDecode(String value) {
    if (value == null || value.indexOf('%') < 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '%' && i + 2 < value.length()) {
        int high = Character.digit(value.charAt(i + 1), 16);
        int low = Character.digit(value.charAt(i + 2), 16);
        if (high >= 0 && low >= 0) {
          decoded.append((char) ((high << 4) + low));
          i += 2;
          continue;
        }
      }
      decoded.append(ch);
    }
    return decoded.toString();
  }

  static String lower(String value) {
    return value == null ? "" : value.toLowerCase(Locale.ROOT);
  }

  static String abbreviate(String value) {
    if (value == null) {
      return "";
    }
    if (value.length() <= 300) {
      return value;
    }
    return value.substring(0, 300) + "...";
  }

  static String normalizePath(String path) {
    if (path == null) {
      return "";
    }
    try {
      return Path.of(path).normalize().toString().replace('\\', '/').toLowerCase(Locale.ROOT);
    } catch (RuntimeException e) {
      return path.replace('\\', '/').toLowerCase(Locale.ROOT);
    }
  }

  static boolean containsPathToken(String path, Set<String> tokens) {
    if (path == null || path.isBlank()) {
      return false;
    }
    for (String segment : path.split("[/;?&#._=-]+")) {
      if (tokens.contains(segment)) {
        return true;
      }
    }
    return false;
  }

  static String protocolOf(String value) {
    if (value == null) {
      return "";
    }
    int index = value.indexOf("://");
    if (index < 1) {
      return "";
    }
    return value.substring(0, index).toLowerCase(Locale.ROOT);
  }

  static String extensionOf(String value) {
    String normalized = lower(value);
    int query = normalized.indexOf('?');
    if (query >= 0) {
      normalized = normalized.substring(0, query);
    }
    int fragment = normalized.indexOf('#');
    if (fragment >= 0) {
      normalized = normalized.substring(0, fragment);
    }
    int dot = normalized.lastIndexOf('.');
    if (dot < 0 || dot == normalized.length() - 1) {
      return "";
    }
    return normalized.substring(dot + 1);
  }
}
