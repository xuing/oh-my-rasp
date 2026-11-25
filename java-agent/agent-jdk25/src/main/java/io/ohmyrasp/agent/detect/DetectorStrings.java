package io.ohmyrasp.agent.detect;

import java.util.Locale;

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
}
