package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;

import io.ohmyrasp.agent.http.PercentEncodedText;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/** Decoding and resource-path recognition shared by request rules. */
final class RequestDecoding {
  private static final Pattern JAVA_UNICODE_ESCAPE =
      Pattern.compile("\\\\u+([0-9a-fA-F]{4})");

  static final Pattern PROTECTED_WEBAPP_RESOURCE =
      Pattern.compile("(?i)(?:^|[/?&=])((?:web-inf|meta-inf))(?:[/\\\\?&#=]|$)");

  private RequestDecoding() {}

  static String decodeJavaUnicodeEscapes(String value) {
    if (value == null || !value.contains("\\u")) {
      return value == null ? "" : value;
    }
    return JAVA_UNICODE_ESCAPE
        .matcher(value)
        .replaceAll(match -> decodeJavaChar(match.group(1), match.group()));
  }

  private static String decodeJavaChar(String value, String fallback) {
    try {
      return String.valueOf((char) Integer.parseInt(value, 16));
    } catch (NumberFormatException e) {
      return fallback;
    }
  }

  static List<String> decodedVariants(String value) {
    if (value == null || value.isBlank()) {
      return List.of();
    }
    String decoded = percentDecode(value);
    return List.of(value, decoded, percentDecode(decoded));
  }

  static String stripWrappingQuotes(String value) {
    if (value.length() >= 2) {
      char first = value.charAt(0);
      char last = value.charAt(value.length() - 1);
      if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
        return value.substring(1, value.length() - 1).trim();
      }
    }
    return value;
  }

  static String decodeXmlCharacterReferences(String value) {
    if (value == null || value.indexOf('&') < 0) {
      return value == null ? "" : value;
    }
    String decoded = value;
    for (int i = 0; i < 2; i++) {
      decoded =
          Pattern.compile("(?i)&#x([0-9a-f]{1,6});")
              .matcher(decoded)
              .replaceAll(
                  match -> decodeXmlCodePoint(match.group(1), 16, match.group()));
      decoded =
          Pattern.compile("&#([0-9]{1,7});")
              .matcher(decoded)
              .replaceAll(
                  match -> decodeXmlCodePoint(match.group(1), 10, match.group()));
    }
    return decoded;
  }

  private static String decodeXmlCodePoint(String value, int radix, String fallback) {
    try {
      int codePoint = Integer.parseInt(value, radix);
      return Character.isValidCodePoint(codePoint)
          ? new String(Character.toChars(codePoint))
          : fallback;
    } catch (NumberFormatException e) {
      return fallback;
    }
  }

  static Optional<String> protectedWebappResource(String value) {
    var matcher = PROTECTED_WEBAPP_RESOURCE.matcher(value);
    if (!matcher.find()) {
      return Optional.empty();
    }
    return Optional.of(matcher.group(1).toUpperCase(Locale.ROOT));
  }

  static List<String> pathVariants(String path) {
    List<String> variants = decodedPathVariants(path);
    addLowByteVariants(variants, path);
    return variants;
  }

  static List<String> decodedPathVariants(String path) {
    var variants = new ArrayList<String>();
    addVariant(variants, path);
    addOverlongUtf8Variants(variants, path);
    String once = PercentEncodedText.decode(path, false);
    addVariant(variants, once);
    addVariant(variants, decodeUnicodeEscapes(once));
    addLenientPercentVariants(variants, once);
    addOverlongUtf8Variants(variants, once);
    String twice = PercentEncodedText.decode(once, false);
    addVariant(variants, twice);
    addVariant(variants, decodeUnicodeEscapes(twice));
    addLenientPercentVariants(variants, twice);
    addOverlongUtf8Variants(variants, twice);
    addLenientPercentVariants(variants, path);
    return variants;
  }

  static void addLowByteVariants(List<String> variants, String path) {
    String ghost = lowByteUnicodeDecode(path);
    if (!ghost.equals(path)) {
      addVariant(variants, ghost);
      addVariant(variants, decodeUnicodeEscapes(ghost));
      addOverlongUtf8Variants(variants, ghost);
      String decodedGhost = PercentEncodedText.decode(ghost, false);
      addVariant(variants, decodedGhost);
      addVariant(variants, decodeUnicodeEscapes(decodedGhost));
      addLenientPercentVariants(variants, decodedGhost);
      addOverlongUtf8Variants(variants, decodedGhost);
    }
  }

  private static void addOverlongUtf8Variants(List<String> variants, String value) {
    String overlong = overlongUtf8Decode(value);
    if (!overlong.equals(value)) {
      addVariant(variants, overlong);
      addVariant(variants, decodeUnicodeEscapes(overlong));
    }
  }

  private static void addLenientPercentVariants(List<String> variants, String value) {
    String lenient = jettyLenientPercentDecode(value);
    if (!lenient.equals(value)) {
      addVariant(variants, lenient);
      addVariant(variants, decodeUnicodeEscapes(lenient));
    }
  }

  static void addVariant(List<String> variants, String value) {
    if (value == null || value.isBlank()) {
      return;
    }
    if (!variants.contains(value)) {
      variants.add(value);
    }
  }

  private static String jettyLenientPercentDecode(String value) {
    return PercentEncodedText.decode(value, true);
  }

  private static String overlongUtf8Decode(String value) {
    if (value == null || value.isBlank()) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    boolean changed = false;
    for (int i = 0; i < value.length(); i++) {
      int first = encodedByteValue(value, i);
      int firstNext = encodedByteNextIndex(value, i);
      if (first >= 0xc0 && first <= 0xdf && firstNext < value.length()) {
        int second = encodedByteValue(value, firstNext);
        int secondNext = encodedByteNextIndex(value, firstNext);
        if ((second & 0xc0) == 0x80) {
          int codepoint = ((first & 0x1f) << 6) | (second & 0x3f);
          if (overlongPathCharacter(codepoint)) {
            decoded.append((char) codepoint);
            i = secondNext - 1;
            changed = true;
            continue;
          }
        }
      }
      if (first == 0xe0 && firstNext < value.length()) {
        int second = encodedByteValue(value, firstNext);
        int secondNext = encodedByteNextIndex(value, firstNext);
        if ((second & 0xc0) == 0x80 && secondNext < value.length()) {
          int third = encodedByteValue(value, secondNext);
          int thirdNext = encodedByteNextIndex(value, secondNext);
          if ((third & 0xc0) == 0x80) {
            int codepoint =
                ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f);
            if (overlongPathCharacter(codepoint)) {
              decoded.append((char) codepoint);
              i = thirdNext - 1;
              changed = true;
              continue;
            }
          }
        }
      }
      decoded.append(value.charAt(i));
    }
    return changed ? decoded.toString() : value;
  }

  private static boolean overlongPathCharacter(int codepoint) {
    return codepoint == '.' || codepoint == '/' || codepoint == '\\';
  }

  private static int encodedByteValue(String value, int index) {
    if (index < 0 || index >= value.length()) {
      return -1;
    }
    char ch = value.charAt(index);
    if (ch == '%' && index + 2 < value.length()) {
      int high = Character.digit(value.charAt(index + 1), 16);
      int low = Character.digit(value.charAt(index + 2), 16);
      if (high >= 0 && low >= 0) {
        return (high << 4) + low;
      }
    }
    return ch <= 0xff ? ch : -1;
  }

  private static int encodedByteNextIndex(String value, int index) {
    if (index < 0 || index >= value.length()) {
      return value.length();
    }
    char ch = value.charAt(index);
    if (ch == '%'
        && index + 2 < value.length()
        && Character.digit(value.charAt(index + 1), 16) >= 0
        && Character.digit(value.charAt(index + 2), 16) >= 0) {
      return index + 3;
    }
    return index + 1;
  }

  static String decodeUnicodeEscapes(String value) {
    if (value == null || lower(value).indexOf("%u") < 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '%'
          && i + 5 < value.length()
          && (value.charAt(i + 1) == 'u' || value.charAt(i + 1) == 'U')) {
        int codepoint = 0;
        boolean valid = true;
        for (int offset = 2; offset < 6; offset++) {
          int digit = Character.digit(value.charAt(i + offset), 16);
          if (digit < 0) {
            valid = false;
            break;
          }
          codepoint = (codepoint << 4) + digit;
        }
        if (valid) {
          decoded.append((char) codepoint);
          i += 5;
          continue;
        }
      }
      decoded.append(ch);
    }
    return decoded.toString();
  }

  private static String lowByteUnicodeDecode(String value) {
    if (value == null || value.isBlank()) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    boolean changed = false;
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch > 0x7f) {
        decoded.append((char) (ch & 0xff));
        changed = true;
      } else {
        decoded.append(ch);
      }
    }
    return changed ? decoded.toString() : value;
  }

  static String stripServletPathParameters(String path) {
    String[] segments = path.split("/", -1);
    StringBuilder builder = new StringBuilder(path.length());
    for (int i = 0; i < segments.length; i++) {
      if (i > 0) {
        builder.append('/');
      }
      String segment = segments[i];
      int semicolon = segment.indexOf(';');
      builder.append(semicolon >= 0 ? segment.substring(0, semicolon) : segment);
    }
    return builder.toString();
  }

  static String collapsePathDotSegments(String path) {
    boolean absolute = path.startsWith("/");
    var segments = new ArrayList<String>();
    for (String segment : path.split("/+", -1)) {
      if (segment.isBlank() || segment.equals(".")) {
        continue;
      }
      if (segment.equals("..")) {
        if (!segments.isEmpty()) {
          segments.remove(segments.size() - 1);
        }
        continue;
      }
      segments.add(segment);
    }
    String collapsed = String.join("/", segments);
    if (absolute) {
      collapsed = "/" + collapsed;
    }
    return collapsed.isBlank() ? "/" : collapsed;
  }

  static boolean hasConfusingDotSegment(String path) {
    for (String rawSegment : path.split("/+")) {
      if (rawSegment.isBlank()) {
        continue;
      }
      String segment = rawSegment;
      int semicolon = segment.indexOf(';');
      if (semicolon >= 0) {
        segment = segment.substring(0, semicolon);
      }
      if (segment.equals("..")) {
        return true;
      }
    }
    return false;
  }
}
