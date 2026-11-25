package io.ohmyrasp.agent.http;

/** One percent-decoding pass. Well-formed UTF-8 represents Unicode text, including actual controls. */
public final class PercentEncodedText {
  private PercentEncodedText() {}

  public static String decode(String value, boolean lenientHex) {
    if (value == null) return "";
    int escape = value.indexOf('%');
    if (escape < 0) return value;
    StringBuilder out = new StringBuilder(value.length());
    int start = 0;
    while (escape >= 0) {
      out.append(value, start, escape);
      int first = octet(value, escape, lenientHex);
      if (first < 0) {
        out.append('%');
        start = escape + 1;
      } else {
        int length = first >= 0xc2 && first <= 0xdf ? 2 : first >= 0xe0 && first <= 0xef ? 3
            : first >= 0xf0 && first <= 0xf4 ? 4 : 1;
        int point = length == 1 ? first : codePoint(value, escape, first, length, lenientHex);
        if (point < 0) {
          // Preserve an unmatched octet for the agent's separate legacy path interpretations.
          point = first;
          length = 1;
        }
        out.appendCodePoint(point);
        start = escape + length * 3;
      }
      escape = value.indexOf('%', start);
    }
    return out.append(value, start, value.length()).toString();
  }

  private static int codePoint(String value, int start, int first, int length, boolean lenientHex) {
    int point = first & (0x7f >> length);
    for (int n = 1; n < length; n++) {
      int next = octet(value, start + 3 * n, lenientHex);
      if ((next & 0xc0) != 0x80) return -1;
      point = (point << 6) | (next & 0x3f);
    }
    if ((length == 3 && point < 0x800) || (length == 4 && point < 0x10000)
        || (point >= 0xd800 && point <= 0xdfff) || point > Character.MAX_CODE_POINT) return -1;
    return point;
  }

  private static int octet(String value, int index, boolean lenientHex) {
    if (index > value.length() - 3 || value.charAt(index) != '%') return -1;
    int high = digit(value.charAt(index + 1), lenientHex);
    int low = digit(value.charAt(index + 2), lenientHex);
    return high < 0 || low < 0 ? -1 : (high << 4) | low;
  }

  private static int digit(char ch, boolean lenientHex) {
    if (!lenientHex) return Character.digit(ch, 16);
    if (ch > 0x7f) return -1;
    int digit = (ch & 0x1f) + ((ch >> 6) * 0x19) - 0x10;
    return digit >= 0 && digit <= 15 ? digit : -1;
  }
}
