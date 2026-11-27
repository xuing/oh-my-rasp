package io.ohmyrasp.agent.http;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Query values available before a servlet container has configured its multipart parser. */
public final class ServletQueryParameters {
  private ServletQueryParameters() {}

  public static Map<String, List<String>> parse(String query) {
    Map<String, List<String>> result = new LinkedHashMap<String, List<String>>();
    if (query == null || query.isEmpty()) {
      return result;
    }
    for (String field : query.split("&")) {
      int equal = field.indexOf('=');
      String name = equal < 0 ? field : field.substring(0, equal);
      if (name.isEmpty()) continue;
      String key = decode(name);
      String value = equal < 0 ? "" : decode(field.substring(equal + 1));
      if (key != null && value != null) {
        List<String> values = result.get(key);
        if (values == null) {
          values = new ArrayList<String>();
          result.put(key, values);
        }
        values.add(value);
      }
    }
    return result;
  }

  private static String decode(String raw) {
    if (raw.indexOf('%') < 0) return raw.replace('+', ' ');
    StringBuilder text = new StringBuilder(raw.length());
    ByteBuffer bytes = ByteBuffer.allocate(raw.length() / 3);
    for (int i = 0; i < raw.length();) {
      char ch = raw.charAt(i);
      if (ch != '%') {
        text.append(ch == '+' ? ' ' : ch);
        i++;
        continue;
      }
      bytes.clear();
      do {
        if (i + 2 >= raw.length()) return null;
        int high = hex(raw.charAt(i + 1));
        int low = hex(raw.charAt(i + 2));
        if (high < 0 || low < 0) return null;
        bytes.put((byte) ((high << 4) | low));
        i += 3;
      } while (i < raw.length() && raw.charAt(i) == '%');
      bytes.flip();
      try {
        text.append(StandardCharsets.UTF_8.newDecoder().decode(bytes));
      } catch (CharacterCodingException malformed) {
        return null;
      }
    }
    return text.toString();
  }

  private static int hex(char ch) {
    return ch <= 127 ? Character.digit(ch, 16) : -1;
  }
}
