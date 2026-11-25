package io.ohmyrasp.agent.http;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
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
      try {
        String key = URLDecoder.decode(name, "UTF-8");
        String value = equal < 0 ? "" : URLDecoder.decode(field.substring(equal + 1), "UTF-8");
        result.computeIfAbsent(key, ignored -> new ArrayList<String>()).add(value);
      } catch (IllegalArgumentException ignored) {
        // A malformed escape provides no reliable decoded value.
      } catch (UnsupportedEncodingException impossible) {
        throw new AssertionError(impossible);
      }
    }
    return result;
  }
}
