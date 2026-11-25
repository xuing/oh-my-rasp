package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Read bounded request metadata without invoking application parsers. */
final class RequestJson {
  private RequestJson() {}

  record JsonStringField(String name, String value) {}

  record JsonStringToken(String value, int nextIndex) {}

  static boolean jsonConfigBody(RequestContext request) {
    if (request.body().isBlank()) {
      return false;
    }
    String method = lower(request.method());
    if (!method.equals("post") && !method.equals("put") && !method.equals("patch")) {
      return false;
    }
    String trimmed = request.body().trim();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
      return false;
    }
    String contentType = lower(request.header("content-type").orElse(""));
    return contentType.isBlank() || contentType.contains("json");
  }

  static List<JsonStringField> jsonStringFields(String json) {
    if (json == null || json.isBlank()) {
      return List.of();
    }
    var fields = new ArrayList<JsonStringField>();
    int index = 0;
    while (index < json.length()) {
      int quote = json.indexOf('"', index);
      if (quote < 0) {
        break;
      }
      Optional<JsonStringToken> key = parseJsonString(json, quote);
      if (key.isEmpty()) {
        index = quote + 1;
        continue;
      }
      JsonStringToken keyToken = key.orElseThrow();
      index = skipWhitespace(json, keyToken.nextIndex());
      if (index >= json.length() || json.charAt(index) != ':') {
        continue;
      }
      index = skipWhitespace(json, index + 1);
      if (index >= json.length()) {
        continue;
      }
      if (json.charAt(index) == '[') {
        int arrayValue = skipWhitespace(json, index + 1);
        if (arrayValue < json.length()
            && (json.charAt(arrayValue) == '"' || json.charAt(arrayValue) == ']')) {
          index = addJsonStringArrayFields(json, index, keyToken.value(), fields);
        } else {
          index = arrayValue;
        }
        continue;
      }
      if (json.charAt(index) != '"') {
        continue;
      }
      Optional<JsonStringToken> value = parseJsonString(json, index);
      if (value.isPresent()) {
        fields.add(new JsonStringField(keyToken.value(), value.orElseThrow().value()));
        index = value.orElseThrow().nextIndex();
      }
    }
    return fields;
  }

  private static int addJsonStringArrayFields(
      String json, int arrayIndex, String fieldName, List<JsonStringField> fields) {
    int current = skipWhitespace(json, arrayIndex + 1);
    while (current < json.length() && json.charAt(current) != ']') {
      if (json.charAt(current) != '"') {
        current++;
        continue;
      }
      Optional<JsonStringToken> value = parseJsonString(json, current);
      if (value.isEmpty()) {
        current++;
        continue;
      }
      fields.add(new JsonStringField(fieldName, value.orElseThrow().value()));
      current = skipWhitespace(json, value.orElseThrow().nextIndex());
      if (current < json.length() && json.charAt(current) == ',') {
        current = skipWhitespace(json, current + 1);
      }
    }
    return current < json.length() ? current + 1 : current;
  }

  static Optional<JsonStringToken> parseJsonString(String json, int quoteIndex) {
    if (json == null
        || quoteIndex < 0
        || quoteIndex >= json.length()
        || json.charAt(quoteIndex) != '"') {
      return Optional.empty();
    }
    var value = new StringBuilder();
    for (int i = quoteIndex + 1; i < json.length(); i++) {
      char ch = json.charAt(i);
      if (ch == '"') {
        return Optional.of(new JsonStringToken(value.toString(), i + 1));
      }
      if (ch != '\\') {
        value.append(ch);
        continue;
      }
      if (++i >= json.length()) {
        return Optional.empty();
      }
      char escaped = json.charAt(i);
      switch (escaped) {
        case '"', '\\', '/' -> value.append(escaped);
        case 'b' -> value.append('\b');
        case 'f' -> value.append('\f');
        case 'n' -> value.append('\n');
        case 'r' -> value.append('\r');
        case 't' -> value.append('\t');
        case 'u' -> {
          if (i + 4 >= json.length()) {
            return Optional.empty();
          }
          int codepoint = 0;
          for (int j = 1; j <= 4; j++) {
            int digit = Character.digit(json.charAt(i + j), 16);
            if (digit < 0) {
              return Optional.empty();
            }
            codepoint = (codepoint << 4) + digit;
          }
          value.append((char) codepoint);
          i += 4;
        }
        default -> value.append(escaped);
      }
    }
    return Optional.empty();
  }

  private static int skipWhitespace(String value, int index) {
    int current = index;
    while (current < value.length() && Character.isWhitespace(value.charAt(current))) {
      current++;
    }
    return current;
  }
}
