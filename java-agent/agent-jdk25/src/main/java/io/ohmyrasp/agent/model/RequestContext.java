package io.ohmyrasp.agent.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class RequestContext {
  private static final int MAX_BODY_CHARS = 8192;
  private final String method;
  private final String uri;
  private final String query;
  private final Map<String, List<String>> parameters;
  private final Map<String, String> headers;
  private final String body;

  public RequestContext(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers) {
    this(method, uri, query, parameters, headers, "");
  }

  public RequestContext(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers,
      String body) {
    this.method = method == null ? "" : method;
    this.uri = uri == null ? "" : uri;
    this.query = query == null ? "" : query;
    this.parameters = immutableCopy(parameters);
    this.headers = Map.copyOf(headers == null ? Map.of() : headers);
    this.body = boundedBody(body);
  }

  public static RequestContext empty() {
    return new RequestContext("", "", "", Map.of(), Map.of());
  }

  public String method() {
    return method;
  }

  public String uri() {
    return uri;
  }

  public String query() {
    return query;
  }

  public Map<String, List<String>> parameters() {
    return parameters;
  }

  public Map<String, String> headers() {
    return headers;
  }

  public String body() {
    return body;
  }

  public boolean active() {
    return !method.isBlank() || !uri.isBlank();
  }

  public Optional<String> header(String name) {
    if (name == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(headers.get(name.toLowerCase(Locale.ROOT)));
  }

  public List<String> allParameterValues() {
    var values = new ArrayList<String>();
    parameters.forEach(
        (name, items) -> {
          if (name != null && !name.isBlank()) {
            values.add(name);
          }
          values.addAll(items);
        });
    return values;
  }

  public boolean hasParameterIn(String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    String normalized = value.toLowerCase(Locale.ROOT);
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      String name = entry.getKey();
      if (isSignificantParameterName(name) && normalized.contains(name.toLowerCase(Locale.ROOT))) {
        return true;
      }
      for (String item : entry.getValue()) {
        if (item != null
            && item.length() >= 2
            && normalized.contains(item.toLowerCase(Locale.ROOT))) {
          return true;
        }
      }
    }
    if (value.length() >= 8
        && body != null
        && !body.isBlank()
        && body.toLowerCase(Locale.ROOT).contains(normalized)) {
      return true;
    }
    return false;
  }

  private static boolean isSignificantParameterName(String name) {
    if (name == null || name.length() < 8) {
      return false;
    }
    for (int i = 0; i < name.length(); i++) {
      char ch = name.charAt(i);
      if (!Character.isLetterOrDigit(ch) && ch != '_' && ch != '-') {
        return true;
      }
    }
    return false;
  }

  private static Map<String, List<String>> immutableCopy(Map<String, List<String>> source) {
    if (source == null || source.isEmpty()) {
      return Map.of();
    }
    var copy = new LinkedHashMap<String, List<String>>();
    source.forEach(
        (key, value) -> copy.put(key, Collections.unmodifiableList(new ArrayList<>(value))));
    return Collections.unmodifiableMap(copy);
  }

  private static String boundedBody(String body) {
    if (body == null || body.isEmpty()) {
      return "";
    }
    return body.length() <= MAX_BODY_CHARS ? body : body.substring(0, MAX_BODY_CHARS);
  }
}
