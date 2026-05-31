package io.ohmyrasp.agent.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class RequestContext {
  private final String method;
  private final String uri;
  private final String query;
  private final Map<String, List<String>> parameters;
  private final Map<String, String> headers;

  public RequestContext(
      String method,
      String uri,
      String query,
      Map<String, List<String>> parameters,
      Map<String, String> headers) {
    this.method = method == null ? "" : method;
    this.uri = uri == null ? "" : uri;
    this.query = query == null ? "" : query;
    this.parameters = immutableCopy(parameters);
    this.headers = Map.copyOf(headers == null ? Map.of() : headers);
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
    for (String parameter : allParameterValues()) {
      if (parameter != null
          && parameter.length() >= 2
          && normalized.contains(parameter.toLowerCase(Locale.ROOT))) {
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
}
