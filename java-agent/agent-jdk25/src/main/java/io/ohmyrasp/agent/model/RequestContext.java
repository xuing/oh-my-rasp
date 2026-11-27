package io.ohmyrasp.agent.model;

import io.ohmyrasp.agent.http.BodyValues;
import io.ohmyrasp.agent.http.RequestBody;
import io.ohmyrasp.agent.http.RequestBodySnapshot;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class RequestContext {
  /** The body cap, the same on every agent line: see {@link RequestBody#MAX_UNITS}. */
  private static final int MAX_BODY_CHARS = RequestBody.MAX_UNITS;
  private final String method;
  private final String uri;
  private final String query;
  private final Map<String, List<String>> parameters;
  private final Map<String, String> headers;
  private final String body;
  // What the application has read of the body so far, set by the request-body hooks; null before the first byte.
  private volatile RequestBodySnapshot recorded;
  // The body this context was built with, as a snapshot, made on first use.
  private volatile RequestBodySnapshot given;
  // parameters() with the body's values added, for the snapshot it was made from.
  private volatile Inputs inputs;

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

  /** The request body: what the application has read of it so far, or the body this context was built with. */
  public String body() {
    RequestBodySnapshot seen = recorded;
    return seen != null ? seen.text() : body;
  }

  /** Records the state of the body the application has read; the request-body hooks call it. */
  public void observeBody(RequestBodySnapshot snapshot) {
    if (snapshot != null) recorded = snapshot;
  }

  /** The body state this context carries, or null when it has none. */
  public RequestBodySnapshot bodySnapshot() {
    RequestBodySnapshot seen = recorded;
    if (seen != null) return seen;
    if (body.isEmpty()) return null;
    RequestBodySnapshot made = given;
    if (made == null) {
      made = RequestBodySnapshot.of(body, headers.get("content-type"));
      given = made;
    }
    return made;
  }

  /**
   * The request input a sink argument is matched against: the parameters, and the names and values extracted
   * from the body (see {@link BodyValues}) as more parameters, under the name each was found under.
   */
  public Map<String, List<String>> inputParameters() {
    RequestBodySnapshot snapshot = bodySnapshot();
    if (snapshot == null) return parameters;
    Inputs cached = inputs;
    if (cached != null && cached.snapshot == snapshot) return cached.parameters;
    BodyValues values = snapshot.values();
    Map<String, List<String>> merged;
    if (values.isEmpty()) {
      merged = parameters;
    } else {
      var copy = new LinkedHashMap<String, List<String>>(parameters);
      values.parameters().forEach((name, items) -> {
        List<String> before = copy.get(name);
        if (before == null) {
          copy.put(name, items);
        } else {
          var joined = new ArrayList<String>(before);
          joined.addAll(items);
          copy.put(name, Collections.unmodifiableList(joined));
        }
      });
      merged = Collections.unmodifiableMap(copy);
    }
    inputs = new Inputs(snapshot, merged);
    return merged;
  }

  /**
   * This request as the request rules see its body: the body's names and values added to the parameters (see
   * {@link #inputParameters}), and the body text. Only for deciding: an event names the request itself, whose
   * parameters hold no body value.
   */
  public RequestContext withBodyParameters() {
    RequestBodySnapshot snapshot = bodySnapshot();
    var view = new RequestContext(method, uri, query, inputParameters(), headers, "");
    if (snapshot != null) view.recorded = snapshot;
    return view;
  }

  private record Inputs(RequestBodySnapshot snapshot, Map<String, List<String>> parameters) {}

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
    for (Map.Entry<String, List<String>> entry : inputParameters().entrySet()) {
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
    String text = body();
    if (value.length() >= 8
        && !text.isBlank()
        && text.toLowerCase(Locale.ROOT).contains(normalized)) {
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
