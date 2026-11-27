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
  private static final java.util.concurrent.atomic.AtomicReferenceFieldUpdater<RequestContext, Recorded> RECORDED =
      java.util.concurrent.atomic.AtomicReferenceFieldUpdater.newUpdater(RequestContext.class, Recorded.class, "recorded");
  private final String method;
  private final String uri;
  private final String query;
  private final Map<String, List<String>> parameters;
  private final Map<String, String> headers;
  private final String body;
  // The container parsed some of the parameters from the request's body (a form or multipart body).
  private final boolean formBody;
  // What the application has read of the body so far, set by the request-body hooks, with the inputs derived from
  // it: one object, replaced whole, so that a cache made from a state that forgetBody dropped is never published.
  private volatile Recorded recorded;
  // Whether a recorded body state was ever observed by this context: kept after forgetBody, so that an operation
  // carried from the request to another thread still reports as a request with a body (see BodyEvidence).
  private volatile boolean bodySeen;
  // The body this context was built with, as a snapshot with its inputs, made on first use.
  private volatile Recorded given;
  // The version of the recorded body state the request rules were last decided on for this context (one context
  // per servlet dispatch: a state decided under an include is decided again for the route it returns to).
  private int bodyDecided;

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
    this.formBody = false;
  }

  /** A copy that shares this context's immutable request line, parameters and headers; no body state. */
  private RequestContext(RequestContext from, String query, Map<String, List<String>> parameters, boolean formBody) {
    this.method = from.method;
    this.uri = from.uri;
    this.query = query;
    this.parameters = parameters;
    this.headers = from.headers;
    this.body = "";
    this.formBody = formBody;
  }

  /** This request, marked as one whose parameters the container parsed (in part) from its body. */
  public RequestContext withFormBody() {
    return new RequestContext(this, query, parameters, true);
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
    Recorded seen = recorded;
    return seen != null ? seen.snapshot.text() : body;
  }

  /** Records the state of the body the application has read; the request-body hooks call it. */
  public void observeBody(RequestBodySnapshot snapshot) {
    if (snapshot == null) return;
    bodySeen = true;
    Recorded seen = recorded;
    if (seen == null || seen.snapshot != snapshot) recorded = new Recorded(snapshot, null);
  }

  /** Drops the recorded body state: the dispatch this context belongs to has ended. */
  public void forgetBody() {
    recorded = null;
    bodyDecided = 0;
  }

  /**
   * Whether an event on this request is built from structured evidence only (see BodyEvidence): the context
   * carries a body, observed one at some time (an operation carried from the request keeps that), or holds
   * parameters the container parsed from the request's body.
   */
  public boolean bodyDerived() {
    return formBody || bodySeen || recorded != null || !body.isEmpty();
  }

  /** The body state version the request rules were last decided on for this context (0: none). */
  public int bodyDecided() {
    return bodyDecided;
  }

  /** Body state {@code version} has been decided for this context. Called by the thread that serves the request. */
  public void bodyDecided(int version) {
    bodyDecided = version;
  }

  /**
   * This request without any body state, as a new object always: the method, URI, query, parameters and headers.
   * An event carries this, so that a queued event keeps neither body text nor the live context.
   */
  public RequestContext withoutBody() {
    return new RequestContext(this, query, parameters, formBody);
  }

  /**
   * What an event on a request with a body shows of the request: the method, the URI, the query as the rule left
   * it, the headers, and no parameters (they may hold a parsed form body).
   */
  public RequestContext publicEnvelope() {
    return new RequestContext(this, query, Map.of(), formBody);
  }

  /** The body state this context carries, or null when it has none. */
  public RequestBodySnapshot bodySnapshot() {
    Recorded seen = state();
    return seen == null ? null : seen.snapshot;
  }

  private Recorded state() {
    Recorded seen = recorded;
    if (seen != null) return seen;
    if (body.isEmpty()) return null;
    Recorded made = given;
    if (made == null) {
      made = new Recorded(RequestBodySnapshot.of(body, headers.get("content-type")), null);
      given = made;
    }
    return made;
  }

  /**
   * The request input a sink argument is matched against: the parameters, and the names and values extracted
   * from the body (see {@link BodyValues}) as more parameters, under the name each was found under. The merged
   * map is cached with the body state it was made from, and only while that state is still the context's.
   */
  public Map<String, List<String>> inputParameters() {
    Recorded state = state();
    if (state == null) return parameters;
    return inputsOf(state);
  }

  /** The merged inputs of {@code state}, made and published as {@link #inputParameters} says. */
  Map<String, List<String>> inputsOf(Recorded state) {
    if (state.inputs != null) return state.inputs;
    RequestBodySnapshot snapshot = state.snapshot;
    BodyValues values = snapshot.values();
    Map<String, List<String>> merged;
    if (values.isEmpty()) {
      merged = parameters;
    } else {
      var copy = new LinkedHashMap<String, List<String>>(parameters);
      // A loop, not a lambda: this runs on the first body a request reads, where a call site would link.
      for (Map.Entry<String, List<String>> field : values.parameters().entrySet()) {
        List<String> before = copy.get(field.getKey());
        if (before == null) {
          copy.put(field.getKey(), field.getValue());
        } else {
          var joined = new ArrayList<String>(before);
          joined.addAll(field.getValue());
          copy.put(field.getKey(), Collections.unmodifiableList(joined));
        }
      }
      merged = Collections.unmodifiableMap(copy);
    }
    Recorded withInputs = new Recorded(snapshot, merged);
    // Published only if the state is still the one it was made from: a forgetBody (or a newer state) in
    // between wins, and the merged map stays with this caller.
    if (state == given) given = withInputs;
    else RECORDED.compareAndSet(this, state, withInputs);
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
    if (snapshot != null) view.observeBody(snapshot);
    return view;
  }

  /** This request with the body's names and values as its only parameters: see {@link #withBodyParameters}. */
  public RequestContext withOnlyBodyParameters() {
    RequestBodySnapshot snapshot = bodySnapshot();
    Map<String, List<String>> fields = snapshot == null ? Map.of() : snapshot.values().parameters();
    var view = new RequestContext(method, uri, query, fields, headers, "");
    if (snapshot != null) view.observeBody(snapshot);
    return view;
  }

  /** The body state this context holds now, for a test that interleaves a worker with {@link #forgetBody}. */
  Recorded recordedState() {
    return recorded;
  }

  /** One body state and, once made, the request inputs merged with its values. */
  static final class Recorded {
    final RequestBodySnapshot snapshot;
    final Map<String, List<String>> inputs;

    Recorded(RequestBodySnapshot snapshot, Map<String, List<String>> inputs) {
      this.snapshot = snapshot;
      this.inputs = inputs;
    }
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
