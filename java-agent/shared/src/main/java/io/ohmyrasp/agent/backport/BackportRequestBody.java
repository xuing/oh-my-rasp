package io.ohmyrasp.agent.backport;

import io.ohmyrasp.agent.http.BodyValues;
import io.ohmyrasp.agent.http.RequestBody;
import io.ohmyrasp.agent.http.RequestBodyCapture;
import io.ohmyrasp.agent.http.RequestBodySnapshot;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The request body on the backport lines, as their rules consult request input: the values extracted from the
 * body the application has read (see {@link BodyValues}) join the request's parameter values, and its names and
 * values join the parameter map the request rules read, exactly as the primary line's RequestContext does.
 */
final class BackportRequestBody {
  private BackportRequestBody() {}

  /** The state of the body the current request has read, or null before its first byte or outside a request. */
  static RequestBodySnapshot current() {
    RequestBody body = RequestBodyCapture.current();
    return body == null ? null : body.snapshot();
  }

  /** {@code parameterValues} followed by the body's values; a new list, or the same one when the body adds none. */
  static List<String> withValues(List<String> parameterValues, BodyValues body) {
    if (body.values().isEmpty()) return parameterValues;
    List<String> joined = new ArrayList<String>(
        (parameterValues == null ? 0 : parameterValues.size()) + body.values().size());
    if (parameterValues != null) joined.addAll(parameterValues);
    joined.addAll(body.values());
    return joined;
  }

  /**
   * The request's parameter map with the body's names and values added as more parameters (String arrays, as a
   * servlet parameter map holds them); a name the request already has gets the body's values after its own.
   */
  static Map<Object, Object> withParameters(Map<?, ?> parameters, BodyValues body) {
    Map<Object, Object> merged = new LinkedHashMap<Object, Object>();
    if (parameters != null) merged.putAll(parameters);
    for (Map.Entry<String, List<String>> field : body.parameters().entrySet()) {
      List<String> values = new ArrayList<String>();
      Object before = merged.get(field.getKey());
      if (before instanceof String[]) {
        for (String value : (String[]) before) values.add(value);
      } else if (before instanceof String) {
        values.add((String) before);
      } else if (before instanceof Iterable<?>) {
        for (Object value : (Iterable<?>) before) values.add(String.valueOf(value));
      }
      values.addAll(field.getValue());
      merged.put(field.getKey(), values.toArray(new String[values.size()]));
    }
    return merged;
  }
}
