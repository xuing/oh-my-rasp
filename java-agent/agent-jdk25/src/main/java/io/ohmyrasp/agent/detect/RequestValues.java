package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.RequestJson.jsonConfigBody;
import static io.ohmyrasp.agent.detect.RequestJson.jsonStringFields;
import io.ohmyrasp.agent.detect.RequestJson.JsonStringField;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Read request values used for correlation with runtime operands. */
final class RequestValues {
  private RequestValues() {}

  static boolean bodyHasSinkValue(RequestContext request, String value) {
    String body = request.body();
    if (body.isEmpty()) {
      return false;
    }
    if (value.equals(body.trim())) {
      return true;
    }
    if ((!body.contains(value) && body.indexOf('\\') < 0) || !jsonConfigBody(request)) {
      return false;
    }
    for (JsonStringField field : jsonStringFields(body)) {
      if (value.equals(field.value())) {
        return true;
      }
    }
    return false;
  }

  static Optional<Map.Entry<String, String>> firstNonBlankParameter(
      Map<String, List<String>> parameters, Set<String> candidateNames) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!candidateNames.contains(normalizeParameterName(entry.getKey()))) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (value != null && !value.isBlank()) {
          return Optional.of(Map.entry(entry.getKey(), value));
        }
      }
    }
    return Optional.empty();
  }
}
