package io.ohmyrasp.agent.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class DetectorTestSupport {
  private DetectorTestSupport() {}

  static RequestContext request() {
    return request(Map.of());
  }

  static RequestContext request(Map<String, List<String>> parameters) {
    return new RequestContext(
        "GET", "/rasp/test", "", parameters, Map.of("user-agent", "JUnit"));
  }

  static RequestContext requestUri(String uri) {
    return new RequestContext("GET", uri, "", Map.of(), Map.of("user-agent", "JUnit"));
  }

  static String jsonString(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  static void assertAlgorithm(Optional<Detection> result, String algorithm) {
    assertTrue(result.isPresent());
    assertEquals(algorithm, result.orElseThrow().algorithm());
  }
}
