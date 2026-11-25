package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** ResponseContentDetector: Personal data in responses and reflected markup. */
final class ResponseContentDetectorTest {
  @Test
  void detectsResponseIdentityCardLeak() {
    var result = ResponseContentDetector.detectResponseDataLeak("application/json", "{\"id\":\"11010519491231002X\"}", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsResponseMobileLeak() {
    var result = ResponseContentDetector.detectResponseDataLeak("text/html", "phone=13800138000", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsResponseBankCardLeak() {
    var result = ResponseContentDetector.detectResponseDataLeak("application/xml", "<card>4111 1111 1111 1111</card>", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsXssEcho() {
    var result =
        ResponseContentDetector.detectXssEcho(
            "hello <script>alert(1)</script>",
            request(Map.of("q", List.of("<script>alert(1)</script>"))));

    assertAlgorithm(result, "xss_echo");
  }

  @Test
  void ignoresApplicationScriptWithoutMatchingRequestParameter() {
    var result = ResponseContentDetector.detectXssEcho("<script src='/assets/report.js'></script>", request(Map.of("q", List.of("weekly"))));
    assertTrue(result.isEmpty());
  }
}
