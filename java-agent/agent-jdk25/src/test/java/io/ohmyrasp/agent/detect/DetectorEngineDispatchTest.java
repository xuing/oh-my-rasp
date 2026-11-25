package io.ohmyrasp.agent.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.ohmyrasp.agent.model.RequestContext;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DetectorEngineDispatchTest {
  @Test
  void retainsFirstMatchOrderAndCredentialRedactionAcrossDomains() {
    var engine = new DetectorEngine();
    String basic = "Basic " + Base64.getEncoder().encodeToString("tomcat:tomcat".getBytes(StandardCharsets.UTF_8));
    var multiple = new RequestContext("GET", "/manager/html", "", Map.of(),
        Map.of("user-agent", "nikto", "authorization", basic));
    assertEquals("request_scanner", engine.detectRequest(multiple).orElseThrow().algorithm());

    var credentials = new RequestContext("GET", "/manager/html", "", Map.of(), Map.of("authorization", basic));
    var finding = engine.detectRequest(credentials).orElseThrow();
    assertEquals("request_default_credential", finding.algorithm());
    assertEquals("Basic [redacted]", finding.request().headers().get("authorization"));
  }
}
