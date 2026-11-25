package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.requestUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** CredentialDetector: JWT verification failures. */
final class CredentialDetectorTest {
  @Test
  void detectsJwtVerificationFailureOnDataEaseApiToken() {
    var context =
        new RequestContext(
            "GET",
            "/de2api/user/info",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "x-de-token", forgedJwt()));

    var result =
        CredentialDetector.detectJwtVerificationFailure(
            "auth0-java-jwt",
            "com.auth0.jwt.exceptions.SignatureVerificationException",
            "The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256",
            context);

    assertAlgorithm(result, "request_jwt_verification_failure");
    assertEquals("x-de-token", result.orElseThrow().details().get("tokenSource"));
    assertEquals("[redacted]", result.orElseThrow().request().headers().get("x-de-token"));
  }

  @Test
  void ignoresJwtVerificationFailureWithoutJwtHeader() {
    var result =
        CredentialDetector.detectJwtVerificationFailure(
            "auth0-java-jwt",
            "com.auth0.jwt.exceptions.SignatureVerificationException",
            "invalid signature",
            requestUri("/de2api/user/info"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresJwtVerificationFailureOutsideControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/assets/app.js",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "authorization", "Bearer " + forgedJwt()));

    var result =
        CredentialDetector.detectJwtVerificationFailure(
            "auth0-java-jwt",
            "com.auth0.jwt.exceptions.SignatureVerificationException",
            "invalid signature",
            context);

    assertTrue(result.isEmpty());
  }

  private static String forgedJwt() {
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        + "eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoyMDAwMDAwMDAwfQ."
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  }
}
