package io.ohmyrasp.agent.model;

import java.time.Instant;
import java.util.Map;

public record Detection(
    Instant timestamp,
    String hook,
    String algorithm,
    String action,
    int confidence,
    String message,
    RequestContext request,
    Map<String, String> details) {

  public static Detection log(
      String hook,
      String algorithm,
      int confidence,
      String message,
      RequestContext request,
      Map<String, String> details) {
    return new Detection(
        Instant.now(),
        hook,
        algorithm,
        "log",
        confidence,
        message,
        request,
        details == null ? Map.of() : Map.copyOf(details));
  }
}
