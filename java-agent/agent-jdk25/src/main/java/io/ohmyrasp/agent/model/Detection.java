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

  /** Metadata-only findings require an explicitly selected policy. */
  public boolean requiresExplicitRule() {
    if (details == null) return false;
    String basis = details.get("decision_basis");
    return ("deleteFile_userinput".equals(algorithm) && "requested_path_only".equals(basis))
        || ("command_reflect".equals(algorithm) && "process_dispatch".equals(basis))
        || ("directory_userinput".equals(algorithm) && "requested_path_only".equals(basis))
        || ("directory_unwanted".equals(algorithm) && "directory_location".equals(basis))
        || ("directory_reflect".equals(algorithm) && "directory_dispatch".equals(basis))
        || ("readFile_outsideWebroot".equals(algorithm) && "system_directory".equals(basis))
        || ("readFile_userinput".equals(algorithm) && "requested_path_only".equals(basis))
        || ("ssrf_userinput".equals(algorithm) && "destination_only".equals(details.get("policy_basis")))
        || ("fileUpload_java_archive".equals(algorithm) && "deployment_context".equals(basis))
        || ("request_metadata".equals(basis) && ("request_sql_sort_injection".equals(algorithm)
            || "request_sql_identifier_injection".equals(algorithm)));
  }

  public Detection withAction(String action) {
    return new Detection(timestamp, hook, algorithm, action, confidence, message, request, details);
  }
}
