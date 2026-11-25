package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.containsPathToken;
import static io.ohmyrasp.agent.detect.DetectorStrings.extensionOf;
import static io.ohmyrasp.agent.detect.DetectorStrings.protocolOf;
import static io.ohmyrasp.agent.detect.ProcessDetector.dangerousRemoteJobCommand;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.model.Detection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Descriptor-level job rules. Spark submit authorization is evaluated separately at servlet dispatch. */
final class RemoteJobDetector {
  private RemoteJobDetector() {}

  private static final Pattern REMOTE_JOB_ARTIFACT =
      Pattern.compile(
          "(?is)[\"'](?:appresource|spark\\.jars|sparkjars|jobjar|appjar|jarurl|resource)[\"']\\s*[:=]\\s*[\"']((?:https?|ftp)://[^\"'\\s,]+\\.(?:jar|war|ear)(?:[?#][^\"'\\s,]*)?)[\"']");
  private static final Pattern REMOTE_JOB_MAIN_CLASS =
      Pattern.compile(
          "(?is)[\"'](?:mainclass|main_class|entryclass|class)[\"']\\s*[:=]\\s*[\"'][A-Za-z_$][\\w.$]{0,180}[\"']");
  private static final Pattern REMOTE_JOB_COMMAND_VALUE =
      Pattern.compile(
          "(?is)[\"'](?:command|cmd|gluesource|shell)[\"']\\s*[:=]\\s*[\"']([^\"']{1,800})[\"']");
  private static final Set<String> REMOTE_JOB_MECHANISMS =
      Set.of("spark", "sparkrest", "yarn", "hadoop", "flink", "job", "jobscheduler");
  private static final Set<String> REMOTE_JOB_PATH_TERMS =
      Set.of(
          "job",
          "jobs",
          "app",
          "apps",
          "application",
          "applications",
          "submission",
          "submissions",
          "driver",
          "drivers",
          "cluster",
          "batch",
          "batches");
  private static final Set<String> REMOTE_JOB_PATH_ACTIONS =
      Set.of("create", "submit", "submissions", "run", "execute", "apps", "batches");

  static Optional<Detection> detect(
      String mechanism, String descriptor, RequestContext request, boolean artifactPolicy) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    String safeDescriptor = descriptor == null ? "" : descriptor;
    String normalizedMechanism = lower(mechanism).replaceAll("[^a-z0-9]", "");
    if (safeDescriptor.isBlank()
        || !safeRequest.active()
        || !remoteJobSubmissionContext(safeRequest, normalizedMechanism, safeDescriptor)) {
      return Optional.empty();
    }
    if (!normalizedMechanism.equals("spark") && !normalizedMechanism.equals("sparkrest")) {
      var command = REMOTE_JOB_COMMAND_VALUE.matcher(safeDescriptor);
      while (command.find()) {
        String value = command.group(1);
        if (dangerousRemoteJobCommand(value)) {
          return Optional.of(
              Detection.log(
                  "request",
                  "request_remote_job_submission",
                  95,
                  "Request submits a shell command to a job control endpoint",
                  safeRequest,
                  Map.of(
                      "mechanism", abbreviate(mechanism),
                      "uri", abbreviate(safeRequest.uri()),
                      "method", safeRequest.method(),
                      "descriptorLength", String.valueOf(safeDescriptor.length()),
                      "commandLength", String.valueOf(value.length()))));
        }
      }
    }
    if (!artifactPolicy) return Optional.empty();
    var artifact = REMOTE_JOB_ARTIFACT.matcher(safeDescriptor);
    if (artifact.find() && REMOTE_JOB_MAIN_CLASS.matcher(safeDescriptor).find()) {
      String artifactUrl = artifact.group(1);
      return Optional.of(
          Detection.log(
              "request",
              "request_remote_job_submission",
              92,
              "Request submits a remote executable artifact to a job control endpoint",
              safeRequest,
              Map.of(
                  "mechanism", abbreviate(mechanism),
                  "uri", abbreviate(safeRequest.uri()),
                  "method", safeRequest.method(),
                  "descriptorLength", String.valueOf(safeDescriptor.length()),
                  "decision_basis", "artifact_descriptor_only",
                  "artifactScheme", protocolOf(artifactUrl),
                  "artifactType", extensionOf(artifactUrl))));
    }
    return Optional.empty();
  }

  private static boolean remoteJobSubmissionContext(
      RequestContext request, String normalizedMechanism, String descriptor) {
    if (REMOTE_JOB_MECHANISMS.contains(normalizedMechanism)) {
      return true;
    }
    String uri = lower(request.uri());
    if (uri.contains("/v1/submissions")
        || uri.contains("/ws/v1/cluster/apps")
        || uri.contains("/cluster/apps")) {
      return true;
    }
    boolean term = containsPathToken(uri, REMOTE_JOB_PATH_TERMS);
    boolean action = containsPathToken(uri, REMOTE_JOB_PATH_ACTIONS);
    if ((term && action) || (uri.contains("job") && uri.contains("submission"))) {
      return remoteJobDescriptorFields(descriptor);
    }
    for (String name : request.parameters().keySet()) {
      String normalizedName = normalizeParameterName(name);
      if (normalizedName.equals("appresource")
          || normalizedName.equals("mainclass")
          || normalizedName.equals("sparkjars")
          || normalizedName.equals("applicationid")) {
        return true;
      }
    }
    return false;
  }

  private static boolean remoteJobDescriptorFields(String descriptor) {
    String normalized = lower(descriptor);
    return normalized.contains("appresource")
        || normalized.contains("mainclass")
        || normalized.contains("spark.jars")
        || normalized.contains("am-container-spec")
        || normalized.contains("application-id")
        || normalized.contains("gluesource");
  }
}
