package io.ohmyrasp.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.policy.AgentPolicy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class AgentRuntimeTest {

  @Test
  void modeParsingAcceptsSynonyms() {
    assertEquals(DetectionMode.OFF, DetectionMode.parse("off"));
    assertEquals(DetectionMode.OFF, DetectionMode.parse("DISABLED"));
    assertEquals(DetectionMode.MONITOR, DetectionMode.parse("record"));
    assertEquals(DetectionMode.MONITOR, DetectionMode.parse(" Observe "));
    assertEquals(DetectionMode.BLOCK, DetectionMode.parse("protect"));
    assertNull(DetectionMode.parse("nonsense"));
    assertNull(DetectionMode.parse(null));
  }

  @Test
  void unsetModePreservesLegacyBehavior() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    assertNull(runtime.mode());
    assertTrue(runtime.detectionEnabled(), "detection on by default");
    assertTrue(runtime.blockingAllowed(), "blocking permitted in legacy mode");
    assertTrue(runtime.isAlgorithmEnabled("sql_userinput"));
  }

  @Test
  void offModeDisablesDetection() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"off\"}");
    assertEquals(DetectionMode.OFF, runtime.mode());
    assertFalse(runtime.detectionEnabled());
    assertFalse(runtime.blockingAllowed());
  }

  @Test
  void monitorModeDetectsButDoesNotBlock() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"monitor\"}");
    assertEquals(DetectionMode.MONITOR, runtime.mode());
    assertTrue(runtime.detectionEnabled());
    assertFalse(runtime.blockingAllowed());
  }

  @Test
  void blockModeAllowsBlocking() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"block\"}");
    assertEquals(DetectionMode.BLOCK, runtime.mode());
    assertTrue(runtime.blockingAllowed());
  }

  @Test
  void algorithmToggleSuppressesNamedAlgorithm() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"block\",\"algorithms\":{\"sql_userinput\":false,\"command\":true}}");
    assertFalse(runtime.isAlgorithmEnabled("sql_userinput"), "explicitly disabled");
    assertTrue(runtime.isAlgorithmEnabled("command"), "explicitly enabled");
    assertTrue(runtime.isAlgorithmEnabled("xxe"), "absent → enabled");
  }

  @Test
  void revisionIsTracked() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"monitor\",\"revision\":7}");
    assertEquals(7, runtime.revision());
  }

  @Test
  void malformedControlDocumentIsIgnored() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"block\"}");
    runtime.apply("not json at all");
    runtime.apply("[1,2,3]");
    // Last good state is retained.
    assertEquals(DetectionMode.BLOCK, runtime.mode());
  }

  @Test
  void onlyACompleteControlObjectWithATopLevelModeChangesTheMode() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"block\"}");
    for (String text :
        new String[] {
          "{\"mode\":\"off\"",
          "{\"mode\":\"of",
          "{\"mode\":\"off\",",
          "{\"policy\":{\"mode\":\"off\"}}",
          "{\"algorithms\":[{\"mode\":\"off\"}]}",
          "{\"note\":\"\\\"mode\\\":\\\"off\\\"\"}",
          "{\"mode\":\"sleep\"}",
          "{\"mode\":\"off\"} trailing",
          "{\"mode\":\"off\"}{}",
          "[{\"mode\":\"off\"}]",
          "{\"mode\":\"off\",}",
          "{\"mode\":off}",
          "{'mode':'off'}",
          "",
        }) {
      runtime.apply(text);
      assertEquals(DetectionMode.BLOCK, runtime.mode(), text);
    }
    runtime.apply("{\"policy\":\"{\\\"mode\\\":\\\"block\\\"}\",\"mode\":\"monitor\"}");
    assertEquals(DetectionMode.MONITOR, runtime.mode());
  }

  @Test
  void aControlFileReadHalfWrittenIsPickedUpOnceCompleteWithTheSameModificationTime(@TempDir Path dir)
      throws Exception {
    Path file = dir.resolve("control.json");
    FileTime sameTime = FileTime.fromMillis(1_500_000_000_000L);
    writeAt(file, "{\"mode\":\"block\"}", FileTime.fromMillis(1_400_000_000_000L));
    AgentRuntime runtime = startPolling(file);
    assertEquals(DetectionMode.BLOCK, runtime.mode());

    writeAt(file, "{\"mode\":\"off\"", sameTime);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.BLOCK, runtime.mode(), "a half-written document changes nothing");
    writeAt(file, "{\"mode\":\"off\"}", sameTime);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode(), "the completed document applies");

    // Content decides, not the modification time: a new document with the same time applies.
    writeAt(file, "{\"mode\":\"monitor\"}", sameTime);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.MONITOR, runtime.mode());
  }

  @Test
  void aMissingControlFileRestoresStartUpSettingsAndAnUnreadableOneKeepsTheLastGoodOnes(@TempDir Path dir)
      throws Exception {
    Path file = dir.resolve("control.json");
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000,mode=block");
    assertEquals(DetectionMode.BLOCK, runtime.mode(), "no file yet");

    String document =
        "{\"mode\":\"off\",\"algorithms\":{\"sql_userinput\":false},\"revision\":4,"
            + "\"policy\":\"{\\\"version\\\":4}\"}";
    Files.writeString(file, document);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode());
    assertFalse(runtime.isAlgorithmEnabled("sql_userinput"));
    assertEquals(4, runtime.revision());
    assertEquals(4, runtime.policy().version());

    // Present but not readable as a document: the daemon replaces the file atomically, so this is
    // transient and the last good settings stay.
    Files.writeString(file, "{\"mode\":\"block\"");
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode(), "truncated content");
    Files.delete(file);
    Files.createDirectory(file);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode(), "a directory in the file's place");
    assertFalse(runtime.isAlgorithmEnabled("sql_userinput"));

    // Removed: every setting taken from the file returns to its start-up value, the policy the
    // file installed included.
    Files.delete(file);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.BLOCK, runtime.mode(), "a missing control file restores the start-up mode");
    assertTrue(runtime.isAlgorithmEnabled("sql_userinput"));
    assertEquals(0, runtime.revision());
    assertSame(AgentPolicy.absent(), runtime.policy(), "the control file's policy is gone");

    // The same document written again applies again, its policy included.
    Files.writeString(file, document);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode(), "the same document after a removal");
    assertFalse(runtime.isAlgorithmEnabled("sql_userinput"));
    assertEquals(4, runtime.policy().version());
  }

  @Test
  void anIgnoreRuleFromARemovedControlFileStopsSuppressingDetections(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("control.json");
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000,mode=block");
    Detection sql = detection("sql_userinput");
    assertFalse(runtime.policy().evaluate(sql, "").ignored(), "no policy at start-up");

    Files.writeString(
        file,
        "{\"mode\":\"monitor\",\"algorithms\":{\"xxe\":false},"
            + "\"policy\":\"{\\\"rules\\\":[{\\\"algorithm\\\":\\\"sql_userinput\\\","
            + "\\\"action\\\":\\\"ignore\\\"}]}\"}");
    runtime.reloadIfChanged();
    AgentRuntime.ControlState fromFile = runtime.state();
    assertEquals(AgentRuntime.PolicySource.CONTROL_FILE, fromFile.policySource());
    assertTrue(fromFile.policy().evaluate(sql, "").ignored(), "the control file's ignore rule");

    Files.delete(file);
    runtime.reloadIfChanged();
    AgentRuntime.ControlState restored = runtime.state();
    assertFalse(
        restored.policy().evaluate(sql, fromFile.policyAgentKey()).ignored(),
        "an ignore rule from a deleted control file still suppresses detections");
    assertSame(AgentPolicy.absent(), restored.policy());
    assertEquals(AgentRuntime.PolicySource.NONE, restored.policySource());
    // One snapshot: everything the file set returned together, and the earlier snapshot a hook may
    // still hold is unchanged.
    assertEquals(DetectionMode.BLOCK, restored.mode());
    assertTrue(restored.isAlgorithmEnabled("xxe"));
    assertEquals(DetectionMode.MONITOR, fromFile.mode());
    assertFalse(fromFile.isAlgorithmEnabled("xxe"));
  }

  @Test
  void aDirectCloudPolicyIsNotTheControlFilesToRemove(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("control.json");
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000,mode=block");
    String document = "{\"policy\":\"{\\\"version\\\":4}\"}";
    Files.writeString(file, document);
    runtime.reloadIfChanged();
    assertEquals(4, runtime.policy().version());

    // The direct-cloud client installs later and owns the policy from then on.
    runtime.installDirectPolicy(AgentPolicy.parse("{\"version\":9}"), "agent-key");
    assertEquals(AgentRuntime.PolicySource.DIRECT_CLOUD, runtime.state().policySource());
    Files.delete(file);
    runtime.reloadIfChanged();
    assertEquals(9, runtime.policy().version(), "removing the control file keeps the cloud policy");
    assertEquals("agent-key", runtime.state().policyAgentKey());

    // A control file that comes back installs its policy again: the last source to install wins.
    Files.writeString(file, document);
    runtime.reloadIfChanged();
    assertEquals(4, runtime.policy().version());
    assertEquals(AgentRuntime.PolicySource.CONTROL_FILE, runtime.state().policySource());
  }

  private static Detection detection(String algorithm) {
    return new Detection(
        Instant.now(), "sql", algorithm, "log", 90, "test", RequestContext.empty(), Map.of());
  }

  /**
   * A runtime polling {@code file}, driven by direct {@link AgentRuntime#reloadIfChanged} calls:
   * its poller thread waits a day before its first poll, so it never runs during a test.
   */
  static AgentRuntime startPolling(Path file) {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000");
    return runtime;
  }

  static void writeAt(Path file, String text, FileTime time) throws Exception {
    Files.writeString(file, text);
    Files.setLastModifiedTime(file, time);
  }

  @Test
  void distributedPolicyIsInstalledOncePerChange() {
    AgentRuntime runtime = AgentRuntime.newForTesting();

    runtime.apply("{\"mode\":\"block\",\"policy\":\"{\\\"version\\\":4}\"}");
    assertEquals(4, runtime.policy().version());
    // A cloud policy installed in between is not replaced by the same control-file policy again.
    runtime.installDirectPolicy(AgentPolicy.parse("{\"version\":9}"), "");
    runtime.apply("{\"mode\":\"monitor\",\"policy\":\"{\\\"version\\\":4}\"}"); // unchanged policy
    assertEquals(9, runtime.policy().version());
    runtime.apply("{\"mode\":\"monitor\",\"policy\":\"{\\\"version\\\":5}\"}"); // changed policy
    assertEquals(5, runtime.policy().version());
    // A policy that does not parse changes nothing.
    runtime.apply("{\"mode\":\"monitor\",\"policy\":\"[1]\"}");
    assertEquals(5, runtime.policy().version());
    assertEquals(AgentRuntime.PolicySource.CONTROL_FILE, runtime.state().policySource());
  }
}
