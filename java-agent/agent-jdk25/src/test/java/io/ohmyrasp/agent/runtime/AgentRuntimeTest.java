package io.ohmyrasp.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
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
    java.util.List<String> installed = new java.util.ArrayList<>();
    runtime.setPolicyInstaller(installed::add);

    runtime.apply("{\"mode\":\"block\",\"policy\":\"{\\\"version\\\":4}\"}");
    runtime.apply("{\"mode\":\"monitor\",\"policy\":\"{\\\"version\\\":4}\"}"); // unchanged policy
    runtime.apply("{\"mode\":\"monitor\",\"policy\":\"{\\\"version\\\":5}\"}"); // changed policy

    assertEquals(java.util.List.of("{\"version\":4}", "{\"version\":5}"), installed);
  }
}
