package io.ohmyrasp.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

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
