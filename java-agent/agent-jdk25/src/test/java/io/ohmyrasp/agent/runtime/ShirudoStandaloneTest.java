package io.ohmyrasp.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ShirudoStandaloneTest {

  private static final List<String> MANAGED_PROPERTIES =
      List.of(
          "ohmyrasp.mode",
          "ohmyrasp.standalone",
          "ohmyrasp.control",
          "ohmyrasp.log",
          "ohmyrasp.latency_sample",
          "ohmyrasp.lock_config");

  @AfterEach
  void clearProperties() {
    for (String key : MANAGED_PROPERTIES) {
      System.clearProperty(key);
    }
  }

  @Test
  void shirudoDefaultsParsesPropertiesAndAbsent() {
    ShirudoDefaults absent = ShirudoDefaults.absent();
    assertFalse(absent.isPresent());
    assertFalse(absent.standalone());
    assertFalse(absent.lockConfig());
    assertNull(absent.mode());
    assertNull(absent.control());
    assertNull(absent.log());
    assertNull(absent.latencySample());

    Properties props = new Properties();
    props.setProperty("standalone", "true");
    props.setProperty("lock_config", "1");
    props.setProperty("mode", "monitor");
    props.setProperty("control", "none");
    props.setProperty("log", "stderr");
    props.setProperty("latency_sample", "0");

    ShirudoDefaults loaded = ShirudoDefaults.fromProperties(props);
    assertTrue(loaded.isPresent());
    assertTrue(loaded.standalone());
    assertTrue(loaded.lockConfig());
    assertEquals(DetectionMode.MONITOR, loaded.mode());
    assertEquals("none", loaded.control());
    assertEquals("stderr", loaded.log());
    assertEquals(0, loaded.latencySample());
  }

  @Test
  void shirudoDefaultsLoadReturnsAbsentWhenResourceMissingFromClasspath() {
    ShirudoDefaults loaded = ShirudoDefaults.load();
    assertFalse(loaded.isPresent());
  }

  @Test
  void lockConfigCannotBeEnabledViaSyspropOrAgentArgs() {
    System.setProperty("ohmyrasp.lock_config", "true");
    AgentRuntime runtime = AgentRuntime.newForTesting(ShirudoDefaults.absent());
    runtime.start("lock_config=true,mode=monitor,standalone=false");

    assertFalse(runtime.shirudoDefaults().lockConfig());
    assertFalse(runtime.isDirectCloudDisabled());
    assertEquals(DetectionMode.MONITOR, runtime.mode());
  }

  @Test
  void lockedStandaloneIgnoresHostileModeControlAndStandaloneOverrides(@TempDir Path tempDir)
      throws Exception {
    Path hostileControl = tempDir.resolve("evil-control.json");
    Files.writeString(hostileControl, "{\"mode\":\"off\",\"revision\":99}");

    System.setProperty("ohmyrasp.mode", "off");
    System.setProperty("ohmyrasp.standalone", "false");
    System.setProperty("ohmyrasp.control", hostileControl.toString());

    Properties props = new Properties();
    props.setProperty("standalone", "true");
    props.setProperty("lock_config", "true");
    props.setProperty("mode", "block");
    props.setProperty("control", "none");
    props.setProperty("log", "stderr");
    props.setProperty("latency_sample", "0");

    ShirudoDefaults defaults = ShirudoDefaults.fromProperties(props);
    AgentRuntime runtime = AgentRuntime.newForTesting(defaults);

    long beforeThreads = countThreadsNamed("ohmyrasp-control-poller");
    runtime.start(
        "mode=off,standalone=false,cloud_direct=true,control="
            + hostileControl
            + ",log=stdout,latency_sample=5");

    assertTrue(runtime.isStandalone());
    assertTrue(runtime.isControlPollingDisabled());
    assertTrue(runtime.isDirectCloudDisabled());
    assertEquals(DetectionMode.BLOCK, runtime.mode());
    assertTrue(runtime.blockingAllowed());
    assertEquals("stdout", runtime.agentArgLogTarget());
    assertEquals(5, runtime.agentArgLatencySample());
    assertEquals(beforeThreads, countThreadsNamed("ohmyrasp-control-poller"));
  }

  @Test
  void unlockedStandaloneAllowsExplicitModeOverrideAndDefaultsUnsetToBlock() {
    Properties props = new Properties();
    props.setProperty("standalone", "true");
    props.setProperty("lock_config", "false");
    props.setProperty("control", "none");

    AgentRuntime defaulted = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    defaulted.start(null);
    assertTrue(defaulted.isStandalone());
    assertTrue(defaulted.isControlPollingDisabled());
    assertTrue(defaulted.isDirectCloudDisabled());
    assertEquals(DetectionMode.BLOCK, defaulted.mode());

    AgentRuntime overridden = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    overridden.start("mode=monitor");
    assertEquals(DetectionMode.MONITOR, overridden.mode());
    assertFalse(overridden.blockingAllowed());
  }

  @Test
  void controlDisabledTokensPreventPollerThreadCreation() {
    for (String token : List.of("none", "OFF", "DiSaBlEd")) {
      long before = countThreadsNamed("ohmyrasp-control-poller");
      AgentRuntime runtime = AgentRuntime.newForTesting();
      runtime.start("control=" + token);
      assertTrue(runtime.isControlPollingDisabled(), "expected disabled for control=" + token);
      assertFalse(runtime.isStandalone());
      assertEquals(before, countThreadsNamed("ohmyrasp-control-poller"));
    }
  }

  @Test
  void loggerStderrModeWritesDetectionsToStderrWithoutFileOrThreads(@TempDir Path tempDir) {
    ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
    ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
    Properties props = new Properties();
    props.setProperty("standalone", "true");
    props.setProperty("log", "stderr");
    props.setProperty("latency_sample", "0");

    long writerBefore = countThreadsNamed("ohmyrasp-event-writer");
    JsonEventLogger logger =
        JsonEventLogger.newForTesting(
            ShirudoDefaults.fromProperties(props),
            null,
            null,
            false,
            new PrintStream(outBuf, true, StandardCharsets.UTF_8),
            new PrintStream(errBuf, true, StandardCharsets.UTF_8));

    assertEquals("stderr", logger.logTarget());
    assertNull(logger.logPath());
    assertEquals(0, logger.latencySampleRate());
    assertEquals(writerBefore, countThreadsNamed("ohmyrasp-event-writer"));

    logger.sampleHookLatency("http_request", 42);
    assertEquals("", errBuf.toString(StandardCharsets.UTF_8));
    assertEquals("", outBuf.toString(StandardCharsets.UTF_8));

    logger.record(sampleDetection(), 15, 3);
    String errText = errBuf.toString(StandardCharsets.UTF_8);
    assertTrue(errText.startsWith("[OHMYRASP] {"));
    assertTrue(errText.contains("\"algorithm\":\"sql_userinput\""));
    assertEquals("", outBuf.toString(StandardCharsets.UTF_8));
    assertFalse(Files.exists(tempDir.resolve("ohmyrasp-events.jsonl")));
  }

  @Test
  void loggerStdoutAndNoneModesRespectTargetAndLatencySampleZero() {
    ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
    ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
    JsonEventLogger stdoutLogger =
        JsonEventLogger.newForTesting(
            ShirudoDefaults.absent(),
            "STDOUT",
            0,
            false,
            new PrintStream(outBuf, true, StandardCharsets.UTF_8),
            new PrintStream(errBuf, true, StandardCharsets.UTF_8));

    assertEquals("stdout", stdoutLogger.logTarget());
    assertEquals(0, stdoutLogger.latencySampleRate());
    stdoutLogger.sampleHookLatency("sql", 20);
    stdoutLogger.record(sampleDetection(), 11, 2);

    String outText = outBuf.toString(StandardCharsets.UTF_8);
    assertTrue(outText.startsWith("[OHMYRASP] {"));
    assertFalse(outText.contains("\"kind\":\"telemetry\""));
    assertEquals("", errBuf.toString(StandardCharsets.UTF_8));

    ByteArrayOutputStream noneOut = new ByteArrayOutputStream();
    ByteArrayOutputStream noneErr = new ByteArrayOutputStream();
    JsonEventLogger noneLogger =
        JsonEventLogger.newForTesting(
            ShirudoDefaults.absent(),
            "none",
            0,
            false,
            new PrintStream(noneOut, true, StandardCharsets.UTF_8),
            new PrintStream(noneErr, true, StandardCharsets.UTF_8));

    assertEquals("none", noneLogger.logTarget());
    noneLogger.sampleHookLatency("sql", 20);
    noneLogger.record(sampleDetection(), 11, 2);
    assertEquals("", noneOut.toString(StandardCharsets.UTF_8));
    assertEquals("", noneErr.toString(StandardCharsets.UTF_8));
  }

  @Test
  void loggerStandaloneDefaultsToStderrAndZeroLatencySampleAndAllowsSyspropOverride() {
    Properties props = new Properties();
    props.setProperty("standalone", "true");
    ShirudoDefaults defaults = ShirudoDefaults.fromProperties(props);

    ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
    ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
    JsonEventLogger standaloneLogger =
        JsonEventLogger.newForTesting(
            defaults,
            null,
            null,
            false,
            new PrintStream(outBuf, true, StandardCharsets.UTF_8),
            new PrintStream(errBuf, true, StandardCharsets.UTF_8));
    assertEquals("stderr", standaloneLogger.logTarget());
    assertEquals(0, standaloneLogger.latencySampleRate());

    System.setProperty("ohmyrasp.log", "stdout");
    System.setProperty("ohmyrasp.latency_sample", "25");
    JsonEventLogger overriddenLogger =
        JsonEventLogger.newForTesting(
            defaults,
            null,
            null,
            false,
            new PrintStream(outBuf, true, StandardCharsets.UTF_8),
            new PrintStream(errBuf, true, StandardCharsets.UTF_8));
    assertEquals("stdout", overriddenLogger.logTarget());
    assertEquals(25, overriddenLogger.latencySampleRate());
  }

  private static Detection sampleDetection() {
    return new Detection(
        Instant.now(),
        "sql",
        "sql_userinput",
        "block",
        95,
        "test detection",
        RequestContext.empty(),
        Map.of("key", "value"));
  }

  private static long countThreadsNamed(String name) {
    return Thread.getAllStackTraces().keySet().stream()
        .filter(thread -> name.equals(thread.getName()))
        .count();
  }
}
