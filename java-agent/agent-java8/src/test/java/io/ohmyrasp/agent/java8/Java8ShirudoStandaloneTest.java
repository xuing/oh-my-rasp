package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

final class Java8ShirudoStandaloneTest {
  @AfterEach
  void clearProperties() {
    System.clearProperty("ohmyrasp.standalone");
    System.clearProperty("ohmyrasp.mode");
    System.clearProperty("ohmyrasp.control");
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.log");
    System.clearProperty("ohmyrasp.latency_sample");
  }

  @Test
  void legacyDefaultsWhenShirudoPropertiesAreAbsent() {
    RaspRuntime.Config config = RaspRuntime.Config.resolve(null, null, null);

    assertFalse(config.standalone);
    assertFalse(config.lockConfig);
    assertNull(config.mode);
    assertFalse(config.controlDisabled);
    assertEquals(Paths.get("/tmp/ohmyrasp-control.json"), config.controlPath);
    assertNull(config.logPath);
    assertEquals(10, config.latencySample);
  }

  @Test
  void standaloneDefaultsModeBlockControlNoneLogStderrAndLatencyZero() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");

    RaspRuntime.Config config = RaspRuntime.Config.resolve(baked, null, null);

    assertTrue(config.standalone);
    assertFalse(config.lockConfig);
    assertEquals(RaspRuntime.Mode.BLOCK, config.mode);
    assertTrue(config.controlDisabled);
    assertNull(config.controlPath);
    assertEquals("stderr", config.logPath);
    assertEquals(0, config.latencySample);
  }

  @Test
  void lockConfigTrueOverridesHostileSyspropsAndEnvironment() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");
    baked.setProperty("lock_config", "true");
    baked.setProperty("mode", "block");
    baked.setProperty("control", "none");
    baked.setProperty("log", "stderr");
    baked.setProperty("latency_sample", "0");

    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.standalone", "false");
    sysProps.setProperty("ohmyrasp.mode", "off");
    sysProps.setProperty("ohmyrasp.control", "/tmp/x");

    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_STANDALONE", "false");
    env.put("OHMYRASP_MODE", "disabled");
    env.put("OHMYRASP_CONTROL", "/tmp/y");

    RaspRuntime.Config config = RaspRuntime.Config.resolve(baked, sysProps, env);

    assertTrue(config.standalone);
    assertTrue(config.lockConfig);
    assertEquals(RaspRuntime.Mode.BLOCK, config.mode);
    assertTrue(config.controlDisabled);
    assertNull(config.controlPath);
    assertEquals("stderr", config.logPath);
    assertEquals(0, config.latencySample);
  }

  @Test
  void lockConfigCannotBeEnabledViaSyspropOrEnv() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");
    baked.setProperty("mode", "block");

    Properties sysProps = new Properties();
    sysProps.setProperty("lock_config", "true");
    sysProps.setProperty("ohmyrasp.lock_config", "true");
    sysProps.setProperty("ohmyrasp.mode", "monitor");

    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_LOCK_CONFIG", "true");

    RaspRuntime.Config config = RaspRuntime.Config.resolve(baked, sysProps, env);

    assertFalse(config.lockConfig);
    assertEquals(RaspRuntime.Mode.MONITOR, config.mode);
  }

  @Test
  void unlockedPrecedenceFollowsSyspropOverEnvOverBakedOverDefaults() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");
    baked.setProperty("lock_config", "false");
    baked.setProperty("mode", "block");
    baked.setProperty("control", "none");
    baked.setProperty("log", "/var/log/baked.jsonl");
    baked.setProperty("latency_sample", "5");

    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_MODE", "monitor");
    env.put("OHMYRASP_CONTROL", "/tmp/env-control.json");
    env.put("OHMYRASP_LOG", "/tmp/env.jsonl");
    env.put("OHMYRASP_LATENCY_SAMPLE", "20");

    RaspRuntime.Config envWins = RaspRuntime.Config.resolve(baked, null, env);
    assertEquals(RaspRuntime.Mode.MONITOR, envWins.mode);
    assertFalse(envWins.controlDisabled);
    assertEquals(Paths.get("/tmp/env-control.json"), envWins.controlPath);
    assertEquals("/tmp/env.jsonl", envWins.logPath);
    assertEquals(20, envWins.latencySample);

    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.mode", "off");
    sysProps.setProperty("ohmyrasp.control", "disabled");
    sysProps.setProperty("ohmyrasp.log", "/tmp/sys.jsonl");
    sysProps.setProperty("ohmyrasp.latency_sample", "0");

    RaspRuntime.Config sysWins = RaspRuntime.Config.resolve(baked, sysProps, env);
    assertEquals(RaspRuntime.Mode.OFF, sysWins.mode);
    assertTrue(sysWins.controlDisabled);
    assertNull(sysWins.controlPath);
    assertEquals("/tmp/sys.jsonl", sysWins.logPath);
    assertEquals(0, sysWins.latencySample);

    sysProps.setProperty("ohmyrasp.java8.log", "/tmp/java8-sys.jsonl");
    RaspRuntime.Config java8SysWins = RaspRuntime.Config.resolve(baked, sysProps, env);
    assertEquals("/tmp/java8-sys.jsonl", java8SysWins.logPath);
  }

  @Test
  void parsesModeAliasesAndControlDisabledAliases() {
    assertEquals(RaspRuntime.Mode.OFF, RaspRuntime.parseMode("off"));
    assertEquals(RaspRuntime.Mode.OFF, RaspRuntime.parseMode("DISABLED"));
    assertEquals(RaspRuntime.Mode.OFF, RaspRuntime.parseMode(" none "));
    assertEquals(RaspRuntime.Mode.MONITOR, RaspRuntime.parseMode("monitor"));
    assertEquals(RaspRuntime.Mode.MONITOR, RaspRuntime.parseMode("record"));
    assertEquals(RaspRuntime.Mode.MONITOR, RaspRuntime.parseMode("observe"));
    assertEquals(RaspRuntime.Mode.MONITOR, RaspRuntime.parseMode("log"));
    assertEquals(RaspRuntime.Mode.BLOCK, RaspRuntime.parseMode("block"));
    assertEquals(RaspRuntime.Mode.BLOCK, RaspRuntime.parseMode("blocking"));
    assertEquals(RaspRuntime.Mode.BLOCK, RaspRuntime.parseMode("protect"));
    assertNull(RaspRuntime.parseMode("unknown"));

    String[] disabledTokens = new String[] {"none", "off", "disabled", " NONE ", "Off", "DISABLED"};
    for (int i = 0; i < disabledTokens.length; i++) {
      Properties sysProps = new Properties();
      sysProps.setProperty("ohmyrasp.control", disabledTokens[i]);
      RaspRuntime.Config cfg = RaspRuntime.Config.resolve(null, sysProps, null);
      assertTrue(cfg.controlDisabled, "Expected disabled for " + disabledTokens[i]);
      assertNull(cfg.controlPath);
    }
  }

  @Test
  void specialLogTargetsDoNotCreateFilesAndRouteToExpectedStreams() throws Exception {
    assertFalse(RaspRuntime.isFileLogTarget(null));
    assertFalse(RaspRuntime.isFileLogTarget(""));
    assertFalse(RaspRuntime.isFileLogTarget("stderr"));
    assertFalse(RaspRuntime.isFileLogTarget("STDERR"));
    assertFalse(RaspRuntime.isFileLogTarget("stdout"));
    assertFalse(RaspRuntime.isFileLogTarget("STDOUT"));
    assertFalse(RaspRuntime.isFileLogTarget("none"));
    assertFalse(RaspRuntime.isFileLogTarget("NONE"));
    assertTrue(RaspRuntime.isFileLogTarget("/tmp/ohmyrasp-test.jsonl"));

    PrintStream origErr = System.err;
    PrintStream origOut = System.out;
    ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
    ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
    Path tempDir = Files.createTempDirectory("ohmyrasp-special-log-check");
    String prevUserDir = System.getProperty("user.dir");
    try {
      System.setErr(new PrintStream(errBuf, true, "UTF-8"));
      System.setOut(new PrintStream(outBuf, true, "UTF-8"));

      RaspRuntime.writeEvent("stderr", "{\"msg\":\"err-line\"}");
      RaspRuntime.writeStartupLine("STDERR", "{\"msg\":\"err-start\"}");
      RaspRuntime.writeEvent("stdout", "{\"msg\":\"out-line\"}");
      RaspRuntime.writeStartupLine("STDOUT", "{\"msg\":\"out-start\"}");
      RaspRuntime.writeEvent("none", "{\"msg\":\"drop-line\"}");
      RaspRuntime.writeStartupLine("NONE", "{\"msg\":\"drop-start\"}");
      RaspRuntime.writeEvent(null, "{\"msg\":\"null-line\"}");

      String errText = new String(errBuf.toByteArray(), StandardCharsets.UTF_8);
      String outText = new String(outBuf.toByteArray(), StandardCharsets.UTF_8);
      assertTrue(errText.contains("err-line"));
      assertTrue(errText.contains("err-start"));
      assertTrue(errText.contains("null-line"));
      assertFalse(errText.contains("drop-line"));
      assertTrue(outText.contains("out-line"));
      assertTrue(outText.contains("out-start"));
      assertFalse(outText.contains("drop-line"));
      assertFalse(Files.exists(Paths.get("stderr")));
      assertFalse(Files.exists(Paths.get("stdout")));
      assertFalse(Files.exists(Paths.get("none")));
    } finally {
      System.setErr(origErr);
      System.setOut(origOut);
      if (prevUserDir != null) {
        System.setProperty("user.dir", prevUserDir);
      }
      Files.deleteIfExists(tempDir);
    }
  }

  @Test
  void blockingAllowedFollowsModeAndStandaloneRules() {
    assertTrue(RaspRuntime.blockingAllowed(false, RaspRuntime.Mode.BLOCK, false));
    assertTrue(RaspRuntime.blockingAllowed(true, RaspRuntime.Mode.BLOCK, false));
    assertFalse(RaspRuntime.blockingAllowed(false, RaspRuntime.Mode.MONITOR, true));
    assertFalse(RaspRuntime.blockingAllowed(true, RaspRuntime.Mode.MONITOR, true));
    assertFalse(RaspRuntime.blockingAllowed(false, RaspRuntime.Mode.OFF, true));
    assertFalse(RaspRuntime.blockingAllowed(true, RaspRuntime.Mode.OFF, true));
    assertTrue(RaspRuntime.blockingAllowed(true, null, false));
    assertTrue(RaspRuntime.blockingAllowed(false, null, true));
    assertFalse(RaspRuntime.blockingAllowed(false, null, false));
  }

  @Test
  void resolveCurrentReadsSystemPropertiesDynamically() {
    System.setProperty("ohmyrasp.java8.log", "stdout");
    System.setProperty("ohmyrasp.latency_sample", "0");

    RaspRuntime.Config current = RaspRuntime.Config.resolveCurrent();
    assertEquals("stdout", current.logPath);
    assertEquals(0, current.latencySample);
    assertEquals("stdout", RaspRuntime.resolveLogPath());
  }

  @Test
  void latencySamplingIgnoresNegativeAndZeroSampleRateWithoutThrowing() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");
    RaspRuntime.Config config =
        RaspRuntime.Config.resolve(baked, null, Collections.<String, String>emptyMap());
    assertEquals(0, config.latencySample);
    RaspRuntime.sampleLatency(-1L);
    RaspRuntime.sampleLatency(100L);
  }
}
