package io.ohmyrasp.agent.java11;

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

final class Java11ShirudoStandaloneTest {
  @AfterEach
  void clearProperties() {
    System.clearProperty("ohmyrasp.java11.log");
    System.clearProperty("ohmyrasp.log");
    System.clearProperty("ohmyrasp.standalone");
    System.clearProperty("ohmyrasp.mode");
    System.clearProperty("ohmyrasp.control");
    System.clearProperty("ohmyrasp.latency_sample");
    System.clearProperty("ohmyrasp.lock_config");
    System.clearProperty("ohmyrasp.java11.block");
  }

  @Test
  void resolvesLegacyDefaultsWhenUnset() {
    RaspRuntime.Config config =
        RaspRuntime.resolve(new Properties(), new Properties(), Collections.<String, String>emptyMap());

    assertFalse(config.standalone);
    assertFalse(config.lockConfig);
    assertNull(config.mode);
    assertFalse(config.controlDisabled);
    assertEquals("/tmp/ohmyrasp-control.json", config.controlPath);
    assertNull(config.logPath);
    assertEquals(10, config.latencySample);
  }

  @Test
  void resolvesStandaloneDefaultsWhenStandaloneEnabled() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");

    RaspRuntime.Config config =
        RaspRuntime.resolve(baked, new Properties(), Collections.<String, String>emptyMap());

    assertTrue(config.standalone);
    assertFalse(config.lockConfig);
    assertNull(config.mode);
    assertTrue(config.controlDisabled);
    assertNull(config.controlPath);
    assertEquals("stderr", config.logPath);
    assertEquals(0, config.latencySample);
  }

  @Test
  void parsesModeAndControlAliases() {
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

    String[] disabledTokens = new String[] {"none", "OFF", "Disabled"};
    for (int i = 0; i < disabledTokens.length; i++) {
      Properties sys = new Properties();
      sys.setProperty("ohmyrasp.control", disabledTokens[i]);
      RaspRuntime.Config config =
          RaspRuntime.resolve(new Properties(), sys, Collections.<String, String>emptyMap());
      assertTrue(config.controlDisabled);
      assertNull(config.controlPath);
    }
  }

  @Test
  void unlockedConfigUsesSyspropOverEnvOverBaked() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "false");
    baked.setProperty("mode", "off");
    baked.setProperty("control", "/baked/control.json");
    baked.setProperty("log", "/baked/log.jsonl");
    baked.setProperty("latency_sample", "5");

    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_STANDALONE", "true");
    env.put("OHMYRASP_MODE", "monitor");
    env.put("OHMYRASP_CONTROL", "/env/control.json");
    env.put("OHMYRASP_LOG", "/env/log.jsonl");
    env.put("OHMYRASP_LATENCY_SAMPLE", "25");

    Properties sys = new Properties();
    sys.setProperty("ohmyrasp.standalone", "false");
    sys.setProperty("ohmyrasp.mode", "block");
    sys.setProperty("ohmyrasp.control", "/sys/control.json");
    sys.setProperty("ohmyrasp.log", "/sys/log.jsonl");
    sys.setProperty("ohmyrasp.java11.log", "/sys/java11.jsonl");
    sys.setProperty("ohmyrasp.latency_sample", "0");

    RaspRuntime.Config fromSys = RaspRuntime.resolve(baked, sys, env);
    assertFalse(fromSys.standalone);
    assertEquals(RaspRuntime.Mode.BLOCK, fromSys.mode);
    assertFalse(fromSys.controlDisabled);
    assertEquals("/sys/control.json", fromSys.controlPath);
    assertEquals("/sys/java11.jsonl", fromSys.logPath);
    assertEquals(0, fromSys.latencySample);

    RaspRuntime.Config fromEnv = RaspRuntime.resolve(baked, new Properties(), env);
    assertTrue(fromEnv.standalone);
    assertEquals(RaspRuntime.Mode.MONITOR, fromEnv.mode);
    assertEquals("/env/control.json", fromEnv.controlPath);
    assertEquals("/env/log.jsonl", fromEnv.logPath);
    assertEquals(25, fromEnv.latencySample);

    RaspRuntime.Config fromBaked =
        RaspRuntime.resolve(baked, new Properties(), Collections.<String, String>emptyMap());
    assertFalse(fromBaked.standalone);
    assertEquals(RaspRuntime.Mode.OFF, fromBaked.mode);
    assertEquals("/baked/control.json", fromBaked.controlPath);
    assertEquals("/baked/log.jsonl", fromBaked.logPath);
    assertEquals(5, fromBaked.latencySample);
  }

  @Test
  void lockConfigIsReadOnlyFromBakedPropertiesAndLocksCoreFields() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");
    baked.setProperty("lock_config", "true");
    baked.setProperty("mode", "block");
    baked.setProperty("control", "none");
    baked.setProperty("log", "stderr");
    baked.setProperty("latency_sample", "0");

    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_STANDALONE", "false");
    env.put("OHMYRASP_LOCK_CONFIG", "false");
    env.put("OHMYRASP_MODE", "off");
    env.put("OHMYRASP_CONTROL", "/tmp/evil.json");
    env.put("OHMYRASP_LOG", "/tmp/env.jsonl");
    env.put("OHMYRASP_LATENCY_SAMPLE", "50");

    Properties sys = new Properties();
    sys.setProperty("ohmyrasp.standalone", "false");
    sys.setProperty("ohmyrasp.lock_config", "false");
    sys.setProperty("ohmyrasp.mode", "monitor");
    sys.setProperty("ohmyrasp.control", "/tmp/override.json");
    sys.setProperty("ohmyrasp.java11.log", "/tmp/override.jsonl");
    sys.setProperty("ohmyrasp.latency_sample", "12");

    RaspRuntime.Config locked = RaspRuntime.resolve(baked, sys, env);
    assertTrue(locked.lockConfig);
    assertTrue(locked.standalone);
    assertEquals(RaspRuntime.Mode.BLOCK, locked.mode);
    assertTrue(locked.controlDisabled);
    assertNull(locked.controlPath);
    assertEquals("/tmp/override.jsonl", locked.logPath);
    assertEquals(12, locked.latencySample);

    // lock_config cannot be enabled via sysprop or env when baked is unlocked.
    Properties unlockedBaked = new Properties();
    unlockedBaked.setProperty("mode", "off");
    sys.setProperty("ohmyrasp.lock_config", "true");
    env.put("OHMYRASP_LOCK_CONFIG", "true");
    RaspRuntime.Config stillUnlocked = RaspRuntime.resolve(unlockedBaked, sys, env);
    assertFalse(stillUnlocked.lockConfig);
    assertEquals(RaspRuntime.Mode.MONITOR, stillUnlocked.mode);
  }

  @Test
  void blockingAllowedHonorsModeStandaloneAndLegacyFlag() {
    RaspRuntime.Config legacy =
        RaspRuntime.resolve(new Properties(), new Properties(), Collections.<String, String>emptyMap());
    Properties standaloneProps = new Properties();
    standaloneProps.setProperty("standalone", "true");
    RaspRuntime.Config standalone =
        RaspRuntime.resolve(standaloneProps, new Properties(), Collections.<String, String>emptyMap());

    assertTrue(RaspRuntime.blockingAllowed(legacy, RaspRuntime.Mode.BLOCK, false));
    assertFalse(RaspRuntime.blockingAllowed(standalone, RaspRuntime.Mode.MONITOR, true));
    assertFalse(RaspRuntime.blockingAllowed(standalone, RaspRuntime.Mode.OFF, true));
    assertTrue(RaspRuntime.blockingAllowed(standalone, null, false));
    assertFalse(RaspRuntime.blockingAllowed(legacy, null, false));
    assertTrue(RaspRuntime.blockingAllowed(legacy, null, true));
  }

  @Test
  void writeEventAndStartupLineHandleStreamsNoneAndFilesWithoutLiteralArtifacts() throws Exception {
    assertFalse(RaspRuntime.isFileLogTarget(null));
    assertFalse(RaspRuntime.isFileLogTarget("stderr"));
    assertFalse(RaspRuntime.isFileLogTarget("STDERR"));
    assertFalse(RaspRuntime.isFileLogTarget("stdout"));
    assertFalse(RaspRuntime.isFileLogTarget("none"));
    assertTrue(RaspRuntime.isFileLogTarget("/tmp/ohmyrasp.jsonl"));

    PrintStream origOut = System.out;
    PrintStream origErr = System.err;
    ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
    ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
    try {
      System.setOut(new PrintStream(outBuf, true, "UTF-8"));
      System.setErr(new PrintStream(errBuf, true, "UTF-8"));

      RaspRuntime.writeStartupLine("stderr", "{\"startup\":\"err\"}");
      RaspRuntime.writeEvent(null, "{\"event\":\"null_err\"}");
      RaspRuntime.writeStartupLine("stdout", "{\"startup\":\"out\"}");
      RaspRuntime.writeEvent("STDOUT", "{\"event\":\"std_out\"}");
      RaspRuntime.writeStartupLine("none", "{\"startup\":\"none\"}");
      RaspRuntime.writeEvent("NONE", "{\"event\":\"none\"}");
    } finally {
      System.setOut(origOut);
      System.setErr(origErr);
    }

    String outText = new String(outBuf.toByteArray(), StandardCharsets.UTF_8);
    String errText = new String(errBuf.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(errText.contains("{\"startup\":\"err\"}"));
    assertTrue(errText.contains("{\"event\":\"null_err\"}"));
    assertTrue(outText.contains("{\"startup\":\"out\"}"));
    assertTrue(outText.contains("{\"event\":\"std_out\"}"));
    assertFalse(outText.contains("none"));
    assertFalse(errText.contains("none"));
    assertFalse(Files.exists(Paths.get("stderr")));
    assertFalse(Files.exists(Paths.get("stdout")));
    assertFalse(Files.exists(Paths.get("none")));

    Path tempDir = Files.createTempDirectory("ohmyrasp-java11-standalone-test");
    Path logFile = tempDir.resolve("nested/events.jsonl");
    System.setProperty("ohmyrasp.java11.log", "none");
    OhMyRaspJava11Agent.premain("", null);
    Java11RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "cat /etc/passwd"));
    assertFalse(Files.exists(Paths.get("none")));

    System.setProperty("ohmyrasp.java11.log", logFile.toString());
    OhMyRaspJava11Agent.premain("", null);
    Java11RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "cat /etc/shadow"));

    String content = new String(Files.readAllBytes(logFile), StandardCharsets.UTF_8);
    assertTrue(content.contains("\"event\":\"ohmyrasp-java11-agent-start\""));
    assertTrue(content.contains("\"event\":\"ohmyrasp-detection\""));
  }
}
