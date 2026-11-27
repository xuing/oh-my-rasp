package io.ohmyrasp.agent.backport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.java8.Java8RaspBlockException;
import io.ohmyrasp.agent.java8.Java8RaspHooks;
import io.ohmyrasp.agent.java8.Java8RaspLine;
import io.ohmyrasp.agent.java8.OhMyRaspJava8Agent;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Configuration precedence, lock_config and log-target routing of the backport RaspRuntime.
 * docs/agent.md "Runtime modes and configuration" describes the contract these tests pin.
 */
final class Java8ShirudoStandaloneTest {
  private static final String WRITER_THREAD = "ohmyrasp-java8-writer";
  private static final String CONTROL_THREAD = "ohmyrasp-java8-control";

  @AfterEach
  void clearProperties() {
    System.clearProperty("ohmyrasp.standalone");
    System.clearProperty("ohmyrasp.mode");
    System.clearProperty("ohmyrasp.control");
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.log");
    System.clearProperty("ohmyrasp.latency_sample");
    System.clearProperty("ohmyrasp.lock_config");
    System.clearProperty("ohmyrasp.java8.block");
  }

  @Test
  void legacyDefaultsWhenShirudoPropertiesAreAbsent() {
    RaspRuntime.Config absent = RaspRuntime.Config.resolve(null, null, null);
    RaspRuntime.Config empty =
        RaspRuntime.Config.resolve(
            new Properties(), new Properties(), Collections.<String, String>emptyMap());

    for (RaspRuntime.Config config : new RaspRuntime.Config[] {absent, empty}) {
      assertFalse(config.standalone);
      assertFalse(config.lockConfig);
      assertNull(config.mode);
      assertFalse(config.controlDisabled);
      assertEquals(Paths.get("/tmp/ohmyrasp-control.json"), config.controlPath);
      assertNull(config.logPath);
      assertEquals(10, config.latencySample);
    }
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
  void lockConfigIgnoresSyspropAndEnvironmentWhenABakedKeyIsMissing() {
    // A locked JAR whose properties lack mode and control: the defaults apply, not sysprop/env.
    Properties baked = new Properties();
    baked.setProperty("lock_config", "true");
    baked.setProperty("standalone", "true");

    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.mode", "off");
    sysProps.setProperty("ohmyrasp.control", "/tmp/hostile-sys-control.json");

    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_MODE", "monitor");
    env.put("OHMYRASP_CONTROL", "/tmp/hostile-env-control.json");

    RaspRuntime.Config missingModeAndControl = RaspRuntime.Config.resolve(baked, sysProps, env);
    assertTrue(missingModeAndControl.lockConfig);
    assertTrue(missingModeAndControl.standalone);
    assertEquals(RaspRuntime.Mode.BLOCK, missingModeAndControl.mode);
    assertTrue(missingModeAndControl.controlDisabled);
    assertNull(missingModeAndControl.controlPath);

    // A locked JAR whose properties lack standalone: it stays false, so legacy defaults apply.
    Properties lockOnly = new Properties();
    lockOnly.setProperty("lock_config", "true");
    sysProps.setProperty("ohmyrasp.standalone", "true");
    env.put("OHMYRASP_STANDALONE", "true");

    RaspRuntime.Config missingStandalone = RaspRuntime.Config.resolve(lockOnly, sysProps, env);
    assertTrue(missingStandalone.lockConfig);
    assertFalse(missingStandalone.standalone);
    assertNull(missingStandalone.mode);
  }

  @Test
  void lockedProfileWithoutABakedControlPathPollsNoControlFile() throws Exception {
    // The default /tmp/ohmyrasp-control.json is world-writable. A locked profile that bakes no
    // control path polls nothing, standalone or not, whatever system properties and env say.
    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.control", "/tmp/hostile-sys-control.json");
    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_CONTROL", "/tmp/hostile-env-control.json");
    String[] standaloneValues = new String[] {null, "false", "true"};
    for (int i = 0; i < standaloneValues.length; i++) {
      Properties baked = new Properties();
      baked.setProperty("lock_config", "true");
      if (standaloneValues[i] != null) {
        baked.setProperty("standalone", standaloneValues[i]);
      }
      RaspRuntime.Config config = RaspRuntime.Config.resolve(baked, sysProps, env);
      assertTrue(config.controlDisabled, "standalone=" + standaloneValues[i]);
      assertNull(config.controlPath, "standalone=" + standaloneValues[i]);
    }

    // A baked control path under lock is polled, the default path included when it is the one
    // baked; standalone never polls (standaloneNeverPollsAControlFileEvenWithAnExplicitPath).
    String[] bakedPaths = new String[] {"/baked/control.json", "/tmp/ohmyrasp-control.json"};
    for (int i = 0; i < 2; i++) {
      for (int j = 0; j < bakedPaths.length; j++) {
        Properties baked = new Properties();
        baked.setProperty("lock_config", "true");
        baked.setProperty("control", bakedPaths[j]);
        if (standaloneValues[i] != null) {
          baked.setProperty("standalone", standaloneValues[i]);
        }
        RaspRuntime.Config config = RaspRuntime.Config.resolve(baked, sysProps, env);
        assertFalse(config.controlDisabled, "standalone=" + standaloneValues[i] + " " + bakedPaths[j]);
        assertEquals(Paths.get(bakedPaths[j]), config.controlPath);
      }
    }

    // The packaged form: a locked JAR without a control key starts no control poller.
    int pollersBefore = threadsNamed(CONTROL_THREAD);
    Map<String, String> init = asyncInit();
    init.remove("ohmyrasp.control");
    loadIsolatedRuntime(init, bakedResource("lock_config=true\nlog=none\n"));
    assertEquals(pollersBefore, threadsNamed(CONTROL_THREAD), "a locked JAR without control polls nothing");
  }

  @Test
  void lockConfigLeavesLogAndLatencySampleOverridable() {
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

    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.standalone", "false");
    sysProps.setProperty("ohmyrasp.lock_config", "false");
    sysProps.setProperty("ohmyrasp.mode", "monitor");
    sysProps.setProperty("ohmyrasp.control", "/tmp/override.json");
    sysProps.setProperty("ohmyrasp.java8.log", "/tmp/override.jsonl");
    sysProps.setProperty("ohmyrasp.latency_sample", "12");

    RaspRuntime.Config locked = RaspRuntime.Config.resolve(baked, sysProps, env);
    assertTrue(locked.lockConfig);
    assertTrue(locked.standalone);
    assertEquals(RaspRuntime.Mode.BLOCK, locked.mode);
    assertTrue(locked.controlDisabled);
    assertNull(locked.controlPath);
    assertEquals("/tmp/override.jsonl", locked.logPath);
    assertEquals(12, locked.latencySample);
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

  /** outside_request resolves like mode: each source on its own, only the baked value under lock_config. */
  @Test
  void outsideRequestResolvesLikeTheMode() {
    assertTrue(RaspRuntime.Config.resolve(null, null, null).outsideRequestBlocks, "the default is block");

    Properties baked = new Properties();
    baked.setProperty("outside_request", "log");
    assertFalse(RaspRuntime.Config.resolve(baked, null, null).outsideRequestBlocks, "baked");

    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_OUTSIDE_REQUEST", "BLOCK");
    assertTrue(RaspRuntime.Config.resolve(baked, null, env).outsideRequestBlocks, "the environment over baked");

    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.outside_request", "sometimes");
    assertTrue(RaspRuntime.Config.resolve(baked, sysProps, env).outsideRequestBlocks,
        "an unusable property leaves the next source in charge");
    sysProps.setProperty("ohmyrasp.outside_request", " log ");
    assertFalse(RaspRuntime.Config.resolve(baked, sysProps, env).outsideRequestBlocks, "the property first");

    baked.setProperty("lock_config", "true");
    baked.setProperty("outside_request", "block");
    assertTrue(RaspRuntime.Config.resolve(baked, sysProps, env).outsideRequestBlocks, "locked: baked only");
    baked.remove("outside_request");
    assertTrue(RaspRuntime.Config.resolve(baked, sysProps, env).outsideRequestBlocks,
        "locked with nothing baked: the default, not the property");
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
    // Not standalone, which never polls: the control path follows the source precedence.
    env.put("OHMYRASP_STANDALONE", "false");
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
  void unlockedStandaloneAndPathsFollowSyspropOverEnvOverBaked() {
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

    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.standalone", "false");
    sysProps.setProperty("ohmyrasp.mode", "block");
    sysProps.setProperty("ohmyrasp.control", "/sys/control.json");
    sysProps.setProperty("ohmyrasp.log", "/sys/log.jsonl");
    sysProps.setProperty("ohmyrasp.java8.log", "/sys/line-log.jsonl");
    sysProps.setProperty("ohmyrasp.latency_sample", "0");

    RaspRuntime.Config fromSys = RaspRuntime.Config.resolve(baked, sysProps, env);
    assertFalse(fromSys.standalone);
    assertEquals(RaspRuntime.Mode.BLOCK, fromSys.mode);
    assertFalse(fromSys.controlDisabled);
    assertEquals(Paths.get("/sys/control.json"), fromSys.controlPath);
    assertEquals("/sys/line-log.jsonl", fromSys.logPath);
    assertEquals(0, fromSys.latencySample);

    RaspRuntime.Config fromEnv = RaspRuntime.Config.resolve(baked, new Properties(), env);
    assertTrue(fromEnv.standalone);
    assertEquals(RaspRuntime.Mode.MONITOR, fromEnv.mode);
    assertNull(fromEnv.controlPath, "standalone never polls");
    env.put("OHMYRASP_STANDALONE", "false");
    assertEquals(
        Paths.get("/env/control.json"),
        RaspRuntime.Config.resolve(baked, new Properties(), env).controlPath);
    env.put("OHMYRASP_STANDALONE", "true");
    assertEquals("/env/log.jsonl", fromEnv.logPath);
    assertEquals(25, fromEnv.latencySample);

    RaspRuntime.Config fromBaked =
        RaspRuntime.Config.resolve(
            baked, new Properties(), Collections.<String, String>emptyMap());
    assertFalse(fromBaked.standalone);
    assertEquals(RaspRuntime.Mode.OFF, fromBaked.mode);
    assertEquals(Paths.get("/baked/control.json"), fromBaked.controlPath);
    assertEquals("/baked/log.jsonl", fromBaked.logPath);
    assertEquals(5, fromBaked.latencySample);
  }

  @Test
  void invalidHigherPriorityValueIsIgnoredAndTheNextSourceApplies() {
    // Security case: a malformed -Dohmyrasp.mode must not mask OHMYRASP_MODE=block, or a
    // non-standalone agent would fall back to legacy mode and allow the operation.
    Properties badSysMode = new Properties();
    badSysMode.setProperty("ohmyrasp.mode", "bogus");
    Map<String, String> envBlock = new HashMap<String, String>();
    envBlock.put("OHMYRASP_MODE", "block");
    RaspRuntime.Config legacy = RaspRuntime.Config.resolve(null, badSysMode, envBlock);
    assertFalse(legacy.standalone);
    assertEquals(RaspRuntime.Mode.BLOCK, legacy.mode);
    assertTrue(RaspRuntime.blockingAllowed(legacy.standalone, legacy.mode, false));

    Properties baked = new Properties();
    baked.setProperty("standalone", "false");
    baked.setProperty("mode", "off");
    baked.setProperty("latency_sample", "5");

    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.mode", "bogus");
    sysProps.setProperty("ohmyrasp.standalone", "maybe");
    sysProps.setProperty("ohmyrasp.latency_sample", "abc");

    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_MODE", "monitor");
    env.put("OHMYRASP_STANDALONE", "true");
    env.put("OHMYRASP_LATENCY_SAMPLE", "7");

    RaspRuntime.Config fromEnv = RaspRuntime.Config.resolve(baked, sysProps, env);
    assertTrue(fromEnv.standalone);
    assertEquals(RaspRuntime.Mode.MONITOR, fromEnv.mode);
    assertEquals(7, fromEnv.latencySample);

    Map<String, String> badEnv = new HashMap<String, String>();
    badEnv.put("OHMYRASP_MODE", "nope");
    badEnv.put("OHMYRASP_STANDALONE", "perhaps");
    badEnv.put("OHMYRASP_LATENCY_SAMPLE", "x");

    RaspRuntime.Config fromBaked = RaspRuntime.Config.resolve(baked, sysProps, badEnv);
    assertFalse(fromBaked.standalone);
    assertEquals(RaspRuntime.Mode.OFF, fromBaked.mode);
    assertEquals(5, fromBaked.latencySample);

    Properties badBaked = new Properties();
    badBaked.setProperty("standalone", "?");
    badBaked.setProperty("mode", "??");
    badBaked.setProperty("latency_sample", "-");
    RaspRuntime.Config defaults = RaspRuntime.Config.resolve(badBaked, sysProps, badEnv);
    assertFalse(defaults.standalone);
    assertNull(defaults.mode);
    assertEquals(10, defaults.latencySample);
    assertEquals(Paths.get("/tmp/ohmyrasp-control.json"), defaults.controlPath);

    // Under lock_config an invalid baked value takes the default; sysprop and env stay ignored.
    Properties lockedBadMode = new Properties();
    lockedBadMode.setProperty("lock_config", "true");
    lockedBadMode.setProperty("standalone", "true");
    lockedBadMode.setProperty("mode", "bogus");
    Properties sysOff = new Properties();
    sysOff.setProperty("ohmyrasp.mode", "off");
    RaspRuntime.Config locked = RaspRuntime.Config.resolve(lockedBadMode, sysOff, env);
    assertEquals(RaspRuntime.Mode.BLOCK, locked.mode);
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
    try {
      System.setErr(new PrintStream(errBuf, true, "UTF-8"));
      System.setOut(new PrintStream(outBuf, true, "UTF-8"));

      RaspRuntime.writeEvent("stderr", "{\"msg\":\"err-line\"}");
      RaspRuntime.writeStartupLine("STDERR", "{\"msg\":\"err-start\"}");
      RaspRuntime.writeEvent("stdout", "{\"msg\":\"out-line\"}");
      RaspRuntime.writeStartupLine("STDOUT", "{\"msg\":\"out-start\"}");
      RaspRuntime.writeEvent("none", "{\"msg\":\"drop-line\"}");
      RaspRuntime.writeEvent("STDERR", "{\"msg\":\"err-upper-line\"}");
      RaspRuntime.writeEvent(" STDOUT ", "{\"msg\":\"out-upper-line\"}");
      RaspRuntime.writeEvent("NONE", "{\"msg\":\"drop-upper-line\"}");
      RaspRuntime.writeStartupLine("NONE", "{\"msg\":\"drop-start\"}");
      RaspRuntime.writeEvent(null, "{\"msg\":\"null-line\"}");
      RaspRuntime.writeStartupLine(null, "{\"msg\":\"null-start\"}");
    } finally {
      System.setErr(origErr);
      System.setOut(origOut);
    }

    String errText = new String(errBuf.toByteArray(), StandardCharsets.UTF_8);
    String outText = new String(outBuf.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(errText.contains("err-line"));
    assertTrue(errText.contains("err-start"));
    assertTrue(errText.contains("err-upper-line"));
    assertTrue(errText.contains("null-line"));
    assertTrue(errText.contains("null-start"));
    assertFalse(errText.contains("drop-"));
    assertTrue(outText.contains("out-line"));
    assertTrue(outText.contains("out-start"));
    assertTrue(outText.contains("out-upper-line"));
    assertFalse(outText.contains("drop-"));
    assertFalse(Files.exists(Paths.get("stderr")));
    assertFalse(Files.exists(Paths.get("stdout")));
    assertFalse(Files.exists(Paths.get("none")));
  }

  @Test
  void nonFileInitialLogTargetWritesLaterFileEventsInlineWithoutAWriterThread() throws Exception {
    Path logFile = Files.createTempDirectory("ohmyrasp-java8-inline-test").resolve("events.jsonl");
    int writersBefore = threadsNamed(WRITER_THREAD);
    Map<String, String> init = asyncInit();
    init.put("ohmyrasp.java8.log", "stderr");
    init.put("ohmyrasp.latency_sample", "1");
    Class<?> runtime = loadIsolatedRuntime(init);
    Method writeEvent = runtime.getMethod("writeEvent", String.class, String.class);

    assertEquals(writersBefore, threadsNamed(WRITER_THREAD), "a stderr target starts no writer");
    writeEvent.invoke(null, "none", "{\"event\":\"dropped\"}");
    writeEvent.invoke(null, logFile.toString(), "{\"event\":\"inline\"}");
    // Inline: the line is on disk when writeEvent returns, and no thread was created for it.
    String content = new String(Files.readAllBytes(logFile), StandardCharsets.UTF_8);
    assertTrue(content.contains("{\"event\":\"inline\"}"), content);
    assertFalse(content.contains("dropped"), content);
    assertEquals(writersBefore, threadsNamed(WRITER_THREAD), "a later file target starts no writer");

    // Latency sampling with sync off and rate 1 reaches the same inline path.
    Method sampleLatency = runtime.getDeclaredMethod("sampleLatency", long.class);
    sampleLatency.setAccessible(true);
    System.setProperty("ohmyrasp.java8.log", logFile.toString());
    try {
      sampleLatency.invoke(null, 4242L);
    } finally {
      System.clearProperty("ohmyrasp.java8.log");
    }
    content = new String(Files.readAllBytes(logFile), StandardCharsets.UTF_8);
    assertTrue(content.contains("\"latency_us\":4242"), content);
    assertEquals(writersBefore, threadsNamed(WRITER_THREAD));
  }

  @Test
  void fileInitialLogTargetStartsTheWriterDuringInitialisation() throws Exception {
    Path logFile = Files.createTempDirectory("ohmyrasp-java8-writer-test").resolve("events.jsonl");
    int writersBefore = threadsNamed(WRITER_THREAD);
    Map<String, String> init = asyncInit();
    init.put("ohmyrasp.java8.log", logFile.toString());
    Class<?> runtime = loadIsolatedRuntime(init);

    assertEquals(writersBefore + 1, threadsNamed(WRITER_THREAD), "the writer exists before any hook");
    Method writeEvent = runtime.getMethod("writeEvent", String.class, String.class);
    writeEvent.invoke(null, logFile.toString(), "{\"event\":\"spooled\"}");
    assertEquals(writersBefore + 1, threadsNamed(WRITER_THREAD), "events reuse that writer");

    String content = "";
    for (int i = 0; i < 100 && !content.contains("spooled"); i++) {
      Thread.sleep(50L);
      content = Files.exists(logFile) ? new String(Files.readAllBytes(logFile), StandardCharsets.UTF_8) : "";
    }
    assertTrue(content.contains("{\"event\":\"spooled\"}"), content);
  }

  @Test
  void malformedBakedPropertiesKeepTheKeysReadBeforeTheBadLine() throws Exception {
    // Properties.load throws IllegalArgumentException on a malformed unicode escape. Initialisation
    // goes on, and the keys read before that line stay: a damaged later line must not erase an
    // already-read lock and let a hostile system property or environment switch detection off.
    Path malformed =
        bakedResource(
            "standalone=true\nlock_config=true\nmode=block\nbad=\\u00zz\nlog=/tmp/after.jsonl\n");
    Map<String, String> init = asyncInit();
    init.put("ohmyrasp.mode", "off");
    init.put("ohmyrasp.standalone", "false");
    Class<?> broken = loadIsolatedRuntime(init, malformed);
    Properties baked = bakedProperties(broken);
    assertEquals("true", baked.getProperty("lock_config"), baked.toString());
    assertEquals("block", baked.getProperty("mode"), baked.toString());
    assertNull(baked.getProperty("log"), "nothing after the malformed line is read");
    Method mode = broken.getDeclaredMethod("mode");
    mode.setAccessible(true);
    assertEquals("BLOCK", String.valueOf(mode.invoke(null)), "-Dohmyrasp.mode=off is ignored");

    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.mode", "off");
    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_MODE", "off");
    RaspRuntime.Config config = RaspRuntime.Config.resolve(baked, sysProps, env);
    assertTrue(config.lockConfig);
    assertEquals(RaspRuntime.Mode.BLOCK, config.mode, "OHMYRASP_MODE=off is ignored");
    Method resolveLogPath = broken.getMethod("resolveLogPath");
    resolveLogPath.invoke(null);

    // Control: the same lookup reads a well-formed resource.
    Path valid = bakedResource("log=none\nlatency_sample=3\n");
    Class<?> readable = loadIsolatedRuntime(asyncInit(), valid);
    assertEquals("none", bakedProperties(readable).getProperty("log"));
    assertEquals("3", bakedProperties(readable).getProperty("latency_sample"));
  }

  @Test
  void bakedPropertiesComeOnlyFromTheRuntimesOwnJarOrDirectory() throws Exception {
    // For a runtime on the bootstrap search, class-relative lookup goes to the system class path,
    // where an application JAR comes before the agent JAR. A same-named resource that is not beside
    // the RaspRuntime classes is therefore not configuration, even when it is found first.
    Path foreign = foreignResource("standalone=true\nlock_config=true\nmode=off\n");
    Class<?> withoutOwn = loadIsolatedRuntime(asyncInit(), foreign);
    assertTrue(bakedProperties(withoutOwn).isEmpty(), bakedProperties(withoutOwn).toString());

    Path own = bakedResource("standalone=true\nlock_config=true\nmode=block\n");
    Class<?> withOwn = loadIsolatedRuntime(asyncInit(), foreign, own);
    assertEquals("block", bakedProperties(withOwn).getProperty("mode"));
    Method mode = withOwn.getDeclaredMethod("mode");
    mode.setAccessible(true);
    assertEquals("BLOCK", String.valueOf(mode.invoke(null)));
  }

  @Test
  void invalidControlPathDoesNotBreakConfigurationOrEventEmission() throws Exception {
    String invalid = "bad\0control.json";
    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.control", invalid);
    RaspRuntime.Config config = RaspRuntime.Config.resolve(null, sysProps, null);
    assertFalse(config.controlDisabled);
    assertEquals(Paths.get("/tmp/ohmyrasp-control.json"), config.controlPath, "the default applies");

    // Set after initialisation: the next event still resolves its log target.
    System.setProperty("ohmyrasp.control", invalid);
    System.setProperty("ohmyrasp.java8.log", "none");
    assertEquals("none", RaspRuntime.resolveLogPath());
    RaspRuntime.writeEvent(RaspRuntime.resolveLogPath(), "{\"event\":\"after-bad-control\"}");
    System.clearProperty("ohmyrasp.control");
    System.clearProperty("ohmyrasp.java8.log");

    // Set before initialisation: the runtime starts and polls the next valid source, the default.
    int pollersBefore = threadsNamed(CONTROL_THREAD);
    Map<String, String> init = asyncInit();
    init.put("ohmyrasp.control", invalid);
    Class<?> runtime = loadIsolatedRuntime(init);
    assertEquals(pollersBefore + 1, threadsNamed(CONTROL_THREAD));
    runtime.getMethod("resolveLogPath").invoke(null);
  }

  @Test
  void invalidControlPathAndPollIntervalDoNotHideAValidLowerPriorityValue() {
    String invalid = "bad\0control.json";
    Properties badSys = new Properties();
    badSys.setProperty("ohmyrasp.control", invalid);
    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_CONTROL", "/env/control.json");
    assertEquals(
        Paths.get("/env/control.json"),
        RaspRuntime.Config.resolve(null, badSys, env).controlPath,
        "an invalid -Dohmyrasp.control must not hide OHMYRASP_CONTROL");

    Properties baked = new Properties();
    baked.setProperty("control", "/baked/control.json");
    Map<String, String> badEnv = new HashMap<String, String>();
    badEnv.put("OHMYRASP_CONTROL", invalid);
    assertEquals(
        Paths.get("/baked/control.json"), RaspRuntime.Config.resolve(baked, badSys, badEnv).controlPath);
    RaspRuntime.Config fallback = RaspRuntime.Config.resolve(null, badSys, badEnv);
    assertFalse(fallback.controlDisabled);
    assertEquals(Paths.get("/tmp/ohmyrasp-control.json"), fallback.controlPath);

    // A disabling token is a valid value and wins over a lower-priority path.
    Properties noneSys = new Properties();
    noneSys.setProperty("ohmyrasp.control", "none");
    assertTrue(RaspRuntime.Config.resolve(null, noneSys, env).controlDisabled);

    // Under lock an invalid baked path polls nothing, and sysprop and env stay ignored.
    Properties lockedBad = new Properties();
    lockedBad.setProperty("lock_config", "true");
    lockedBad.setProperty("control", invalid);
    RaspRuntime.Config locked = RaspRuntime.Config.resolve(lockedBad, null, env);
    assertTrue(locked.controlDisabled);
    assertNull(locked.controlPath);

    assertEquals(500L, RaspRuntime.pollMillis("soon", "500"), "an invalid poll_ms property");
    assertEquals(300L, RaspRuntime.pollMillis("300", "900"));
    assertEquals(200L, RaspRuntime.pollMillis(null, "50"), "the floor still applies");
    assertEquals(2000L, RaspRuntime.pollMillis("soon", "later"));
  }

  @Test
  void invalidSyncPropertyDoesNotHideAValidEnvironmentValue() {
    assertTrue(RaspRuntime.syncFlag("maybe", "true"), "an invalid log.sync property");
    assertFalse(RaspRuntime.syncFlag("false", "true"));
    assertFalse(RaspRuntime.syncFlag("maybe", "perhaps"));
  }

  @Test
  void invalidLegacyBlockPropertyDoesNotHideAValidEnvironmentValue() {
    assertTrue(RaspRuntime.legacyBlockFlag("maybe", "true"), "an invalid ohmyrasp.java8.block property");
    assertFalse(RaspRuntime.legacyBlockFlag("no", "true"));
    assertTrue(RaspRuntime.legacyBlockFlag(null, "yes"));
    assertFalse(RaspRuntime.legacyBlockFlag("maybe", null));
  }

  @Test
  void agentStartupAndDetectionReachTheConfiguredLogTarget() throws Exception {
    Path tempDir = Files.createTempDirectory("ohmyrasp-java8-standalone-test");
    Path logFile = tempDir.resolve("nested/events.jsonl");

    System.setProperty("ohmyrasp.java8.log", "none");
    OhMyRaspJava8Agent.premain("", null);
    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "cat /etc/passwd"));
    assertFalse(Files.exists(Paths.get("none")));

    System.setProperty("ohmyrasp.java8.log", logFile.toString());
    OhMyRaspJava8Agent.premain("", null);
    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "cat /etc/shadow"));

    String content = new String(Files.readAllBytes(logFile), StandardCharsets.UTF_8);
    assertTrue(content.contains("\"event\":\"ohmyrasp-java8-agent-start\""), content);
    assertTrue(content.contains("\"event\":\"ohmyrasp-detection\""), content);
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
  void latencySamplingRecordsOneRequestPerSampleRateAndNoneWhenSuppressed() {
    AtomicLong counter = new AtomicLong();
    assertFalse(RaspRuntime.latencySampled(true, false, 100L, 1, counter), "sync mode");
    assertFalse(RaspRuntime.latencySampled(false, true, 100L, 1, counter), "detection off");
    assertFalse(RaspRuntime.latencySampled(false, false, -1L, 1, counter), "negative latency");
    assertFalse(RaspRuntime.latencySampled(false, false, 100L, 0, counter), "rate 0");
    assertEquals(0L, counter.get(), "suppressed requests do not advance the counter");

    assertTrue(RaspRuntime.latencySampled(false, false, 0L, 1, counter));
    assertTrue(RaspRuntime.latencySampled(false, false, 100L, 1, counter));

    StringBuilder pattern = new StringBuilder();
    for (int i = 0; i < 6; i++) {
      pattern.append(RaspRuntime.latencySampled(false, false, 100L, 3, counter) ? 'x' : '.');
    }
    assertEquals("..x..x", pattern.toString());

    // This JVM runs with ohmyrasp.log.sync=true: the live entry point records nothing and never throws.
    RaspRuntime.sampleLatency(-1L);
    RaspRuntime.sampleLatency(100L);
  }

  @Test
  void standaloneNeverPollsAControlFileEvenWithAnExplicitPath() throws Exception {
    // As on the primary agent: standalone mode is self-contained, so no control path from any
    // source turns polling on.
    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.standalone", "true");
    sysProps.setProperty("ohmyrasp.control", "/sys/control.json");
    Map<String, String> env = new HashMap<String, String>();
    env.put("OHMYRASP_STANDALONE", "true");
    env.put("OHMYRASP_CONTROL", "/env/control.json");
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");
    baked.setProperty("control", "/baked/control.json");

    RaspRuntime.Config fromSys = RaspRuntime.Config.resolve(new Properties(), sysProps, env);
    RaspRuntime.Config fromEnv = RaspRuntime.Config.resolve(new Properties(), new Properties(), env);
    RaspRuntime.Config fromBaked =
        RaspRuntime.Config.resolve(baked, new Properties(), Collections.<String, String>emptyMap());
    Properties locked = new Properties();
    locked.putAll(baked);
    locked.setProperty("lock_config", "true");
    RaspRuntime.Config fromLocked =
        RaspRuntime.Config.resolve(locked, new Properties(), Collections.<String, String>emptyMap());
    RaspRuntime.Config[] configs = new RaspRuntime.Config[] {fromSys, fromEnv, fromBaked, fromLocked};
    String[] names = new String[] {"system property", "environment", "baked", "baked under lock"};
    for (int i = 0; i < configs.length; i++) {
      assertTrue(configs[i].standalone, names[i]);
      assertTrue(configs[i].controlDisabled, "standalone with a control path from the " + names[i]);
      assertNull(configs[i].controlPath, names[i]);
    }

    // The packaged form starts no control poller.
    int pollersBefore = threadsNamed(CONTROL_THREAD);
    Map<String, String> init = asyncInit();
    init.put("ohmyrasp.standalone", "true");
    init.put("ohmyrasp.control", "/tmp/ohmyrasp-standalone-control.json");
    init.put("ohmyrasp.java8.log", "none");
    loadIsolatedRuntime(init);
    assertEquals(pollersBefore, threadsNamed(CONTROL_THREAD), "a standalone runtime polls nothing");
  }

  @Test
  void classesTheHooksUseFirstAreLoadedWhenTheRuntimeInitialises() throws Exception {
    // A hook must not load a class for the first time: the hooks run inside JDK classes.
    // Initialising RaspRuntime, before any hook runs, loads the queued-event class.
    Class<?> runtime = loadIsolatedRuntime(asyncInit());
    IsolatedLoader loader = (IsolatedLoader) runtime.getClassLoader();
    String event = RaspRuntime.class.getName() + "$Event";
    assertTrue(loader.loaded(event), event + " was not loaded by initialisation");
  }

  @Test
  void theLinesStartLoadsEveryNamedClassOfTheSharedDecisionsAndTheLinesOwn() throws Exception {
    // The entry class starts the line before it registers any transformer, so no hook loads one of
    // these for the first time inside a JDK class. Anonymous classes are left out: the runtime makes
    // the ones it needs (sink, poller, shutdown hook) while it starts, and tests make the others.
    Class<?> runtime = loadIsolatedRuntime(asyncInit());
    IsolatedLoader loader = (IsolatedLoader) runtime.getClassLoader();
    List<String> expected = new ArrayList<String>();
    Path classes =
        Paths.get(RaspRuntime.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    String packagePath = RaspRuntime.class.getPackage().getName().replace('.', '/');
    FileSystem jar =
        Files.isDirectory(classes) ? null : FileSystems.newFileSystem(classes, (ClassLoader) null);
    try {
      Path source = jar == null ? classes.resolve(packagePath) : jar.getPath("/" + packagePath);
      DirectoryStream<Path> files = Files.newDirectoryStream(source, "*.class");
      try {
        for (Path file : files) {
          String name = file.getFileName().toString();
          name = name.substring(0, name.length() - ".class".length());
          if (!name.matches(".*\\$[0-9]+")) {
            expected.add(packagePath.replace('/', '.') + "." + name);
          }
        }
      } finally {
        files.close();
      }
    } finally {
      if (jar != null) {
        jar.close();
      }
    }
    assertTrue(expected.contains(BackportHooks.class.getName() + "$Finding"), expected.toString());
    expected.add(Java8RaspHooks.class.getName());
    expected.add(Java8RaspBlockException.class.getName());
    expected.add(Java8RaspLine.class.getName());
    List<String> missing = new ArrayList<String>();
    for (String name : expected) {
      if (!loader.loaded(name)) {
        missing.add(name);
      }
    }
    assertTrue(missing.isEmpty(), "not loaded by the line's start: " + missing);
  }

  /**
   * A JAR at {@code jar} holding the RaspRuntime classes, a manifest that says it is an upatch JAR when
   * {@code upatch}, and {@code baked} (none when null), its compressed data overwritten when {@code corrupt}.
   */
  private static Path runtimeJar(Path jar, String baked, boolean upatch, boolean corrupt) throws Exception {
    Path classes = bakedResource("");
    Files.delete(classes.resolve("META-INF/ohmyrasp-shirudo.properties"));
    Files.createDirectories(jar.getParent());
    java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
    if (upatch) {
      manifest.getMainAttributes().putValue("OhMyRasp-Shirudo-Upatch", "true");
    }
    String packagePath = RaspRuntime.class.getPackage().getName().replace('.', '/');
    java.util.jar.JarOutputStream out = new java.util.jar.JarOutputStream(Files.newOutputStream(jar), manifest);
    try {
      DirectoryStream<Path> files = Files.newDirectoryStream(classes.resolve(packagePath));
      try {
        for (Path file : files) {
          out.putNextEntry(new java.util.jar.JarEntry(packagePath + "/" + file.getFileName()));
          out.write(Files.readAllBytes(file));
          out.closeEntry();
        }
      } finally {
        files.close();
      }
      if (baked != null) {
        byte[] bytes = baked.getBytes(StandardCharsets.UTF_8);
        java.util.jar.JarEntry entry = new java.util.jar.JarEntry("META-INF/ohmyrasp-shirudo.properties");
        out.putNextEntry(entry);
        out.write(bytes);
        out.closeEntry();
      }
    } finally {
      out.close();
    }
    if (corrupt) {
      // The compressed data of the settings, overwritten: reading them fails in the inflater.
      byte[] all = Files.readAllBytes(jar);
      byte[] name = "META-INF/ohmyrasp-shirudo.properties".getBytes(StandardCharsets.UTF_8);
      int header = new String(all, StandardCharsets.ISO_8859_1).indexOf(new String(name, StandardCharsets.ISO_8859_1)) - 30;
      assertTrue(header >= 0, "the settings are in the JAR");
      int nameLength = (all[header + 26] & 0xff) | (all[header + 27] & 0xff) << 8;
      int extraLength = (all[header + 28] & 0xff) | (all[header + 29] & 0xff) << 8;
      int data = header + 30 + nameLength + extraLength;
      for (int i = 0; i < 4; i++) {
        all[data + i] = (byte) 0xff;
      }
      Files.write(jar, all);
    }
    return jar;
  }

  @Test
  void bakedPropertiesAreReadFromAJarUnderADirectoryWhoseNameEndsInABang() throws Exception {
    // A jar: URL takes the first "!/" as the end of the archive name: the settings were silently lost.
    Path jar = runtimeJar(Files.createTempDirectory("ohmyrasp-java8-bang").resolve("odd!").resolve("ohmyrasp.jar"),
        "standalone=true\nlock_config=true\nmode=block\n", true, false);
    Map<String, String> init = asyncInit();
    init.put("ohmyrasp.mode", "off");
    Class<?> runtime = loadIsolatedRuntime(init, jar);
    assertEquals("block", bakedProperties(runtime).getProperty("mode"), bakedProperties(runtime).toString());
    assertEquals("BLOCK", String.valueOf(call(runtime, "mode")), "the locked baked mode wins over -Dohmyrasp.mode=off");
  }

  @Test
  void anUpatchJarWhoseSettingsAreMissingOrUnreadableFailsTheStart() throws Exception {
    Path dir = Files.createTempDirectory("ohmyrasp-java8-unreadable");
    java.lang.reflect.InvocationTargetException missing = assertThrows(java.lang.reflect.InvocationTargetException.class,
        () -> loadIsolatedRuntime(asyncInit(), runtimeJar(dir.resolve("missing.jar"), null, true, false)));
    assertTrue(String.valueOf(missing.getCause()).contains("upatch JAR without"), String.valueOf(missing.getCause()));

    java.lang.reflect.InvocationTargetException corrupt = assertThrows(java.lang.reflect.InvocationTargetException.class,
        () -> loadIsolatedRuntime(asyncInit(),
            runtimeJar(dir.resolve("corrupt.jar"), "standalone=true\nlock_config=true\nmode=block\n", true, true)));
    assertTrue(String.valueOf(corrupt.getCause()).contains("cannot read"), String.valueOf(corrupt.getCause()));

    // A general JAR carries no settings: none, not an error.
    Class<?> general = loadIsolatedRuntime(asyncInit(), runtimeJar(dir.resolve("general.jar"), null, false, false));
    assertTrue(bakedProperties(general).isEmpty());
  }

  /** An isolated runtime that polls a control file and writes through the writer thread: both threads run. */
  private static Class<?> startIsolatedWithThreads() throws Exception {
    Path dir = Files.createTempDirectory("ohmyrasp-java8-threads");
    Map<String, String> init = new HashMap<String, String>();
    init.put("ohmyrasp.log.sync", "false");
    init.put("ohmyrasp.control", dir.resolve("control.json").toString());
    init.put("ohmyrasp.java8.log", dir.resolve("events.jsonl").toString());
    return loadIsolatedRuntime(init);
  }

  private static Object call(Class<?> type, String name) throws Exception {
    Method method = type.getDeclaredMethod(name);
    method.setAccessible(true);
    try {
      return method.invoke(null);
    } catch (java.lang.reflect.InvocationTargetException e) {
      if (e.getCause() instanceof Exception) {
        throw (Exception) e.getCause();
      }
      throw e;
    }
  }

  @Test
  void stopEndsTheThreadsOfAStartAndAStartCanFollow() throws Exception {
    int pollers = threadsNamed(CONTROL_THREAD);
    int writers = threadsNamed(WRITER_THREAD);
    Class<?> runtime = startIsolatedWithThreads();
    assertEquals(pollers + 1, threadsNamed(CONTROL_THREAD));
    assertEquals(writers + 1, threadsNamed(WRITER_THREAD));

    call(runtime, "stop");
    assertEquals(Boolean.FALSE, call(runtime, "isRunning"), "the runtime still runs after a stop");
    // What it resolved stays readable, for a hook that was already running: the hooks' on and off is HookActivation's.
    assertEquals(Boolean.TRUE, call(runtime, "isStarted"));
    assertEquals(pollers, threadsNamed(CONTROL_THREAD), "the poller stopped");
    assertEquals(writers, threadsNamed(WRITER_THREAD), "the writer stopped");

    System.setProperty("ohmyrasp.control", "none");
    try {
      assertEquals(Boolean.TRUE, call(runtime, "start"), "a start after a stop starts again");
    } finally {
      System.clearProperty("ohmyrasp.control");
    }
    assertEquals(Boolean.TRUE, call(runtime, "isRunning"));
    call(runtime, "stop");
  }

  @Test
  void anInterruptedCallerStillWaitsForTheThreadsItStops() throws Exception {
    // A worker that takes 300 ms to end once interrupted, stopped from a caller whose interrupt status is set.
    final Thread slow = new Thread(new Runnable() {
      public void run() {
        long until = System.nanoTime() + 300000000L;
        while (System.nanoTime() < until) {
          Thread.interrupted();
        }
      }
    }, "slow-to-stop");
    slow.setDaemon(true);
    slow.start();
    final Method stopQuietly = RaspRuntime.class.getDeclaredMethod("stopQuietly", Thread.class, Throwable.class);
    stopQuietly.setAccessible(true);
    final Object[] seen = new Object[2];
    Thread caller = new Thread(new Runnable() {
      public void run() {
        Thread.currentThread().interrupt();
        try {
          stopQuietly.invoke(null, slow, new IllegalStateException("cleanup"));
        } catch (Exception e) {
          seen[0] = e;
          return;
        }
        seen[0] = Boolean.valueOf(slow.isAlive());
        seen[1] = Boolean.valueOf(Thread.currentThread().isInterrupted());
      }
    }, "interrupted-stopper");
    caller.start();
    caller.join(10000L);
    assertEquals(Boolean.FALSE, seen[0], "the worker ended before stopQuietly returned");
    assertEquals(Boolean.TRUE, seen[1], "the caller keeps its interrupt status");
  }

  @Test
  void theShutdownHookWaitsForAStartAndNoStartFollowsIt() throws Exception {
    final Class<?> runtime = startIsolatedWithThreads();
    call(runtime, "stop");
    Field lockField = runtime.getDeclaredField("START_LOCK");
    lockField.setAccessible(true);
    Object startLock = lockField.get(null);
    Thread hook = new Thread(new Runnable() {
      public void run() {
        try {
          call(runtime, "closeForShutdown");
        } catch (Exception e) {
          throw new IllegalStateException(e);
        }
      }
    }, "shutdown-hook-stand-in");
    synchronized (startLock) {
      hook.start();
      for (int i = 0; i < 200 && hook.getState() != Thread.State.BLOCKED; i++) {
        Thread.sleep(10L);
      }
      assertEquals(Thread.State.BLOCKED, hook.getState(), "the hook waits for a start in progress");
    }
    hook.join(10000L);
    IllegalStateException refused = assertThrows(IllegalStateException.class, () -> call(runtime, "start"));
    assertTrue(refused.getMessage().contains("shutting down"), refused.getMessage());
    assertEquals(Boolean.FALSE, call(runtime, "isRunning"));
  }

  /** System properties for an isolated runtime: async writes, no control file. */
  private static Map<String, String> asyncInit() {
    Map<String, String> init = new HashMap<String, String>();
    init.put("ohmyrasp.log.sync", "false");
    init.put("ohmyrasp.control", "none");
    return init;
  }

  /**
   * Starts a fresh RaspRuntime in its own class loader, as the line's entry class starts it, with
   * the given system properties set only while it starts, and returns that loader's RaspRuntime.
   * The build sets ohmyrasp.log.sync=true for every test JVM, which the test JVM's RaspRuntime has
   * already read. {@code roots} are searched in order before the compiled classes (the shared
   * classes, then the line's): a {@link #bakedResource} root also holds the runtime classes, so
   * its META-INF/ohmyrasp-shirudo.properties is the runtime's own; a {@link #foreignResource} root
   * holds only the resource.
   */
  private static Class<?> loadIsolatedRuntime(Map<String, String> init, Path... roots)
      throws Exception {
    URL[] urls = new URL[roots.length + 2];
    for (int i = 0; i < roots.length; i++) {
      urls[i] = roots[i].toUri().toURL();
    }
    urls[roots.length] = RaspRuntime.class.getProtectionDomain().getCodeSource().getLocation();
    urls[roots.length + 1] = Java8RaspLine.class.getProtectionDomain().getCodeSource().getLocation();
    IsolatedLoader isolated = new IsolatedLoader(urls);
    Map<String, String> previous = new HashMap<String, String>();
    for (Map.Entry<String, String> entry : init.entrySet()) {
      previous.put(entry.getKey(), System.getProperty(entry.getKey()));
      System.setProperty(entry.getKey(), entry.getValue());
    }
    try {
      Class.forName(Java8RaspLine.class.getName(), true, isolated).getMethod("start").invoke(null);
      return Class.forName(RaspRuntime.class.getName(), false, isolated);
    } finally {
      for (Map.Entry<String, String> entry : previous.entrySet()) {
        restore(entry.getKey(), entry.getValue());
      }
    }
  }

  /** A class loader that answers whether it has loaded a class. */
  private static final class IsolatedLoader extends URLClassLoader {
    IsolatedLoader(URL[] urls) {
      super(urls, null);
    }

    boolean loaded(String name) {
      return findLoadedClass(name) != null;
    }
  }

  /**
   * A class-path root holding the RaspRuntime classes and, beside them, this baked resource. The
   * classes come from the shared module's class directory or JAR, whichever the test runs with.
   */
  private static Path bakedResource(String content) throws Exception {
    Path root = foreignResource(content);
    Path classes =
        Paths.get(RaspRuntime.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    String packagePath = RaspRuntime.class.getPackage().getName().replace('.', '/');
    Path target = Files.createDirectories(root.resolve(packagePath));
    FileSystem jar =
        Files.isDirectory(classes) ? null : FileSystems.newFileSystem(classes, (ClassLoader) null);
    try {
      Path source = jar == null ? classes.resolve(packagePath) : jar.getPath("/" + packagePath);
      DirectoryStream<Path> files = Files.newDirectoryStream(source, "RaspRuntime*.class");
      try {
        for (Path file : files) {
          String name = file.getFileName().toString();
          if (name.equals("RaspRuntime.class") || name.startsWith("RaspRuntime$")) {
            Files.copy(file, target.resolve(name));
          }
        }
      } finally {
        files.close();
      }
    } finally {
      if (jar != null) {
        jar.close();
      }
    }
    assertTrue(Files.exists(target.resolve("RaspRuntime.class")), target.toString());
    return root;
  }

  /** A class-path root holding only META-INF/ohmyrasp-shirudo.properties. */
  private static Path foreignResource(String content) throws Exception {
    Path root = Files.createTempDirectory("ohmyrasp-java8-baked-test");
    Path file = root.resolve("META-INF/ohmyrasp-shirudo.properties");
    Files.createDirectories(file.getParent());
    Files.write(file, content.getBytes(StandardCharsets.UTF_8));
    return root;
  }

  private static Properties bakedProperties(Class<?> runtime) throws Exception {
    Method baked = runtime.getDeclaredMethod("bakedProperties");
    baked.setAccessible(true);
    return (Properties) baked.invoke(null);
  }

  private static int threadsNamed(String name) {
    int count = 0;
    for (Thread thread : Thread.getAllStackTraces().keySet()) {
      if (name.equals(thread.getName()) && thread.isAlive()) {
        count++;
      }
    }
    return count;
  }

  private static void restore(String key, String value) {
    if (value == null) {
      System.clearProperty(key);
    } else {
      System.setProperty(key, value);
    }
  }
}
