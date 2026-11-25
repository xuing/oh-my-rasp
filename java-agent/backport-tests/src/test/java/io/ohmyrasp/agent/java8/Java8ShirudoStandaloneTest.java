package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
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
    assertFalse(missingStandalone.controlDisabled);
    assertEquals(Paths.get("/tmp/ohmyrasp-control.json"), missingStandalone.controlPath);
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
    assertEquals(Paths.get("/env/control.json"), fromEnv.controlPath);
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
    Class<?> runtime = loadIsolatedRuntime(init, null);
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
    Class<?> runtime = loadIsolatedRuntime(init, null);

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
  void malformedBakedPropertiesFallBackToDefaultsWithoutAbortingInitialisation() throws Exception {
    // Properties.load throws IllegalArgumentException on a malformed unicode escape. The line
    // before it must not survive as a partial read either.
    Path malformed = bakedResource("log=/tmp/partial.jsonl\nstandalone=true\nbad=\\u00zz\n");
    Class<?> broken = loadIsolatedRuntime(asyncInit(), malformed);
    assertTrue(bakedProperties(broken).isEmpty(), bakedProperties(broken).toString());
    Method resolveLogPath = broken.getMethod("resolveLogPath");
    resolveLogPath.invoke(null);

    // Control: the same lookup reads a well-formed resource.
    Path valid = bakedResource("log=none\nlatency_sample=3\n");
    Class<?> readable = loadIsolatedRuntime(asyncInit(), valid);
    assertEquals("none", bakedProperties(readable).getProperty("log"));
    assertEquals("3", bakedProperties(readable).getProperty("latency_sample"));
  }

  @Test
  void invalidControlPathDoesNotBreakConfigurationOrEventEmission() throws Exception {
    String invalid = "bad\0control.json";
    Properties sysProps = new Properties();
    sysProps.setProperty("ohmyrasp.control", invalid);
    RaspRuntime.Config config = RaspRuntime.Config.resolve(null, sysProps, null);
    assertFalse(config.controlDisabled);
    assertNull(config.controlPath);

    // Set after initialisation: the next event still resolves its log target.
    System.setProperty("ohmyrasp.control", invalid);
    System.setProperty("ohmyrasp.java8.log", "none");
    assertEquals("none", RaspRuntime.resolveLogPath());
    RaspRuntime.writeEvent(RaspRuntime.resolveLogPath(), "{\"event\":\"after-bad-control\"}");
    System.clearProperty("ohmyrasp.control");
    System.clearProperty("ohmyrasp.java8.log");

    // Set before initialisation: the runtime starts and polls nothing.
    int pollersBefore = threadsNamed(CONTROL_THREAD);
    Map<String, String> init = asyncInit();
    init.put("ohmyrasp.control", invalid);
    Class<?> runtime = loadIsolatedRuntime(init, null);
    assertEquals(pollersBefore, threadsNamed(CONTROL_THREAD));
    runtime.getMethod("resolveLogPath").invoke(null);
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

  /** System properties for an isolated runtime: async writes, no control file. */
  private static Map<String, String> asyncInit() {
    Map<String, String> init = new HashMap<String, String>();
    init.put("ohmyrasp.log.sync", "false");
    init.put("ohmyrasp.control", "none");
    return init;
  }

  /**
   * Loads and initialises a fresh RaspRuntime in its own class loader, with the given system
   * properties set only while its static initialiser runs. The build sets ohmyrasp.log.sync=true for
   * every test JVM, which the shared RaspRuntime has already read. {@code bakedRoot}, when not null,
   * is searched first, so a META-INF/ohmyrasp-shirudo.properties there becomes the baked resource.
   */
  private static Class<?> loadIsolatedRuntime(Map<String, String> init, Path bakedRoot)
      throws Exception {
    URL classes = RaspRuntime.class.getProtectionDomain().getCodeSource().getLocation();
    URL[] urls =
        bakedRoot == null ? new URL[] {classes} : new URL[] {bakedRoot.toUri().toURL(), classes};
    URLClassLoader isolated = new URLClassLoader(urls, null);
    Map<String, String> previous = new HashMap<String, String>();
    for (Map.Entry<String, String> entry : init.entrySet()) {
      previous.put(entry.getKey(), System.getProperty(entry.getKey()));
      System.setProperty(entry.getKey(), entry.getValue());
    }
    try {
      return Class.forName(RaspRuntime.class.getName(), true, isolated);
    } finally {
      for (Map.Entry<String, String> entry : previous.entrySet()) {
        restore(entry.getKey(), entry.getValue());
      }
    }
  }

  private static Path bakedResource(String content) throws Exception {
    Path root = Files.createTempDirectory("ohmyrasp-java8-baked-test");
    Path file = root.resolve("META-INF/ohmyrasp-shirudo.properties");
    Files.createDirectories(file.getParent());
    Files.write(file, content.getBytes(StandardCharsets.UTF_8));
    return root;
  }

  private static Properties bakedProperties(Class<?> runtime) throws Exception {
    Field field = runtime.getDeclaredField("BAKED_PROPERTIES");
    field.setAccessible(true);
    return (Properties) field.get(null);
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
