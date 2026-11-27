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
          "ohmyrasp.control.poll_ms",
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
  void shirudoDefaultsIgnoreASameNamedResourceOutsideTheAgentsOwnLocation() {
    // src/test/resources carries META-INF/ohmyrasp-shirudo.properties with lock_config=true and
    // mode=off. It is on the class path but not where the agent classes are, so it must not count.
    assertTrue(ShirudoStandaloneTest.class.getResource(ShirudoDefaults.RESOURCE_PATH) != null);
    ShirudoDefaults loaded = ShirudoDefaults.load();
    assertFalse(loaded.isPresent());
  }

  @Test
  void shirudoDefaultsAreReadFromTheAgentsOwnLocation(@TempDir Path root) throws Exception {
    Object loaded = loadFromIsolatedCopy(root, "standalone=true\nlock_config=true\nmode=monitor\n");
    assertEquals(true, loaded.getClass().getMethod("isPresent").invoke(loaded));
    assertEquals(true, loaded.getClass().getMethod("lockConfig").invoke(loaded));
    assertEquals("MONITOR", String.valueOf(loaded.getClass().getMethod("mode").invoke(loaded)));
  }

  @Test
  void shirudoDefaultsKeepTheKeysReadBeforeAMalformedLine(@TempDir Path root) throws Exception {
    // Properties.load throws on the bad unicode escape. The lock and mode read before it must stay,
    // or a damaged later line would hand the mode back to system properties and environment.
    Object loaded =
        loadFromIsolatedCopy(root, "standalone=true\nlock_config=true\nmode=block\nbad=\\u00zz\nlog=none\n");
    assertEquals(true, loaded.getClass().getMethod("isPresent").invoke(loaded));
    assertEquals(true, loaded.getClass().getMethod("lockConfig").invoke(loaded));
    assertEquals("BLOCK", String.valueOf(loaded.getClass().getMethod("mode").invoke(loaded)));
  }

  /** Loads ShirudoDefaults from a copy of the runtime classes that has {@code baked} beside it. */
  private static Object loadFromIsolatedCopy(Path root, String baked) throws Exception {
    Path classes = Path.of(ShirudoDefaults.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    String packageDir = "io/ohmyrasp/agent/runtime";
    Files.createDirectories(root.resolve(packageDir));
    try (var files = Files.list(classes.resolve(packageDir))) {
      for (Path file : files.toList()) {
        Files.copy(file, root.resolve(packageDir).resolve(file.getFileName().toString()));
      }
    }
    Files.createDirectories(root.resolve("META-INF"));
    Files.writeString(root.resolve("META-INF/ohmyrasp-shirudo.properties"), baked);
    return loadIsolated(root);
  }

  /** ShirudoDefaults.load() of a ShirudoDefaults whose code source is {@code location}, a directory or JAR. */
  private static Object loadIsolated(Path location) throws Exception {
    java.net.URL shared =
        io.ohmyrasp.agent.util.BakedProperties.class.getProtectionDomain().getCodeSource().getLocation();
    try (var loader = new java.net.URLClassLoader(
        new java.net.URL[] {location.toUri().toURL(), shared}, ClassLoader.getPlatformClassLoader())) {
      Class<?> isolated = Class.forName("io.ohmyrasp.agent.runtime.ShirudoDefaults", true, loader);
      return isolated.getMethod("load").invoke(null);
    }
  }

  /**
   * A JAR at {@code jar} holding the runtime classes, a manifest that says it is an upatch JAR when
   * {@code upatch}, and {@code baked} (none when null), its compressed data overwritten when {@code corrupt}.
   */
  private static Path runtimeJar(Path jar, String baked, boolean upatch, boolean corrupt) throws Exception {
    Path classes = Path.of(ShirudoDefaults.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    String packageDir = "io/ohmyrasp/agent/runtime";
    Files.createDirectories(jar.getParent());
    var manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
    if (upatch) {
      manifest.getMainAttributes().putValue("OhMyRasp-Shirudo-Upatch", "true");
    }
    try (var out = new java.util.jar.JarOutputStream(Files.newOutputStream(jar), manifest);
        var files = Files.list(classes.resolve(packageDir))) {
      for (Path file : files.toList()) {
        out.putNextEntry(new java.util.jar.JarEntry(packageDir + "/" + file.getFileName()));
        out.write(Files.readAllBytes(file));
        out.closeEntry();
      }
      if (baked != null) {
        byte[] bytes = baked.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        var entry = new java.util.jar.JarEntry("META-INF/ohmyrasp-shirudo.properties");
        out.putNextEntry(entry);
        out.write(bytes);
        out.closeEntry();
      }
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
  void shirudoDefaultsAreReadFromAJarUnderADirectoryWhoseNameEndsInABang(@TempDir Path root) throws Exception {
    // A jar: URL takes the first "!/" as the end of the archive name: the settings were silently lost.
    Path jar = runtimeJar(root.resolve("odd!").resolve("ohmyrasp.jar"),
        "standalone=true\nlock_config=true\nmode=block\n", true, false);
    Object loaded = loadIsolated(jar);
    assertEquals(true, loaded.getClass().getMethod("isPresent").invoke(loaded));
    assertEquals(true, loaded.getClass().getMethod("lockConfig").invoke(loaded));
    assertEquals("BLOCK", String.valueOf(loaded.getClass().getMethod("mode").invoke(loaded)));
  }

  @Test
  void anUpatchJarWhoseSettingsAreMissingOrUnreadableDoesNotLoad(@TempDir Path root) throws Exception {
    Path missing = runtimeJar(root.resolve("missing.jar"), null, true, false);
    var failure = org.junit.jupiter.api.Assertions.assertThrows(
        java.lang.reflect.InvocationTargetException.class, () -> loadIsolated(missing));
    assertTrue(String.valueOf(failure.getCause()).contains("upatch JAR without"), String.valueOf(failure.getCause()));

    Path corrupt = runtimeJar(root.resolve("corrupt.jar"), "standalone=true\nlock_config=true\nmode=block\n", true, true);
    failure = org.junit.jupiter.api.Assertions.assertThrows(
        java.lang.reflect.InvocationTargetException.class, () -> loadIsolated(corrupt));
    assertTrue(String.valueOf(failure.getCause()).contains("cannot read"), String.valueOf(failure.getCause()));

    // A general JAR carries no settings: absent, not an error.
    Object general = loadIsolated(runtimeJar(root.resolve("general.jar"), null, false, false));
    assertEquals(false, general.getClass().getMethod("isPresent").invoke(general));
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
  void lockedProfileWithoutABakedControlPathPollsNoControlFile(@TempDir Path tempDir) {
    // The default /tmp/ohmyrasp-control.json is world-writable. A locked profile that bakes no
    // control path polls nothing, whatever agent arguments and system properties say.
    System.setProperty("ohmyrasp.control", tempDir.resolve("sys-control.json").toString());
    Properties props = new Properties();
    props.setProperty("lock_config", "true");
    props.setProperty("standalone", "false");
    long before = countThreadsNamed("ohmyrasp-control-poller");
    AgentRuntime runtime = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    runtime.start("control=" + tempDir.resolve("arg-control.json"));
    assertFalse(runtime.isStandalone());
    assertTrue(runtime.isControlPollingDisabled(), "a locked profile without a baked control path");
    assertEquals(before, countThreadsNamed("ohmyrasp-control-poller"));

    // A baked control path under lock keeps working.
    props.setProperty("control", tempDir.resolve("baked-control.json").toString());
    AgentRuntime baked = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    baked.start("control=none");
    assertFalse(baked.isControlPollingDisabled(), "a locked profile with a baked control path");
  }

  @Test
  void invalidControlPathAndPollIntervalDoNotHideAValidLowerPriorityValue(@TempDir Path tempDir) {
    String invalid = "bad\0control.json";
    Path sysControl = tempDir.resolve("sys-control.json");
    System.setProperty("ohmyrasp.control", sysControl.toString());
    AgentRuntime fromProperty = AgentRuntime.newForTesting(ShirudoDefaults.absent());
    fromProperty.start("control=" + invalid);
    assertFalse(fromProperty.isControlPollingDisabled());
    assertEquals(sysControl, fromProperty.controlPath(), "an invalid control argument");
    System.clearProperty("ohmyrasp.control");

    Properties props = new Properties();
    props.setProperty("control", tempDir.resolve("baked-control.json").toString());
    AgentRuntime fromBaked = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    fromBaked.start("control=" + invalid);
    assertEquals(tempDir.resolve("baked-control.json"), fromBaked.controlPath());

    // Under lock an invalid baked path polls nothing.
    Properties locked = new Properties();
    locked.setProperty("lock_config", "true");
    locked.setProperty("control", invalid);
    AgentRuntime lockedRuntime = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(locked));
    lockedRuntime.start(null);
    assertTrue(lockedRuntime.isControlPollingDisabled());
    assertNull(lockedRuntime.controlPath());

    System.setProperty("ohmyrasp.control.poll_ms", "700");
    assertEquals(700L, AgentRuntime.pollIntervalMillis("control_poll_ms=soon"), "an invalid poll argument");
    assertEquals(300L, AgentRuntime.pollIntervalMillis("control_poll_ms=300"));
    assertEquals(200L, AgentRuntime.pollIntervalMillis("control_poll_ms=5"), "the floor still applies");
    System.setProperty("ohmyrasp.control.poll_ms", "later");
    assertEquals(2000L, AgentRuntime.pollIntervalMillis("control_poll_ms=soon"));
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
  void invalidHigherPriorityModeDoesNotHideAValidLowerPriorityMode() {
    Properties props = new Properties();
    props.setProperty("standalone", "true");
    props.setProperty("lock_config", "false");
    props.setProperty("control", "none");
    props.setProperty("mode", "monitor");
    System.setProperty("ohmyrasp.mode", "block");

    // A mistyped agent argument must not switch protection off: the next source applies.
    AgentRuntime runtime = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    runtime.start("mode=blokc");
    assertEquals(DetectionMode.BLOCK, runtime.mode());
    assertTrue(runtime.blockingAllowed());

    // With no valid explicit source at all, the baked mode applies.
    System.setProperty("ohmyrasp.mode", "also-wrong");
    AgentRuntime baked = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    baked.start("mode=blokc");
    assertEquals(DetectionMode.MONITOR, baked.mode());
  }

  @Test
  void invalidHigherPriorityStandaloneDoesNotHideAValidLowerPriorityValue() {
    Properties props = new Properties();
    props.setProperty("lock_config", "false");
    props.setProperty("control", "none");
    System.setProperty("ohmyrasp.standalone", "true");

    AgentRuntime runtime = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    runtime.start("standalone=maybe");
    assertTrue(runtime.isStandalone());
    assertEquals(DetectionMode.BLOCK, runtime.mode());

    // An explicit false is a valid value and still wins over a lower-priority true.
    AgentRuntime explicit = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    explicit.start("standalone=false");
    assertFalse(explicit.isStandalone());
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

  /**
   * The logger's standalone defaults (log target stderr, latency sample 0) follow the standalone
   * value the runtime resolved, not any source that says true.
   */
  @Test
  void loggerTakesItsStandaloneDefaultsFromTheRuntimesResolvedValue() {
    Properties props = new Properties();
    props.setProperty("standalone", "true");
    props.setProperty("log", "none"); // no file writer; the sample rate shows the defaults chosen
    PrintStream quiet = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);

    AgentRuntime argumentSaysNo = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    argumentSaysNo.start("standalone=false,control=none");
    assertFalse(argumentSaysNo.isStandalone());
    assertEquals(
        10,
        JsonEventLogger.newForTesting(argumentSaysNo, quiet, quiet).latencySampleRate(),
        "a baked standalone=true overrode the agent argument standalone=false");

    System.setProperty("ohmyrasp.standalone", "true");
    try {
      AgentRuntime propertyLoses = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
      propertyLoses.start("standalone=false,control=none");
      assertEquals(
          10,
          JsonEventLogger.newForTesting(propertyLoses, quiet, quiet).latencySampleRate(),
          "a lower-priority ohmyrasp.standalone=true overrode the agent argument");
    } finally {
      System.clearProperty("ohmyrasp.standalone");
    }

    AgentRuntime standalone = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(props));
    standalone.start("control=none");
    assertTrue(standalone.isStandalone());
    assertEquals(0, JsonEventLogger.newForTesting(standalone, quiet, quiet).latencySampleRate());
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
