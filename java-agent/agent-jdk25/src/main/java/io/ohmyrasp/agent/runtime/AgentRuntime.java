package io.ohmyrasp.agent.runtime;

import io.ohmyrasp.agent.policy.SimpleJson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Live, hot-reloadable agent control state: the detection mode and per-algorithm
 * enable switches.
 *
 * <p>This is the agent side of the one-way control channel
 * {@code console/operator → daemon → control file → agent}. The daemon (or a
 * human, when standalone) owns a small JSON control file; the agent polls it on
 * a background daemon thread and applies changes without a restart. Polling
 * (rather than a filesystem watch) is deliberate — control latency is irrelevant
 * and polling avoids platform-specific watch quirks.
 *
 * <p>The agent never talks to the daemon directly: it reads this file and writes
 * its events to the spool file. When running standalone (or with baked-in
 * {@link ShirudoDefaults}), control-file polling and direct cloud reporting can
 * be disabled altogether.
 */
public final class AgentRuntime {
  private static final AgentRuntime INSTANCE = new AgentRuntime(ShirudoDefaults.load());

  /** Default control file, matching the daemon's default. */
  private static final String DEFAULT_CONTROL = "/tmp/ohmyrasp-control.json";

  private volatile DetectionMode mode; // null = unset → legacy behavior
  private volatile Map<String, Boolean> algorithms = Map.of();
  private volatile long revision;

  private volatile ShirudoDefaults defaults;
  private volatile boolean standalone;
  private volatile boolean controlPollingDisabled;
  private volatile boolean directCloudDisabled;
  private volatile String argLogTarget;
  private volatile Integer argLatencySample;

  private Path controlPath;
  private volatile long lastModifiedMillis = Long.MIN_VALUE;
  private final AtomicBoolean started = new AtomicBoolean();

  // Cloud policy distributed via the control file: installed through this
  // callback (set by BootstrapAgent), de-duplicated on the raw JSON.
  private volatile java.util.function.Consumer<String> policyInstaller;
  private volatile String lastPolicyJson;

  private AgentRuntime(ShirudoDefaults defaults) {
    ShirudoDefaults active = defaults == null ? ShirudoDefaults.absent() : defaults;
    this.defaults = active;
    this.standalone = active.standalone();
    this.directCloudDisabled = active.standalone() || active.lockConfig();
    this.controlPollingDisabled =
        active.standalone() || isControlDisabledToken(active.control());
  }

  public static AgentRuntime get() {
    return INSTANCE;
  }

  /** Creates an isolated instance for tests, leaving the shared singleton untouched. */
  static AgentRuntime newForTesting() {
    return new AgentRuntime(ShirudoDefaults.absent());
  }

  /** Creates an isolated instance seeded with baked-in defaults for tests. */
  static AgentRuntime newForTesting(ShirudoDefaults defaults) {
    return new AgentRuntime(defaults);
  }

  /**
   * Register the callback that installs a cloud policy carried in the control
   * file. Set this before {@link #start} so the initial load applies any policy.
   */
  public void setPolicyInstaller(java.util.function.Consumer<String> installer) {
    this.policyInstaller = installer;
  }

  /** Initialise from configuration and start the control-file poller (idempotent). */
  public void start(String agentArgs) {
    start(agentArgs, this.defaults);
  }

  /** Initialise from configuration and explicit {@link ShirudoDefaults} (idempotent). */
  void start(String agentArgs, ShirudoDefaults defaults) {
    if (!started.compareAndSet(false, true)) {
      return;
    }
    ShirudoDefaults activeDefaults = defaults == null ? ShirudoDefaults.absent() : defaults;
    this.defaults = activeDefaults;
    boolean lockConfig = activeDefaults.lockConfig();

    boolean resolvedStandalone;
    if (lockConfig) {
      resolvedStandalone = activeDefaults.standalone();
    } else {
      Boolean explicitStandalone =
          resolveValid(agentArgs, "standalone", "ohmyrasp.standalone", "OHMYRASP_STANDALONE", AgentRuntime::parseBooleanOrNull);
      resolvedStandalone = explicitStandalone != null ? explicitStandalone : activeDefaults.standalone();
    }
    this.standalone = resolvedStandalone;
    this.directCloudDisabled = resolvedStandalone || lockConfig;

    String rawLog = argValue(agentArgs, "log");
    if (notBlank(rawLog)) {
      this.argLogTarget = rawLog.trim();
    }
    String rawLatency = argValue(agentArgs, "latency_sample");
    if (notBlank(rawLatency)) {
      try {
        this.argLatencySample = Integer.valueOf(rawLatency.trim());
      } catch (NumberFormatException ignored) {
        // Ignore invalid override and let sysprop/env/defaults apply.
      }
    }

    String controlSetting;
    if (lockConfig) {
      // Only a baked control path counts. Without one nothing is polled: the default lives in
      // world-writable /tmp and must not steer a locked profile.
      String baked = validControl(activeDefaults.control());
      controlSetting = baked != null ? baked : "none";
    } else {
      String explicit =
          resolveValid(agentArgs, "control", "ohmyrasp.control", "OHMYRASP_CONTROL", AgentRuntime::validControl);
      controlSetting = explicit != null ? explicit : validControl(activeDefaults.control());
    }
    boolean disableControl = resolvedStandalone || isControlDisabledToken(controlSetting);
    this.controlPollingDisabled = disableControl;

    // Seed the initial mode from baked-in/explicit settings; when control polling is
    // enabled, the control file (when present) takes over as the live source of truth.
    DetectionMode resolvedMode;
    if (lockConfig) {
      resolvedMode = activeDefaults.mode();
    } else {
      DetectionMode explicit =
          resolveValid(agentArgs, "mode", "ohmyrasp.mode", "OHMYRASP_MODE", DetectionMode::parse);
      resolvedMode = explicit != null ? explicit : activeDefaults.mode();
    }
    if (resolvedMode == null && resolvedStandalone) {
      resolvedMode = DetectionMode.BLOCK;
    }
    if (resolvedMode != null) {
      mode = resolvedMode;
    }

    if (disableControl) {
      controlPath = null;
      return;
    }

    controlPath = Path.of(controlSetting != null ? controlSetting : DEFAULT_CONTROL);
    reloadIfChanged();
    startPoller(pollIntervalMillis(agentArgs));
  }

  public boolean isStandalone() {
    return standalone;
  }

  public boolean isControlPollingDisabled() {
    return controlPollingDisabled;
  }

  public boolean isDirectCloudDisabled() {
    return directCloudDisabled;
  }

  public ShirudoDefaults shirudoDefaults() {
    return defaults;
  }

  public String defaultLogTarget() {
    return defaults.log();
  }

  public Integer defaultLatencySample() {
    return defaults.latencySample();
  }

  public String agentArgLogTarget() {
    return argLogTarget;
  }

  public Integer agentArgLatencySample() {
    return argLatencySample;
  }

  private static boolean isControlDisabledToken(String value) {
    if (!notBlank(value)) {
      return false;
    }
    return switch (value.trim().toLowerCase(Locale.ROOT)) {
      case "none", "off", "disabled" -> true;
      default -> false;
    };
  }

  /**
   * The trimmed control setting when it disables polling or names a valid path, else null, so
   * that an unusable value leaves the next source in charge.
   */
  private static String validControl(String value) {
    if (!notBlank(value)) {
      return null;
    }
    String trimmed = value.trim();
    if (isControlDisabledToken(trimmed)) {
      return trimmed;
    }
    try {
      Path.of(trimmed);
      return trimmed;
    } catch (java.nio.file.InvalidPathException e) {
      return null;
    }
  }

  /** False only when detection is explicitly turned OFF. */
  public boolean detectionEnabled() {
    return mode != DetectionMode.OFF;
  }

  /** Whether blocking is permitted. Unset (legacy) and BLOCK permit it; MONITOR/OFF do not. */
  public boolean blockingAllowed() {
    DetectionMode current = mode;
    return current == null || current == DetectionMode.BLOCK;
  }

  /** An algorithm is enabled unless the control file explicitly disables it. */
  public boolean isAlgorithmEnabled(String algorithm) {
    if (algorithm == null || algorithm.isEmpty()) {
      return true;
    }
    Boolean enabled = algorithms.get(algorithm);
    return enabled == null || enabled;
  }

  public DetectionMode mode() {
    return mode;
  }

  public long revision() {
    return revision;
  }

  private void startPoller(long intervalMillis) {
    Thread poller =
        new Thread(
            () -> {
              while (true) {
                try {
                  Thread.sleep(intervalMillis);
                  reloadIfChanged();
                } catch (InterruptedException e) {
                  Thread.currentThread().interrupt();
                  return;
                } catch (RuntimeException e) {
                  // Never let control polling disturb the protected application.
                }
              }
            },
            "ohmyrasp-control-poller");
    poller.setDaemon(true);
    poller.start();
  }

  private void reloadIfChanged() {
    Path path = controlPath;
    if (path == null) {
      return;
    }
    try {
      if (!Files.isRegularFile(path)) {
        return;
      }
      long modified = Files.getLastModifiedTime(path).toMillis();
      if (modified == lastModifiedMillis) {
        return;
      }
      lastModifiedMillis = modified;
      apply(Files.readString(path));
    } catch (RuntimeException | java.io.IOException e) {
      // Tolerate transient read/parse failures; keep the last known good state.
    }
  }

  void apply(String json) {
    Object parsed;
    try {
      parsed = SimpleJson.parse(json);
    } catch (RuntimeException e) {
      return; // ignore malformed control documents
    }
    if (!(parsed instanceof Map<?, ?> object)) {
      return;
    }
    if (object.get("mode") instanceof String token) {
      DetectionMode parsedMode = DetectionMode.parse(token);
      if (parsedMode != null) {
        mode = parsedMode;
      }
    }
    if (object.get("algorithms") instanceof Map<?, ?> map) {
      Map<String, Boolean> next = new HashMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (entry.getValue() instanceof Boolean enabled) {
          next.put(String.valueOf(entry.getKey()), enabled);
        }
      }
      algorithms = Map.copyOf(next);
    }
    if (object.get("revision") instanceof Number number) {
      revision = number.longValue();
    }
    // Install a cloud policy distributed through the control file, once per change.
    if (object.get("policy") instanceof String policyJson && !policyJson.isBlank()) {
      if (!policyJson.equals(lastPolicyJson)) {
        lastPolicyJson = policyJson;
        java.util.function.Consumer<String> installer = policyInstaller;
        if (installer != null) {
          try {
            installer.accept(policyJson);
          } catch (RuntimeException e) {
            // A bad policy document must never disturb the protected application.
          }
        }
      }
    }
  }

  /** The control file this runtime polls, or null when polling is disabled. */
  Path controlPath() {
    return controlPath;
  }

  /** The first source that holds a number, floored at 200 ms; else 2000 ms. */
  static long pollIntervalMillis(String agentArgs) {
    Long configured =
        resolveValid(
            agentArgs, "control_poll_ms", "ohmyrasp.control.poll_ms", "OHMYRASP_CONTROL_POLL_MS", AgentRuntime::parseLongOrNull);
    return configured == null ? 2000 : Math.max(200, configured);
  }

  private static Long parseLongOrNull(String value) {
    try {
      return Long.valueOf(value.trim());
    } catch (NumberFormatException e) {
      return null;
    }
  }

  /**
   * The first of agent argument, system property and environment whose value the parser accepts. A value
   * the parser rejects (a typo such as mode=blokc) is skipped, so it cannot hide a valid lower-priority
   * setting and switch protection off.
   */
  private static <T> T resolveValid(
      String agentArgs, String key, String property, String env, java.util.function.Function<String, T> parser) {
    for (String raw : new String[] {argValue(agentArgs, key), System.getProperty(property), System.getenv(env)}) {
      if (notBlank(raw)) {
        T parsed = parser.apply(raw.trim());
        if (parsed != null) {
          return parsed;
        }
      }
    }
    return null;
  }

  private static Boolean parseBooleanOrNull(String value) {
    return switch (value.trim().toLowerCase(Locale.ROOT)) {
      case "true", "1", "yes", "on" -> Boolean.TRUE;
      case "false", "0", "no", "off" -> Boolean.FALSE;
      default -> null;
    };
  }

  private static String argValue(String agentArgs, String key) {
    if (agentArgs == null || agentArgs.isBlank()) {
      return null;
    }
    String normalizedKey = key.replace('.', '_').replace('-', '_');
    for (String item : agentArgs.split("[,;]")) {
      int separator = item.indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String itemKey = item.substring(0, separator).trim().replace('.', '_').replace('-', '_');
      if (itemKey.equalsIgnoreCase(normalizedKey)) {
        return item.substring(separator + 1);
      }
    }
    return null;
  }

  private static boolean notBlank(String value) {
    return value != null && !value.isBlank();
  }
}
