package io.ohmyrasp.agent.runtime;

import io.ohmyrasp.agent.policy.SimpleJson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
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
 * its events to the spool file. If neither the daemon nor a control file is
 * present the agent runs fully standalone with legacy (unset-mode) behavior.
 */
public final class AgentRuntime {
  private static final AgentRuntime INSTANCE = new AgentRuntime();

  /** Default control file, matching the daemon's default. */
  private static final String DEFAULT_CONTROL = "/tmp/ohmyrasp-control.json";

  private volatile DetectionMode mode; // null = unset → legacy behavior
  private volatile Map<String, Boolean> algorithms = Map.of();
  private volatile long revision;

  private Path controlPath;
  private volatile long lastModifiedMillis = Long.MIN_VALUE;
  private final AtomicBoolean started = new AtomicBoolean();

  private AgentRuntime() {}

  public static AgentRuntime get() {
    return INSTANCE;
  }

  /** Creates an isolated instance for tests, leaving the shared singleton untouched. */
  static AgentRuntime newForTesting() {
    return new AgentRuntime();
  }

  /** Initialise from configuration and start the control-file poller (idempotent). */
  public void start(String agentArgs) {
    if (!started.compareAndSet(false, true)) {
      return;
    }
    controlPath = Path.of(resolve(agentArgs, "control", "ohmyrasp.control", "OHMYRASP_CONTROL", DEFAULT_CONTROL));

    // Seed the initial mode from an explicit setting; the control file (when
    // present) then takes over as the live source of truth.
    DetectionMode explicit = DetectionMode.parse(resolve(agentArgs, "mode", "ohmyrasp.mode", "OHMYRASP_MODE", null));
    if (explicit != null) {
      mode = explicit;
    }
    reloadIfChanged();
    startPoller(pollIntervalMillis(agentArgs));
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
  }

  private static long pollIntervalMillis(String agentArgs) {
    String raw = resolve(agentArgs, "control_poll_ms", "ohmyrasp.control.poll_ms", "OHMYRASP_CONTROL_POLL_MS", "2000");
    try {
      return Math.max(200, Long.parseLong(raw.trim()));
    } catch (NumberFormatException e) {
      return 2000;
    }
  }

  private static String resolve(String agentArgs, String key, String property, String env, String fallback) {
    String fromArgs = argValue(agentArgs, key);
    if (notBlank(fromArgs)) {
      return fromArgs.trim();
    }
    String fromProperty = System.getProperty(property);
    if (notBlank(fromProperty)) {
      return fromProperty.trim();
    }
    String fromEnv = System.getenv(env);
    if (notBlank(fromEnv)) {
      return fromEnv.trim();
    }
    return fallback;
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
