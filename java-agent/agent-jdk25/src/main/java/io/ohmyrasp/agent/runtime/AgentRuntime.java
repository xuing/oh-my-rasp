package io.ohmyrasp.agent.runtime;

import io.ohmyrasp.agent.policy.AgentPolicy;
import io.ohmyrasp.agent.policy.SimpleJson;
import io.ohmyrasp.agent.util.ControlDocument;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Live, hot-reloadable agent control state: the detection mode, per-algorithm
 * enable switches and the installed policy, published together as one
 * {@link ControlState}.
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
  static {
    // Hooks call AgentOwnIo on every file operation. BootstrapAgent initialises this class before
    // it installs the transformer, so no hook loads or initialises AgentOwnIo for the first time.
    AgentOwnIo.active();
  }

  private static final AgentRuntime INSTANCE = new AgentRuntime(ShirudoDefaults.load());

  /** Default control file, matching the daemon's default. */
  private static final String DEFAULT_CONTROL = "/tmp/ohmyrasp-control.json";

  /** A control file larger than this many bytes is unparseable; only this many + 1 are read. */
  static final int MAX_CONTROL_BYTES = 1 << 20;

  /** Which source installed the policy in the current {@link ControlState}. */
  public enum PolicySource {
    /** No policy was installed: the start-up state. */
    NONE,
    /** The {@code policy} member of the control file. */
    CONTROL_FILE,
    /** The direct-cloud {@code ControlPlaneClient} (cloud_direct=true). */
    DIRECT_CLOUD
  }

  /**
   * Everything the control file and the policy sources set, as one immutable value. It is
   * published through a single volatile reference, so a hook that reads it once never sees a
   * restored mode next to a stale switch or policy.
   */
  public static final class ControlState {
    private final DetectionMode mode; // null = unset → legacy behavior
    private final Map<String, Boolean> algorithms;
    private final long revision;
    private final AgentPolicy policy;
    private final String policyAgentKey;
    private final PolicySource policySource;
    // Poller bookkeeping: the control file content last applied, and the policy text the control
    // file last carried, so an unchanged policy is not parsed and installed again.
    private final String appliedContent;
    private final String controlPolicyJson;

    private ControlState(
        DetectionMode mode,
        Map<String, Boolean> algorithms,
        long revision,
        AgentPolicy policy,
        String policyAgentKey,
        PolicySource policySource,
        String appliedContent,
        String controlPolicyJson) {
      this.mode = mode;
      this.algorithms = algorithms;
      this.revision = revision;
      this.policy = policy;
      this.policyAgentKey = policyAgentKey;
      this.policySource = policySource;
      this.appliedContent = appliedContent;
      this.controlPolicyJson = controlPolicyJson;
    }

    static ControlState startUp(DetectionMode mode) {
      return new ControlState(mode, Map.of(), 0, AgentPolicy.absent(), "", PolicySource.NONE, null, null);
    }

    public DetectionMode mode() {
      return mode;
    }

    /** False only when detection is explicitly turned OFF. */
    public boolean detectionEnabled() {
      return mode != DetectionMode.OFF;
    }

    /** Whether blocking is permitted. Unset (legacy) and BLOCK permit it; MONITOR/OFF do not. */
    public boolean blockingAllowed() {
      return mode == null || mode == DetectionMode.BLOCK;
    }

    /** An algorithm is enabled unless the control file explicitly disables it. */
    public boolean isAlgorithmEnabled(String algorithm) {
      if (algorithm == null || algorithm.isEmpty()) {
        return true;
      }
      Boolean enabled = algorithms.get(algorithm);
      return enabled == null || enabled;
    }

    public long revision() {
      return revision;
    }

    public AgentPolicy policy() {
      return policy;
    }

    public String policyAgentKey() {
      return policyAgentKey;
    }

    public PolicySource policySource() {
      return policySource;
    }
  }

  private volatile ControlState state = ControlState.startUp(null);
  // The mode resolved by start, before any control file. Written once, before polling starts.
  private volatile DetectionMode startUpMode;
  // Serialises the writers of {@link #state}: the poller, start-up and the direct-cloud client.
  private final Object stateLock = new Object();

  private volatile ShirudoDefaults defaults;
  private volatile boolean standalone;
  private volatile boolean controlPollingDisabled;
  private volatile boolean directCloudDisabled;
  private volatile String argLogTarget;
  private volatile Integer argLatencySample;

  private Path controlPath;
  private final AtomicBoolean started = new AtomicBoolean();

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
   * Installs a policy from the direct-cloud client. The last source to install a policy owns it:
   * a later control-file policy replaces this one, and removing the control file leaves it in
   * place, because the control file did not install it.
   */
  public void installDirectPolicy(AgentPolicy policy, String agentKey) {
    synchronized (stateLock) {
      ControlState current = state;
      state =
          new ControlState(
              current.mode,
              current.algorithms,
              current.revision,
              policy == null ? AgentPolicy.empty() : policy,
              agentKey == null ? "" : agentKey,
              PolicySource.DIRECT_CLOUD,
              current.appliedContent,
              current.controlPolicyJson);
    }
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
    synchronized (stateLock) {
      startUpMode = resolvedMode;
      ControlState current = state;
      state =
          new ControlState(
              resolvedMode,
              current.algorithms,
              current.revision,
              current.policy,
              current.policyAgentKey,
              current.policySource,
              current.appliedContent,
              current.controlPolicyJson);
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

  /**
   * The current control state. A caller that needs several of its values reads it once and uses
   * that one snapshot.
   */
  public ControlState state() {
    return state;
  }

  /** False only when detection is explicitly turned OFF. */
  public boolean detectionEnabled() {
    return state.detectionEnabled();
  }

  /** Whether blocking is permitted. Unset (legacy) and BLOCK permit it; MONITOR/OFF do not. */
  public boolean blockingAllowed() {
    return state.blockingAllowed();
  }

  /** An algorithm is enabled unless the control file explicitly disables it. */
  public boolean isAlgorithmEnabled(String algorithm) {
    return state.isAlgorithmEnabled(algorithm);
  }

  public DetectionMode mode() {
    return state.mode();
  }

  public long revision() {
    return state.revision();
  }

  public AgentPolicy policy() {
    return state.policy();
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
                } catch (RuntimeException | Error e) {
                  // Never let control polling disturb the protected application or stop polling.
                }
              }
            },
            "ohmyrasp-control-poller");
    poller.setDaemon(true);
    poller.start();
  }

  /**
   * One polling step; the poller thread calls it, and so can a test. The control file overrides
   * the start-up settings only while it exists: when it is gone they return. When it exists but
   * cannot be read or parsed, the last good settings stay; the daemon replaces the file
   * atomically, so such a read is transient.
   */
  void reloadIfChanged() {
    Path path = controlPath;
    if (path == null) {
      return;
    }
    try {
      reload(path);
    } catch (RuntimeException | StackOverflowError | OutOfMemoryError e) {
      // Nothing the poll step throws escapes it: the last good state stays.
    }
  }

  private void reload(Path path) {
    String text;
    boolean ownIo = AgentOwnIo.enter();
    try {
      if (Files.notExists(path)) {
        restoreStartUpSettings();
        return;
      }
      if (!Files.isRegularFile(path)) {
        return;
      }
      // Bounded, strict UTF-8: an oversized or malformed file is unparseable.
      text = ControlDocument.read(path, MAX_CONTROL_BYTES);
    } catch (java.nio.file.NoSuchFileException gone) {
      restoreStartUpSettings();
      return;
    } catch (RuntimeException | java.io.IOException e) {
      return;
    } finally {
      AgentOwnIo.exit(ownIo);
    }
    // Read on every poll and applied when the content differs from what was last applied. Content
    // that fails to parse is not recorded, so a document read half-written is applied once it is
    // complete, whatever its modification time.
    if (text.equals(state.appliedContent)) {
      return;
    }
    apply(text);
  }

  /**
   * Returns everything the control file set to its start-up value in one step: the mode, the
   * per-algorithm switches, the revision and, when the control file installed the current policy,
   * the policy (start-up has none). A policy the direct-cloud client installed stays: the control
   * file did not install it.
   */
  private void restoreStartUpSettings() {
    synchronized (stateLock) {
      ControlState current = state;
      boolean ownsPolicy = current.policySource == PolicySource.CONTROL_FILE;
      state =
          new ControlState(
              startUpMode,
              Map.of(),
              0,
              ownsPolicy ? AgentPolicy.absent() : current.policy,
              ownsPolicy ? "" : current.policyAgentKey,
              ownsPolicy ? PolicySource.NONE : current.policySource,
              null,
              null);
    }
  }

  /**
   * Applies a control document; false, changing nothing, when it is not exactly one well-formed
   * JSON object, or is one that SimpleJson cannot read (an integer outside long, for example).
   */
  boolean apply(String json) {
    Object parsed;
    try {
      // The strict scanner decides what is well-formed; SimpleJson is lenient about some input.
      ControlDocument.requireObject(json);
      parsed = SimpleJson.parse(json);
    } catch (RuntimeException e) {
      return false; // ignore malformed control documents
    }
    if (!(parsed instanceof Map<?, ?> object)) {
      return false;
    }
    synchronized (stateLock) {
      ControlState current = state;
      DetectionMode nextMode = current.mode;
      if (object.get("mode") instanceof String token) {
        DetectionMode parsedMode = DetectionMode.parse(token);
        if (parsedMode != null) {
          nextMode = parsedMode;
        }
      }
      Map<String, Boolean> nextAlgorithms = current.algorithms;
      if (object.get("algorithms") instanceof Map<?, ?> map) {
        Map<String, Boolean> next = new HashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
          if (entry.getValue() instanceof Boolean enabled) {
            next.put(String.valueOf(entry.getKey()), enabled);
          }
        }
        nextAlgorithms = Map.copyOf(next);
      }
      long nextRevision = current.revision;
      if (object.get("revision") instanceof Number number) {
        nextRevision = number.longValue();
      }
      AgentPolicy nextPolicy = current.policy;
      String nextKey = current.policyAgentKey;
      PolicySource nextSource = current.policySource;
      String nextPolicyJson = current.controlPolicyJson;
      // A cloud policy distributed through the control file, installed once per change.
      if (object.get("policy") instanceof String policyJson
          && !policyJson.isBlank()
          && !policyJson.equals(current.controlPolicyJson)) {
        nextPolicyJson = policyJson;
        AgentPolicy installed = parsePolicy(policyJson);
        if (installed != null) {
          nextPolicy = installed;
          nextKey = "";
          nextSource = PolicySource.CONTROL_FILE;
        }
      }
      state =
          new ControlState(
              nextMode, nextAlgorithms, nextRevision, nextPolicy, nextKey, nextSource, json, nextPolicyJson);
    }
    return true;
  }

  /** The policy in {@code json}, or null when it does not parse; a bad policy changes nothing. */
  private static AgentPolicy parsePolicy(String json) {
    try {
      return AgentPolicy.parse(json);
    } catch (RuntimeException | StackOverflowError e) {
      // SimpleJson recurses per nesting level; a deeply nested policy overflows the stack.
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP] distributed policy parse failed: " + e);
      }
      return null;
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
