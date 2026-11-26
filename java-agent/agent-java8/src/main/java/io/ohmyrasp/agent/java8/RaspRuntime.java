package io.ohmyrasp.agent.java8;

import io.ohmyrasp.agent.util.ControlDocument;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Java 8 backport runtime: asynchronous event spool plus control-file-driven
 * detection mode and optional shirudo upatch standalone configuration. Mirrors
 * the agent-jdk25 design using only Java 8 APIs.
 *
 * <p>Deliberately self-contained and duplicated per backport module (no shared
 * module), so each backport jar stays independently buildable. When the log
 * target resolved at start-up is a file path, events go through a background
 * daemon writer thread so the protected request never blocks on a file write;
 * a target that becomes a file later, or {@code OHMYRASP_LOG_SYNC=true}, writes
 * inline.
 */
public final class RaspRuntime {
  enum Mode {
    OFF,
    MONITOR,
    BLOCK
  }

  static final String SHIRUDO_PROPERTIES_RESOURCE = "/META-INF/ohmyrasp-shirudo.properties";
  private static final String AGENT_ENTRY_CLASS = "io.ohmyrasp.agent.java8.OhMyRaspJava8Agent";

  private interface PropertyLookup {
    String get(String key);
  }

  /** Immutable resolved runtime configuration. */
  static final class Config {
    final boolean standalone;
    final boolean lockConfig;
    final Mode mode;
    final Path controlPath;
    final boolean controlDisabled;
    final String logPath;
    final int latencySample;

    private Config(
        boolean standalone,
        boolean lockConfig,
        Mode mode,
        Path controlPath,
        boolean controlDisabled,
        String logPath,
        int latencySample) {
      this.standalone = standalone;
      this.lockConfig = lockConfig;
      this.mode = mode;
      this.controlPath = controlPath;
      this.controlDisabled = controlDisabled;
      this.logPath = logPath;
      this.latencySample = latencySample;
    }

    static Config resolveCurrent() {
      return resolve(
          BAKED_PROPERTIES,
          new PropertyLookup() {
            public String get(String key) {
              return System.getProperty(key);
            }
          },
          new PropertyLookup() {
            public String get(String key) {
              return System.getenv(key);
            }
          });
    }

    static Config resolve(Properties baked, final Properties sysProps, final Map<String, String> env) {
      return resolve(
          baked,
          new PropertyLookup() {
            public String get(String key) {
              return sysProps == null ? null : sysProps.getProperty(key);
            }
          },
          new PropertyLookup() {
            public String get(String key) {
              return env == null ? null : env.get(key);
            }
          });
    }

    private static Config resolve(Properties baked, PropertyLookup sysProps, PropertyLookup env) {
      boolean lockConfig = parseBoolean(bakedProperty(baked, "lock_config"));

      // Each source is parsed on its own: an invalid value is ignored and the next source applies.
      // Under lock_config only the baked value counts, and a missing one takes the default.
      Boolean bakedStandalone = parseBooleanObject(bakedProperty(baked, "standalone"));
      Boolean chosenStandalone =
          lockConfig
              ? bakedStandalone
              : firstNonNull(
                  parseBooleanObject(sysProps.get("ohmyrasp.standalone")),
                  parseBooleanObject(env.get("OHMYRASP_STANDALONE")),
                  bakedStandalone);
      boolean standalone = Boolean.TRUE.equals(chosenStandalone);

      Mode bakedMode = parseMode(bakedProperty(baked, "mode"));
      Mode resolvedMode =
          lockConfig
              ? bakedMode
              : firstNonNull(
                  parseMode(sysProps.get("ohmyrasp.mode")),
                  parseMode(env.get("OHMYRASP_MODE")),
                  bakedMode);
      if (resolvedMode == null && standalone) {
        resolvedMode = Mode.BLOCK;
      }

      String bakedControl = validControl(bakedProperty(baked, "control"));
      String controlRaw;
      if (lockConfig) {
        // Only a baked control path counts. Without one nothing is polled, standalone or not: the
        // default lives in world-writable /tmp and must not steer a locked profile.
        controlRaw = bakedControl != null ? bakedControl : "none";
      } else {
        controlRaw =
            firstNonNull(
                validControl(sysProps.get("ohmyrasp.control")),
                validControl(env.get("OHMYRASP_CONTROL")),
                bakedControl);
        if (controlRaw == null) {
          controlRaw = standalone ? "none" : "/tmp/ohmyrasp-control.json";
        }
      }
      boolean controlDisabled = isControlDisabledValue(controlRaw);
      Path controlPath = controlDisabled ? null : toPathOrNull(controlRaw);

      String bakedLog = bakedProperty(baked, "log");
      String logPath =
          firstNonBlank(
              sysProps.get("ohmyrasp.java8.log"),
              sysProps.get("ohmyrasp.log"),
              env.get("OHMYRASP_LOG"),
              bakedLog);
      if (logPath == null) {
        if (standalone) {
          logPath = "stderr";
        }
      } else {
        logPath = logPath.trim();
      }

      Integer chosenSample =
          firstNonNull(
              parseSampleRate(sysProps.get("ohmyrasp.latency_sample")),
              parseSampleRate(env.get("OHMYRASP_LATENCY_SAMPLE")),
              parseSampleRate(bakedProperty(baked, "latency_sample")));
      int latencySample = chosenSample != null ? chosenSample.intValue() : (standalone ? 0 : 10);

      return new Config(
          standalone,
          lockConfig,
          resolvedMode,
          controlPath,
          controlDisabled,
          logPath,
          latencySample);
    }
  }

  private RaspRuntime() {}

  // ---- detection mode, polled from the control file -----------------------

  /**
   * The detection mode and the control file that steers it. {@link #poll} is one polling step:
   * the poller thread calls it, and so can a test, without the thread.
   */
  static final class ControlState {
    private final Mode startup;
    private volatile Mode mode; // null = unset -> legacy behavior
    // The content last applied. The file is read on every poll and applied when its content
    // differs; content that fails to parse is not recorded, so a document read half-written is
    // applied once it is complete, whatever its modification time.
    private volatile String applied;

    ControlState(Mode startup) {
      this.startup = startup;
      this.mode = startup;
    }

    Mode mode() {
      return mode;
    }

    /**
     * One polling step. The control file overrides the start-up mode only while it exists: when it
     * is gone the start-up mode returns. When it exists but cannot be read or parsed, the last good
     * mode stays; the daemon replaces the file atomically, so such a read is transient.
     */
    void poll(Path path) {
      if (path == null) {
        return;
      }
      String text;
      try {
        if (Files.notExists(path)) {
          restoreStartup();
          return;
        }
        if (!Files.isRegularFile(path)) {
          return;
        }
        text = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
      } catch (NoSuchFileException gone) {
        restoreStartup();
        return;
      } catch (IOException | RuntimeException unreadable) {
        return;
      }
      if (text.equals(applied)) {
        return;
      }
      String token;
      try {
        // Only one complete JSON object counts, and only its top-level mode.
        token = ControlDocument.topLevelString(text, "mode");
      } catch (IllegalArgumentException malformed) {
        return; // keep the last good state and record nothing
      }
      applied = text;
      Mode parsed = parseMode(token);
      if (parsed != null) {
        mode = parsed; // an unrecognised mode changes nothing
      }
    }

    private void restoreStartup() {
      applied = null;
      mode = startup;
    }
  }

  private static final Properties BAKED_PROPERTIES = loadBakedProperties();
  private static final Config INITIAL_CONFIG = Config.resolveCurrent();
  private static final Path CONTROL_PATH = INITIAL_CONFIG.controlPath;
  private static final ControlState CONTROL = new ControlState(INITIAL_CONFIG.mode);

  // ---- asynchronous event spool -------------------------------------------

  private static final BlockingQueue<String> QUEUE = new ArrayBlockingQueue<String>(8192);
  private static final AtomicLong DROPPED = new AtomicLong();
  private static final AtomicLong SAMPLE_COUNTER = new AtomicLong();
  private static final boolean SYNC = syncFlag();
  private static final int SAMPLE_RATE = INITIAL_CONFIG.latencySample;
  // The writer thread exists only when the log target resolved at start-up is a file. It is never
  // created inside a hook: a target that becomes a file later is written inline.
  private static final boolean WRITER_ENABLED = isFileLogTarget(INITIAL_CONFIG.logPath);
  private static volatile boolean running = true;
  private static volatile String lastLogPath;

  static {
    if (CONTROL_PATH != null) {
      reloadControl();
      Thread poller =
          new Thread(
              new Runnable() {
                public void run() {
                  while (true) {
                    try {
                      Thread.sleep(pollMillis());
                      reloadControl();
                    } catch (InterruptedException e) {
                      Thread.currentThread().interrupt();
                      return;
                    } catch (RuntimeException ignored) {
                      // never let control polling disturb the application
                    }
                  }
                }
              },
              "ohmyrasp-java8-control");
      poller.setDaemon(true);
      poller.start();
    }
    if (WRITER_ENABLED) {
      startWriter();
    }
  }

  static Mode mode() {
    return CONTROL.mode();
  }

  /** True only when detection is explicitly OFF. */
  static boolean detectionOff() {
    return CONTROL.mode() == Mode.OFF;
  }

  /** BLOCK or standalone unset permit blocking; MONITOR/OFF do not; legacy falls back to flag. */
  static boolean blockingAllowed(boolean legacyEnvFlag) {
    return blockingAllowed(INITIAL_CONFIG.standalone, CONTROL.mode(), legacyEnvFlag);
  }

  static boolean blockingAllowed(boolean standalone, Mode currentMode, boolean legacyEnvFlag) {
    if (currentMode == Mode.BLOCK) {
      return true;
    }
    if (currentMode == Mode.MONITOR || currentMode == Mode.OFF) {
      return false;
    }
    if (standalone) {
      return true;
    }
    return legacyEnvFlag;
  }

  private static void reloadControl() {
    CONTROL.poll(CONTROL_PATH);
  }

  static Mode parseMode(String token) {
    if (token == null) {
      return null;
    }
    String value = token.trim().toLowerCase(Locale.ROOT);
    if (value.equals("off") || value.equals("disabled") || value.equals("none")) {
      return Mode.OFF;
    }
    if (value.equals("monitor")
        || value.equals("record")
        || value.equals("observe")
        || value.equals("log")) {
      return Mode.MONITOR;
    }
    if (value.equals("block") || value.equals("blocking") || value.equals("protect")) {
      return Mode.BLOCK;
    }
    return null;
  }

  private static boolean isControlDisabledValue(String value) {
    if (value == null) {
      return true;
    }
    String normalized = value.trim().toLowerCase(Locale.ROOT);
    return normalized.equals("none")
        || normalized.equals("off")
        || normalized.equals("disabled");
  }

  private static long pollMillis() {
    return pollMillis(
        System.getProperty("ohmyrasp.control.poll_ms"), System.getenv("OHMYRASP_CONTROL_POLL_MS"));
  }

  /** The poll interval: the first source that holds a number, floored at 200 ms; else 2000 ms. */
  static long pollMillis(String sysValue, String envValue) {
    Long configured = parseMillis(sysValue);
    if (configured == null) {
      configured = parseMillis(envValue);
    }
    return configured == null ? 2000L : Math.max(200L, configured.longValue());
  }

  private static Long parseMillis(String value) {
    if (!hasText(value)) {
      return null;
    }
    try {
      return Long.valueOf(Long.parseLong(value.trim()));
    } catch (NumberFormatException ignored) {
      return null;
    }
  }

  /** The legacy per-line block flag, read on every blocking decision. */
  static boolean legacyBlockFlag() {
    return legacyBlockFlag(System.getProperty("ohmyrasp.java8.block"), System.getenv("OHMYRASP_JAVA8_BLOCK"));
  }

  /** The first source that holds a recognised boolean decides; none means false. */
  static boolean legacyBlockFlag(String sysValue, String envValue) {
    return firstValidFlag(sysValue, envValue);
  }

  private static boolean firstValidFlag(String sysValue, String envValue) {
    Boolean chosen = parseBooleanObject(sysValue);
    if (chosen == null) {
      chosen = parseBooleanObject(envValue);
    }
    return Boolean.TRUE.equals(chosen);
  }

  /** Resolve the spool path the same way the detection writer does. */
  public static String resolveLogPath() {
    return Config.resolveCurrent().logPath;
  }

  static boolean isFileLogTarget(String logPath) {
    if (logPath == null) {
      return false;
    }
    String trimmed = logPath.trim();
    if (trimmed.length() == 0) {
      return false;
    }
    String normalized = trimmed.toLowerCase(Locale.ROOT);
    return !normalized.equals("stderr")
        && !normalized.equals("stdout")
        && !normalized.equals("none");
  }

  /** Write a startup line synchronously, honoring stderr/stdout/none special targets. */
  public static void writeStartupLine(String logPath, String line) {
    if (emitSpecialTarget(logPath, line)) {
      return;
    }
    appendBatch(logPath.trim(), Collections.singletonList(line));
  }

  /** Off the business hot path: enqueue an already-built event line. */
  public static void writeEvent(String logPath, String line) {
    if (emitSpecialTarget(logPath, line)) {
      return;
    }
    String fileTarget = logPath.trim();
    lastLogPath = fileTarget;
    if (SYNC || !WRITER_ENABLED) {
      appendBatch(fileTarget, Collections.singletonList(line));
      return;
    }
    if (!QUEUE.offer(line)) {
      DROPPED.incrementAndGet();
    }
  }

  private static boolean emitSpecialTarget(String logPath, String line) {
    if (logPath == null || logPath.trim().length() == 0) {
      System.err.println(line);
      return true;
    }
    String normalized = logPath.trim().toLowerCase(Locale.ROOT);
    if (normalized.equals("stderr")) {
      System.err.println(line);
      return true;
    }
    if (normalized.equals("stdout")) {
      System.out.println(line);
      return true;
    }
    if (normalized.equals("none")) {
      return true;
    }
    return false;
  }

  private static void startWriter() {
    Thread writer =
        new Thread(
            new Runnable() {
              public void run() {
                drain();
              }
            },
            "ohmyrasp-java8-writer");
    writer.setDaemon(true);
    writer.start();
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                new Runnable() {
                  public void run() {
                    running = false;
                    flushRemaining();
                  }
                }));
  }

  /**
   * Record a sampled measurement of the overhead added to a (usually benign)
   * request as a telemetry line, so the daemon's latency panel reflects real
   * traffic. Suppressed in sync mode to keep acceptance output deterministic.
   */
  static void sampleLatency(long micros) {
    if (!latencySampled(SYNC, detectionOff(), micros, SAMPLE_RATE, SAMPLE_COUNTER)) {
      return;
    }
    String line =
        "{\"timestamp\":"
            + System.currentTimeMillis()
            + ",\"kind\":\"telemetry\",\"hook\":\"http_request\",\"algorithm\":\"hook_latency\","
            + "\"action\":\"observe\",\"confidence\":0,\"latency_us\":"
            + micros
            + "}";
    writeEvent(resolveLogPath(), line);
  }

  /** Whether this request's latency is recorded: one in {@code sampleRate}, never in sync mode. */
  static boolean latencySampled(
      boolean sync, boolean off, long micros, int sampleRate, AtomicLong counter) {
    if (sync || off || micros < 0 || sampleRate <= 0) {
      return false;
    }
    return sampleRate == 1 || counter.incrementAndGet() % sampleRate == 0;
  }

  private static void drain() {
    List<String> batch = new ArrayList<String>(64);
    while (running || !QUEUE.isEmpty()) {
      try {
        String first = QUEUE.poll(200, TimeUnit.MILLISECONDS);
        if (first == null) {
          continue;
        }
        batch.clear();
        batch.add(first);
        QUEUE.drainTo(batch, 511);
        String target = lastLogPath;
        if (isFileLogTarget(target)) {
          appendBatch(target, batch);
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      } catch (RuntimeException e) {
        System.err.println("[OHMYRASP-JAVA8] event writer error: " + e);
      }
    }
  }

  private static void flushRemaining() {
    List<String> rest = new ArrayList<String>();
    QUEUE.drainTo(rest);
    String target = lastLogPath;
    if (isFileLogTarget(target) && !rest.isEmpty()) {
      appendBatch(target, rest);
    }
  }

  private static void appendBatch(String logPath, List<String> lines) {
    File target = new File(logPath);
    File parent = target.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      System.err.println("[OHMYRASP-JAVA8] could not create log directory: " + parent);
      return;
    }
    synchronized (RaspRuntime.class) {
      FileWriter writer = null;
      try {
        writer = new FileWriter(target, true);
        String separator = System.lineSeparator();
        for (int i = 0; i < lines.size(); i++) {
          writer.write(lines.get(i));
          writer.write(separator);
        }
      } catch (IOException e) {
        System.err.println("[OHMYRASP-JAVA8] could not write detection event: " + e);
      } finally {
        if (writer != null) {
          try {
            writer.close();
          } catch (IOException ignored) {
            // nothing useful to do during sink protection
          }
        }
      }
    }
  }

  private static Properties loadBakedProperties() {
    Properties props = new Properties();
    InputStream in = null;
    try {
      URL resource = ownResource(SHIRUDO_PROPERTIES_RESOURCE);
      if (resource == null) {
        return props;
      }
      URLConnection connection = resource.openConnection();
      connection.setUseCaches(false);
      in = connection.getInputStream();
      props.load(new InputStreamReader(in, StandardCharsets.UTF_8));
    } catch (IOException | RuntimeException e) {
      // A missing resource (FileNotFoundException) leaves no keys. An unreadable or malformed
      // one (Properties.load throws IllegalArgumentException on a malformed unicode escape) never
      // aborts start-up, and the keys read before the bad line stay, so a damaged later line
      // cannot erase an already-read lock_config or mode.
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (IOException ignored) {
          // nothing useful to do
        }
      }
    }
    return props;
  }

  /**
   * The URL of {@code name} in the agent's own JAR or class directory, or null when that location
   * is unknown. Class-relative lookup is not used: for a class on the bootstrap search it is a
   * system class path lookup, where an application JAR comes before the agent JAR, so a same-named
   * resource there would win.
   */
  private static URL ownResource(String name) throws MalformedURLException {
    URL location = codeLocation(RaspRuntime.class);
    if (location == null) {
      // Defined by the bootstrap loader, which records no code source. The agent JAR is the one the
      // system class loader loaded the entry class from; loadClass returns that loaded class.
      try {
        ClassLoader system = ClassLoader.getSystemClassLoader();
        location = codeLocation(Class.forName(AGENT_ENTRY_CLASS, false, system));
      } catch (ClassNotFoundException | LinkageError e) {
        return null;
      }
    }
    if (location == null) {
      return null;
    }
    String base = location.toString();
    String entry = name.substring(1);
    if (base.endsWith("/")) {
      return new URL(base.concat(entry));
    }
    return new URL("jar:".concat(base).concat("!/").concat(entry));
  }

  private static URL codeLocation(Class<?> type) {
    if (type.getProtectionDomain() == null || type.getProtectionDomain().getCodeSource() == null) {
      return null;
    }
    return type.getProtectionDomain().getCodeSource().getLocation();
  }

  private static String bakedProperty(Properties baked, String key) {
    if (baked == null) {
      return null;
    }
    String value = baked.getProperty(key);
    return hasText(value) ? value.trim() : null;
  }

  private static boolean parseBoolean(String value) {
    return Boolean.TRUE.equals(parseBooleanObject(value));
  }

  /** TRUE or FALSE for a recognised token, null for a blank or unrecognised one. */
  private static Boolean parseBooleanObject(String value) {
    if (!hasText(value)) {
      return null;
    }
    String normalized = value.trim().toLowerCase(Locale.ROOT);
    if (normalized.equals("true")
        || normalized.equals("1")
        || normalized.equals("yes")
        || normalized.equals("on")) {
      return Boolean.TRUE;
    }
    if (normalized.equals("false")
        || normalized.equals("0")
        || normalized.equals("no")
        || normalized.equals("off")) {
      return Boolean.FALSE;
    }
    return null;
  }

  /** A non-negative rate, or null for a blank or non-numeric value. */
  private static Integer parseSampleRate(String value) {
    if (!hasText(value)) {
      return null;
    }
    try {
      return Integer.valueOf(Math.max(0, Integer.parseInt(value.trim())));
    } catch (NumberFormatException ignored) {
      return null;
    }
  }

  /**
   * The trimmed control setting when it disables polling or names a valid path on this platform,
   * else null, so that an unusable value leaves the next source in charge.
   */
  private static String validControl(String value) {
    if (!hasText(value)) {
      return null;
    }
    String trimmed = value.trim();
    if (isControlDisabledValue(trimmed) || toPathOrNull(trimmed) != null) {
      return trimmed;
    }
    return null;
  }

  /** The control path, or null when the value is not a valid path on this platform. */
  private static Path toPathOrNull(String value) {
    try {
      return Paths.get(value);
    } catch (InvalidPathException ignored) {
      return null;
    }
  }

  private static boolean syncFlag() {
    return syncFlag(System.getProperty("ohmyrasp.log.sync"), System.getenv("OHMYRASP_LOG_SYNC"));
  }

  /** The first source that holds a recognised boolean decides; none means false. */
  static boolean syncFlag(String sysValue, String envValue) {
    return firstValidFlag(sysValue, envValue);
  }

  private static boolean hasText(String value) {
    return value != null && value.trim().length() > 0;
  }

  private static <T> T firstNonNull(T first, T second, T third) {
    if (first != null) {
      return first;
    }
    if (second != null) {
      return second;
    }
    return third;
  }

  private static String firstNonBlank(
      String first, String second, String third, String fourth) {
    if (hasText(first)) {
      return first;
    }
    if (hasText(second)) {
      return second;
    }
    if (hasText(third)) {
      return third;
    }
    if (hasText(fourth)) {
      return fourth;
    }
    return null;
  }
}
