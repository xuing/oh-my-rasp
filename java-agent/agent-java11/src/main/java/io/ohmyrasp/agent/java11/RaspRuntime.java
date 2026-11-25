package io.ohmyrasp.agent.java11;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java 11 backport runtime: asynchronous event spool plus control-file-driven
 * or standalone baked-in detection mode. Mirrors the agent-jdk25 design using
 * only Java 11 APIs.
 *
 * <p>Deliberately self-contained and duplicated per backport module (no shared
 * module), so each backport jar stays independently buildable. Event reporting
 * runs on a background daemon thread when targeting a file path so the
 * protected request never blocks on a file write; {@code OHMYRASP_LOG_SYNC=true}
 * reverts to inline writes for deterministic acceptance/CI runs.
 */
public final class RaspRuntime {
  enum Mode {
    OFF,
    MONITOR,
    BLOCK
  }

  static final class Config {
    final boolean standalone;
    final boolean lockConfig;
    final Mode mode;
    final String controlPath;
    final boolean controlDisabled;
    final String logPath;
    final int latencySample;

    Config(
        boolean standalone,
        boolean lockConfig,
        Mode mode,
        String controlPath,
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
  }

  private RaspRuntime() {}

  private static final String SHIRUDO_CONFIG_RESOURCE = "/META-INF/ohmyrasp-shirudo.properties";
  private static final String DEFAULT_CONTROL_PATH = "/tmp/ohmyrasp-control.json";
  private static final Pattern MODE_PATTERN = Pattern.compile("\"mode\"\\s*:\\s*\"([a-zA-Z]+)\"");

  private static final Properties BAKED_PROPERTIES = loadBakedProperties();
  private static final Config INITIAL_CONFIG = resolveCurrent();
  private static final Path CONTROL_PATH =
      INITIAL_CONFIG.controlDisabled || INITIAL_CONFIG.controlPath == null
          ? null
          : Paths.get(INITIAL_CONFIG.controlPath);
  private static volatile Mode mode = INITIAL_CONFIG.mode; // null = unset -> legacy/standalone default
  private static volatile long controlMtime = Long.MIN_VALUE;

  static {
    if (!INITIAL_CONFIG.controlDisabled && CONTROL_PATH != null) {
      reloadControl();
      var poller =
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
              "ohmyrasp-java11-control");
      poller.setDaemon(true);
      poller.start();
    }
  }

  static Config resolveCurrent() {
    return resolve(BAKED_PROPERTIES, System.getProperties(), System.getenv());
  }

  static Config resolve(Properties baked, Properties sysProps, Map<String, String> env) {
    boolean lockConfig = parseBoolean(getProp(baked, "lock_config"), false);

    Boolean sysStandalone = parseBooleanObject(getProp(sysProps, "ohmyrasp.standalone"));
    Boolean envStandalone = parseBooleanObject(getEnv(env, "OHMYRASP_STANDALONE"));
    Boolean bakedStandalone = parseBooleanObject(getProp(baked, "standalone"));
    Boolean chosenStandalone =
        lockConfig
            ? firstNonNull(bakedStandalone, sysStandalone, envStandalone)
            : firstNonNull(sysStandalone, envStandalone, bakedStandalone);
    boolean standalone = chosenStandalone != null && chosenStandalone.booleanValue();

    Mode sysMode = parseMode(getProp(sysProps, "ohmyrasp.mode"));
    Mode envMode = parseMode(getEnv(env, "OHMYRASP_MODE"));
    Mode bakedMode = parseMode(getProp(baked, "mode"));
    Mode resolvedMode =
        lockConfig
            ? firstNonNull(bakedMode, sysMode, envMode)
            : firstNonNull(sysMode, envMode, bakedMode);

    String sysControl = trimToNull(getProp(sysProps, "ohmyrasp.control"));
    String envControl = trimToNull(getEnv(env, "OHMYRASP_CONTROL"));
    String bakedControl = trimToNull(getProp(baked, "control"));
    String controlRaw =
        lockConfig
            ? firstNonBlank(bakedControl, sysControl, envControl)
            : firstNonBlank(sysControl, envControl, bakedControl);
    if (controlRaw == null) {
      controlRaw = standalone ? "none" : DEFAULT_CONTROL_PATH;
    }
    boolean controlDisabled = isDisabledControl(controlRaw);
    String controlPath = controlDisabled ? null : controlRaw;

    String logPath =
        firstNonBlank(
            trimToNull(getProp(sysProps, "ohmyrasp.java11.log")),
            trimToNull(getProp(sysProps, "ohmyrasp.log")),
            trimToNull(getEnv(env, "OHMYRASP_LOG")),
            trimToNull(getProp(baked, "log")));
    if (logPath == null && standalone) {
      logPath = "stderr";
    }

    Integer sysSample = parseSampleRate(getProp(sysProps, "ohmyrasp.latency_sample"));
    Integer envSample = parseSampleRate(getEnv(env, "OHMYRASP_LATENCY_SAMPLE"));
    Integer bakedSample = parseSampleRate(getProp(baked, "latency_sample"));
    Integer chosenSample = firstNonNull(sysSample, envSample, bakedSample);
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

  static Mode mode() {
    return mode;
  }

  /** True only when detection is explicitly OFF. */
  static boolean detectionOff() {
    return mode == Mode.OFF;
  }

  /** BLOCK or standalone unset permit blocking; MONITOR/OFF do not; otherwise legacy env flag. */
  static boolean blockingAllowed(boolean legacyEnvFlag) {
    return blockingAllowed(INITIAL_CONFIG, mode, legacyEnvFlag);
  }

  static boolean blockingAllowed(Config config, Mode currentMode, boolean legacyEnvFlag) {
    if (currentMode == Mode.BLOCK) {
      return true;
    }
    if (currentMode == Mode.MONITOR || currentMode == Mode.OFF) {
      return false;
    }
    if (config != null && config.standalone) {
      return true;
    }
    return legacyEnvFlag;
  }

  private static void reloadControl() {
    try {
      if (CONTROL_PATH == null || !Files.isRegularFile(CONTROL_PATH)) {
        return;
      }
      long mtime = Files.getLastModifiedTime(CONTROL_PATH).toMillis();
      if (mtime == controlMtime) {
        return;
      }
      controlMtime = mtime;
      var text = new String(Files.readAllBytes(CONTROL_PATH), StandardCharsets.UTF_8);
      Matcher matcher = MODE_PATTERN.matcher(text);
      if (matcher.find()) {
        Mode parsed = parseMode(matcher.group(1));
        if (parsed != null) {
          mode = parsed;
        }
      }
    } catch (IOException | RuntimeException ignored) {
      // keep last known good state
    }
  }

  static Mode parseMode(String token) {
    if (token == null) {
      return null;
    }
    String value = token.trim().toLowerCase(Locale.ROOT);
    if (value.equals("off") || value.equals("disabled") || value.equals("none")) {
      return Mode.OFF;
    }
    if (value.equals("monitor") || value.equals("record") || value.equals("observe") || value.equals("log")) {
      return Mode.MONITOR;
    }
    if (value.equals("block") || value.equals("blocking") || value.equals("protect")) {
      return Mode.BLOCK;
    }
    return null;
  }

  private static long pollMillis() {
    String configured =
        firstNonBlank(
            System.getProperty("ohmyrasp.control.poll_ms"), System.getenv("OHMYRASP_CONTROL_POLL_MS"));
    if (configured != null) {
      try {
        return Math.max(200L, Long.parseLong(configured.trim()));
      } catch (NumberFormatException ignored) {
        // fall through
      }
    }
    return 2000L;
  }

  // ---- asynchronous event spool -------------------------------------------

  private static final BlockingQueue<String> QUEUE = new ArrayBlockingQueue<String>(8192);
  private static final AtomicLong DROPPED = new AtomicLong();
  private static final AtomicLong SAMPLE_COUNTER = new AtomicLong();
  private static final boolean SYNC = syncFlag();
  private static final int SAMPLE_RATE = INITIAL_CONFIG.latencySample;
  private static final boolean WRITER_ENABLED = isFileLogTarget(INITIAL_CONFIG.logPath);
  private static volatile boolean running = true;
  private static volatile String lastLogPath;

  static {
    if (WRITER_ENABLED) {
      var writer =
          new Thread(
              new Runnable() {
                public void run() {
                  drain();
                }
              },
              "ohmyrasp-java11-writer");
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
  }

  /** Resolve the spool path the same way the detection writer does. */
  public static String resolveLogPath() {
    return resolveCurrent().logPath;
  }

  static boolean isFileLogTarget(String logPath) {
    String target = normalizeLogTarget(logPath);
    return target != null
        && !"stderr".equalsIgnoreCase(target)
        && !"stdout".equalsIgnoreCase(target)
        && !"none".equalsIgnoreCase(target);
  }

  public static void writeStartupLine(String logPath, String line) {
    String target = normalizeLogTarget(logPath);
    if (target == null || "stderr".equalsIgnoreCase(target)) {
      System.err.println(line);
      return;
    }
    if ("stdout".equalsIgnoreCase(target)) {
      System.out.println(line);
      return;
    }
    if ("none".equalsIgnoreCase(target)) {
      return;
    }
    appendBatch(target, Collections.singletonList(line));
  }

  /** Off the business hot path: enqueue an already-built event line. */
  public static void writeEvent(String logPath, String line) {
    String target = normalizeLogTarget(logPath);
    if (target == null || "stderr".equalsIgnoreCase(target)) {
      System.err.println(line);
      return;
    }
    if ("stdout".equalsIgnoreCase(target)) {
      System.out.println(line);
      return;
    }
    if ("none".equalsIgnoreCase(target)) {
      return;
    }
    lastLogPath = target;
    if (SYNC || !WRITER_ENABLED) {
      appendBatch(target, Collections.singletonList(line));
      return;
    }
    if (!QUEUE.offer(line)) {
      DROPPED.incrementAndGet();
    }
  }

  /**
   * Record a sampled measurement of the overhead added to a (usually benign)
   * request as a telemetry line, so the daemon's latency panel reflects real
   * traffic. Suppressed in sync mode to keep acceptance output deterministic.
   */
  static void sampleLatency(long micros) {
    if (SYNC || detectionOff() || micros < 0 || SAMPLE_RATE <= 0) {
      return;
    }
    if (SAMPLE_RATE > 1 && SAMPLE_COUNTER.incrementAndGet() % SAMPLE_RATE != 0) {
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
        if (target != null) {
          appendBatch(target, batch);
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      } catch (RuntimeException e) {
        System.err.println("[OHMYRASP-JAVA11] event writer error: " + e);
      }
    }
  }

  private static void flushRemaining() {
    List<String> rest = new ArrayList<String>();
    QUEUE.drainTo(rest);
    String target = lastLogPath;
    if (target != null && !rest.isEmpty()) {
      appendBatch(target, rest);
    }
  }

  private static void appendBatch(String logPath, List<String> lines) {
    var target = new File(logPath);
    File parent = target.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      System.err.println("[OHMYRASP-JAVA11] could not create log directory: " + parent);
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
        System.err.println("[OHMYRASP-JAVA11] could not write detection event: " + e);
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
    var props = new Properties();
    try (InputStream stream = RaspRuntime.class.getResourceAsStream(SHIRUDO_CONFIG_RESOURCE)) {
      if (stream != null) {
        props.load(stream);
      }
    } catch (IOException | RuntimeException ignored) {
      // treat unreadable baked config as absent
    }
    return props;
  }

  private static boolean syncFlag() {
    String value =
        firstNonBlank(System.getProperty("ohmyrasp.log.sync"), System.getenv("OHMYRASP_LOG_SYNC"));
    return parseBoolean(value, false);
  }

  private static boolean parseBoolean(String value, boolean defaultValue) {
    Boolean parsed = parseBooleanObject(value);
    return parsed != null ? parsed.booleanValue() : defaultValue;
  }

  private static Boolean parseBooleanObject(String value) {
    String trimmed = trimToNull(value);
    if (trimmed == null) {
      return null;
    }
    String normalized = trimmed.toLowerCase(Locale.ROOT);
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

  private static Integer parseSampleRate(String value) {
    String trimmed = trimToNull(value);
    if (trimmed == null) {
      return null;
    }
    try {
      return Integer.valueOf(Math.max(0, Integer.parseInt(trimmed)));
    } catch (NumberFormatException ignored) {
      return null;
    }
  }

  private static boolean isDisabledControl(String token) {
    if (token == null) {
      return true;
    }
    String normalized = token.trim().toLowerCase(Locale.ROOT);
    return normalized.equals("none")
        || normalized.equals("off")
        || normalized.equals("disabled");
  }

  private static String normalizeLogTarget(String logPath) {
    return trimToNull(logPath);
  }

  private static String getProp(Properties props, String key) {
    return props == null ? null : props.getProperty(key);
  }

  private static String getEnv(Map<String, String> env, String key) {
    return env == null ? null : env.get(key);
  }

  private static String trimToNull(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.length() > 0 ? trimmed : null;
  }

  private static String firstNonBlank(String... candidates) {
    if (candidates == null) {
      return null;
    }
    for (int i = 0; i < candidates.length; i++) {
      String candidate = trimToNull(candidates[i]);
      if (candidate != null) {
        return candidate;
      }
    }
    return null;
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
}
