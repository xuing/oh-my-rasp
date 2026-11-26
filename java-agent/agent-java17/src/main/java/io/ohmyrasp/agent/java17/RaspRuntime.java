package io.ohmyrasp.agent.java17;

import io.ohmyrasp.agent.util.ControlDocument;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
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
import java.util.concurrent.locks.ReentrantLock;

/**
 * Java 17 backport runtime: asynchronous event spool plus control-file-driven
 * detection mode and optional shirudo upatch standalone configuration. Mirrors
 * the agent-jdk25 design using only Java 17 APIs.
 *
 * <p>Duplicated per backport module, token for token; beyond the JDK it uses only
 * shared/ sources, which every line compiles in, so each backport jar stays
 * independently buildable. When the log
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
  private static final String AGENT_ENTRY_CLASS = "io.ohmyrasp.agent.java17.OhMyRaspJava17Agent";

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
        // Only a baked control path counts. Without one nothing is polled: the default lives in
        // world-writable /tmp and must not steer a locked profile.
        controlRaw = bakedControl != null ? bakedControl : "none";
      } else {
        controlRaw =
            firstNonNull(
                validControl(sysProps.get("ohmyrasp.control")),
                validControl(env.get("OHMYRASP_CONTROL")),
                bakedControl);
        if (controlRaw == null) {
          controlRaw = "/tmp/ohmyrasp-control.json";
        }
      }
      // Standalone mode is self-contained and never polls, whatever control path is set.
      boolean controlDisabled = standalone || isControlDisabledValue(controlRaw);
      Path controlPath = controlDisabled ? null : toPathOrNull(controlRaw);

      String bakedLog = bakedProperty(baked, "log");
      String logPath =
          firstNonBlank(
              sysProps.get("ohmyrasp.java17.log"),
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

  // ---- the agent's own I/O -------------------------------------------------

  // Set while this thread does the agent's own event or control-file I/O. The hooks then neither
  // report nor block, so a log or control path that matches a file rule cannot re-enter them.
  private static final ThreadLocal<Boolean> OWN_IO = new ThreadLocal<Boolean>();

  static boolean inOwnIo() {
    return OWN_IO.get() != null;
  }

  /** Marks this thread as doing the agent's own I/O; false when it already was. */
  static boolean enterOwnIo() {
    if (OWN_IO.get() != null) {
      return false;
    }
    OWN_IO.set(Boolean.TRUE);
    return true;
  }

  static void exitOwnIo(boolean entered) {
    if (entered) {
      OWN_IO.remove();
    }
  }

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
      try {
        pollOnce(path);
      } catch (RuntimeException | StackOverflowError | OutOfMemoryError e) {
        // Nothing the poll step throws escapes it: the last good mode stays.
      }
    }

    private void pollOnce(Path path) {
      String text;
      boolean ownIo = enterOwnIo();
      try {
        if (Files.notExists(path)) {
          restoreStartup();
          return;
        }
        if (!Files.isRegularFile(path)) {
          return;
        }
        // Bounded, strict UTF-8: an oversized or malformed file is unparseable.
        text = ControlDocument.read(path, MAX_CONTROL_BYTES);
      } catch (NoSuchFileException gone) {
        restoreStartup();
        return;
      } catch (IOException | RuntimeException unreadable) {
        return;
      } finally {
        exitOwnIo(ownIo);
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

  /** A control file larger than this many bytes is unparseable; only this many + 1 are read. */
  static final int MAX_CONTROL_BYTES = 1 << 20;

  private static final Properties BAKED_PROPERTIES = loadBakedProperties();
  private static final Config INITIAL_CONFIG = Config.resolveCurrent();
  private static final Path CONTROL_PATH = INITIAL_CONFIG.controlPath;
  private static final ControlState CONTROL = new ControlState(INITIAL_CONFIG.mode);

  // ---- asynchronous event spool -------------------------------------------

  // The shutdown hook waits this long for the writer to finish the batch it holds.
  private static final long SHUTDOWN_JOIN_MILLIS = 2000L;
  // Once shutdown has begun, a write waits this long for the write lock and then gives up.
  private static final long SHUTDOWN_LOCK_MILLIS = 1000L;
  // Serialises appends to the log files, so concurrent writers never interleave a line.
  static final ReentrantLock WRITE_LOCK = new ReentrantLock();
  /** Appends to the log file named by the target, under {@link #WRITE_LOCK}. */
  static final Sink FILE_SINK =
      new Sink() {
        public void append(String target, List<String> lines, boolean bounded) {
          appendBatch(target, lines, bounded);
        }
      };
  private static final EventSpool SPOOL = new EventSpool(FILE_SINK);
  private static final AtomicLong SAMPLE_COUNTER = new AtomicLong();
  private static final boolean SYNC = syncFlag();
  private static final int SAMPLE_RATE = INITIAL_CONFIG.latencySample;
  // The writer thread exists only when the log target resolved at start-up is a file. It is never
  // created inside a hook: a target that becomes a file later is written inline.
  private static final boolean WRITER_ENABLED = isFileLogTarget(INITIAL_CONFIG.logPath);

  static {
    // Load and initialise, before any hook runs, the classes a hook would otherwise load first:
    // the hooks run inside JDK classes, where loading a class can re-enter them.
    new Event("", "");
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
                    } catch (RuntimeException | Error ignored) {
                      // never let control polling disturb the application or stop polling
                    }
                  }
                }
              },
              "ohmyrasp-java17-control");
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

  /** True when detection is explicitly OFF, and during the agent's own I/O on this thread. */
  static boolean detectionOff() {
    return CONTROL.mode() == Mode.OFF || inOwnIo();
  }

  /**
   * BLOCK or standalone unset permit blocking; MONITOR/OFF do not; legacy falls back to flag. The
   * agent's own I/O is never blocked.
   */
  static boolean blockingAllowed(boolean legacyEnvFlag) {
    if (inOwnIo()) {
      return false;
    }
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
    return legacyBlockFlag(System.getProperty("ohmyrasp.java17.block"), System.getenv("OHMYRASP_JAVA17_BLOCK"));
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
    if (SYNC || !WRITER_ENABLED) {
      appendBatch(fileTarget, Collections.singletonList(line));
      return;
    }
    SPOOL.offer(fileTarget, line);
  }

  private static boolean emitSpecialTarget(String logPath, String line) {
    PrintStream stream;
    String normalized =
        logPath == null ? "" : logPath.trim().toLowerCase(Locale.ROOT);
    if (normalized.length() == 0 || normalized.equals("stderr")) {
      stream = System.err;
    } else if (normalized.equals("stdout")) {
      stream = System.out;
    } else {
      return normalized.equals("none");
    }
    boolean ownIo = enterOwnIo();
    try {
      stream.println(line);
    } finally {
      exitOwnIo(ownIo);
    }
    return true;
  }

  private static void startWriter() {
    SPOOL.start("ohmyrasp-java17-writer");
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                new Runnable() {
                  public void run() {
                    SPOOL.shutdown(SHUTDOWN_JOIN_MILLIS);
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

  /**
   * Where the spool writes a batch of event lines. A {@code bounded} append, made once shutdown
   * has begun, waits only a bounded time for anything it shares with other writers.
   */
  interface Sink {
    void append(String target, List<String> lines, boolean bounded);
  }

  /** One queued event line and the file target it was accepted for. */
  private static final class Event {
    final String target;
    final String line;

    Event(String target, String line) {
      this.target = target;
      this.line = line;
    }
  }

  /**
   * The bounded queue between the hooks and the writer thread. Each event keeps the target it was
   * accepted for, so a later change of log target does not move it. {@link #drainOnce} is one
   * writer step and {@link #shutdown} is the shutdown hook's work, so a test can drive both.
   */
  static final class EventSpool implements Runnable {
    private final BlockingQueue<Event> queue = new ArrayBlockingQueue<Event>(8192);
    private final AtomicLong dropped = new AtomicLong();
    private final List<Event> batch = new ArrayList<Event>(64);
    private final Sink sink;
    private volatile boolean running = true;
    // Set by shutdown once the writer is gone or given up on: from then on events are written on
    // the caller's thread, since no writer will take them from the queue.
    private volatile boolean closed;
    private volatile Thread writer;

    EventSpool(Sink sink) {
      this.sink = sink;
    }

    void offer(String target, String line) {
      if (closed) {
        sink.append(target, Collections.singletonList(line), true);
        return;
      }
      if (!queue.offer(new Event(target, line))) {
        dropped.incrementAndGet();
      }
      if (closed) {
        // Shutdown may have drained the queue before this event arrived: write what is left.
        writeRest();
      }
    }

    /** Waits up to {@code waitMillis} for an event, then writes everything queued. */
    void drainOnce(long waitMillis) throws InterruptedException {
      Event first = queue.poll(waitMillis, TimeUnit.MILLISECONDS);
      if (first == null) {
        return;
      }
      batch.clear();
      batch.add(first);
      queue.drainTo(batch, 511);
      write(batch, closed);
    }

    /** Writes everything still queued; each event leaves the queue once, so none is written twice. */
    private void writeRest() {
      List<Event> rest = new ArrayList<Event>();
      queue.drainTo(rest);
      write(rest, true);
    }

    /** Writes events in order, one sink call per run of events with the same target. */
    private void write(List<Event> events, boolean bounded) {
      int start = 0;
      while (start < events.size()) {
        String target = events.get(start).target;
        List<String> lines = new ArrayList<String>();
        int end = start;
        while (end < events.size() && events.get(end).target.equals(target)) {
          lines.add(events.get(end).line);
          end++;
        }
        sink.append(target, lines, bounded);
        start = end;
      }
    }

    public void run() {
      while (running) {
        try {
          drainOnce(200L);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          return;
        } catch (RuntimeException e) {
          System.err.println("[OHMYRASP-JAVA17] event writer error: " + e);
        }
      }
    }

    Thread start(String name) {
      Thread thread = new Thread(this, name);
      thread.setDaemon(true);
      writer = thread;
      thread.start();
      return thread;
    }

    /**
     * Stops the writer, waits up to {@code joinMillis} for it to finish the batch it holds, then
     * writes what is still queued, waiting a bounded time for the write lock. An event offered
     * after that is written on the caller's thread. Each event leaves the queue once, so none is
     * written twice. A batch the writer still holds when the wait ends, because it is stalled in
     * an output call, can be lost.
     */
    void shutdown(long joinMillis) {
      running = false;
      Thread current = writer;
      if (current != null && current != Thread.currentThread()) {
        try {
          current.join(joinMillis);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      closed = true;
      writeRest();
    }
  }

  /** Appends lines to a log file as the agent's own I/O, invisible to the file hooks. */
  private static void appendBatch(String logPath, List<String> lines) {
    appendBatch(logPath, lines, false);
  }

  private static void appendBatch(String logPath, List<String> lines, boolean bounded) {
    boolean ownIo = enterOwnIo();
    try {
      appendLines(logPath, lines, bounded);
    } finally {
      exitOwnIo(ownIo);
    }
  }

  private static void appendLines(String logPath, List<String> lines, boolean bounded) {
    File target = new File(logPath);
    File parent = target.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      System.err.println("[OHMYRASP-JAVA17] could not create log directory: " + parent);
      return;
    }
    if (!lockWrites(bounded)) {
      return; // shutdown gave up on a writer stalled with the lock: these lines are lost
    }
    try {
      FileWriter writer = null;
      try {
        writer = new FileWriter(target, true);
        String separator = System.lineSeparator();
        for (int i = 0; i < lines.size(); i++) {
          writer.write(lines.get(i));
          writer.write(separator);
        }
      } catch (IOException e) {
        System.err.println("[OHMYRASP-JAVA17] could not write detection event: " + e);
      } finally {
        if (writer != null) {
          try {
            writer.close();
          } catch (IOException ignored) {
            // nothing useful to do during sink protection
          }
        }
      }
    } finally {
      WRITE_LOCK.unlock();
    }
  }

  /** Takes the write lock; a bounded caller waits at most SHUTDOWN_LOCK_MILLIS. */
  private static boolean lockWrites(boolean bounded) {
    if (!bounded) {
      WRITE_LOCK.lock();
      return true;
    }
    try {
      return WRITE_LOCK.tryLock(SHUTDOWN_LOCK_MILLIS, TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
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
