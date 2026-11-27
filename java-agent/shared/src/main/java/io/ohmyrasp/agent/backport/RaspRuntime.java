package io.ohmyrasp.agent.backport;

import io.ohmyrasp.agent.rules.OutsideRequest;
import io.ohmyrasp.agent.util.ControlDocument;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
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
 * The backport runtime: asynchronous event spool plus control-file-driven
 * detection mode and optional shirudo upatch standalone configuration. Mirrors
 * the agent-jdk25 design using only Java 8 APIs.
 *
 * <p>One copy for the three backport lines. What differs between them (the line's
 * own property names, thread names and log prefix) comes from the installed
 * {@link BackportLine}. The line's entry class installs the line and calls
 * {@link #start} before it registers any transformer; until then the runtime
 * refuses to run and throws IllegalStateException. When the log
 * target resolved at start-up is a file path, events go through a background
 * daemon writer thread so the protected request never blocks on a file write;
 * a target that becomes a file later, or {@code OHMYRASP_LOG_SYNC=true}, writes
 * inline. At JVM exit the shutdown hook writes nothing itself: it lets that thread drain the
 * queue for a bounded time ({@link #closeForShutdown}). Diagnostic lines take a path of their own
 * ({@link #writeDiagnostic}). Every line written to a file is UTF-8.
 */
public final class RaspRuntime {
  enum Mode {
    OFF,
    MONITOR,
    BLOCK
  }

  static final String SHIRUDO_PROPERTIES_RESOURCE = "/META-INF/ohmyrasp-shirudo.properties";

  private interface PropertyLookup {
    String get(String key);
  }

  /** Immutable resolved runtime configuration. */
  static final class Config {
    final boolean standalone;
    final boolean lockConfig;
    final Mode mode;
    // Whether a finding outside an HTTP request blocks; see OutsideRequest.
    final boolean outsideRequestBlocks;
    final Path controlPath;
    final boolean controlDisabled;
    final String logPath;
    final int latencySample;

    private Config(
        boolean standalone,
        boolean lockConfig,
        Mode mode,
        boolean outsideRequestBlocks,
        Path controlPath,
        boolean controlDisabled,
        String logPath,
        int latencySample) {
      this.standalone = standalone;
      this.lockConfig = lockConfig;
      this.mode = mode;
      this.outsideRequestBlocks = outsideRequestBlocks;
      this.controlPath = controlPath;
      this.controlDisabled = controlDisabled;
      this.logPath = logPath;
      this.latencySample = latencySample;
    }

    static Config resolveCurrent() {
      return resolveCurrent(started().baked);
    }

    private static Config resolveCurrent(Properties baked) {
      return resolve(
          baked,
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

      // Resolved like mode: each source on its own, only the baked value under lock_config.
      Boolean bakedOutside = OutsideRequest.parse(bakedProperty(baked, OutsideRequest.CONTROL_KEY));
      Boolean chosenOutside =
          lockConfig
              ? bakedOutside
              : firstNonNull(
                  OutsideRequest.parse(sysProps.get(OutsideRequest.PROPERTY)),
                  OutsideRequest.parse(env.get(OutsideRequest.ENVIRONMENT)),
                  bakedOutside);
      boolean outsideRequestBlocks =
          chosenOutside == null ? OutsideRequest.DEFAULT_BLOCKS : chosenOutside.booleanValue();

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
              sysProps.get(BackportLine.current().logProperty),
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
          outsideRequestBlocks,
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
   * What the control file steers, published as one value: a hook reads it once and never sees a
   * new mode beside an old {@code outside_request}.
   */
  static final class Settings {
    final Mode mode; // null = unset -> legacy behavior
    // The host's outside_request: the document's top-level member, or the start-up value.
    final boolean hostOutsideRequestBlocks;
    // Whether the installed cloud policy permits blocking outside a request (its config.hardening).
    final boolean policyPermitsOutsideBlock;
    // Whether a context-dependent finding outside a request blocks: both the host and the policy say so.
    final boolean outsideRequestBlocks;

    Settings(Mode mode, boolean hostOutsideRequestBlocks) {
      this(mode, hostOutsideRequestBlocks, true);
    }

    Settings(Mode mode, boolean hostOutsideRequestBlocks, boolean policyPermitsOutsideBlock) {
      this.mode = mode;
      this.hostOutsideRequestBlocks = hostOutsideRequestBlocks;
      this.policyPermitsOutsideBlock = policyPermitsOutsideBlock;
      this.outsideRequestBlocks = hostOutsideRequestBlocks && policyPermitsOutsideBlock;
    }
  }

  private static final String[] CONTROL_KEYS = {"mode", OutsideRequest.CONTROL_KEY, "policy"};

  /**
   * The detection mode, whether a finding outside a request blocks, and the control file that
   * steers them. {@link #poll} is one polling step: the poller thread calls it, and so can a test,
   * without the thread.
   */
  static final class ControlState {
    private final Settings startup;
    private volatile Settings current;
    // The content last applied. The file is read on every poll and applied when its content
    // differs; content that fails to parse is not recorded, so a document read half-written is
    // applied once it is complete, whatever its modification time.
    private volatile String applied;

    ControlState(Mode startup) {
      this(startup, OutsideRequest.DEFAULT_BLOCKS);
    }

    ControlState(Mode startup, boolean outsideRequestBlocks) {
      this.startup = new Settings(startup, outsideRequestBlocks);
      this.current = this.startup;
    }

    Mode mode() {
      return current.mode;
    }

    Settings settings() {
      return current;
    }

    /**
     * One polling step. The control file overrides the start-up settings only while it exists:
     * when it is gone they return. When it exists but cannot be read or parsed, the last good
     * settings stay; the daemon replaces the file atomically, so such a read is transient.
     */
    void poll(Path path) {
      if (path == null) {
        return;
      }
      try {
        pollOnce(path);
      } catch (Throwable e) {
        // Nothing the poll step throws escapes it, an Error from a file system provider included:
        // the last good settings stay, and the first poll, made while RaspRuntime initialises
        // before any hook is installed, cannot abort the JVM's start-up.
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
      Object[] values;
      try {
        // Only one complete JSON object counts, and only its top-level members.
        values = ControlDocument.topLevelValues(text, CONTROL_KEYS);
      } catch (IllegalArgumentException malformed) {
        return; // keep the last good state and record nothing
      }
      applied = text;
      Settings now = current;
      // An unrecognised mode changes nothing.
      Mode parsed = values[0] instanceof String ? parseMode((String) values[0]) : null;
      // The cloud's outside_request travels in the policy and leaves with it; a document without a policy has none.
      boolean policyPermits = OutsideRequest.policyPermitsBlocking(values[2] instanceof String ? (String) values[2] : null);
      current = new Settings(parsed != null ? parsed : now.mode, outsideRequest(values[1], now), policyPermits);
    }

    /**
     * The host's {@code outside_request} a document sets: absent or null returns the start-up value,
     * a value nobody accepts changes nothing, as an unrecognised mode does.
     */
    private boolean outsideRequest(Object value, Settings now) {
      if (value == null) {
        return startup.hostOutsideRequestBlocks;
      }
      Boolean parsed = value instanceof String ? OutsideRequest.parse((String) value) : null;
      return parsed != null ? parsed.booleanValue() : now.hostOutsideRequestBlocks;
    }

    private void restoreStartup() {
      applied = null;
      current = startup;
    }
  }

  /** A control file larger than this many bytes is unparseable; only this many + 1 are read. */
  static final int MAX_CONTROL_BYTES = 1 << 20;

  // ---- asynchronous event spool -------------------------------------------

  // At JVM exit, how long the shutdown hook lets the writer drain what was queued before the hook returns. The hook
  // does no output itself: what the writer has not taken by then is dropped and counted.
  private static final long SHUTDOWN_JOIN_MILLIS = 2000L;
  // A stop (the undo of a failed start, or a test) waits this long for each thread it stops.
  private static final long STOP_JOIN_MILLIS = 2000L;
  // Serialises appends of detection and start lines to the log files, so concurrent writers never interleave a line.
  // A diagnostic line never takes it (see writeDiagnostic).
  static final ReentrantLock WRITE_LOCK = new ReentrantLock();
  /** Appends to the log file named by the target, under {@link #WRITE_LOCK}. */
  static final Sink FILE_SINK =
      new Sink() {
        public void append(String target, List<String> lines) {
          appendBatch(target, lines);
        }
      };
  private static final AtomicLong SAMPLE_COUNTER = new AtomicLong();
  // Diagnostic lines dropped: a console or none target, a stopped runtime, a spool closed at exit, a failed write.
  private static final AtomicLong DIAGNOSTICS_DROPPED = new AtomicLong();

  /** How a diagnostic line reaches its file: one append, on the hook-miss worker's thread. Tests replace it. */
  interface DiagnosticOutput {
    void append(File target, byte[] line) throws IOException;
  }

  static final DiagnosticOutput FILE_APPEND =
      new DiagnosticOutput() {
        public void append(File target, byte[] line) throws IOException {
          appendBytes(target, line);
        }
      };
  static volatile DiagnosticOutput diagnosticOutput = FILE_APPEND;

  /** What one {@link #start} resolved and started. */
  private static final class Started {
    final BackportLine line;
    final Properties baked;
    final Config initial;
    final Path controlPath;
    final ControlState control;
    final boolean sync;
    final int sampleRate;
    // The writer thread exists only when the log target resolved at start-up is a file. It is never
    // created inside a hook: a target that becomes a file later is written inline.
    final boolean writerEnabled;
    // This start's own queue and writer: the writer of a start that was stopped cannot take a later start's events.
    final EventSpool spool;
    // The threads this start started and its shutdown hook. Written under START_LOCK before the start is published.
    Thread poller;
    Thread shutdownHook;
    // Set when this start is stopped: from then on it writes nothing. Its configuration stays readable.
    volatile boolean stopped;

    Started(BackportLine line, Properties baked, Config initial, boolean sync) {
      this.line = line;
      this.baked = baked;
      this.initial = initial;
      this.controlPath = initial.controlPath;
      this.control = new ControlState(initial.mode, initial.outsideRequestBlocks);
      this.sync = sync;
      this.sampleRate = initial.latencySample;
      this.writerEnabled = isFileLogTarget(initial.logPath);
      this.spool = new EventSpool(FILE_SINK);
    }
  }

  private static final Object START_LOCK = new Object();
  // The line's one start per JVM, whichever entry makes it: NONE until an entry claims it, then STARTING, then
  // STARTED or FAILED for good. Guarded by START_LOCK. This class is defined once, by the bootstrap loader (the entry
  // checks it), so the claim holds for every entry: premain, agentmain, the launcher's and a direct one.
  private static final int CLAIM_NONE = 0;
  private static final int CLAIM_STARTING = 1;
  private static final int CLAIM_STARTED = 2;
  private static final int CLAIM_FAILED = 3;
  private static int claim = CLAIM_NONE;
  // At JVM exit, how long the hook-miss report may take to finish a line it is writing before its admission closes.
  private static final long DIAGNOSTIC_HANDOFF_MILLIS = 500;
  // Guarded by START_LOCK: set once the shutdown hook has run; then no start succeeds.
  private static boolean shuttingDown;
  // Guarded by START_LOCK: the start whose threads run, for stop(); null when none does.
  private static Started running;
  // The configuration of the latest start, published once its threads run and never taken back: a stop leaves it
  // readable, so a hook that was already past HookActivation when an undo ran finishes with the configuration it
  // started with and never meets an unstarted runtime (which throws IllegalStateException). The hooks act only while
  // HookActivation is on, which the entry class turns on after its start committed.
  private static volatile Started started;

  /** The started runtime. Throws when {@link #start} has not run: the runtime never runs unconfigured. */
  private static Started started() {
    Started current = started;
    if (current == null) {
      throw new IllegalStateException(
          "the backport runtime has not started: the line's entry class starts it before it installs any hook");
    }
    return current;
  }

  /**
   * Whether a {@link #start} has completed in this JVM: its configuration is readable from then on, also after a
   * {@link #stop}. Whether the hooks act is {@link io.ohmyrasp.agent.hook.HookActivation}'s.
   */
  static boolean isStarted() {
    return started != null;
  }

  /** Whether a started runtime is running: its threads run and it writes. Tests only. */
  static boolean isRunning() {
    synchronized (START_LOCK) {
      return running != null;
    }
  }

  /**
   * Claims the line's one start in this JVM for the calling entry. Throws, and changes nothing, when an entry already
   * claimed it: one that is starting, one that started, or one whose start failed (a failed start is not retried; its
   * undo cannot take out the calls its transformers already injected). The entry class calls it once the agent JAR
   * is on the bootstrap search and this class is the bootstrap one, before it starts or registers anything, and
   * {@link #endClaim} when its start has ended.
   */
  public static void claimStart() {
    synchronized (START_LOCK) {
      if (claim != CLAIM_NONE) {
        throw new IllegalStateException("[OHMYRASP] the backport line was already "
            + (claim == CLAIM_STARTING ? "being started" : claim == CLAIM_STARTED ? "started" : "started once and failed")
            + " in this JVM: this start does nothing");
      }
      claim = CLAIM_STARTING;
    }
  }

  /** Ends the claim of {@link #claimStart}: the start committed, or it failed and was undone. */
  public static void endClaim(boolean committed) {
    synchronized (START_LOCK) {
      claim = committed ? CLAIM_STARTED : CLAIM_FAILED;
    }
  }

  /**
   * Resolves the configuration, reads the control file once and starts the poller and writer threads, for the
   * installed {@link BackportLine}. The line's start calls it before the entry class registers any transformer, so
   * no hook does this work on an application thread. Starting the runtime does not turn the hooks on: the entry class
   * does that ({@link io.ohmyrasp.agent.hook.HookActivation}) once its whole start has committed.
   *
   * <p>All or nothing: what can fail (the configuration, the first control-file read, registering the shutdown
   * hook, which the JVM refuses once it has begun to shut down) comes before any thread starts. If starting a
   * thread fails, the threads already started are stopped and the shutdown hook is removed, the runtime stays
   * unstarted, and a later call starts it from the beginning. The started state is published last, through the
   * volatile {@code started}. The shutdown hook takes the same lock briefly, so a start after the hook has run fails.
   *
   * @return true when this call started the runtime, false when it was running already
   */
  public static boolean start() {
    synchronized (START_LOCK) {
      if (running != null) {
        return false;
      }
      if (shuttingDown) {
        throw new IllegalStateException("the JVM is shutting down: the backport runtime does not start");
      }
      BackportLine line = BackportLine.current();
      Properties baked = loadBakedProperties(line);
      final Started state = new Started(line, baked, Config.resolveCurrent(baked), syncFlag());
      // Load and initialise, before any hook runs, the classes a hook would otherwise load first:
      // the hooks run inside JDK classes, where loading a class can re-enter them. Mode is used by
      // every detectionOff() and is otherwise loaded only once a mode has been read.
      new Event("", "");
      BackportLine.initialise(Mode.class, Settings.class, OutsideRequest.class);
      // The hook-miss writer, which the entry class turns on next; its worker writes through this runtime.
      BackportLine.initialise(BackportHookMisses.class);
      if (state.controlPath != null) {
        state.control.poll(state.controlPath);
      }
      Thread shutdown = null;
      if (state.writerEnabled) {
        shutdown =
            new Thread(
                new Runnable() {
                  public void run() {
                    closeForShutdown();
                  }
                },
                line.writerThreadName + "-exit");
        Runtime.getRuntime().addShutdownHook(shutdown);
      }
      Thread poller = null;
      try {
        if (state.controlPath != null) {
          poller =
              new Thread(
                  new Runnable() {
                    public void run() {
                      while (true) {
                        try {
                          Thread.sleep(pollMillis());
                          state.control.poll(state.controlPath);
                        } catch (InterruptedException e) {
                          Thread.currentThread().interrupt();
                          return;
                        } catch (RuntimeException | Error ignored) {
                          // never let control polling disturb the application or stop polling
                        }
                      }
                    }
                  },
                  line.controlThreadName);
          poller.setDaemon(true);
          poller.start();
        }
        if (state.writerEnabled) {
          state.spool.start(line.writerThreadName);
        }
        state.poller = poller;
        state.shutdownHook = shutdown;
        running = state;
        started = state;
        return true;
      } catch (RuntimeException | Error failure) {
        stopStarted(state, poller, shutdown, failure);
        throw failure;
      }
    }
  }

  /**
   * The shutdown hook's work, for the start that is running. It writes nothing itself and holds no lock while it
   * waits, so a stalled file or console cannot hold up the JVM's exit beyond its two bounded waits:
   *
   * <ol>
   *   <li>the hook-miss report gets {@value #DIAGNOSTIC_HANDOFF_MILLIS} ms to finish a line it is writing on its own
   *       thread, and is then closed: it takes no more misses and writes nothing more;
   *   <li>under the start lock, briefly (a start in progress finishes first): no start succeeds from now on, and the
   *       running start is the one to close;
   *   <li>the spool closes its admission, so what is queued is its writer's last work, and the hook waits at most
   *       {@value #SHUTDOWN_JOIN_MILLIS} ms for that daemon writer to write it. What it has not taken by then is
   *       dropped and counted; a writer stalled in an output call is left to it.
   * </ol>
   */
  static void closeForShutdown() {
    try {
      io.ohmyrasp.agent.hookmiss.HookMisses.awaitIdle(DIAGNOSTIC_HANDOFF_MILLIS);
      io.ohmyrasp.agent.hookmiss.HookMisses.close();
    } catch (Throwable ignored) {
      // A diagnostic never holds up the events.
    }
    Started state;
    synchronized (START_LOCK) {
      shuttingDown = true;
      state = running;
    }
    if (state != null) {
      state.spool.shutdown(SHUTDOWN_JOIN_MILLIS);
    }
  }

  /**
   * Stops the running runtime: from the first step its start writes nothing more, then the poller and the writer are
   * stopped (each waited for up to {@value #STOP_JOIN_MILLIS} ms, outside the start lock) and the shutdown hook is
   * removed. What was resolved stays readable (see {@code started}). Only the entry class calls it, when a step after
   * the start fails, and tests. A runtime that is not running is left alone.
   */
  public static void stop() {
    Started state;
    synchronized (START_LOCK) {
      state = running;
      if (state == null) {
        return;
      }
      running = null;
      state.stopped = true;
    }
    IllegalStateException problems = new IllegalStateException("stopping the backport runtime failed");
    stopStarted(state, state.poller, state.shutdownHook, problems);
    if (problems.getSuppressed().length > 0) {
      throw problems;
    }
  }

  /**
   * Stops what one start started: it writes nothing more, its spool drops what is queued, its threads are stopped and
   * its shutdown hook is removed. A failure on the way is added to {@code failure} as suppressed and the remaining
   * steps still run.
   */
  private static void stopStarted(Started state, Thread poller, Thread shutdown, Throwable failure) {
    state.stopped = true;
    stopQuietly(poller, failure);
    stopQuietly(state.spool.cancel(), failure);
    if (shutdown != null) {
      try {
        Runtime.getRuntime().removeShutdownHook(shutdown);
      } catch (IllegalStateException shuttingDown) {
        // the hook runs and finds a cancelled spool: nothing is lost
      } catch (RuntimeException | Error other) {
        failure.addSuppressed(other);
      }
    }
  }

  /**
   * Interrupts a thread this runtime started and waits up to {@value #STOP_JOIN_MILLIS} ms for it to end. A caller
   * that is interrupted itself still waits, and has its interrupt status back afterwards. A thread stuck in an
   * uninterruptible call (file-system I/O) can outlive the wait; it writes nothing more once that call returns.
   */
  private static void stopQuietly(Thread thread, Throwable failure) {
    if (thread == null) {
      return;
    }
    boolean interrupted = Thread.interrupted();
    try {
      thread.interrupt();
      thread.join(STOP_JOIN_MILLIS);
    } catch (InterruptedException e) {
      interrupted = true;
    } catch (RuntimeException | Error other) {
      failure.addSuppressed(other);
    } finally {
      if (interrupted) {
        Thread.currentThread().interrupt();
      }
    }
  }

  static Mode mode() {
    return started().control.mode();
  }

  /** One polling step of the started runtime against {@code path}, as the poller makes it. Tests only. */
  static void pollControl(Path path) {
    started().control.poll(path);
  }

  /** True when detection is explicitly OFF, and during the agent's own I/O on this thread. */
  static boolean detectionOff() {
    return started().control.mode() == Mode.OFF || inOwnIo();
  }

  /**
   * BLOCK or standalone unset permit blocking; MONITOR/OFF do not; legacy falls back to flag. The
   * agent's own I/O is never blocked.
   */
  static boolean blockingAllowed(boolean legacyEnvFlag) {
    if (inOwnIo()) {
      return false;
    }
    Started state = started();
    return blockingAllowed(state.initial.standalone, state.control.mode(), legacyEnvFlag);
  }

  /**
   * Whether a finding of block-scope class {@code scope} ({@link OutsideRequest#scope}) blocks here:
   * {@link #blockingAllowed(boolean)}, and {@link OutsideRequest#mayBlock} with the request evidence and the
   * {@code outside_request} in force. One read of the control settings.
   */
  static boolean findingBlocks(boolean legacyEnvFlag, boolean requestEvidence, int scope) {
    if (inOwnIo()) {
      return false;
    }
    Started state = started();
    Settings settings = state.control.settings();
    return blockingAllowed(state.initial.standalone, settings.mode, legacyEnvFlag)
        && OutsideRequest.mayBlock(scope, requestEvidence, settings.outsideRequestBlocks);
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
    BackportLine line = started().line;
    return legacyBlockFlag(System.getProperty(line.blockProperty), System.getenv(line.blockEnvironment));
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

  /** The baked shirudo properties read at start. */
  static Properties bakedProperties() {
    return started().baked;
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
    Started state = started();
    if (state.stopped) {
      return;
    }
    if (emitSpecialTarget(logPath, line)) {
      return;
    }
    appendBatch(logPath.trim(), Collections.singletonList(line));
  }

  /**
   * Off the business hot path: enqueue an already-built event line. A start that was stopped (its undo ran) writes
   * nothing more; after the JVM's exit began, an event for the queue is dropped and counted.
   */
  public static void writeEvent(String logPath, String line) {
    Started state = started();
    if (state.stopped) {
      return;
    }
    if (emitSpecialTarget(logPath, line)) {
      return;
    }
    String fileTarget = logPath.trim();
    if (state.sync || !state.writerEnabled) {
      appendBatch(fileTarget, Collections.singletonList(line));
      return;
    }
    state.spool.offer(fileTarget, line);
  }

  /**
   * Writes one diagnostic line (the hook-miss report's, on its own worker thread). It shares nothing with the
   * detections that could make one of them wait: not their queue, not their write lock, not their console stream. A
   * file target gets the line as one UTF-8 append of its own, one write call (detection batches are one write call
   * each too, so a line is never split); a console or {@code none} target gets nothing, since a diagnostic stalled
   * in the stream the detections are written to would hold them up. The line is also dropped when the runtime was
   * stopped, when the JVM's exit closed the spool, and when the write fails. Each dropped line is counted
   * ({@link #diagnosticsDropped}).
   */
  public static void writeDiagnostic(String logPath, String line) {
    Started state = started();
    if (state.stopped || state.spool.isClosed() || !isFileLogTarget(logPath)) {
      DIAGNOSTICS_DROPPED.incrementAndGet();
      return;
    }
    boolean ownIo = enterOwnIo();
    try {
      File target = new File(logPath.trim());
      File parent = target.getParentFile();
      if (parent != null && !parent.exists() && !parent.mkdirs()) {
        DIAGNOSTICS_DROPPED.incrementAndGet();
        return;
      }
      diagnosticOutput.append(target, (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
    } catch (IOException | RuntimeException dropped) {
      // The line is lost: a diagnostic is not worth a message on the application's console.
      DIAGNOSTICS_DROPPED.incrementAndGet();
    } finally {
      exitOwnIo(ownIo);
    }
  }

  /** How many diagnostic lines {@link #writeDiagnostic} dropped in this JVM. */
  static long diagnosticsDropped() {
    return DIAGNOSTICS_DROPPED.get();
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

  /**
   * Record a sampled measurement of the overhead added to a (usually benign)
   * request as a telemetry line, so the daemon's latency panel reflects real
   * traffic. Suppressed in sync mode to keep acceptance output deterministic.
   */
  static void sampleLatency(long micros) {
    Started state = started();
    if (!latencySampled(state.sync, detectionOff(), micros, state.sampleRate, SAMPLE_COUNTER)) {
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

  /** Where the spool writes a batch of event lines. */
  interface Sink {
    void append(String target, List<String> lines);
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
   * The bounded queue between the hooks and the writer thread, one per start. Each event keeps the target it was
   * accepted for, so a later change of log target does not move it. All its output is on the writer thread:
   * {@link #drainOnce} is one writer step, {@link #shutdown} closes the admission and waits for the writer, and
   * {@link #cancel} drops everything, so a test can drive each of them.
   */
  static final class EventSpool implements Runnable {
    private final BlockingQueue<Event> queue = new ArrayBlockingQueue<Event>(8192);
    private final AtomicLong dropped = new AtomicLong();
    private final List<Event> batch = new ArrayList<Event>(64);
    private final Sink sink;
    // Admission: set when the JVM's exit begins or the start is stopped; from then on no event is queued.
    private volatile boolean closed;
    // Set when the start is stopped: what is queued is dropped and the writer writes nothing more.
    private volatile boolean cancelled;
    // Set by the writer when it ends: an event queued after that would never be taken.
    private volatile boolean writerDone;
    private volatile Thread writer;

    EventSpool(Sink sink) {
      this.sink = sink;
    }

    /** Whether the admission is closed: the JVM's exit began, or the start was stopped. */
    boolean isClosed() {
      return closed;
    }

    /** How many events were not written: the queue was full, the admission closed, or the writer ran out of time. */
    long droppedCount() {
      return dropped.get();
    }

    void offer(String target, String line) {
      if (closed) {
        dropped.incrementAndGet();
        return;
      }
      Event event = new Event(target, line);
      if (!queue.offer(event)) {
        dropped.incrementAndGet();
        return;
      }
      if (closed && (writerDone || writer == null) && queue.remove(event)) {
        // The admission closed while this event was queued, and no writer will take it.
        dropped.incrementAndGet();
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
      if (cancelled) {
        batch.clear();
        return; // a stopped start writes nothing
      }
      write(batch);
      batch.clear();
    }

    /** Writes events in order, one sink call per run of events with the same target. */
    private void write(List<Event> events) {
      int start = 0;
      while (start < events.size()) {
        String target = events.get(start).target;
        List<String> lines = new ArrayList<String>();
        int end = start;
        while (end < events.size() && events.get(end).target.equals(target)) {
          lines.add(events.get(end).line);
          end++;
        }
        sink.append(target, lines);
        start = end;
      }
    }

    /** The writer: drains until the start is stopped, or until the admission closed and the queue is empty. */
    public void run() {
      try {
        while (!cancelled && !(closed && queue.isEmpty())) {
          try {
            drainOnce(200L);
          } catch (InterruptedException e) {
            // cancel() interrupts; anything else does not end the writer while events can still come
          } catch (RuntimeException e) {
            System.err.println(started().line.logPrefix + " event writer error: " + e);
          }
        }
      } finally {
        writerDone = true;
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
     * For a start that was stopped: closes the admission, drops what is queued and tells the writer to write nothing
     * more. Returns the writer, or null, for the caller to interrupt and wait for; a writer in an output call finishes
     * that call on its own and then ends.
     */
    Thread cancel() {
      cancelled = true;
      closed = true;
      queue.clear();
      return writer;
    }

    /**
     * The shutdown hook's part: closes the admission, so what is queued now is the writer's last work, and waits up to
     * {@code joinMillis} for the writer, a daemon thread, to write it and end. It writes nothing and takes no lock
     * itself: what the writer has not taken from the queue by then is dropped and counted, and a writer stalled in an
     * output call is left to it. Each event leaves the queue once, so none is written twice.
     *
     * @return whether the writer had ended (or never ran) when the wait was over
     */
    boolean shutdown(long joinMillis) {
      closed = true;
      Thread current = writer;
      if (current != null && current != Thread.currentThread()) {
        boolean interrupted = Thread.interrupted();
        try {
          current.join(joinMillis);
        } catch (InterruptedException e) {
          interrupted = true;
        } finally {
          if (interrupted) {
            Thread.currentThread().interrupt();
          }
        }
      }
      List<Event> left = new ArrayList<Event>();
      queue.drainTo(left);
      dropped.addAndGet(left.size());
      return current == null || !current.isAlive();
    }
  }

  /** Appends lines to a log file as the agent's own I/O, invisible to the file hooks. */
  private static void appendBatch(String logPath, List<String> lines) {
    boolean ownIo = enterOwnIo();
    try {
      appendLines(logPath, lines);
    } finally {
      exitOwnIo(ownIo);
    }
  }

  /** Appends the lines, UTF-8 encoded whatever the JVM's default charset, as one write under {@link #WRITE_LOCK}. */
  private static void appendLines(String logPath, List<String> lines) {
    File target = new File(logPath);
    File parent = target.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      System.err.println(started().line.logPrefix + " could not create log directory: " + parent);
      return;
    }
    StringBuilder text = new StringBuilder();
    String separator = System.lineSeparator();
    for (int i = 0; i < lines.size(); i++) {
      text.append(lines.get(i)).append(separator);
    }
    byte[] bytes = text.toString().getBytes(StandardCharsets.UTF_8);
    WRITE_LOCK.lock();
    try {
      appendBytes(target, bytes);
    } catch (IOException e) {
      System.err.println(started().line.logPrefix + " could not write detection event: " + e);
    } finally {
      WRITE_LOCK.unlock();
    }
  }

  /**
   * One append of {@code bytes} to {@code target}. A {@code FileOutputStream} in append mode hands the whole array to
   * one write call on a file opened with O_APPEND, so what another writer appends at the same time lands before or
   * after it, never inside it.
   */
  static void appendBytes(File target, byte[] bytes) throws IOException {
    FileOutputStream out = new FileOutputStream(target, true);
    try {
      out.write(bytes);
    } finally {
      out.close();
    }
  }

  /**
   * The baked shirudo settings from the agent's own JAR or class directory, read by
   * {@link io.ohmyrasp.agent.util.BakedProperties}: none for a general JAR; a start failure for an upatch JAR
   * whose settings are missing or cannot be read.
   */
  private static Properties loadBakedProperties(BackportLine line) {
    Properties baked = io.ohmyrasp.agent.util.BakedProperties.read(RaspRuntime.class, line.entryClass);
    return baked == null ? new Properties() : baked;
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
