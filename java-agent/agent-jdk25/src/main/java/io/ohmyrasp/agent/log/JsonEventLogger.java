package io.ohmyrasp.agent.log;

import io.ohmyrasp.agent.control.ControlPlaneClient;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.runtime.AgentOwnIo;
import io.ohmyrasp.agent.runtime.AgentRuntime;
import io.ohmyrasp.agent.runtime.ShirudoDefaults;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Writes security events to the local NDJSON spool the daemon tails, and to
 * stdout.
 *
 * <p>All I/O happens on a dedicated background daemon thread fed by a bounded
 * queue, so the protected request never blocks on a file write, a {@code
 * System.out.println}, or a control-plane upload. The blocking/allow decision is
 * still made synchronously in the hook (see {@code OhMyRaspHooks}); only the
 * reporting is asynchronous. If the queue is full (a sustained event storm) the
 * event is dropped and counted rather than stalling business logic.
 */
public final class JsonEventLogger {
  private static final JsonEventLogger INSTANCE = new JsonEventLogger();
  // The shutdown hook waits this long for the writer to finish the batch it holds.
  private static final long SHUTDOWN_JOIN_MILLIS = 2000;
  // cancel waits at most this long for the writer to end; a writer stuck in an output call is left to it.
  private static final long CANCEL_JOIN_MILLIS = 1000;
  // At JVM exit, the hook-miss report may hand its pending lines to this logger for this long before it drains.
  private static final long DIAGNOSTIC_HANDOFF_MILLIS = 500;
  // Once shutdown has begun, a write waits this long for the write lock and then gives up.
  private static final long SHUTDOWN_LOCK_MILLIS = 1000;
  private static final String REDACTED = "[redacted]";
  // A query longer than this is not scanned: it is replaced by the marker as a whole.
  private static final int MAX_REDACTED_QUERY_LENGTH = 8192;
  private static final int MAX_QUERY_DECODE_ROUNDS = 8;
  private static final Set<String> SENSITIVE_HEADER_NAMES =
      Set.of(
          "authorization",
          "cookie",
          "set-cookie",
          "x-api-key",
          "api-key",
          "x-auth-token",
          "access-token",
          "refresh-token",
          "id-token");
  private static final Set<String> SENSITIVE_PARAMETER_NAMES =
      Set.of(
          "authorization",
          "password",
          "passwd",
          "pwd",
          "pass",
          "token",
          "accesstoken",
          "refreshtoken",
          "idtoken",
          "secret",
          "apikey",
          "xapikey",
          "auth",
          "credential",
          "credentials");
  private static final Set<String> EXECUTABLE_SOURCE_PARAMETER_NAMES =
      Set.of(
          "gluesource",
          "executorparams",
          "script",
          "source",
          "command",
          "commandline",
          "cmd",
          "shell",
          "code",
          "payload",
          "dataconfig",
          "routeconfig",
          "routedefinition",
          "gatewayroute",
          "filterconfig",
          "scriptfields",
          "scriptfield",
          "scriptconfig",
          "template",
          "expression");

  /**
   * One queued record: either a security {@code detection} (with its measured
   * in-hook latencies), a periodic latency {@code telemetryHook} sample that
   * feeds the daemon's business-impact panel without being a detection, or an agent
   * {@code diagnostic} line written as it is.
   */
  private record Sample(
      Detection detection, String telemetryHook, long latencyUs, long ruleEvaluationUs, String diagnostic) {}

  private enum LogTarget {
    FILE,
    STDERR,
    STDOUT,
    NONE
  }

  private final LogTarget target;
  private final String targetName;
  private final Path logPath;
  private final BlockingQueue<Sample> queue;
  private final AtomicLong dropped = new AtomicLong();
  private final AtomicLong sampleCounter = new AtomicLong();
  // Serialises file and console output, so concurrent writers never interleave a line.
  final ReentrantLock writeLock = new ReentrantLock();
  private final boolean syncWrites;
  private final int latencySampleRate;
  private final PrintStream customOut;
  private final PrintStream customErr;
  // Guards the start against the shutdown hook and cancel: writer, shutdownHook and shutdownBegan.
  private final Object lifecycle = new Object();
  // The writer thread and the JVM shutdown hook that flushes the queue, once start ran; null before, and
  // always for a target without a queue. Guarded by lifecycle; written once.
  private volatile Thread writer;
  private Thread shutdownHook;
  // Guarded by lifecycle: the shutdown hook has begun, so no start succeeds any more.
  private boolean shutdownBegan;
  private volatile boolean running = true;
  // Set by shutdown once the writer is gone or given up on: from then on events are written on
  // the caller's thread, and writes wait only a bounded time for the write lock.
  private volatile boolean closed;
  // Set by cancel, for a start that failed: every event from then on is dropped, and nothing is written.
  private volatile boolean cancelled;
  private volatile ControlPlaneClient controlPlaneClient;

  private JsonEventLogger() {
    this(
        ShirudoDefaults.load(),
        AgentRuntime.get(),
        null,
        null,
        flag("ohmyrasp.log.sync", "OHMYRASP_LOG_SYNC"),
        null,
        null);
  }

  private JsonEventLogger(
      ShirudoDefaults defaults,
      AgentRuntime runtime,
      String targetOverride,
      Integer latencySampleOverride,
      boolean syncWrites,
      PrintStream customOut,
      PrintStream customErr) {
    ShirudoDefaults activeDefaults = defaults == null ? ShirudoDefaults.load() : defaults;
    // AgentRuntime owns the standalone decision (lock_config, then the first valid source); a
    // logger without a runtime, which only tests create, takes the baked value.
    boolean standalone = runtime != null ? runtime.isStandalone() : activeDefaults.standalone();

    String configured = resolveTarget(activeDefaults, runtime, targetOverride, standalone);
    String normalized = configured.trim().toLowerCase(Locale.ROOT);
    switch (normalized) {
      case "stderr" -> {
        this.target = LogTarget.STDERR;
        this.targetName = "stderr";
        this.logPath = null;
      }
      case "stdout" -> {
        this.target = LogTarget.STDOUT;
        this.targetName = "stdout";
        this.logPath = null;
      }
      case "none" -> {
        this.target = LogTarget.NONE;
        this.targetName = "none";
        this.logPath = null;
      }
      default -> {
        this.target = LogTarget.FILE;
        this.logPath = Path.of(configured.trim());
        this.targetName = this.logPath.toString();
      }
    }

    // Acceptance/CI determinism: write inline so the event is on disk before the
    // hook returns. Trades the no-business-latency property for repeatability.
    this.syncWrites = syncWrites;
    this.customOut = customOut;
    this.customErr = customErr;

    int defaultSampleRate =
        activeDefaults.latencySample() != null
            ? activeDefaults.latencySample()
            : (standalone ? 0 : 10);
    if (latencySampleOverride != null) {
      this.latencySampleRate = latencySampleOverride;
    } else {
      Integer argSample = runtime == null ? null : runtime.agentArgLatencySample();
      this.latencySampleRate =
          argSample != null
              ? argSample
              : intSetting("ohmyrasp.latency_sample", "OHMYRASP_LATENCY_SAMPLE", defaultSampleRate);
    }

    // Construction starts no thread and registers no shutdown hook (start does), so creating the logger, which
    // the shared one does in its class initialiser, cannot fail half-way or leave a thread behind.
    this.queue = this.target == LogTarget.FILE ? new ArrayBlockingQueue<>(queueCapacity()) : null;
  }

  /**
   * Starts the writer thread of a file target and registers the JVM shutdown hook that flushes its queue, on the
   * start thread before any hook acts. The hook is registered first: when the JVM is already shutting down that
   * throws and nothing is started. Synchronised with the shutdown hook, which then waits for a start in progress
   * and closes a logger that is fully started; a start after the hook has begun throws. A logger without a queue,
   * a started one and a cancelled one start nothing more.
   */
  public void start() {
    if (queue == null) {
      return;
    }
    synchronized (lifecycle) {
      if (writer != null || cancelled) {
        return;
      }
      if (shutdownBegan) {
        throw new IllegalStateException("the JVM is shutting down: the event writer does not start");
      }
      Thread hook = new Thread(this::shutdownForExit, "ohmyrasp-event-writer-shutdown");
      Runtime.getRuntime().addShutdownHook(hook);
      Thread thread = new Thread(this::drainLoop, "ohmyrasp-event-writer");
      thread.setDaemon(true);
      try {
        thread.start();
      } catch (RuntimeException | Error failure) {
        try {
          Runtime.getRuntime().removeShutdownHook(hook);
        } catch (IllegalStateException shuttingDown) {
          // The hook runs and finds no writer.
        }
        throw failure;
      }
      shutdownHook = hook;
      writer = thread;
    }
  }

  /** A logger that writes nothing anywhere and reports nothing to a cloud client: the warm-up's. */
  public static JsonEventLogger discarding() {
    return new JsonEventLogger(ShirudoDefaults.absent(), null, "none", 0, true, null, null);
  }

  /** Whether this logger drops every event and error report. */
  public boolean discards() {
    return target == LogTarget.NONE && controlPlaneClient == null;
  }

  public static JsonEventLogger get() {
    return INSTANCE;
  }

  /** Creates an isolated, started logger for unit tests without touching {@link #INSTANCE}. */
  public static JsonEventLogger newForTesting(
      ShirudoDefaults defaults,
      String targetOverride,
      Integer latencySampleOverride,
      boolean syncWrites,
      PrintStream out,
      PrintStream err) {
    JsonEventLogger logger =
        new JsonEventLogger(defaults, null, targetOverride, latencySampleOverride, syncWrites, out, err);
    logger.start();
    return logger;
  }

  /** Creates an isolated, started logger for unit tests from a started {@code runtime}'s settings. */
  public static JsonEventLogger newForTesting(AgentRuntime runtime, PrintStream out, PrintStream err) {
    JsonEventLogger logger = new JsonEventLogger(runtime.shirudoDefaults(), runtime, null, null, false, out, err);
    logger.start();
    return logger;
  }

  /** Creates an isolated logger for unit tests that is not started: no writer thread, no shutdown hook. */
  static JsonEventLogger unstartedForTesting(String targetOverride, PrintStream out, PrintStream err) {
    return new JsonEventLogger(ShirudoDefaults.absent(), null, targetOverride, 0, false, out, err);
  }

  public String logTarget() {
    return targetName;
  }

  public Path logPath() {
    return logPath;
  }

  public int latencySampleRate() {
    return latencySampleRate;
  }

  public void setControlPlaneClient(ControlPlaneClient controlPlaneClient) {
    this.controlPlaneClient = controlPlaneClient;
  }

  /** Number of events dropped because the async queue was saturated. */
  public long droppedCount() {
    return dropped.get();
  }

  /** Asynchronously record a detection with no measured latency. */
  public void log(Detection detection) {
    record(detection, -1, -1);
  }

  /**
   * Asynchronously record a detection together with the in-hook latency it added
   * to the request path. This is the primary entry point used by the hooks.
   */
  public void record(Detection detection, long latencyUs, long ruleEvaluationUs) {
    if (detection == null) {
      return;
    }
    submit(new Sample(detection, null, latencyUs, ruleEvaluationUs, null));
  }

  /**
   * Record a sampled measurement of the overhead a hook adds to a normal (often
   * benign) request. Sampled 1-in-N so it costs almost nothing on the hot path,
   * yet keeps the daemon's business-latency panel populated under live traffic —
   * unlike detection latency, which is only observed when an attack fires.
   */
  public void sampleHookLatency(String hook, long latencyUs) {
    // Sync mode or non-positive sample rate disables periodic latency telemetry.
    if (latencySampleRate <= 0 || syncWrites || latencyUs < 0) {
      return;
    }
    if (latencySampleRate > 1 && sampleCounter.incrementAndGet() % latencySampleRate != 0) {
      return;
    }
    submit(new Sample(null, hook == null ? "" : hook, latencyUs, -1, null));
  }

  /**
   * Record an agent diagnostic, not a detection: {@code {"timestamp":...,"kind":"diagnostic","diagnostic":<name>,
   * <fields>}}, where {@code fields} is JSON members without braces. It goes where detections go (the spool, or the
   * console in standalone mode) and never to the direct-cloud client. The hook-miss report is its only writer.
   */
  public void recordDiagnostic(String diagnostic, String fields) {
    var builder = new StringBuilder(64 + fields.length());
    builder.append('{');
    field(builder, "timestamp", java.time.Instant.now().toString()).append(',');
    field(builder, "kind", "diagnostic").append(',');
    field(builder, "diagnostic", diagnostic).append(',');
    builder.append(fields).append('}');
    submit(new Sample(null, null, -1, -1, builder.toString()));
  }

  private void submit(Sample sample) {
    if (cancelled) {
      return;
    }
    if (target != LogTarget.FILE) {
      if (target == LogTarget.NONE && controlPlaneClient == null) {
        return;
      }
      flush(List.of(sample));
      return;
    }
    if (syncWrites || closed) {
      flush(List.of(sample));
      return;
    }
    if (!queue.offer(sample)) {
      dropped.incrementAndGet();
    }
    if (closed) {
      // Shutdown may have drained the queue before this event arrived: write what is left.
      flushRest();
    }
  }

  /** Retained for backward compatibility; latency now travels with {@link #record}. */
  public void recordHookTelemetry(Detection detection, long latencyUs, long ruleEvaluationUs) {
    ControlPlaneClient client = controlPlaneClient;
    if (client != null) {
      client.submitHookTelemetry(detection, latencyUs, ruleEvaluationUs);
    }
  }

  public void reportError(String hook, Throwable throwable) {
    ControlPlaneClient client = controlPlaneClient;
    if (client != null) {
      client.submitError(hook, "Agent hook failure", throwable);
    }
  }

  private void drainLoop() {
    List<Sample> batch = new ArrayList<>(64);
    // Stops once shutdown begins; the shutdown hook writes what is still queued.
    while (running) {
      try {
        Sample first = queue.poll(200, TimeUnit.MILLISECONDS);
        if (first == null) {
          continue;
        }
        batch.clear();
        batch.add(first);
        queue.drainTo(batch, 511);
        if (cancelled) {
          return; // a failed start: what was queued is dropped, nothing is written
        }
        flush(batch);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      } catch (RuntimeException e) {
        // Never let the writer thread die from a transient failure.
        errStream().println("[OHMYRASP] event writer error: " + e);
      }
    }
  }

  /** Writes a batch as the agent's own I/O, invisible to the hooks. */
  private void flush(List<Sample> batch) {
    boolean ownIo = AgentOwnIo.enter();
    try {
      write(batch);
    } finally {
      AgentOwnIo.exit(ownIo);
    }
  }

  private void write(List<Sample> batch) {
    StringBuilder fileBuffer = target == LogTarget.FILE ? new StringBuilder(batch.size() * 256) : null;
    StringBuilder consoleBuffer = target == LogTarget.NONE ? null : new StringBuilder(batch.size() * 256);
    String separator = System.lineSeparator();
    for (Sample sample : batch) {
      if (target == LogTarget.NONE) {
        continue;
      }
      String json =
          sample.diagnostic() != null
              ? sample.diagnostic()
              : sample.detection() == null
                  ? telemetryJson(sample.telemetryHook(), sample.latencyUs())
                  : toJson(sample.detection(), sample.latencyUs());
      if (fileBuffer != null) {
        fileBuffer.append(json).append(separator);
      }
      // Telemetry is high-volume and uninteresting on the console; keep it off stdout/stderr.
      if (consoleBuffer != null && (sample.detection() != null || sample.diagnostic() != null)) {
        consoleBuffer.append("[OHMYRASP] ").append(json).append(separator);
      }
    }
    boolean fileOutput = target == LogTarget.FILE && fileBuffer != null && fileBuffer.length() > 0;
    boolean consoleOutput = consoleBuffer != null && consoleBuffer.length() > 0;
    // One lock for both outputs, so concurrent writers never interleave a line.
    if ((fileOutput || consoleOutput) && lockWrites()) {
      try {
        if (fileOutput) {
          try {
            Path parent = logPath.getParent();
            if (parent != null) {
              Files.createDirectories(parent);
            }
            Files.writeString(
                logPath,
                fileBuffer.toString(),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
          } catch (IOException e) {
            if (!cancelled) {
              errStream().println("[OHMYRASP] failed to write event log: " + e);
            }
          }
        }
        if (consoleOutput) {
          if (target == LogTarget.STDERR) {
            errStream().print(consoleBuffer);
          } else if (target == LogTarget.STDOUT || target == LogTarget.FILE) {
            outStream().print(consoleBuffer);
          }
        }
      } finally {
        writeLock.unlock();
      }
    }

    ControlPlaneClient client = controlPlaneClient;
    if (client != null) {
      for (Sample sample : batch) {
        if (sample.detection() == null) {
          continue; // telemetry stays local
        }
        Detection upload = withRedactedQuery(sample.detection());
        client.submit(upload);
        if (sample.latencyUs() >= 0) {
          client.submitHookTelemetry(upload, sample.latencyUs(), sample.ruleEvaluationUs());
        }
      }
    }
  }

  /**
   * The detection as the direct-cloud client uploads it: its {@code request.query} attribute is
   * the query string, so it gets the redaction the spool line gets.
   */
  private static Detection withRedactedQuery(Detection detection) {
    RequestContext request = detection.request();
    if (request == null) {
      return detection;
    }
    String redacted = redactedQuery(request.query());
    if (redacted == null || redacted.equals(request.query())) {
      return detection;
    }
    return new Detection(
        detection.timestamp(),
        detection.hook(),
        detection.algorithm(),
        detection.action(),
        detection.confidence(),
        detection.message(),
        new RequestContext(
            request.method(),
            request.uri(),
            redacted,
            request.parameters(),
            request.headers(),
            request.body()),
        detection.details());
  }

  private PrintStream outStream() {
    return customOut != null ? customOut : System.out;
  }

  private PrintStream errStream() {
    return customErr != null ? customErr : System.err;
  }

  private static String resolveTarget(
      ShirudoDefaults defaults, AgentRuntime runtime, String targetOverride, boolean standalone) {
    if (targetOverride != null && !targetOverride.isBlank()) {
      return targetOverride;
    }
    if (runtime != null) {
      String argLog = runtime.agentArgLogTarget();
      if (argLog != null && !argLog.isBlank()) {
        return argLog;
      }
    }
    String configured = System.getProperty("ohmyrasp.log");
    if (configured != null && !configured.isBlank()) {
      return configured;
    }
    configured = System.getenv("OHMYRASP_LOG");
    if (configured != null && !configured.isBlank()) {
      return configured;
    }
    if (defaults.log() != null && !defaults.log().isBlank()) {
      return defaults.log();
    }
    return standalone ? "stderr" : "/tmp/ohmyrasp-events.jsonl";
  }

  /**
   * The JVM shutdown hook's work. Under the lifecycle lock first, so a start in progress finishes and no start
   * succeeds afterwards; then the hook-miss report may hand over what it holds, for a bounded time, so a line it
   * was writing is queued before the queue is drained; then the queue is drained as {@link #shutdown(long)} says.
   */
  private void shutdownForExit() {
    synchronized (lifecycle) {
      shutdownBegan = true;
    }
    try {
      io.ohmyrasp.agent.hookmiss.HookMisses.awaitIdle(DIAGNOSTIC_HANDOFF_MILLIS);
    } catch (Throwable ignored) {
      // A diagnostic never holds up the events.
    }
    shutdown(SHUTDOWN_JOIN_MILLIS);
  }

  /**
   * Undoes {@link #start} for a start that failed, without writing anything: every event queued or submitted from
   * now on is dropped, the shutdown hook is removed, and the writer is told to stop and waited for at most
   * {@value #CANCEL_JOIN_MILLIS} ms. It never takes the write lock and never waits on a file or the console: a
   * writer stuck in an output call (a full pipe) is left to finish it on its own and then ends, dropping the rest.
   */
  public void cancel() {
    Thread current;
    Thread hook;
    synchronized (lifecycle) {
      cancelled = true;
      current = writer;
      hook = shutdownHook;
    }
    running = false;
    if (queue != null) {
      queue.clear();
    }
    if (hook != null) {
      try {
        Runtime.getRuntime().removeShutdownHook(hook);
      } catch (IllegalStateException shuttingDown) {
        // The JVM is exiting: the hook runs and finds the queue empty.
      }
    }
    if (current != null && current != Thread.currentThread()) {
      boolean interrupted = Thread.interrupted();
      try {
        current.interrupt();
        current.join(CANCEL_JOIN_MILLIS);
      } catch (InterruptedException e) {
        interrupted = true;
      } finally {
        if (interrupted) {
          Thread.currentThread().interrupt();
        }
      }
    }
    if (queue != null) {
      queue.clear();
    }
  }

  /** The writer thread once started, else null. Tests only. */
  Thread writerThread() {
    return writer;
  }

  /**
   * Stops the writer, waits up to {@code joinMillis} for it to finish the batch it holds, then
   * writes what is still queued, waiting a bounded time for the write lock, so events queued at
   * exit still reach the spool. An event submitted after that is written on the caller's thread.
   * Each event leaves the queue once, so none is written twice. A batch the writer still holds
   * when the wait ends, because it is stalled in an output call, can be lost.
   */
  void shutdown(long joinMillis) {
    running = false;
    Thread current;
    synchronized (lifecycle) {
      current = writer;
    }
    if (current != null && current != Thread.currentThread()) {
      try {
        current.join(joinMillis);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    closed = true;
    flushRest();
  }

  /** Writes everything still queued. */
  private void flushRest() {
    if (cancelled) {
      return;
    }
    List<Sample> remaining = new ArrayList<>();
    queue.drainTo(remaining);
    if (!remaining.isEmpty()) {
      flush(remaining);
    }
  }

  /** Takes the write lock; once shutdown has begun, waits at most SHUTDOWN_LOCK_MILLIS for it. */
  private boolean lockWrites() {
    if (!closed) {
      writeLock.lock();
      return true;
    }
    try {
      return writeLock.tryLock(SHUTDOWN_LOCK_MILLIS, TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  private static int queueCapacity() {
    return Math.max(256, intSetting("ohmyrasp.log.queue", "OHMYRASP_LOG_QUEUE", 8192));
  }

  private static boolean flag(String property, String env) {
    return flagValue(System.getProperty(property), System.getenv(env));
  }

  /**
   * The flag from a system property value and an environment value: the first that holds a
   * recognised boolean decides, so an unrecognised property does not hide a valid environment
   * value. Neither means false.
   */
  static boolean flagValue(String propertyValue, String envValue) {
    Boolean chosen = booleanOrNull(propertyValue);
    if (chosen == null) {
      chosen = booleanOrNull(envValue);
    }
    return Boolean.TRUE.equals(chosen);
  }

  private static Boolean booleanOrNull(String value) {
    if (value == null) {
      return null;
    }
    return switch (value.trim().toLowerCase(Locale.ROOT)) {
      case "true", "1", "yes", "on" -> Boolean.TRUE;
      case "false", "0", "no", "off" -> Boolean.FALSE;
      default -> null;
    };
  }

  private static int intSetting(String property, String env, int fallback) {
    return intValue(System.getProperty(property), System.getenv(env), fallback);
  }

  /**
   * The integer from a system property value and an environment value: the first that holds an
   * integer decides, so an invalid property does not hide a valid environment value. Neither
   * means {@code fallback}.
   */
  static int intValue(String propertyValue, String envValue, int fallback) {
    Integer chosen = intOrNull(propertyValue);
    if (chosen == null) {
      chosen = intOrNull(envValue);
    }
    return chosen == null ? fallback : chosen;
  }

  private static Integer intOrNull(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Integer.valueOf(value.trim());
    } catch (NumberFormatException e) {
      return null;
    }
  }

  /** Minimal telemetry line: a hook-overhead latency sample, not a detection. */
  private static String telemetryJson(String hook, long latencyUs) {
    var builder = new StringBuilder(160);
    builder.append('{');
    field(builder, "timestamp", java.time.Instant.now().toString()).append(',');
    field(builder, "kind", "telemetry").append(',');
    field(builder, "hook", hook == null ? "" : hook).append(',');
    field(builder, "algorithm", "hook_latency").append(',');
    field(builder, "action", "observe").append(',');
    numberField(builder, "confidence", 0).append(',');
    longField(builder, "latency_us", latencyUs);
    builder.append('}');
    return builder.toString();
  }

  private static String toJson(Detection detection, long latencyUs) {
    var builder = new StringBuilder(512);
    builder.append('{');
    field(builder, "timestamp", detection.timestamp().toString()).append(',');
    field(builder, "kind", "detection").append(',');
    field(builder, "hook", detection.hook()).append(',');
    field(builder, "algorithm", detection.algorithm()).append(',');
    field(builder, "action", detection.action()).append(',');
    numberField(builder, "confidence", detection.confidence()).append(',');
    if (latencyUs >= 0) {
      longField(builder, "latency_us", latencyUs).append(',');
    }
    field(builder, "message", detection.message()).append(',');
    builder.append("\"request\":");
    request(builder, detection.request());
    builder.append(',');
    builder.append("\"details\":");
    stringMap(builder, detection.details());
    builder.append('}');
    return builder.toString();
  }

  private static void request(StringBuilder builder, RequestContext request) {
    RequestContext current = request == null ? RequestContext.empty() : request;
    builder.append('{');
    field(builder, "method", current.method()).append(',');
    field(builder, "uri", current.uri()).append(',');
    field(builder, "query", redactedQuery(current.query())).append(',');
    builder.append("\"parameters\":");
    parameterMap(builder, current.parameters());
    builder.append(',');
    builder.append("\"headers\":");
    headerMap(builder, current.headers());
    builder.append('}');
  }

  private static StringBuilder field(StringBuilder builder, String name, String value) {
    return builder.append('"').append(escape(name)).append("\":\"").append(escape(value)).append('"');
  }

  private static StringBuilder numberField(StringBuilder builder, String name, int value) {
    return builder.append('"').append(escape(name)).append("\":").append(value);
  }

  private static StringBuilder longField(StringBuilder builder, String name, long value) {
    return builder.append('"').append(escape(name)).append("\":").append(value);
  }

  private static void stringMap(StringBuilder builder, Map<String, String> map) {
    builder.append('{');
    boolean first = true;
    for (var entry : map.entrySet()) {
      if (!first) {
        builder.append(',');
      }
      first = false;
      field(builder, entry.getKey(), entry.getValue());
    }
    builder.append('}');
  }

  private static void headerMap(StringBuilder builder, Map<String, String> map) {
    builder.append('{');
    boolean first = true;
    for (var entry : map.entrySet()) {
      if (!first) {
        builder.append(',');
      }
      first = false;
      field(builder, entry.getKey(), redactedHeaderValue(entry.getKey(), entry.getValue()));
    }
    builder.append('}');
  }

  private static String redactedHeaderValue(String name, String value) {
    String normalized = name == null ? "" : name.toLowerCase(Locale.ROOT);
    if (!SENSITIVE_HEADER_NAMES.contains(normalized)) {
      return value;
    }
    if (value == null || value.isBlank()) {
      return "";
    }
    String trimmed = value.trim();
    if (trimmed.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
      return "Bearer [redacted]";
    }
    if (trimmed.regionMatches(true, 0, "Basic ", 0, "Basic ".length())) {
      return "Basic [redacted]";
    }
    return REDACTED;
  }

  private static void parameterMap(StringBuilder builder, Map<String, List<String>> map) {
    builder.append('{');
    boolean firstEntry = true;
    for (var entry : map.entrySet()) {
      if (!firstEntry) {
        builder.append(',');
      }
      firstEntry = false;
      builder.append('"').append(escape(entry.getKey())).append("\":[");
      boolean firstValue = true;
      for (String value : entry.getValue()) {
        if (!firstValue) {
          builder.append(',');
        }
        firstValue = false;
        builder
            .append('"')
            .append(escape(redactedParameterValue(entry.getKey(), value)))
            .append('"');
      }
      builder.append(']');
    }
    builder.append('}');
  }

  private static String redactedParameterValue(String name, String value) {
    if (value == null || value.isBlank()) {
      return value;
    }
    return isRedactedParameterName(name) ? REDACTED : value;
  }

  /** The one name rule for {@code parameters} and for the parameters inside {@code query}. */
  private static boolean isRedactedParameterName(String name) {
    String normalized = normalizeName(name);
    return SENSITIVE_PARAMETER_NAMES.contains(normalized)
        || EXECUTABLE_SOURCE_PARAMETER_NAMES.contains(normalized);
  }

  /**
   * The query string with every piece that names a sensitive parameter carrying the marker in
   * place of its value. The query is split once, left to right, on {@code &} only, and the
   * separators stay: a {@code ;} is part of its piece, as Tomcat reads it, so
   * {@code password=alpha;omega} is one value. A piece is sensitive when it, or what it decodes to
   * (percent escapes and {@code +}, repeated until the text stops changing, at most
   * {@value #MAX_QUERY_DECODE_ROUNDS} rounds; a piece still changing after that is sensitive),
   * holds a name {@link #isRedactedParameterName} names as a token: a run of ASCII
   * letters, digits and underscores, or of those and hyphens, so {@code amp;password},
   * {@code user[password]}, {@code {"password":"x"}} and {@code next=/cb?token=abc} match and
   * {@code passwordless} does not. A sensitive piece keeps its text up to and including the first
   * {@code =} and gets the marker as its value, as long as that text is a plain parameter name;
   * a piece with no {@code =}, or whose text before it holds punctuation that could carry the
   * secret ({@code {"password":"a=b"}}), is replaced as a whole. A parameter with an empty value
   * has nothing to hide and stays. A query longer than {@value #MAX_REDACTED_QUERY_LENGTH}
   * characters is not scanned and becomes the marker. Runs on the event-writing path: plain
   * loops over ASCII comparisons, no regular expression, no lambda and no Unicode tables.
   */
  static String redactedQuery(String query) {
    if (query == null || query.isEmpty()) {
      return query;
    }
    int length = query.length();
    if (length > MAX_REDACTED_QUERY_LENGTH) {
      return REDACTED;
    }
    var out = new StringBuilder(length + 16);
    boolean changed = false;
    int start = 0;
    for (int i = 0; i <= length; i++) {
      if (i < length && query.charAt(i) != '&') {
        continue;
      }
      String piece = query.substring(start, i);
      String written = redactedPiece(piece);
      changed |= written != piece;
      out.append(written);
      if (i < length) {
        out.append(query.charAt(i));
      }
      start = i + 1;
    }
    return changed ? out.toString() : query;
  }

  /** The piece itself when nothing in it is sensitive, so the caller can tell by identity. */
  private static String redactedPiece(String piece) {
    if (piece.isEmpty() || !holdsRedactedName(piece)) {
      return piece;
    }
    int equals = piece.indexOf('=');
    if (equals < 0 || !isPlainParameterName(piece.substring(0, equals))) {
      return REDACTED;
    }
    if (equals + 1 == piece.length()) {
      return piece;
    }
    return piece.substring(0, equals + 1) + REDACTED;
  }

  /**
   * Whether the text, or any of its decodings, holds a redacted parameter name as a token. Text
   * that is still changing after {@link #MAX_QUERY_DECODE_ROUNDS} rounds counts as holding one: a
   * name could be behind the next layer.
   */
  private static boolean holdsRedactedName(String text) {
    String current = text;
    for (int round = 0; ; round++) {
      String lower = asciiLowerCase(current);
      if (holdsRedactedToken(lower, false) || holdsRedactedToken(lower, true)) {
        return true;
      }
      String next = percentDecode(current);
      if (next.equals(current)) {
        return false;
      }
      if (round == MAX_QUERY_DECODE_ROUNDS) {
        return true;
      }
      current = next;
    }
  }

  /**
   * Whether a token of {@code lower} is a redacted name. A token is a maximal run of ASCII
   * letters, digits and underscores, or, with {@code hyphenJoins}, of those and hyphens, which
   * keeps {@code api-key} and {@code access-token} one name.
   */
  private static boolean holdsRedactedToken(String lower, boolean hyphenJoins) {
    int length = lower.length();
    int from = 0;
    while (from < length) {
      while (from < length && !isTokenChar(lower.charAt(from), hyphenJoins)) {
        from++;
      }
      int to = from;
      while (to < length && isTokenChar(lower.charAt(to), hyphenJoins)) {
        to++;
      }
      if (to > from && isRedactedParameterName(lower.substring(from, to))) {
        return true;
      }
      from = to;
    }
    return false;
  }

  private static boolean isTokenChar(char ch, boolean hyphenJoins) {
    return (ch >= 'a' && ch <= 'z')
        || (ch >= 'A' && ch <= 'Z')
        || (ch >= '0' && ch <= '9')
        || ch == '_'
        || (hyphenJoins && ch == '-');
  }

  /**
   * Whether the text before the first {@code =} is only a parameter name once decoded: letters,
   * digits, {@code _ - . [ ]}, spaces and non-ASCII characters. Quotes, braces, colons, slashes
   * and a {@code %} left over after the decoding rounds could carry a secret.
   */
  private static boolean isPlainParameterName(String rawKey) {
    String current = rawKey;
    for (int round = 0; round < MAX_QUERY_DECODE_ROUNDS; round++) {
      String next = percentDecode(current);
      if (next.equals(current)) {
        break;
      }
      current = next;
    }
    for (int i = 0; i < current.length(); i++) {
      char ch = current.charAt(i);
      boolean plain =
          isTokenChar(ch, true) || ch == '.' || ch == '[' || ch == ']' || ch == ' ' || ch > 0x7f;
      if (!plain) {
        return false;
      }
    }
    return true;
  }

  /**
   * ASCII lower-casing, with the two characters whose Unicode lower case is ASCII ({@code U+212A}
   * Kelvin sign, {@code U+0130} dotted capital I) mapped by hand, so a server that folds case
   * with Unicode rules still reads {@code to\u212Aen} as {@code token}. The same string comes
   * back when nothing changes.
   */
  private static String asciiLowerCase(String text) {
    char[] chars = null;
    for (int i = 0; i < text.length(); i++) {
      char ch = text.charAt(i);
      char lower = ch;
      if (ch >= 'A' && ch <= 'Z') {
        lower = (char) (ch + ('a' - 'A'));
      } else if (ch == '\u212A') {
        lower = 'k';
      } else if (ch == '\u0130') {
        lower = 'i';
      }
      if (lower != ch) {
        if (chars == null) {
          chars = text.toCharArray();
        }
        chars[i] = lower;
      }
    }
    return chars == null ? text : new String(chars);
  }

  /** URL-decodes a query component: {@code %XX} as UTF-8 bytes, {@code +} as a space. */
  private static String percentDecode(String value) {
    if (value.indexOf('%') < 0 && value.indexOf('+') < 0) {
      return value;
    }
    int length = value.length();
    var out = new StringBuilder(length);
    byte[] run = new byte[length];
    int runLength = 0;
    for (int i = 0; i < length; i++) {
      char ch = value.charAt(i);
      int high = ch == '%' && i + 2 < length ? hexValue(value.charAt(i + 1)) : -1;
      int low = high < 0 ? -1 : hexValue(value.charAt(i + 2));
      if (low >= 0) {
        run[runLength++] = (byte) (high * 16 + low);
        i += 2;
        continue;
      }
      if (runLength > 0) {
        out.append(new String(run, 0, runLength, StandardCharsets.UTF_8));
        runLength = 0;
      }
      out.append(ch == '+' ? ' ' : ch);
    }
    if (runLength > 0) {
      out.append(new String(run, 0, runLength, StandardCharsets.UTF_8));
    }
    return out.toString();
  }

  private static int hexValue(char ch) {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
      return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
      return ch - 'A' + 10;
    }
    return -1;
  }

  private static String normalizeName(String name) {
    return name == null ? "" : name.replace("_", "").replace("-", "").toLowerCase(Locale.ROOT);
  }

  private static String escape(String value) {
    if (value == null) {
      return "";
    }
    var builder = new StringBuilder(value.length() + 16);
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> builder.append("\\\"");
        case '\\' -> builder.append("\\\\");
        case '\b' -> builder.append("\\b");
        case '\f' -> builder.append("\\f");
        case '\n' -> builder.append("\\n");
        case '\r' -> builder.append("\\r");
        case '\t' -> builder.append("\\t");
        default -> {
          if (ch < 0x20) {
            builder.append(String.format("\\u%04x", (int) ch));
          } else {
            builder.append(ch);
          }
        }
      }
    }
    return builder.toString();
  }
}
