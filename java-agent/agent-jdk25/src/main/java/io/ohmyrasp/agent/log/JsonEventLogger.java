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
  // Once shutdown has begun, a write waits this long for the write lock and then gives up.
  private static final long SHUTDOWN_LOCK_MILLIS = 1000;
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
   * in-hook latencies) or a periodic latency {@code telemetryHook} sample that
   * feeds the daemon's business-impact panel without being a detection.
   */
  private record Sample(
      Detection detection, String telemetryHook, long latencyUs, long ruleEvaluationUs) {}

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
  private final Thread writer;
  private volatile boolean running = true;
  // Set by shutdown once the writer is gone or given up on: from then on events are written on
  // the caller's thread, and writes wait only a bounded time for the write lock.
  private volatile boolean closed;
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
    boolean standalone =
        activeDefaults.lockConfig()
            ? activeDefaults.standalone()
            : (flag("ohmyrasp.standalone", "OHMYRASP_STANDALONE")
                || activeDefaults.standalone()
                || (runtime != null && runtime.isStandalone()));

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

    if (this.target == LogTarget.FILE) {
      this.queue = new ArrayBlockingQueue<>(queueCapacity());
      Thread writer = new Thread(this::drainLoop, "ohmyrasp-event-writer");
      writer.setDaemon(true);
      this.writer = writer;
      writer.start();
      Runtime.getRuntime()
          .addShutdownHook(new Thread(this::shutdown, "ohmyrasp-event-writer-shutdown"));
    } else {
      this.queue = null;
      this.writer = null;
    }
  }

  public static JsonEventLogger get() {
    return INSTANCE;
  }

  /** Creates an isolated logger for unit tests without touching {@link #INSTANCE}. */
  public static JsonEventLogger newForTesting(
      ShirudoDefaults defaults,
      String targetOverride,
      Integer latencySampleOverride,
      boolean syncWrites,
      PrintStream out,
      PrintStream err) {
    return new JsonEventLogger(
        defaults, null, targetOverride, latencySampleOverride, syncWrites, out, err);
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
    submit(new Sample(detection, null, latencyUs, ruleEvaluationUs));
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
    submit(new Sample(null, hook == null ? "" : hook, latencyUs, -1));
  }

  private void submit(Sample sample) {
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
          sample.detection() == null
              ? telemetryJson(sample.telemetryHook(), sample.latencyUs())
              : toJson(sample.detection(), sample.latencyUs());
      if (fileBuffer != null) {
        fileBuffer.append(json).append(separator);
      }
      // Telemetry is high-volume and uninteresting on the console; keep it off stdout/stderr.
      if (consoleBuffer != null && sample.detection() != null) {
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
            errStream().println("[OHMYRASP] failed to write event log: " + e);
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
        client.submit(sample.detection());
        if (sample.latencyUs() >= 0) {
          client.submitHookTelemetry(
              sample.detection(), sample.latencyUs(), sample.ruleEvaluationUs());
        }
      }
    }
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

  private void shutdown() {
    shutdown(SHUTDOWN_JOIN_MILLIS);
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
    Thread current = writer;
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
    String value = System.getProperty(property);
    if (value == null || value.isBlank()) {
      value = System.getenv(env);
    }
    if (value != null && !value.isBlank()) {
      try {
        return Integer.parseInt(value.trim());
      } catch (NumberFormatException ignored) {
        // fall through to default
      }
    }
    return fallback;
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
    field(builder, "query", current.query()).append(',');
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
    return "[redacted]";
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
    String normalized = normalizeName(name);
    if (SENSITIVE_PARAMETER_NAMES.contains(normalized)
        || EXECUTABLE_SOURCE_PARAMETER_NAMES.contains(normalized)) {
      return "[redacted]";
    }
    return value;
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
