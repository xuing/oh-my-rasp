package io.ohmyrasp.agent.log;

import io.ohmyrasp.agent.control.ControlPlaneClient;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.io.IOException;
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

  /** One queued event plus its measured in-hook latencies (microseconds, -1 if unknown). */
  private record Sample(Detection detection, long latencyUs, long ruleEvaluationUs) {}

  private final Path logPath;
  private final BlockingQueue<Sample> queue;
  private final AtomicLong dropped = new AtomicLong();
  private volatile boolean running = true;
  private volatile ControlPlaneClient controlPlaneClient;

  private JsonEventLogger() {
    String configured = System.getProperty("ohmyrasp.log");
    if (configured == null || configured.isBlank()) {
      configured = System.getenv("OHMYRASP_LOG");
    }
    if (configured == null || configured.isBlank()) {
      configured = "/tmp/ohmyrasp-events.jsonl";
    }
    logPath = Path.of(configured);
    queue = new ArrayBlockingQueue<>(queueCapacity());

    Thread writer = new Thread(this::drainLoop, "ohmyrasp-event-writer");
    writer.setDaemon(true);
    writer.start();
    Runtime.getRuntime()
        .addShutdownHook(new Thread(this::shutdown, "ohmyrasp-event-writer-shutdown"));
  }

  public static JsonEventLogger get() {
    return INSTANCE;
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
    if (!queue.offer(new Sample(detection, latencyUs, ruleEvaluationUs))) {
      dropped.incrementAndGet();
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
    while (running || !queue.isEmpty()) {
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
        System.err.println("[OHMYRASP] event writer error: " + e);
      }
    }
  }

  private void flush(List<Sample> batch) {
    StringBuilder fileBuffer = new StringBuilder(batch.size() * 256);
    StringBuilder stdoutBuffer = new StringBuilder(batch.size() * 256);
    String separator = System.lineSeparator();
    for (Sample sample : batch) {
      String json = toJson(sample.detection(), sample.latencyUs());
      fileBuffer.append(json).append(separator);
      stdoutBuffer.append("[OHMYRASP] ").append(json).append(separator);
    }
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
      System.err.println("[OHMYRASP] failed to write event log: " + e);
    }
    System.out.print(stdoutBuffer);

    ControlPlaneClient client = controlPlaneClient;
    if (client != null) {
      for (Sample sample : batch) {
        client.submit(sample.detection());
        if (sample.latencyUs() >= 0) {
          client.submitHookTelemetry(
              sample.detection(), sample.latencyUs(), sample.ruleEvaluationUs());
        }
      }
    }
  }

  private void shutdown() {
    running = false;
    // Best-effort final drain so events queued at exit still reach the spool.
    List<Sample> remaining = new ArrayList<>();
    queue.drainTo(remaining);
    if (!remaining.isEmpty()) {
      flush(remaining);
    }
  }

  private static int queueCapacity() {
    String configured = System.getProperty("ohmyrasp.log.queue");
    if (configured == null || configured.isBlank()) {
      configured = System.getenv("OHMYRASP_LOG_QUEUE");
    }
    if (configured != null && !configured.isBlank()) {
      try {
        return Math.max(256, Integer.parseInt(configured.trim()));
      } catch (NumberFormatException ignored) {
        // fall through to default
      }
    }
    return 8192;
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
