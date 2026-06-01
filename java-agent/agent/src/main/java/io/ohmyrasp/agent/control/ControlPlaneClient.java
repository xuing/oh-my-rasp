package io.ohmyrasp.agent.control;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.policy.AgentPolicy;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

public final class ControlPlaneClient implements AutoCloseable {
  private final ControlPlaneConfig config;
  private final ScheduledExecutorService executor;
  private final BiConsumer<AgentPolicy, String> policyInstaller;
  private final AtomicBoolean initialReportsSent = new AtomicBoolean();
  private volatile String agentId;
  private volatile String policyId;
  private volatile int policyVersion;
  private volatile String cachedPolicy;

  public ControlPlaneClient(ControlPlaneConfig config) {
    this(config, (policy, agentKey) -> {});
  }

  public ControlPlaneClient(
      ControlPlaneConfig config, BiConsumer<AgentPolicy, String> policyInstaller) {
    this.config = config;
    this.policyInstaller = policyInstaller == null ? (policy, agentKey) -> {} : policyInstaller;
    this.executor =
        Executors.newSingleThreadScheduledExecutor(
            task -> {
              Thread thread = new Thread(task, "ohmyrasp-control-plane");
              thread.setDaemon(true);
              return thread;
            });
  }

  public static ControlPlaneClient start(ControlPlaneConfig config) {
    return start(config, (policy, agentKey) -> {});
  }

  public static ControlPlaneClient start(
      ControlPlaneConfig config, BiConsumer<AgentPolicy, String> policyInstaller) {
    if (config == null || !config.enabled()) {
      return null;
    }
    ControlPlaneClient client = new ControlPlaneClient(config, policyInstaller);
    client.executor.execute(client::registerAndHeartbeat);
    client.executor.scheduleAtFixedRate(client::heartbeatQuietly, 30, 30, TimeUnit.SECONDS);
    return client;
  }

  public void submit(Detection detection) {
    if (detection == null) {
      return;
    }
    executor.execute(() -> uploadQuietly(detection));
  }

  public void submitHookTelemetry(Detection detection, long latencyUs, long ruleEvaluationUs) {
    if (detection == null) {
      return;
    }
    executor.execute(() -> uploadHookTelemetryQuietly(detection, latencyUs, ruleEvaluationUs));
  }

  public void submitError(String hook, String message, Throwable throwable) {
    executor.execute(() -> uploadErrorQuietly(hook, message, throwable));
  }

  public void submitCrash(String threadName, Throwable throwable) {
    executor.execute(() -> uploadCrashQuietly(threadName, throwable));
  }

  @Override
  public void close() {
    executor.shutdownNow();
  }

  private void registerAndHeartbeat() {
    try {
      ensureRegistered();
      heartbeat();
      pullPolicy();
      reportInitialRuntimeState();
      reportPerformanceSample("startup");
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      uploadErrorQuietly("control-plane.registration", "control-plane registration failed", e);
      System.err.println("[OHMYRASP] control-plane registration failed: " + e);
    }
  }

  private synchronized String ensureRegistered() throws IOException, InterruptedException {
    if (agentId != null && !agentId.isBlank()) {
      return agentId;
    }
    String body =
        "{"
            + field("environment_id", config.environmentId())
            + ","
            + field("hostname", config.hostname())
            + ","
            + field("runtime", config.runtime())
            + ","
            + field("version", config.version())
            + "}";
    Response response = send("POST", "/agents/register", body);
    requireSuccess(response, "register agent");
    String id = extractString(response.body(), "id");
    if (id == null || id.isBlank()) {
      throw new IOException("register agent response did not include id");
    }
    agentId = id;
    updateAgentAssignment(response.body());
    return agentId;
  }

  private void heartbeatQuietly() {
    try {
      heartbeat();
      pullPolicy();
      reportPerformanceSample("heartbeat");
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      uploadErrorQuietly("control-plane.heartbeat", "control-plane heartbeat failed", e);
      System.err.println("[OHMYRASP] control-plane heartbeat failed: " + e);
    }
  }

  private void heartbeat() throws IOException, InterruptedException {
    String id = ensureRegistered();
    Response response =
        send(
            "POST",
            "/agents/" + encodePath(id) + "/heartbeat",
            "{" + field("status", "online") + "}");
    requireSuccess(response, "heartbeat");
    updateAgentAssignment(response.body());
  }

  private void pullPolicy() throws IOException, InterruptedException {
    String id = ensureRegistered();
    Response response = send("GET", "/agents/" + encodePath(id) + "/policy", "");
    if (response.statusCode() == 404) {
      cachedPolicy = "";
      policyInstaller.accept(AgentPolicy.empty(), id);
      return;
    }
    requireSuccess(response, "pull policy");
    cachedPolicy = response.body();
    try {
      policyInstaller.accept(AgentPolicy.parse(cachedPolicy), id);
    } catch (IllegalArgumentException e) {
      uploadErrorQuietly("control-plane.policy", "policy parse failed", e);
      System.err.println("[OHMYRASP] policy parse failed: " + e.getMessage());
    }
  }

  private void uploadQuietly(Detection detection) {
    try {
      upload(detection);
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      System.err.println("[OHMYRASP] control-plane event upload failed: " + e);
    }
  }

  private void upload(Detection detection) throws IOException, InterruptedException {
    String id = ensureRegistered();
    String body =
        "{"
            + field("application_id", config.applicationId())
            + ","
            + field("environment_id", config.environmentId())
            + ","
            + field("agent_id", id)
            + ","
            + field("hook", detection.hook())
            + ","
            + field("algorithm", detection.algorithm())
            + ","
            + field("severity", severity(detection.confidence()))
            + ","
            + field("message", detection.message())
            + ","
            + field("occurred_at", detection.timestamp().toString())
            + policyFields()
            + ",\"attributes\":"
            + attributes(detection)
            + "}";
    Response response = send("POST", "/events/attack", body);
    requireSuccess(response, "upload event");
  }

  private void uploadHookTelemetryQuietly(
      Detection detection, long latencyUs, long ruleEvaluationUs) {
    try {
      uploadHookTelemetry(detection, latencyUs, ruleEvaluationUs);
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      System.err.println("[OHMYRASP] control-plane telemetry upload failed: " + e);
    }
  }

  private void uploadHookTelemetry(Detection detection, long latencyUs, long ruleEvaluationUs)
      throws IOException, InterruptedException {
    Map<String, Object> attributes = runtimePerformanceAttributes();
    attributes.put("action", detection.action());
    attributes.put("latency_us", positive(latencyUs));
    attributes.put("hook_latency_p50_us", positive(latencyUs));
    attributes.put("hook_latency_p95_us", positive(latencyUs));
    attributes.put("rule_eval_p95_us", positive(ruleEvaluationUs));
    attributes.put("confidence", detection.confidence());
    attributes.put("message", detection.message());

    uploadEvent(
        "hook",
        detection.hook(),
        detection.algorithm(),
        "low",
        "Hook telemetry for " + detection.hook(),
        attributes,
        true);
    uploadEvent(
        "performance",
        detection.hook(),
        detection.algorithm(),
        "low",
        "Agent hook performance sample",
        attributes,
        true);
  }

  private void uploadErrorQuietly(String hook, String message, Throwable throwable) {
    try {
      Map<String, Object> attributes = throwableAttributes(throwable);
      attributes.put("stage", hook == null ? "" : hook);
      uploadEvent("error", hook, "agent_error", "medium", message, attributes, false);
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
    }
  }

  private void uploadCrashQuietly(String threadName, Throwable throwable) {
    try {
      Map<String, Object> attributes = throwableAttributes(throwable);
      attributes.put("thread", threadName == null ? "" : threadName);
      uploadEvent(
          "crash",
          "agent",
          "uncaught_exception",
          "high",
          "Uncaught exception observed by OhMyRASP agent",
          attributes,
          false);
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
    }
  }

  private void reportInitialRuntimeState() {
    if (!initialReportsSent.compareAndSet(false, true)) {
      return;
    }
    for (Map<String, Object> dependency : runtimeDependencies()) {
      try {
        uploadDependency(dependency);
      } catch (IOException | InterruptedException e) {
        if (e instanceof InterruptedException) {
          Thread.currentThread().interrupt();
        }
        uploadErrorQuietly("control-plane.dependencies", "dependency report failed", e);
      }
    }
    for (Map<String, Object> finding : runtimeBaselineFindings()) {
      try {
        uploadBaselineFinding(finding);
      } catch (IOException | InterruptedException e) {
        if (e instanceof InterruptedException) {
          Thread.currentThread().interrupt();
        }
        uploadErrorQuietly("control-plane.baseline", "baseline report failed", e);
      }
    }
  }

  private void reportPerformanceSample(String reason) {
    try {
      Map<String, Object> attributes = runtimePerformanceAttributes();
      attributes.put("reason", reason);
      attributes.put("latency_us", 0);
      attributes.put("hook_latency_p50_us", 0);
      attributes.put("hook_latency_p95_us", 0);
      attributes.put("rule_eval_p95_us", 0);
      uploadEvent(
          "performance",
          "agent",
          "runtime_sample",
          "low",
          "Agent runtime performance sample",
          attributes,
          false);
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
    }
  }

  private void uploadDependency(Map<String, Object> dependency)
      throws IOException, InterruptedException {
    String id = ensureRegistered();
    Map<String, Object> body = new LinkedHashMap<>(dependency);
    body.put("application_id", config.applicationId());
    body.put("agent_id", id);
    body.put("observed_at", Instant.now().toString());
    Response response = send("POST", "/dependencies", object(body));
    requireSuccess(response, "upload dependency");
  }

  private void uploadBaselineFinding(Map<String, Object> finding)
      throws IOException, InterruptedException {
    String id = ensureRegistered();
    Map<String, Object> body = new LinkedHashMap<>(finding);
    body.put("application_id", config.applicationId());
    body.put("environment_id", config.environmentId());
    body.put("agent_id", id);
    body.put("observed_at", Instant.now().toString());
    Response response = send("POST", "/baseline-findings", object(body));
    requireSuccess(response, "upload baseline finding");
  }

  private void uploadEvent(
      String type,
      String hook,
      String algorithm,
      String severity,
      String message,
      Map<String, Object> attributes,
      boolean requireRegistration)
      throws IOException, InterruptedException {
    String id = requireRegistration ? ensureRegistered() : agentId;
    if (id == null || id.isBlank()) {
      return;
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("application_id", config.applicationId());
    body.put("environment_id", config.environmentId());
    body.put("agent_id", id);
    if (policyId != null && !policyId.isBlank()) {
      body.put("policy_id", policyId);
      if (policyVersion > 0) {
        body.put("policy_version", policyVersion);
      }
    }
    if (hook != null && !hook.isBlank()) {
      body.put("hook", hook);
    }
    if (algorithm != null && !algorithm.isBlank()) {
      body.put("algorithm", algorithm);
    }
    body.put("severity", severity == null || severity.isBlank() ? "low" : severity);
    body.put("message", message == null || message.isBlank() ? "agent event" : message);
    body.put("occurred_at", Instant.now().toString());
    body.put("attributes", attributes == null ? Map.of() : attributes);
    Response response = send("POST", "/events/" + type, object(body));
    requireSuccess(response, "upload " + type + " event");
  }

  private static List<Map<String, Object>> runtimeDependencies() {
    List<Map<String, Object>> dependencies = new ArrayList<>();
    dependencies.add(
        dependency(
            "java-runtime",
            System.getProperty("java.version", "unknown"),
            "jvm",
            System.getProperty("java.home", "")));
    dependencies.add(
        dependency(
            "ohmyrasp-agent",
            ControlPlaneConfig.class.getPackage().getImplementationVersion() == null
                ? "unknown"
                : ControlPlaneConfig.class.getPackage().getImplementationVersion(),
            "java-agent",
            agentCodeSource()));
    dependencies.addAll(classPathJarDependencies());
    return dependencies;
  }

  private static Map<String, Object> dependency(
      String name, String version, String ecosystem, String packagePath) {
    Map<String, Object> dependency = new LinkedHashMap<>();
    dependency.put("name", name);
    dependency.put("version", version == null || version.isBlank() ? "unknown" : version);
    dependency.put("ecosystem", ecosystem);
    dependency.put("package_path", packagePath == null ? "" : packagePath);
    dependency.put("licenses", List.of());
    dependency.put("vulnerabilities", List.of());
    return dependency;
  }

  private static List<Map<String, Object>> classPathJarDependencies() {
    List<Map<String, Object>> dependencies = new ArrayList<>();
    String classPath = System.getProperty("java.class.path", "");
    if (classPath.isBlank()) {
      return dependencies;
    }
    String[] entries = classPath.split(File.pathSeparator);
    for (String entry : entries) {
      if (dependencies.size() >= 20) {
        break;
      }
      if (entry == null || !entry.toLowerCase().endsWith(".jar")) {
        continue;
      }
      File file = new File(entry);
      String filename = file.getName();
      String name = filename.substring(0, filename.length() - 4);
      dependencies.add(dependency(name, jarVersionFromName(name), "maven", file.getPath()));
    }
    return dependencies;
  }

  private static String jarVersionFromName(String name) {
    int dash = name.lastIndexOf('-');
    if (dash < 0 || dash + 1 >= name.length()) {
      return "unknown";
    }
    String suffix = name.substring(dash + 1);
    return Character.isDigit(suffix.charAt(0)) ? suffix : "unknown";
  }

  private static List<Map<String, Object>> runtimeBaselineFindings() {
    List<Map<String, Object>> findings = new ArrayList<>();
    List<String> inputArguments = jvmInputArguments();
    boolean debugEnabled = inputArguments.stream().anyMatch(arg -> arg.contains("jdwp"));
    findings.add(
        baselineFinding(
            "jvm.debug.disabled",
            debugEnabled ? "JVM remote debug transport is enabled" : "JVM remote debug transport is disabled",
            "runtime",
            debugEnabled ? "high" : "info",
            debugEnabled ? "warning" : "passed",
            "jvm",
            debugEnabled
                ? "Disable JDWP or bind it only to trusted administrative interfaces."
                : "No JDWP transport was observed.",
            Map.of("input_arguments", inputArguments)));

    int major = javaMajorVersion(System.getProperty("java.version", ""));
    boolean jdk25 = major == 25;
    findings.add(
        baselineFinding(
            "jvm.version.supported",
            jdk25 ? "Java runtime is in the primary supported range" : "Java runtime is outside the primary supported range",
            "runtime",
            jdk25 ? "info" : "medium",
            jdk25 ? "passed" : "warning",
            "java-" + (major == 0 ? "unknown" : major),
            "Use the agent build matching the runtime LTS line before production rollout.",
            Map.of(
                "java_version", System.getProperty("java.version", "unknown"),
                "java_vendor", System.getProperty("java.vendor", "unknown"))));

    return findings;
  }

  private static Map<String, Object> baselineFinding(
      String checkID,
      String title,
      String category,
      String severity,
      String status,
      String resource,
      String remediation,
      Map<String, Object> attributes) {
    Map<String, Object> finding = new LinkedHashMap<>();
    finding.put("check_id", checkID);
    finding.put("title", title);
    finding.put("category", category);
    finding.put("severity", severity);
    finding.put("status", status);
    finding.put("resource", resource);
    finding.put("remediation", remediation);
    finding.put("attributes", attributes);
    return finding;
  }

  private static Map<String, Object> runtimePerformanceAttributes() {
    Runtime runtime = Runtime.getRuntime();
    Map<String, Object> attributes = new LinkedHashMap<>();
    attributes.put("cpu_overhead_pct", 0.0);
    attributes.put("memory_overhead_bytes", runtime.totalMemory() - runtime.freeMemory());
    attributes.put("runtime", "java");
    attributes.put("java_version", System.getProperty("java.version", "unknown"));
    return attributes;
  }

  private static Map<String, Object> throwableAttributes(Throwable throwable) {
    Map<String, Object> attributes = runtimePerformanceAttributes();
    if (throwable == null) {
      return attributes;
    }
    attributes.put("exception_class", throwable.getClass().getName());
    attributes.put("exception_message", throwable.getMessage() == null ? "" : throwable.getMessage());
    StackTraceElement[] stackTrace = throwable.getStackTrace();
    if (stackTrace.length > 0) {
      attributes.put("top_frame", stackTrace[0].toString());
    }
    return attributes;
  }

  private static List<String> jvmInputArguments() {
    try {
      RuntimeMXBean bean = ManagementFactory.getRuntimeMXBean();
      return List.copyOf(bean.getInputArguments());
    } catch (RuntimeException e) {
      return List.of();
    }
  }

  private static int javaMajorVersion(String version) {
    if (version == null || version.isBlank()) {
      return 0;
    }
    String normalized = version.startsWith("1.") ? version.substring(2) : version;
    int end = 0;
    while (end < normalized.length() && Character.isDigit(normalized.charAt(end))) {
      end++;
    }
    if (end == 0) {
      return 0;
    }
    try {
      return Integer.parseInt(normalized.substring(0, end));
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  private static String agentCodeSource() {
    try {
      CodeSource codeSource = ControlPlaneClient.class.getProtectionDomain().getCodeSource();
      if (codeSource == null || codeSource.getLocation() == null) {
        return "";
      }
      return codeSource.getLocation().toString();
    } catch (RuntimeException e) {
      return "";
    }
  }

  private static long positive(long value) {
    return Math.max(0, value);
  }

  private Response send(String method, String path, String body) throws IOException {
    HttpURLConnection connection = (HttpURLConnection) endpoint(path).toURL().openConnection();
    connection.setConnectTimeout(3_000);
    connection.setReadTimeout(5_000);
    connection.setRequestMethod(method);
    connection.setRequestProperty("Accept", "application/json");
    connection.setRequestProperty("Content-Type", "application/json");
    connection.setRequestProperty("X-OhMyRasp-App-ID", config.applicationId());
    connection.setRequestProperty("X-OhMyRasp-App-Secret", config.applicationSecret());
    if (!body.isEmpty()) {
      connection.setDoOutput(true);
      byte[] data = body.getBytes(StandardCharsets.UTF_8);
      connection.setFixedLengthStreamingMode(data.length);
      try (OutputStream output = connection.getOutputStream()) {
        output.write(data);
      }
    }
    int status = connection.getResponseCode();
    try (InputStream input = status >= 400 ? connection.getErrorStream() : connection.getInputStream()) {
      String responseBody =
          input == null ? "" : new String(input.readAllBytes(), StandardCharsets.UTF_8);
      return new Response(status, responseBody);
    } finally {
      connection.disconnect();
    }
  }

  private URI endpoint(String path) {
    String base = config.backendUrl().trim();
    while (base.endsWith("/")) {
      base = base.substring(0, base.length() - 1);
    }
    if (!base.endsWith("/api/v1")) {
      base += "/api/v1";
    }
    return URI.create(base + path);
  }

  private static void requireSuccess(Response response, String action) throws IOException {
    if (response.statusCode() < 200 || response.statusCode() > 299) {
      throw new IOException(action + " returned " + response.statusCode() + ": " + response.body());
    }
  }

  private record Response(int statusCode, String body) {}

  private static String object(Map<String, ?> values) {
    StringBuilder builder = new StringBuilder(256);
    appendObject(builder, values == null ? Map.of() : values);
    return builder.toString();
  }

  private static void appendObject(StringBuilder builder, Map<String, ?> values) {
    builder.append('{');
    boolean first = true;
    for (Map.Entry<String, ?> entry : values.entrySet()) {
      if (!first) {
        builder.append(',');
      }
      first = false;
      builder.append('"').append(escape(entry.getKey())).append("\":");
      appendValue(builder, entry.getValue());
    }
    builder.append('}');
  }

  private static void appendArray(StringBuilder builder, Iterable<?> values) {
    builder.append('[');
    boolean first = true;
    for (Object value : values) {
      if (!first) {
        builder.append(',');
      }
      first = false;
      appendValue(builder, value);
    }
    builder.append(']');
  }

  @SuppressWarnings("unchecked")
  private static void appendValue(StringBuilder builder, Object value) {
    if (value == null) {
      builder.append("null");
    } else if (value instanceof Number || value instanceof Boolean) {
      builder.append(value);
    } else if (value instanceof Map<?, ?> map) {
      appendObject(builder, (Map<String, ?>) map);
    } else if (value instanceof Iterable<?> iterable) {
      appendArray(builder, iterable);
    } else {
      builder.append('"').append(escape(String.valueOf(value))).append('"');
    }
  }

  private static String attributes(Detection detection) {
    StringBuilder builder = new StringBuilder(256);
    builder.append('{');
    field(builder, "action", detection.action());
    builder.append(',');
    builder.append("\"confidence\":").append(detection.confidence());
    for (Map.Entry<String, String> entry : detection.details().entrySet()) {
      builder.append(',');
      field(builder, "detail." + entry.getKey(), entry.getValue());
    }
    if (detection.request() != null && detection.request().active()) {
      builder.append(',');
      field(builder, "request.method", detection.request().method());
      builder.append(',');
      field(builder, "request.uri", detection.request().uri());
      builder.append(',');
      field(builder, "request.query", detection.request().query());
    }
    builder.append('}');
    return builder.toString();
  }

  private void updateAgentAssignment(String body) {
    String currentPolicyId = extractString(body, "policy_id");
    if (currentPolicyId != null && !currentPolicyId.isBlank()) {
      policyId = currentPolicyId;
    }
    Integer currentPolicyVersion = extractInt(body, "policy_version");
    if (currentPolicyVersion != null && currentPolicyVersion > 0) {
      policyVersion = currentPolicyVersion;
    }
  }

  private String policyFields() {
    String currentPolicyId = policyId;
    if (currentPolicyId == null || currentPolicyId.isBlank()) {
      return "";
    }
    String fields = "," + field("policy_id", currentPolicyId);
    if (policyVersion > 0) {
      fields += ",\"policy_version\":" + policyVersion;
    }
    return fields;
  }

  private static String severity(int confidence) {
    if (confidence >= 90) {
      return "critical";
    }
    if (confidence >= 75) {
      return "high";
    }
    if (confidence >= 50) {
      return "medium";
    }
    return "low";
  }

  private static String field(String name, String value) {
    return "\"" + escape(name) + "\":\"" + escape(value) + "\"";
  }

  private static void field(StringBuilder builder, String name, String value) {
    builder.append(field(name, value));
  }

  private static String escape(String value) {
    if (value == null) {
      return "";
    }
    StringBuilder builder = new StringBuilder(value.length() + 16);
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

  private static String encodePath(String value) {
    return value.replace("/", "%2F");
  }

  private static String extractString(String json, String field) {
    String needle = "\"" + field + "\":";
    int start = json.indexOf(needle);
    if (start < 0) {
      return null;
    }
    start += needle.length();
    while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
      start++;
    }
    if (start >= json.length() || json.charAt(start) != '"') {
      return null;
    }
    start++;
    StringBuilder value = new StringBuilder();
    boolean escaped = false;
    for (int i = start; i < json.length(); i++) {
      char ch = json.charAt(i);
      if (escaped) {
        value.append(ch);
        escaped = false;
        continue;
      }
      if (ch == '\\') {
        escaped = true;
        continue;
      }
      if (ch == '"') {
        return value.toString();
      }
      value.append(ch);
    }
    return null;
  }

  private static Integer extractInt(String json, String field) {
    String needle = "\"" + field + "\":";
    int start = json.indexOf(needle);
    if (start < 0) {
      return null;
    }
    start += needle.length();
    while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
      start++;
    }
    int end = start;
    while (end < json.length() && Character.isDigit(json.charAt(end))) {
      end++;
    }
    if (end == start) {
      return null;
    }
    return Integer.parseInt(json.substring(start, end));
  }
}
