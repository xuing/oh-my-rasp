package io.ohmyrasp.agent.control;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.policy.AgentPolicy;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

public final class ControlPlaneClient implements AutoCloseable {
  private final ControlPlaneConfig config;
  private final ScheduledExecutorService executor;
  private final BiConsumer<AgentPolicy, String> policyInstaller;
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

  @Override
  public void close() {
    executor.shutdownNow();
  }

  private void registerAndHeartbeat() {
    try {
      ensureRegistered();
      heartbeat();
      pullPolicy();
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
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
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
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
