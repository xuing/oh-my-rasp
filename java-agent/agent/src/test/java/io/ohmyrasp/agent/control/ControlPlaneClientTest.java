package io.ohmyrasp.agent.control;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.policy.AgentPolicy;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class ControlPlaneClientTest {
  @Test
  void registersAndUploadsDetection() throws Exception {
    List<String> requests = new ArrayList<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/api/v1/agents/register",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 201, "{\"id\":\"agt_test\",\"policy_id\":\"pol_test\",\"policy_version\":3}");
        });
    server.createContext(
        "/api/v1/events/attack",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 201, "{\"id\":\"evt_test\"}");
        });
    server.start();
    try {
      ControlPlaneConfig config =
          new ControlPlaneConfig(
              "http://127.0.0.1:" + server.getAddress().getPort(),
              "app_test",
              "secret_test",
              "env_test",
              "node-test",
              "java",
              "1.0.0");
      try (ControlPlaneClient client = new ControlPlaneClient(config)) {
        client.submit(
            new Detection(
                Instant.parse("2026-06-01T00:00:00Z"),
                "command",
                "command_common",
                "log",
                95,
                "dangerous command",
                new RequestContext("GET", "/run", "cmd=id", Map.of(), Map.of()),
                Map.of("command", "id")));
        waitFor(requests, 2);
      }
    } finally {
      server.stop(0);
    }

    assertTrue(requests.get(0).contains("POST /api/v1/agents/register"));
    assertTrue(requests.get(0).contains("X-OhMyRasp-App-ID=app_test"));
    assertTrue(requests.get(0).contains("\"environment_id\":\"env_test\""));
    assertTrue(requests.get(1).contains("POST /api/v1/events/attack"));
    assertTrue(requests.get(1).contains("\"agent_id\":\"agt_test\""));
    assertTrue(requests.get(1).contains("\"policy_id\":\"pol_test\""));
    assertTrue(requests.get(1).contains("\"policy_version\":3"));
    assertTrue(requests.get(1).contains("\"message\":\"dangerous command\""));
    assertTrue(requests.get(1).contains("\"detail.command\":\"id\""));
  }

  @Test
  void pullsPolicyAndInstallsParsedPolicy() throws Exception {
    List<String> requests = new ArrayList<>();
    AtomicReference<AgentPolicy> installedPolicy = new AtomicReference<>();
    AtomicReference<String> installedAgentKey = new AtomicReference<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/api/v1/agents/register",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 201, "{\"id\":\"agt_policy\",\"policy_id\":\"pol_test\",\"policy_version\":4}");
        });
    server.createContext(
        "/api/v1/agents/agt_policy/heartbeat",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 200, "{\"id\":\"agt_policy\",\"policy_id\":\"pol_test\",\"policy_version\":4}");
        });
    server.createContext(
        "/api/v1/agents/agt_policy/policy",
        exchange -> {
          record(requests, exchange);
          respond(
              exchange,
              200,
              """
              {
                "version": 4,
                "status": "active",
                "canary_percent": 100,
                "rules": [
                  {
                    "name": "SQL block",
                    "hook": "sql",
                    "algorithm": "sql_userinput",
                    "action": "block",
                    "severity": "critical",
                    "expression": "algorithm == \\"sql_userinput\\""
                  }
                ]
              }
              """);
        });
    server.start();
    try {
      ControlPlaneConfig config =
          new ControlPlaneConfig(
              "http://127.0.0.1:" + server.getAddress().getPort(),
              "app_test",
              "secret_test",
              "env_test",
              "node-test",
              "java",
              "1.0.0");
      try (ControlPlaneClient ignored =
          ControlPlaneClient.start(
              config,
              (policy, agentKey) -> {
                installedPolicy.set(policy);
                installedAgentKey.set(agentKey);
              })) {
        waitFor(requests, 3);
        waitForPolicy(installedPolicy);
      }
    } finally {
      server.stop(0);
    }

    assertTrue(requests.get(0).contains("POST /api/v1/agents/register"));
    assertTrue(requests.get(1).contains("POST /api/v1/agents/agt_policy/heartbeat"));
    assertTrue(requests.get(2).contains("GET /api/v1/agents/agt_policy/policy"));
    assertTrue(installedPolicy.get().loaded());
    assertTrue(installedPolicy.get().evaluate(sqlDetection(), installedAgentKey.get()).detection().action().equals("block"));
    assertTrue("agt_policy".equals(installedAgentKey.get()));
  }

  @Test
  void reportsRuntimeProducersAndOperationalEvents() throws Exception {
    List<String> requests = new ArrayList<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/api/v1/agents/register",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 201, "{\"id\":\"agt_runtime\",\"policy_id\":\"pol_runtime\",\"policy_version\":1}");
        });
    server.createContext(
        "/api/v1/agents/agt_runtime/heartbeat",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 200, "{\"id\":\"agt_runtime\",\"policy_id\":\"pol_runtime\",\"policy_version\":1}");
        });
    server.createContext(
        "/api/v1/agents/agt_runtime/policy",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 404, "{\"error\":\"not_found\"}");
        });
    server.createContext(
        "/api/v1/dependencies",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 202, "{\"id\":\"dep_test\"}");
        });
    server.createContext(
        "/api/v1/baseline-findings",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 202, "{\"id\":\"bsl_test\"}");
        });
    server.createContext(
        "/api/v1/events/hook",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 202, "{\"id\":\"evt_hook\"}");
        });
    server.createContext(
        "/api/v1/events/performance",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 202, "{\"id\":\"evt_perf\"}");
        });
    server.createContext(
        "/api/v1/events/error",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 202, "{\"id\":\"evt_error\"}");
        });
    server.createContext(
        "/api/v1/events/crash",
        exchange -> {
          record(requests, exchange);
          respond(exchange, 202, "{\"id\":\"evt_crash\"}");
        });
    server.start();
    try {
      ControlPlaneConfig config =
          new ControlPlaneConfig(
              "http://127.0.0.1:" + server.getAddress().getPort(),
              "app_test",
              "secret_test",
              "env_test",
              "node-test",
              "java",
              "1.0.0");
      try (ControlPlaneClient client = ControlPlaneClient.start(config)) {
        waitForContaining(requests, "POST /api/v1/dependencies");
        waitForContaining(requests, "\"name\":\"java-runtime\"");
        waitForContaining(requests, "POST /api/v1/baseline-findings");
        waitForContaining(requests, "\"check_id\":\"jvm.debug.disabled\"");
        waitForContaining(requests, "POST /api/v1/events/performance");

        client.submitHookTelemetry(sqlDetection(), 1234, 55);
        client.submitError("test-hook", "simulated hook error", new IllegalStateException("boom"));
        client.submitCrash("crash-thread", new RuntimeException("dead"));

        waitForContaining(requests, "POST /api/v1/events/hook");
        waitForContaining(requests, "\"latency_us\":1234");
        waitForContaining(requests, "POST /api/v1/events/error");
        waitForContaining(requests, "\"exception_class\":\"java.lang.IllegalStateException\"");
        waitForContaining(requests, "POST /api/v1/events/crash");
        waitForContaining(requests, "\"thread\":\"crash-thread\"");
      }
    } finally {
      server.stop(0);
    }
  }

  private static void waitFor(List<String> requests, int count) throws InterruptedException {
    long deadline = System.currentTimeMillis() + 3_000;
    while (System.currentTimeMillis() < deadline) {
      synchronized (requests) {
        if (requests.size() >= count) {
          return;
        }
      }
      Thread.sleep(25);
    }
    throw new AssertionError("timed out waiting for " + count + " requests, got " + requests);
  }

  private static void waitForPolicy(AtomicReference<AgentPolicy> policy) throws InterruptedException {
    long deadline = System.currentTimeMillis() + 3_000;
    while (System.currentTimeMillis() < deadline) {
      if (policy.get() != null) {
        return;
      }
      Thread.sleep(25);
    }
    throw new AssertionError("timed out waiting for policy install");
  }

  private static void waitForContaining(List<String> requests, String needle)
      throws InterruptedException {
    long deadline = System.currentTimeMillis() + 3_000;
    while (System.currentTimeMillis() < deadline) {
      synchronized (requests) {
        for (String request : requests) {
          if (request.contains(needle)) {
            return;
          }
        }
      }
      Thread.sleep(25);
    }
    throw new AssertionError("timed out waiting for request containing " + needle + ", got " + requests);
  }

  private static Detection sqlDetection() {
    return new Detection(
        Instant.parse("2026-06-01T00:00:00Z"),
        "sql",
        "sql_userinput",
        "log",
        95,
        "SQL query structure appears altered by request input",
        new RequestContext("GET", "/login", "value=x", Map.of("value", List.of("' OR '1'='1")), Map.of()),
        Map.of("query", "select * from users where name = '' OR '1'='1'"));
  }

  private static void record(List<String> requests, HttpExchange exchange) throws IOException {
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String request =
        exchange.getRequestMethod()
            + " "
            + exchange.getRequestURI()
            + " X-OhMyRasp-App-ID="
            + exchange.getRequestHeaders().getFirst("X-OhMyRasp-App-ID")
            + " "
            + body;
    synchronized (requests) {
      requests.add(request);
    }
  }

  private static void respond(HttpExchange exchange, int status, String body) throws IOException {
    byte[] data = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, data.length);
    exchange.getResponseBody().write(data);
    exchange.close();
  }
}
