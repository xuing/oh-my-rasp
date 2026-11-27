package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.http.RequestBody;
import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The work a request body costs its thread, worst case: bodies of the cap's size built to be expensive, read one
 * byte at a time with a hook that decides after every byte (the pattern that decided every prefix before the
 * state budget), through the primary's whole request chain. Prints one line per body, "BODY-COST name ms
 * states", which docs/agent.md quotes; fails only past a bound far above what was measured, so that a change
 * that makes the work grow with the body's length again shows.
 */
final class OhMyRaspHooksRequestBodyCostTest {
  private static final Object STREAM = new Object();
  private static final long BOUND_MS = 4000;

  @BeforeEach
  void quiet() {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    PrintStream out = new PrintStream(sink, true, StandardCharsets.UTF_8);
    OhMyRaspHooks.reportTo(JsonEventLogger.newForTesting(null, "stdout", 0, false, out, out));
  }

  @AfterEach
  void reset() {
    OhMyRaspHooks.reportTo(null);
    OhMyRaspHooks.exitHttpRequest();
  }

  static Map<String, String> adversarialBodies() {
    int cap = RequestBody.MAX_UNITS;
    Map<String, String> bodies = new LinkedHashMap<>();
    bodies.put("deep-nesting", "[".repeat(cap / 2) + "]".repeat(cap / 2));
    bodies.put("deep-objects", "{\"a\":".repeat(cap / 5) + "1" + "}".repeat(cap / 5));
    bodies.put("one-huge-string", "{\"a\":\"" + "x".repeat(cap - 10) + "\"}");
    StringBuilder duplicates = new StringBuilder("{");
    while (duplicates.length() < cap - 12) duplicates.append("\"a\":\"1\",");
    bodies.put("duplicate-keys", duplicates.append("\"a\":\"1\"}").toString());
    StringBuilder keys = new StringBuilder("{");
    for (int i = 0; keys.length() < cap - 20; i++) keys.append("\"k").append(i).append("\":\"v").append(i).append("\",");
    bodies.put("many-keys", keys.append("\"z\":\"z\"}").toString());
    bodies.put("escapes", "{\"a\":\"" + "\\u0041".repeat((cap - 10) / 6) + "\"}");
    bodies.put("regex-hostile", "{\"file\":\"" + "a/".repeat((cap - 40) / 4) + "\",\"type\":\""
        + "java.lang.".repeat((cap - 40) / 40) + "\"}");
    bodies.put("expression-hostile", "{\"q\":\"" + "${T(".repeat((cap - 20) / 4) + "\"}");
    bodies.put("form-percent", "a=" + "%25".repeat((cap - 4) / 3));
    return bodies;
  }

  /** One request: the body read one byte at a time, a deciding hook after each byte, then end of stream. */
  private static long byteAtATime(String body) {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    String type = body.startsWith("a=") ? "application/x-www-form-urlencoded" : "application/json";
    long started = System.nanoTime();
    OhMyRaspHooks.enterHttpRequest(new OhMyRaspHooksRequestBodyTest.BodyRequest("PATCH", "/customers/1", type, -1),
        new OhMyRaspHooksPolicyTest.FakeResponse());
    for (int i = 0; i < bytes.length; i++) {
      Object token = OhMyRaspHooks.enterBodyRead(STREAM);
      OhMyRaspHooks.exitBodyRead(1, token, bytes, i);
      OhMyRaspHooks.currentRequest(); // what any hook that reads the request does before it decides
    }
    Object token = OhMyRaspHooks.enterBodyRead(STREAM);
    OhMyRaspHooks.exitBodyRead(-1, token, bytes, 0);
    OhMyRaspHooks.exitHttpRequest();
    return (System.nanoTime() - started) / 1_000_000;
  }

  @Test
  void theWorstBodiesOfTheCapsSizeCostABoundedAmount() {
    Map<String, String> bodies = adversarialBodies();
    for (String body : bodies.values()) byteAtATime(body); // warm the JIT, as a server that has run a while is
    for (Map.Entry<String, String> body : bodies.entrySet()) {
      long worst = 0;
      for (int run = 0; run < 3; run++) worst = Math.max(worst, byteAtATime(body.getValue()));
      System.out.println("BODY-COST " + body.getKey() + " " + worst + " ms, " + body.getValue().length()
          + " bytes read one at a time, " + (RequestBody.MAX_STATES + 1) + " states decided at most");
      assertTrue(worst < BOUND_MS, body.getKey() + " took " + worst + " ms");
    }
  }
}
