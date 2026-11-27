package io.ohmyrasp.agent.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.http.RequestBodySnapshot;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The body state a request context holds: one generation, dropped whole, and the provenance it leaves behind. */
final class RequestContextBodyTest {
  private static RequestContext context() {
    return new RequestContext("POST", "/app/ping", "lang=en", Map.of("lang", List.of("en")), Map.of());
  }

  /**
   * A worker that read the body state before the dispatch ended and made the merged inputs after forgetBody must
   * not publish them: the context keeps no body-derived cache past the dispatch.
   */
  @Test
  void inputsMadeFromAStateThatForgetBodyDroppedAreNotPublished() {
    RequestContext context = context();
    context.observeBody(RequestBodySnapshot.of("{\"cmd\":\"hunter2-Secret\"}", "application/json"));
    RequestContext.Recorded before = context.recordedState(); // what the worker read
    context.forgetBody();                                      // the dispatch ended
    Map<String, List<String>> merged = context.inputsOf(before); // the worker goes on with what it read
    assertEquals(List.of("hunter2-Secret"), merged.get("cmd"), "the worker gets its own result");
    assertNull(context.recordedState(), "nothing was published back into the context");
    assertNull(context.bodySnapshot());
    assertEquals(Map.of("lang", List.of("en")), context.inputParameters(), "the context's inputs hold no body field");
  }

  @Test
  void inputsMadeFromTheCurrentStateAreCachedWithIt() {
    RequestContext context = context();
    context.observeBody(RequestBodySnapshot.of("{\"cmd\":\"id\"}", "application/json"));
    Map<String, List<String>> first = context.inputParameters();
    assertSame(first, context.inputParameters(), "made once per state");
    context.observeBody(RequestBodySnapshot.of("{\"cmd\":\"id\",\"x\":\"y\"}", "application/json"));
    assertNotSame(first, context.inputParameters(), "a new state, new inputs");
  }

  @Test
  void aContextThatSawABodyStillSaysSoAfterTheDispatch() {
    RequestContext context = context();
    assertTrue(!context.bodyDerived());
    context.observeBody(RequestBodySnapshot.of("a=b", "application/x-www-form-urlencoded"));
    context.forgetBody();
    assertTrue(context.bodyDerived(), "an operation carried from this request reports as one with a body");
    assertTrue(context.withFormBody().bodyDerived());
    assertNotSame(context, context.withoutBody(), "an event never holds the live context");
    assertEquals(Map.of(), context.publicEnvelope().parameters());
  }
}
