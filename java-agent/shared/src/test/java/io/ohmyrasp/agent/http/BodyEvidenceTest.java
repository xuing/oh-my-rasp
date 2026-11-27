package io.ohmyrasp.agent.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

/** What leaves a rule names the body field its evidence came from, never the field's value or body text. */
class BodyEvidenceTest {
  private static final String CANARY_BODY = "{\"username\":\"a\",\"password\":\"hunter2-Secret\",\"cmd\":\"127.0.0.1; id\"}";
  private static final RequestBodySnapshot BODY = RequestBodySnapshot.of(CANARY_BODY, "application/json");

  private static String scrub(String text) {
    return BodyEvidence.scrub(text, BODY, Collections.<String>emptySet(), Arrays.asList("POST", "/app/ping", ""));
  }

  private static void assertClean(String scrubbed) {
    assertFalse(scrubbed.contains("hunter2"), scrubbed);
    assertFalse(scrubbed.contains("127.0.0.1"), scrubbed);
    assertFalse(scrubbed.contains("; id"), scrubbed);
  }

  @Test
  void aMatchedKeyIsNamedAsABodyField() {
    assertEquals("body:cmd", scrub("cmd"));
    assertEquals("body:password", scrub("password"));
  }

  @Test
  void aMatchedValueIsReplacedByItsFieldsName() {
    assertEquals("[body:cmd]", scrub("127.0.0.1; id"));
    assertEquals("[body:password]", scrub("hunter2-Secret"));
    assertEquals("[body:username]", scrub("a"), "a short value equal to the whole detail is replaced too");
  }

  @Test
  void aSinkOperandAssembledFromTheBodyKeepsItsOwnText() {
    String command = scrub("sh -c ping -c1 127.0.0.1; id");
    assertEquals("sh -c ping -c1 [body:cmd]", command);
    String sql = scrub("select * from users where name = 'a' and secret = 'hunter2-Secret'");
    assertClean(sql);
    assertTrue(sql.contains("[body:password]"), sql);
  }

  @Test
  void aFragmentQuotedFromTheBodyIsReplaced() {
    assertEquals("[body:password]", scrub("hunter2-S"), "a fragment of a value");
    String composite = scrub("uri=/app/ping parameter=password value=hunter2 x");
    assertClean(composite);
    assertTrue(composite.contains("body:password"), composite);
    assertClean(scrub("\"password\":\"hunter2"));
  }

  @Test
  void textWithNothingOfTheBodyIsLeftAsItIs() {
    assertEquals("/app/ping", scrub("/app/ping"));
    assertEquals("command_userinput", scrub("command_userinput"));
    assertEquals("ProcessBuilder.start", scrub("ProcessBuilder.start"));
  }

  @Test
  void aLongNameIsCut() {
    StringBuilder key = new StringBuilder();
    for (int i = 0; i < 100; i++) key.append('k');
    RequestBodySnapshot body = RequestBodySnapshot.of("{\"" + key + "\":1}", "application/json");
    String shown = BodyEvidence.scrub("parameter " + key, body, null, null);
    assertTrue(shown.length() < 100, shown);
    assertTrue(shown.contains("body:kkkk"), shown);
  }

  @Test
  void aRequestParameterOfTheSameNameIsNotMarked() {
    assertEquals("cmd", BodyEvidence.scrub("cmd", BODY, Collections.singleton("cmd"), null));
  }
}
