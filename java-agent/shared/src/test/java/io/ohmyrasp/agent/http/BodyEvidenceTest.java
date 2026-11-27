package io.ohmyrasp.agent.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.util.Redaction;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The allow-list an event on a request with a body is built from: which input it names, and nothing else. */
class BodyEvidenceTest {
  private static Map<String, List<String>> fields(String... pairs) {
    Map<String, List<String>> fields = new LinkedHashMap<String, List<String>>();
    for (int i = 0; i < pairs.length; i += 2) fields.put(pairs[i], Collections.singletonList(pairs[i + 1]));
    return fields;
  }

  @Test
  void theFieldWhoseValueTheOperandContainsIsTheOneShown() {
    Map<String, List<String>> body = fields("username", "a", "password", "hunter2-Secret", "cmd", "127.0.0.1; id");
    String[] input = BodyEvidence.matched(body, null, Collections.singletonList("ping -c 1 127.0.0.1; id"));
    assertArrayEquals(new String[] {"cmd", "127.0.0.1; id"}, input);
  }

  @Test
  void theLongestContainedValueWinsAndCaseIsIgnored() {
    Map<String, List<String>> body = fields("short", "ID", "long", "127.0.0.1; ID");
    assertArrayEquals(new String[] {"long", "127.0.0.1; ID"},
        BodyEvidence.matched(body, null, Collections.singletonList("sh -c 'ping 127.0.0.1; id'")));
  }

  @Test
  void aNamedParameterIsShownWithTheValueTheOperandHolds() {
    Map<String, List<String>> body = new LinkedHashMap<String, List<String>>();
    body.put("tpl", Arrays.asList("innocent", "http://evil/x.ftl"));
    assertArrayEquals(new String[] {"tpl", "http://evil/x.ftl"},
        BodyEvidence.matched(body, "tpl", Collections.singletonList("uri=/r parameter=tpl source=http://evil/x.ftl")));
    assertArrayEquals(new String[] {"tpl", "innocent"},
        BodyEvidence.matched(body, "tpl", Collections.<String>emptyList()), "else its first value");
    assertArrayEquals(new String[] {"absent", null},
        BodyEvidence.matched(body, "absent", Collections.<String>emptyList()), "a name the rule gave, without a value");
  }

  /**
   * The matched input is the attacker's payload, but two things in it are a user's or the application's secret
   * and reach no event: a URL's credentials (a repository URL with a token posted in a body) and the value of a
   * field that names a credential (a password with a quote in it that a SQL rule matched).
   */
  @Test
  void aMatchedValueShowsNoUrlCredentialAndNoCredentialField() {
    Map<String, List<String>> body = new LinkedHashMap<String, List<String>>();
    String repository = "https://deploy:tok3n-SENTINEL@git.example/app.git?access_token=SENTINEL2";
    body.put("repository", Collections.singletonList(repository));
    body.put("password", Collections.singletonList("x' OR '1'='1 SENTINEL3"));

    String[] named = BodyEvidence.matched(body, "repository", Collections.<String>emptyList());
    assertEquals("repository", named[0]);
    assertFalse(named[1].contains("SENTINEL"), named[1]);
    assertTrue(named[1].contains("git.example/app.git"), "the rest of the URL is the evidence: " + named[1]);

    String[] contained = BodyEvidence.matched(body, null, Collections.singletonList("git clone " + repository));
    assertEquals("repository", contained[0]);
    assertFalse(contained[1].contains("SENTINEL"), contained[1]);

    String[] credential = BodyEvidence.matched(body, null,
        Collections.singletonList("SELECT 1 FROM users WHERE pw = 'x' OR '1'='1 SENTINEL3'"));
    assertArrayEquals(new String[] {"password", Redaction.MARKER}, credential);
    assertArrayEquals(new String[] {"password", Redaction.MARKER},
        BodyEvidence.matched(body, "password", Collections.<String>emptyList()));
  }

  /** A credential's name is read as a token of the field's name, as in a URL's parameters. */
  @Test
  void aFieldWhoseNameHoldsACredentialsNameShowsNoValue() {
    for (String name : new String[] {"user[password]", "login.api-key", "%70assword", "access_token", "Auth"}) {
      assertArrayEquals(new String[] {name, Redaction.MARKER},
          BodyEvidence.matched(fields(name, "SENTINEL-value"), null, Collections.singletonList("x SENTINEL-value y")),
          name);
    }
    assertArrayEquals(new String[] {"passwordless", "SENTINEL-value"},
        BodyEvidence.matched(fields("passwordless", "SENTINEL-value"), null,
            Collections.singletonList("x SENTINEL-value y")), "a longer word is another name");
  }

  /** A JSON key can be any text: one that is a URL is shown without its credentials too. */
  @Test
  void aFieldNameThatIsAUrlShowsNoCredential() {
    String[] shown = BodyEvidence.matched(fields("https://u:SENTINEL@example.test/", "alpha-value"), null,
        Collections.singletonList("echo alpha-value"));
    assertArrayEquals(new String[] {"https://" + Redaction.MARKER + "@example.test/", "alpha-value"}, shown);
  }

  /** The URL is read before the value is cut: a credential the cut would split does not leave its first half. */
  @Test
  void aCredentialTheCutWouldSplitIsRemovedWhole() {
    StringBuilder user = new StringBuilder();
    for (int i = 0; i < BodyEvidence.MAX_VALUE_CHARS - 20; i++) user.append('u');
    StringBuilder path = new StringBuilder();
    for (int i = 0; i < 2 * BodyEvidence.MAX_VALUE_CHARS; i++) path.append('p');
    String url = "http://" + user + ":SENTINEL-first-half-SENTINEL-second-half@host.example/" + path;

    String[] shown = BodyEvidence.matched(fields("callback", url), "callback", Collections.<String>emptyList());

    String whole = "http://" + Redaction.MARKER + "@host.example/" + path;
    assertEquals(whole.substring(0, BodyEvidence.MAX_VALUE_CHARS), shown[1]);
  }

  /**
   * The body's extraction cuts a value at BodyValues.MAX_VALUE_CHARS, which can take the {@code @} that ends a
   * URL's user information: what is left of that authority is not shown. A URL whose authority ended before the
   * cut is unaffected.
   */
  @Test
  void aUrlWhoseAuthorityTheExtractionCutIsNotShown() {
    StringBuilder open = new StringBuilder("https://u:SENTINEL");
    while (open.length() < BodyValues.MAX_VALUE_CHARS) open.append('x');
    String[] cut = BodyEvidence.matched(fields("callback", open.toString()), "callback",
        Collections.<String>emptyList());
    assertEquals("https://" + Redaction.MARKER, cut[1]);

    StringBuilder closed = new StringBuilder("https://host.example/SENTINEL-is-a-path-here/");
    while (closed.length() < BodyValues.MAX_VALUE_CHARS) closed.append('x');
    String[] kept = BodyEvidence.matched(fields("callback", closed.toString()), "callback",
        Collections.<String>emptyList());
    assertEquals(closed.substring(0, BodyEvidence.MAX_VALUE_CHARS), kept[1]);
  }

  @Test
  void nothingMatchesNothingIsShown() {
    assertNull(BodyEvidence.matched(fields("a", "x"), null, Collections.singletonList("ls")), "a one-character value");
    assertNull(BodyEvidence.matched(fields("note", "hello"), null, Collections.singletonList("/bin/ls")));
    assertNull(BodyEvidence.matched(null, null, Collections.singletonList("/bin/ls")));
  }

  @Test
  void backportParameterMapsAreRead() {
    Map<Object, Object> parameters = new LinkedHashMap<Object, Object>();
    parameters.put("path", new String[] {"../../etc/passwd"});
    assertArrayEquals(new String[] {"path", "../../etc/passwd"},
        BodyEvidence.matched(parameters, null, Collections.singletonList("/srv/app/../../etc/passwd")));
  }

  @Test
  void namesAndValuesAreCut() {
    StringBuilder name = new StringBuilder();
    StringBuilder value = new StringBuilder();
    for (int i = 0; i < 100; i++) name.append('n');
    for (int i = 0; i < 300; i++) value.append('v');
    String[] input = BodyEvidence.matched(fields(name.toString(), value.toString()), null,
        Collections.singletonList("x" + value + "x"));
    assertEquals(BodyEvidence.MAX_NAME_CHARS, input[0].length());
    assertEquals(BodyEvidence.MAX_VALUE_CHARS, input[1].length());
    String surrogates = "😀😀";
    StringBuilder pairs = new StringBuilder();
    while (pairs.length() < 300) pairs.append(surrogates);
    String cut = BodyEvidence.cutValue("a" + pairs);
    assertFalse(Character.isHighSurrogate(cut.charAt(cut.length() - 1)), "no half of a surrogate pair at the end");
  }

  @Test
  void operandsAreAKindAndALength() {
    assertEquals("command, 23 chars",
        BodyEvidence.operand("command", Arrays.asList("ping -c 1 127.0.0.1; id", "short")));
    assertEquals("operand, 2 chars", BodyEvidence.operand(null, Collections.singletonList("ab")));
    assertNull(BodyEvidence.operand("sql", Collections.<String>emptyList()));
  }

  @Test
  void theMessageIsMadeFromTheRuleIdAlone() {
    String message = BodyEvidence.fixedMessage("command_userinput");
    assertTrue(message.contains("command_userinput"));
    assertEquals(message, BodyEvidence.fixedMessage("command_userinput"));
  }
}
