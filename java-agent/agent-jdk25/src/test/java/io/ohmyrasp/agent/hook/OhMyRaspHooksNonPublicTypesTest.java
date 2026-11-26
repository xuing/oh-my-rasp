package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.hook.nonpublic.NonPublicTypes;
import io.ohmyrasp.agent.log.JsonEventLogger;
import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A hook reads a public method of an object through reflection; when the object's class is not public (a
 * container's wrapper, an implementation class), the lookup has to land on a public type that declares it.
 */
final class OhMyRaspHooksNonPublicTypesTest {
  private final ByteArrayOutputStream events = new ByteArrayOutputStream();

  @BeforeEach
  void record() {
    PrintStream out = new PrintStream(events, true, StandardCharsets.UTF_8);
    OhMyRaspHooks.reportTo(JsonEventLogger.newForTesting(null, "stdout", 0, true, out, out));
  }

  @AfterEach
  void reset() {
    OhMyRaspHooks.reportTo(null);
    OhMyRaspHooks.exitHttpRequest();
    System.clearProperty("ohmyrasp.block");
    System.clearProperty("ohmyrasp.spark.submitRole");
    System.clearProperty("ohmyrasp.yarn.submitRole");
  }

  private static void inRequest() {
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.enterHttpRequest(
        new OhMyRaspHooksPolicyTest.FakeRequest(), new OhMyRaspHooksPolicyTest.FakeResponse());
  }

  private String recorded() {
    return events.toString(StandardCharsets.UTF_8);
  }

  @Test
  void readsAnExpressionHeldByANonPublicClass() {
    inRequest();
    var expression =
        NonPublicTypes.expression("T(java.lang.Runtime).getRuntime().exec('id')");
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeExpressionEvaluation("spel", expression),
        "the text of a non-public expression object was not read");
  }

  @Test
  void readsTheSystemIdOfANonPublicXmlSource() {
    inRequest();
    var source = NonPublicTypes.xmlSource("file:///etc/passwd");
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeXmlEntity("xxe", source),
        "the system id of a non-public XML source was not read");
  }

  /** The hook runs from inside XMLDecoder, as it does when the decoder evaluates a statement. */
  public static final class Trigger {
    static volatile boolean blocked;

    public static Object fire() {
      try {
        OhMyRaspHooks.beforeJavaBeansStatement(
            NonPublicTypes.statement(Runtime.getRuntime(), "exec", "id"));
      } catch (OhMyRaspBlockException expected) {
        blocked = true; // the decoder would swallow it
      }
      return "fired";
    }
  }

  @Test
  void readsAStatementWhoseAccessorsAreOverriddenInANonPublicClass() {
    inRequest();
    Trigger.blocked = false;
    String xml =
        "<java version=\"1.8.0\" class=\"java.beans.XMLDecoder\"><object class=\""
            + Trigger.class.getName()
            + "\" method=\"fire\"/></java>";
    var decoder = new XMLDecoder(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    try {
      decoder.readObject();
    } finally {
      decoder.close();
    }
    assertTrue(Trigger.blocked, "the target, method and arguments of a non-public Statement were not read");
  }

  @Test
  void recordsTheRequestOfASparkSubmissionHeldByANonPublicClass() {
    System.setProperty("ohmyrasp.block", "true");
    System.setProperty("ohmyrasp.spark.submitRole", "submitter");
    var request = NonPublicTypes.request("POST", "/v1/submissions/create");
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeSparkSubmitDispatch(true, request, NonPublicTypes.RequestLike.class));
    assertTrue(recorded().contains("/v1/submissions/create"), recorded());
  }

  @Test
  void recordsTheRequestOfAYarnSubmissionHeldByANonPublicClass() {
    System.setProperty("ohmyrasp.block", "true");
    System.setProperty("ohmyrasp.yarn.submitRole", "submitter");
    var request = NonPublicTypes.request("POST", "/ws/v1/cluster/apps");
    assertThrows(
        OhMyRaspBlockException.class,
        () ->
            OhMyRaspHooks.afterYarnSubmitPrepared(
                new Object(), request, NonPublicTypes.RequestLike.class));
    assertTrue(recorded().contains("/ws/v1/cluster/apps"), recorded());
  }

  @Test
  void recordsTheRequestOfADataEaseFilterContinuationHeldByANonPublicClass() {
    System.setProperty("ohmyrasp.block", "true");
    var request = NonPublicTypes.request("GET", "/de2api/datasource/list");
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeDataEaseFilterContinuation("token rejected", request));
    String log = recorded();
    assertTrue(log.contains("/de2api/datasource/list"), log);
    assertTrue(log.contains("GET"), log);
  }

  @Test
  void stillReadsAPublicTypeAndSurvivesAnObjectWithNothingToRead() {
    inRequest();
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeExpressionEvaluation("spel", new Object()));
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeXmlEntity("xxe", new Object()));
  }
}
