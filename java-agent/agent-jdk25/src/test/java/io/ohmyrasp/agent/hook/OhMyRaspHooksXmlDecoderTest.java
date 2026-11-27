package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The entries XMLDecoder's {@code <method>}, {@code <property>} and {@code <new>} elements call: the same
 * classification as the statement path, with no stack to walk (the caller is the decoder's own class).
 */
final class OhMyRaspHooksXmlDecoderTest {
  private final ByteArrayOutputStream events = new ByteArrayOutputStream();

  @BeforeEach
  void record() {
    PrintStream out = new PrintStream(events, true, StandardCharsets.UTF_8);
    OhMyRaspHooks.reportTo(JsonEventLogger.newForTesting(null, "stdout", 0, true, out, out));
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.enterHttpRequest(
        new OhMyRaspHooksPolicyTest.FakeRequest(), new OhMyRaspHooksPolicyTest.FakeResponse());
  }

  @AfterEach
  void reset() {
    OhMyRaspHooks.reportTo(null);
    OhMyRaspHooks.exitHttpRequest();
    System.clearProperty("ohmyrasp.block");
  }

  private String recorded() {
    return events.toString(StandardCharsets.UTF_8);
  }

  @Test
  void blocksAProcessBuilderStartedByAMethodElement() throws Exception {
    ProcessBuilder target = new ProcessBuilder("sh", "-c", "id");
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeXmlDecoderInvoke(
            new Object[0], ProcessBuilder.class.getMethod("start"), target));
    assertTrue(recorded().contains("xml_decoder_runtime"), recorded());
  }

  @Test
  void blocksRuntimeExecReachedByAMethodElement() throws Exception {
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeXmlDecoderInvoke(
            new Object[] {"id"}, Runtime.class.getMethod("exec", String.class), Runtime.getRuntime()));
  }

  @Test
  void blocksAScriptWriterBuiltByANewElement() {
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeXmlDecoderNew(
            PrintWriter.class, new Object[] {"/srv/app/webapps/ROOT/shell.jsp"}));
    assertTrue(recorded().contains("xml_decoder_webshell"), recorded());
  }

  @Test
  void passesAnOrdinaryCallItsOwnArguments() throws Exception {
    Object[] arguments = {"7"};
    assertSame(arguments, OhMyRaspHooks.beforeXmlDecoderInvoke(
        arguments, Integer.class.getMethod("valueOf", String.class), Integer.class));
    OhMyRaspHooks.beforeXmlDecoderNew(StringBuilder.class, new Object[] {"weekly"});
    OhMyRaspHooks.beforeXmlDecoderNew(null, new Object[0]);
    assertSame(arguments, OhMyRaspHooks.beforeXmlDecoderInvoke(arguments, null, null));
    assertFalse(recorded().contains("xml_decoder"), recorded());
  }
}
