package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.log.JsonEventLogger;
import java.beans.Expression;
import java.beans.Statement;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
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
    System.clearProperty("ohmyrasp.debug");
    HookActivation.activate();
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

  @Test
  void anOperationNoRuleCanMatchNeverTouchesItsArguments() throws Exception {
    Watched watched = new Watched();
    List<Object> bean = new ArrayList<>();
    OhMyRaspHooks.beforeXmlDecoderInvoke(new Object[] {watched}, ArrayList.class.getMethod("add", Object.class), bean);
    OhMyRaspHooks.beforeXmlDecoderNew(StringBuilder.class, new Object[] {watched});
    OhMyRaspHooks.beforeJavaBeansStatement(new Statement(bean, "add", new Object[] {watched}));
    OhMyRaspHooks.beforeJavaBeansStatement(new Expression(bean, "add", new Object[] {watched}));
    assertEquals(List.of(), watched.calls);
    assertFalse(recorded().contains("xml_decoder"), recorded());
  }

  @Test
  void aCandidateWithAnEndlessIterableArgumentReturns() throws Exception {
    Endless endless = new Endless();
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeXmlDecoderInvoke(
            new Object[] {endless}, Runtime.class.getMethod("exec", String[].class), Runtime.getRuntime()));
    assertTrue(endless.taken <= 64, "elements taken: " + endless.taken);
  }

  @Test
  void withTheHooksOffAnEntryReturnsItsArgumentsAndDoesNothing() throws Exception {
    Watched watched = new Watched();
    Object[] arguments = {watched};
    HookActivation.deactivate();
    assertSame(arguments, OhMyRaspHooks.beforeXmlDecoderInvoke(
        arguments, ProcessBuilder.class.getMethod("start"), new ProcessBuilder("sh", "-c", "id")));
    OhMyRaspHooks.beforeXmlDecoderNew(PrintWriter.class, new Object[] {"/srv/app/webapps/ROOT/shell.jsp", watched});
    HookActivation.activate();
    assertEquals(List.of(), watched.calls);
    assertFalse(recorded().contains("xml_decoder"), recorded());
  }

  @Test
  void aNullArgumentsArrayIsPassedOnAndTheTargetStillDecides() throws Exception {
    assertNull(OhMyRaspHooks.beforeXmlDecoderInvoke(
        null, Integer.class.getMethod("valueOf", String.class), Integer.class));
    OhMyRaspHooks.beforeXmlDecoderNew(PrintWriter.class, null);
    assertFalse(recorded().contains("xml_decoder"), recorded());
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeXmlDecoderInvoke(
            null, ProcessBuilder.class.getMethod("start"), new ProcessBuilder("sh", "-c", "id")));
  }

  @Test
  void anInternalFailureReturnsAndItsReportCannotThrow() throws Exception {
    System.setProperty("ohmyrasp.debug", "true");
    PrintStream err = System.err;
    System.setErr(new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
    try {
      Object[] arguments = {new Failing()};
      assertSame(arguments, OhMyRaspHooks.beforeXmlDecoderInvoke(
          arguments, Runtime.class.getMethod("exec", String[].class), Runtime.getRuntime()));
      OhMyRaspHooks.beforeXmlDecoderNew(PrintWriter.class, new Object[] {new Failing()});
      OhMyRaspHooks.quiet("test", new Unprintable());
    } finally {
      System.setErr(err);
    }
  }

  /** An argument that records any call the agent makes on it. */
  private static final class Watched implements Iterable<Object> {
    final List<String> calls = new ArrayList<>();

    @Override
    public Iterator<Object> iterator() {
      calls.add("iterator");
      return Collections.emptyIterator();
    }

    @Override
    public String toString() {
      calls.add("toString");
      return "watched";
    }
  }

  /** Hands out nulls and blanks for ever; gives up after 100000, so a test without a bound fails instead of hanging. */
  private static final class Endless implements Iterable<Object> {
    int taken;

    @Override
    public Iterator<Object> iterator() {
      return new Iterator<>() {
        @Override
        public boolean hasNext() {
          return true;
        }

        @Override
        public Object next() {
          if (++taken > 100_000) throw new IllegalStateException("not bounded");
          return taken % 2 == 0 ? null : " ";
        }
      };
    }
  }

  /** A failure whose own description throws, as an application's exception may. */
  private static final class Unprintable extends RuntimeException {
    @Override
    public String getMessage() {
      throw new IllegalStateException("getMessage");
    }

    @Override
    public String toString() {
      throw new IllegalStateException("toString");
    }
  }

  private static final class Failing implements Iterable<Object> {
    @Override
    public Iterator<Object> iterator() {
      throw new Unprintable();
    }
  }
}
