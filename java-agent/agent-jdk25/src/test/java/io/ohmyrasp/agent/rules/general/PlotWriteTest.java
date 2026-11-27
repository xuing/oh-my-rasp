package io.ohmyrasp.agent.rules.general;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class PlotWriteTest {
  private static PlotWrite prepare(Object owner, String text) {
    byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
    return PlotWrite.bytes(owner, bytes, 0, bytes.length);
  }

  /**
   * The backport file transformers call these from FileOutputStream. While the hooks are off (before a start commits,
   * or after a failed one left the calls behind) a write is not scanned and an open or close changes no stream.
   */
  @Test void whileTheHooksAreOffAWriteIsNeitherRegisteredNorScanned() {
    Object registered = new Object();
    Object openedWhileOff = new Object();
    String directive = "set xrange [system(0)]\n";
    PlotWrite.opened(registered, "chart.plot", false);
    io.ohmyrasp.agent.hook.HookActivation.deactivate();
    try {
      PlotWrite.opened(openedWhileOff, "chart.plot", false);
      assertNull(prepare(registered, directive), "a write was scanned while the hooks were off");
      assertNull(PlotWrite.single(registered, 's'), "a single-byte write was scanned while the hooks were off");
      PlotWrite.exposed(registered);
      PlotWrite.closed(registered);
    } finally {
      io.ohmyrasp.agent.hook.HookActivation.activate();
    }
    assertNull(prepare(openedWhileOff, directive), "an open while the hooks were off registered the stream");
    assertTrue(prepareAndCommit(registered, directive), "a close while the hooks were off forgot the stream");
  }

  @Test void commitOnlySuccessfulBytesAndRecoverAfterAnUncertainWrite() {
    Object owner = new Object();
    PlotWrite.opened(owner, "chart.plot", false);
    PlotWrite.finished(prepare(owner, "set yrange [sys"), true);
    PlotWrite denied = prepare(owner, "tem(0)]");
    assertTrue(denied.hasDirective());
    PlotWrite.cancelled(denied);
    assertFalse(prepareAndCommit(owner, "log(0)]\n"));
    PlotWrite.finished(prepare(owner, "set yrange [sys"), false);
    assertFalse(prepareAndCommit(owner, "tem(0)]\n"));
    assertTrue(prepareAndCommit(owner, "set xrange [system(0)]\n"));
    assertFalse(prepareAndCommit(owner, "plot 42\n"));
    PlotWrite.closed(owner);
    assertNull(prepare(owner, "set xrange [system(0)]"));
  }

  private static boolean prepareAndCommit(Object owner, String text) {
    PlotWrite write = prepare(owner, text);
    PlotWrite.finished(write, true);
    return write.hasDirective();
  }

  @Test void unrelatedOrOverlappingWritesCannotCompleteAnotherPrefix() {
    Object owner = new Object(), other = new Object();
    PlotWrite.opened(owner, "chart.plot", false);
    PlotWrite.opened(other, "chart.plot", false);
    PlotWrite first = prepare(owner, "set yrange [sys");
    PlotWrite second = prepare(owner, "tem(0)]");
    assertFalse(second.hasDirective());
    PlotWrite.finished(second, true);
    PlotWrite.finished(first, true);
    assertFalse(prepareAndCommit(owner, "tem(0)]\n"));
    assertFalse(prepareAndCommit(other, "tem(0)]\n"));
    PlotWrite.finished(prepare(owner, "set xrange [sys"), true);
    PlotWrite.exposed(owner);
    assertFalse(prepareAndCommit(owner, "tem(0)]"));
  }

  @Test void protectEarlierBytesOfALargeWriteAndIgnoreQuotedOrCommentedText() {
    Object owner = new Object();
    PlotWrite.opened(owner, "chart.gp", false);
    assertFalse(prepareAndCommit(owner, "set key title 'Steve''s "));
    assertFalse(prepareAndCommit(owner, "system(0)'\n# set xrange [system(0)]\n"));
    assertFalse(prepareAndCommit(owner, "set key title \"system(0)\" # key; system 'reference'\r\n"));
    assertFalse(prepareAndCommit(owner, "set xrange [SYSTEM(0)]# key; system 'notes'\n"));
    assertFalse(prepareAndCommit(owner, "set key; system"));
    assertFalse(prepareAndCommit(owner, "atic = 42\n"));
    assertTrue(prepareAndCommit(owner, "set xrange [system(0)]\n" + "x".repeat(20000)));
  }
}
