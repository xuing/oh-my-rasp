package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.OutputStream;
import java.io.PrintStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Reporting a detection never decides whether it is enforced. */
final class OhMyRaspHooksReportingTest {
  @AfterEach
  void reset() {
    OhMyRaspHooks.reportTo(null);
    OhMyRaspHooks.exitHttpRequest();
    System.clearProperty("ohmyrasp.block");
  }

  /**
   * The event goes inline to a console the application replaced with one that throws. The write
   * was decided as a block, so it is blocked; only the event is lost.
   */
  @Test
  void aBlockingDetectionBlocksWhenItsEventCannotBeRecorded() {
    PrintStream failing = new PrintStream(new FailingOutput());
    OhMyRaspHooks.reportTo(
        JsonEventLogger.newForTesting(null, "stdout", 0, false, failing, failing));
    String script = "/srv/app/webapps/ROOT/shell.jsp";

    // Not blocking: the failed report is the hook's own error and the application goes on.
    OhMyRaspHooks.enterHttpRequest(new OhMyRaspHooksPolicyTest.FakeRequest(), new OhMyRaspHooksPolicyTest.FakeResponse());
    assertDoesNotThrow(() -> OhMyRaspHooks.beforeFileWrite(script));
    OhMyRaspHooks.exitHttpRequest();

    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.enterHttpRequest(new OhMyRaspHooksPolicyTest.FakeRequest(), new OhMyRaspHooksPolicyTest.FakeResponse());
    assertThrows(
        OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeFileWrite(script),
        "a failure while recording the event let a blocked write proceed");
  }

  /** An output stream that fails every write with an unchecked exception. */
  private static final class FailingOutput extends OutputStream {
    @Override
    public void write(int b) {
      throw new IllegalStateException("console closed by the application");
    }

    @Override
    public void write(byte[] bytes, int offset, int length) {
      throw new IllegalStateException("console closed by the application");
    }
  }
}
