package io.ohmyrasp.agent;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.control.ControlPlaneClient;
import io.ohmyrasp.agent.control.ControlPlaneConfig;
import io.ohmyrasp.agent.hook.HookActivation;
import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.OutputStream;
import java.io.PrintStream;
import org.junit.jupiter.api.Test;

/** Once the hooks are on, nothing in a start's commit may throw out of the start: the launcher would report a failure. */
final class BootstrapAgentCommitTest {
  /**
   * The cloud client refuses to start (its executor is shut down), and the line that reports this cannot be printed
   * because the application replaced stderr with a stream that throws. The commit still returns, with the hooks on
   * and the client closed.
   */
  @Test
  void aCommitDoesNotThrowWhenCloudReportingFailsAndItsReportCannotBePrinted() {
    boolean wasActive = HookActivation.active();
    PrintStream original = System.err;
    ControlPlaneClient client = ControlPlaneClient.prepare(
        new ControlPlaneConfig("http://127.0.0.1:9", "app", "secret", "env", "node", "java", "1"), (policy, key) -> {});
    client.close();
    BootstrapAgent.Started started = new BootstrapAgent.Started();
    started.controlPlane = client;
    started.logger = JsonEventLogger.discarding();
    try {
      System.setErr(new PrintStream(new OutputStream() {
        @Override public void write(int b) {
          throw new IllegalStateException("console closed by the application");
        }

        @Override public void write(byte[] bytes, int offset, int length) {
          throw new IllegalStateException("console closed by the application");
        }
      }));
      assertDoesNotThrow(started::commit);
      assertTrue(HookActivation.active(), "the commit did not turn the hooks on");
    } finally {
      System.setErr(original);
      if (!wasActive) {
        HookActivation.deactivate();
      }
    }
  }
}
