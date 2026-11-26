package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.runtime.AgentOwnIo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The agent's own event and control I/O is invisible to its hooks. The packaged-agent probe
 * java-agent/probes/own-writes runs the same case through the instrumented JDK file classes.
 */
final class OhMyRaspHooksOwnIoTest {
  @AfterEach
  void reset() {
    OhMyRaspHooks.exitHttpRequest();
    System.clearProperty("ohmyrasp.block");
  }

  @Test
  void theAgentsOwnIoIsNeitherReportedNorBlocked() {
    System.setProperty("ohmyrasp.block", "true");
    OhMyRaspHooks.enterHttpRequest(new OhMyRaspHooksPolicyTest.FakeRequest(), new OhMyRaspHooksPolicyTest.FakeResponse());
    String spool = "/srv/app/webapps/ROOT/events.jsp";

    boolean entered = AgentOwnIo.enter();
    try {
      assertTrue(entered);
      assertFalse(AgentOwnIo.enter(), "a nested mark leaves clearing to the outermost caller");
      assertDoesNotThrow(() -> OhMyRaspHooks.beforeFileWrite(spool));
    } finally {
      AgentOwnIo.exit(entered);
    }
    assertFalse(AgentOwnIo.active());

    // The same write by the application is blocked.
    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeFileWrite(spool));
  }
}
