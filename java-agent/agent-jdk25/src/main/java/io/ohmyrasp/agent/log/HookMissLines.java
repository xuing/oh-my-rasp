package io.ohmyrasp.agent.log;

import io.ohmyrasp.agent.hookmiss.HookExpectations;
import io.ohmyrasp.agent.hookmiss.HookMissSink;
import io.ohmyrasp.agent.hookmiss.HookMisses;
import io.ohmyrasp.agent.runtime.AgentOwnIo;

/**
 * The primary agent's hook-miss writer: each diagnostic is one {@code "kind":"diagnostic"} line through
 * {@link JsonEventLogger#recordDiagnostic}, which the daemon classifies by its {@code kind} and never uploads as
 * an attack.
 */
public final class HookMissLines implements HookMissSink {
  private final JsonEventLogger logger;

  public HookMissLines(JsonEventLogger logger) {
    this.logger = logger;
  }

  /**
   * Turns the report on with the primary table, before the transformer is added. A table that cannot be read
   * leaves the report off and the agent starts as before: the diagnostic must not cost the protection.
   *
   * @return whether the report is on
   */
  public static boolean start() {
    try {
      HookMisses.start(HookExpectations.load("primary"), new HookMissLines(JsonEventLogger.get()));
      return true;
    } catch (Throwable unavailable) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP] hook-miss report off: " + unavailable);
      }
      return false;
    }
  }

  @Override
  public void write(String diagnostic, String fields) {
    logger.recordDiagnostic(diagnostic, fields);
  }

  @Override
  public boolean enterOwnIo() {
    return AgentOwnIo.enter();
  }

  @Override
  public void exitOwnIo(boolean entered) {
    AgentOwnIo.exit(entered);
  }
}
