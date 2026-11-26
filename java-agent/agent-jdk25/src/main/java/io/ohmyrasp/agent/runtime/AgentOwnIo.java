package io.ohmyrasp.agent.runtime;

/**
 * Marks the agent's own event and control-file I/O on the current thread. While it is marked the
 * hooks neither report nor block, so a log or control path that matches a file rule cannot
 * re-enter them.
 */
public final class AgentOwnIo {
  private static final ThreadLocal<Boolean> ACTIVE = new ThreadLocal<>();

  private AgentOwnIo() {}

  public static boolean active() {
    return ACTIVE.get() != null;
  }

  /** Marks this thread; false when it already was, so only the outermost caller clears it. */
  public static boolean enter() {
    if (ACTIVE.get() != null) {
      return false;
    }
    ACTIVE.set(Boolean.TRUE);
    return true;
  }

  public static void exit(boolean entered) {
    if (entered) {
      ACTIVE.remove();
    }
  }
}
