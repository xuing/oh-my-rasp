package io.ohmyrasp.agent.backport;

import io.ohmyrasp.agent.hookmiss.HookExpectations;
import io.ohmyrasp.agent.hookmiss.HookMissSink;
import io.ohmyrasp.agent.hookmiss.HookMisses;

/**
 * The backport lines' hook-miss writer: each diagnostic is one event line through {@link RaspRuntime#writeEvent},
 * {@code {"event":"ohmyrasp-hook-miss","timestamp":<epoch ms>,...}} or, after the limit,
 * {@code "event":"ohmyrasp-hook-miss-suppressed"}. Like the start line it has an {@code event} member and no
 * {@code algorithm} or {@code action}, so a daemon that does not know it counts it as an ignored line, never as a
 * detection.
 */
public final class BackportHookMisses implements HookMissSink {
  BackportHookMisses() {}

  /**
   * Turns the report on with the backport table, before the line registers a transformer, held: what a class loaded
   * during the start reports is queued, and the report's worker thread is created only by {@link HookMisses#release},
   * which the entry class calls once the start has committed ({@link HookMisses#stop} drops it when the start
   * fails). A table that cannot be read leaves the report off and the line starts as before: the diagnostic must not
   * cost the protection.
   *
   * @return whether the report is on
   */
  public static boolean start() {
    try {
      HookMisses.startHeld(HookExpectations.load("backport"), new BackportHookMisses());
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
    String event = "hook_miss".equals(diagnostic) ? "ohmyrasp-hook-miss" : "ohmyrasp-hook-miss-suppressed";
    RaspRuntime.writeEvent(RaspRuntime.resolveLogPath(),
        "{\"event\":\"" + event + "\",\"timestamp\":" + System.currentTimeMillis() + "," + fields + "}");
  }

  @Override
  public boolean enterOwnIo() {
    return RaspRuntime.enterOwnIo();
  }

  @Override
  public void exitOwnIo(boolean entered) {
    RaspRuntime.exitOwnIo(entered);
  }
}
