package io.ohmyrasp.agent.hook;

/**
 * Whether the code the primary line injects into application and JDK classes acts. Removing a transformer does not
 * remove what it already injected, and a class rewritten during a start that then fails keeps the calls; so every
 * entry the injected code calls ({@link OhMyRaspHooks}, {@link DeserializationGuard}) first asks {@link #inactive}
 * and, when it is, returns at once with what the uninstrumented code would have had: no detection, no event, no
 * block, no request state.
 *
 * <p>The flag is off until {@code BootstrapAgent} commits a start (the last step, after which nothing of the start
 * can fail) and is turned off as the first step of undoing a start that failed. It is one static volatile field of
 * a class on the bootstrap search, so the injected calls of every loader see the same value: one volatile read per
 * hook entry once the agent runs. The start's warm-up calls the hooks before the flag is on, on its own thread
 * only ({@link #warmingUp}); no other thread sees them act before the commit.
 */
public final class HookActivation {
  private static volatile boolean active;
  // The thread running Warmup, while it runs: the hooks act for it alone before the start commits.
  private static volatile Thread warmingUp;

  private HookActivation() {}

  /** True when a hook entry must do nothing: the start has not committed, or it failed and was undone. */
  public static boolean inactive() {
    return !active && warmingUp != Thread.currentThread();
  }

  /** Whether a start committed and was not undone. */
  public static boolean active() {
    return active;
  }

  /** Turns the hooks on. Only the start calls it, once it has committed. */
  public static void activate() {
    active = true;
  }

  /** Turns the hooks off. The undo of a failed start calls it first. */
  public static void deactivate() {
    active = false;
  }

  /** Lets the hooks act on the current thread only, until {@link #endWarmUp}; the warm-up runs between the two. */
  static void beginWarmUp() {
    warmingUp = Thread.currentThread();
  }

  static void endWarmUp() {
    warmingUp = null;
  }
}
