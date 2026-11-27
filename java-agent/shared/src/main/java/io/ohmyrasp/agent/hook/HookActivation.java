package io.ohmyrasp.agent.hook;

/**
 * Whether the code an agent line injects into application and JDK classes acts. Removing a transformer does not
 * remove what it already injected, and a class rewritten during a start that then fails keeps the calls; so every
 * method the injected code calls (the primary's {@code OhMyRaspHooks} and {@code DeserializationGuard}, the backports'
 * {@code BackportHooks}, and the helpers in {@code :shared} that a visitor calls directly) first asks
 * {@link #inactive} and, when it is, returns at once with what the uninstrumented code would have had: no
 * detection, no event, no block, no request or scope state; a helper that stands in for an application call makes
 * that call. A scope exit is the exception: it takes the token its entry returned (null when the entry opened
 * nothing, as it does while the hooks are off) and undoes exactly that, whatever the flag says by then. The primary's
 * {@code HookActivationTest} checks this against an inventory of the calls in transformed bytecode.
 *
 * <p>The flag is off until the line's start commits (the last step, after which nothing of the start can fail: the
 * primary's {@code BootstrapAgent}, a backport's entry class once its start line is written) and is turned off as
 * the first step of undoing a start that failed. It is one static volatile field of a class on the bootstrap search,
 * so the injected calls of every loader see the same value: one volatile read per hook entry once the agent runs. A
 * JVM runs one line, so the primary and the backports never share it. The primary's warm-up calls the hooks before
 * the flag is on, on its own thread only ({@link #warmingUp}); no other thread sees them act before the commit.
 */
public final class HookActivation {
  private static volatile boolean active;
  // The thread running the primary's Warmup, while it runs: the hooks act for it alone before the start commits.
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
